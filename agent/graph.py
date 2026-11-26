"""The triage workflow as a LangGraph graph (ADR 0007, ADR 0009).

    START -> analyze --(submit_triage called)--------------> submit ---------> END
                     --(tool calls, under the cap)--> tools -> analyze ...      ^
                     --(no tool calls, or cap hit)--> finalize -----------------'
                                       (submit with invalid args also -> finalize)

- analyze:  the LLM reads the alert and may request tool calls
- tools:    runs the requested read-only tools
- submit:   the LLM handed in its final answer via the submit_triage tool; validate it
- finalize: fallback - ask for the answer in the TriageResult schema and validate it

Why submit_triage exists: some models (gpt-oss-20b) hand in their final answer as a
tool call during analysis. Offering a real "submit" tool matches that behaviour and
saves one LLM call per alert; finalize remains the safety net.

The tool-call cap keeps the agent from looping forever and protects the free-tier quota.
Before the graph runs, a prompt-injection classifier scans the alert (agent/guard.py).
A human-approval pause will be added in Phase 6, when the first real actions exist.
"""

import logging
from typing import Annotated, TypedDict

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from pydantic import ValidationError

from agent.guard import scan
from agent.prepare import alert_for_llm
from agent.prompts import FINAL_INSTRUCTION, SYSTEM_PROMPT, user_message
from agent.schema import TriageResult
from agent.tools import make_tools

logger = logging.getLogger(__name__)

MAX_TOOL_CALLS = 3
SUBMIT_TOOL = "submit_triage"


def submit_tool_schema():
    """The TriageResult schema exposed as a tool the LLM calls to hand in its answer."""
    spec = convert_to_openai_tool(TriageResult)
    spec["function"]["name"] = SUBMIT_TOOL
    spec["function"]["description"] = (
        "Submit your final triage for this alert. Call this exactly once, when you are done."
    )
    return spec


def _submit_call(message):
    """Return the submit_triage tool call in an AI message, if there is one."""
    for call in getattr(message, "tool_calls", None) or []:
        if call["name"] == SUBMIT_TOOL:
            return call
    return None


class TriageState(TypedDict):
    messages: Annotated[list, add_messages]  # add_messages appends instead of replacing
    tool_calls_made: int
    result: dict | None


def build_graph(llm, tools):
    """Wire the nodes together. `llm` is any LangChain chat model that supports tools."""
    llm_with_tools = llm.bind_tools([*tools, submit_tool_schema()])
    structured_llm = llm.with_structured_output(TriageResult)
    tool_node = ToolNode(tools)

    def analyze(state):
        return {"messages": [llm_with_tools.invoke(state["messages"])]}

    def submit(state):
        # Same Pydantic validation as finalize: the tool route is not a shortcut around it.
        call = _submit_call(state["messages"][-1])
        return {"result": TriageResult(**call["args"]).model_dump()}

    def run_tools(state):
        requested = len(state["messages"][-1].tool_calls)
        out = tool_node.invoke(state)
        return {**out, "tool_calls_made": state["tool_calls_made"] + requested}

    def finalize(state):
        messages = list(state["messages"])
        # If the cap stopped us mid-request, drop the unanswered tool request:
        # the API rejects a tool call that has no matching tool result.
        if isinstance(messages[-1], AIMessage) and messages[-1].tool_calls:
            messages = messages[:-1]
        result = structured_llm.invoke(messages + [HumanMessage(FINAL_INSTRUCTION)])
        return {"result": result.model_dump()}

    def route_after_analyze(state):
        last = state["messages"][-1]
        call = _submit_call(last)
        if call is not None:
            try:
                TriageResult(**call["args"])
                return "submit"
            except (ValidationError, TypeError):
                logger.info("submit_triage arguments invalid; falling back to finalize")
                return "finalize"
        if getattr(last, "tool_calls", None) and state["tool_calls_made"] < MAX_TOOL_CALLS:
            return "tools"
        return "finalize"

    graph = StateGraph(TriageState)
    graph.add_node("analyze", analyze)
    graph.add_node("tools", run_tools)
    graph.add_node("submit", submit)
    graph.add_node("finalize", finalize)
    graph.add_edge(START, "analyze")
    graph.add_conditional_edges("analyze", route_after_analyze, ["submit", "tools", "finalize"])
    graph.add_edge("tools", "analyze")
    graph.add_edge("submit", END)
    graph.add_edge("finalize", END)
    return graph.compile()


OVERRIDE_VERDICTS = {"false_positive", "benign_true_positive"}
OVERRIDE_EVIDENCE = "Prompt-injection attempt detected in alert text by classifier; verdict raised to needs_investigation."


def apply_guard_override(result, guard_result):
    """If injection is suspected, never let the alert be dismissed as harmless (ADR 0008).

    Returns (result, overridden). true_positive / needs_investigation are left alone.
    """
    if not (guard_result.get("suspected") and result and result["verdict"] in OVERRIDE_VERDICTS):
        return result, False
    result = {**result, "verdict": "needs_investigation",
              "key_evidence": [OVERRIDE_EVIDENCE, *result.get("key_evidence", [])][:5]}
    return result, True


def triage(alert, batch, llm, guard=scan):
    """Triage one enriched alert. Never raises: errors are recorded on the result (fail soft).

    `guard` is injectable so tests can pass a fake prompt-injection scanner.
    """
    alert_id = alert.get("alert_id")
    guard_result = guard(alert)
    try:
        view = alert_for_llm(alert)
        if guard_result.get("suspected"):
            view["prompt_injection_suspected"] = {
                "score": guard_result["score"],
                "note": "A classifier flagged text in this alert as a likely prompt-injection attempt.",
            }
        app = build_graph(llm, make_tools(batch, alert_id))
        state = app.invoke(
            {
                "messages": [SystemMessage(SYSTEM_PROMPT), HumanMessage(user_message(view))],
                "tool_calls_made": 0,
                "result": None,
            },
            {"recursion_limit": 2 * MAX_TOOL_CALLS + 5},
        )
        result, overridden = apply_guard_override(state["result"], guard_result)
        return {"alert_id": alert_id, "triage": result, "tool_calls": state["tool_calls_made"],
                "prompt_guard": guard_result, "guard_override": overridden, "error": None}
    except Exception as e:  # noqa: BLE001 - one bad alert must not stop the batch
        logger.warning("Triage failed for alert %s: %s", alert_id, e)
        return {"alert_id": alert_id, "triage": None, "tool_calls": 0,
                "prompt_guard": guard_result, "guard_override": False, "error": str(e)[:300]}
