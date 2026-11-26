"""The triage workflow as a LangGraph graph (ADR 0007).

    START -> analyze --(tool calls, under the cap)--> tools -> analyze ...
                     --(no tool calls, or cap hit)--> finalize -> END

- analyze:  the LLM reads the alert and may request tool calls
- tools:    runs the requested tools (read-only)
- finalize: asks for the answer in the TriageResult schema and validates it

The tool-call cap keeps the agent from looping forever and protects the free-tier quota.
A human-approval pause will be added in Phase 6, when the first real actions exist.
"""

import logging
from typing import Annotated, TypedDict

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from agent.prepare import alert_for_llm
from agent.prompts import FINAL_INSTRUCTION, SYSTEM_PROMPT, user_message
from agent.schema import TriageResult
from agent.tools import make_tools

logger = logging.getLogger(__name__)

MAX_TOOL_CALLS = 3


class TriageState(TypedDict):
    messages: Annotated[list, add_messages]  # add_messages appends instead of replacing
    tool_calls_made: int
    result: dict | None


def build_graph(llm, tools):
    """Wire the nodes together. `llm` is any LangChain chat model that supports tools."""
    llm_with_tools = llm.bind_tools(tools)
    structured_llm = llm.with_structured_output(TriageResult)
    tool_node = ToolNode(tools)

    def analyze(state):
        return {"messages": [llm_with_tools.invoke(state["messages"])]}

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
        if getattr(last, "tool_calls", None) and state["tool_calls_made"] < MAX_TOOL_CALLS:
            return "tools"
        return "finalize"

    graph = StateGraph(TriageState)
    graph.add_node("analyze", analyze)
    graph.add_node("tools", run_tools)
    graph.add_node("finalize", finalize)
    graph.add_edge(START, "analyze")
    graph.add_conditional_edges("analyze", route_after_analyze, ["tools", "finalize"])
    graph.add_edge("tools", "analyze")
    graph.add_edge("finalize", END)
    return graph.compile()


def triage(alert, batch, llm):
    """Triage one enriched alert. Never raises: errors are recorded on the result (fail soft)."""
    alert_id = alert.get("alert_id")
    try:
        app = build_graph(llm, make_tools(batch, alert_id))
        state = app.invoke(
            {
                "messages": [SystemMessage(SYSTEM_PROMPT), HumanMessage(user_message(alert_for_llm(alert)))],
                "tool_calls_made": 0,
                "result": None,
            },
            {"recursion_limit": 2 * MAX_TOOL_CALLS + 5},
        )
        return {"alert_id": alert_id, "triage": state["result"],
                "tool_calls": state["tool_calls_made"], "error": None}
    except Exception as e:  # noqa: BLE001 - one bad alert must not stop the batch
        logger.warning("Triage failed for alert %s: %s", alert_id, e)
        return {"alert_id": alert_id, "triage": None, "tool_calls": 0, "error": str(e)[:300]}
