"""The agent's output contract: what a triage result looks like.

Discord, DFIR-IRIS and the evaluation (Phase 7) all depend on these fields, so
changing them means updating those too. The LLM's answer is validated against this
schema; anything that doesn't fit is rejected or trimmed.

The LLM's output is also treated as untrusted (a prompt injection could influence it),
so text is cleaned and list lengths are capped on the way out too.
"""

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from pipeline.sanitize import clean_text, unique_clean

Verdict = Literal["true_positive", "benign_true_positive", "false_positive", "needs_investigation"]
Confidence = Literal["low", "medium", "high"]

ATTACK_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
MAX_LIST = 5


class TriageResult(BaseModel):
    summary: str = Field(
        description="2-4 sentences: what happened, on which host/user, and why it matters."
    )
    verdict: Verdict = Field(
        description=(
            "true_positive = real malicious activity. "
            "benign_true_positive = the detection is correct but the activity is harmless or "
            "authorised (e.g. a test file, an admin task). "
            "false_positive = the detection fired on something that did not happen as described. "
            "needs_investigation = not enough evidence to decide."
        )
    )
    confidence: Confidence = Field(description="How sure you are of the verdict.")
    confidence_reason: str = Field(description="One sentence explaining the confidence level.")
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs that fit the activity, e.g. T1110 or T1110.001.",
    )
    key_evidence: list[str] = Field(
        default_factory=list,
        description="Up to 5 short facts from the alert data that support the verdict.",
    )
    next_steps: list[str] = Field(
        default_factory=list,
        description="Up to 5 recommended actions for a human analyst. Recommendations only.",
    )

    @field_validator("summary", mode="after")
    @classmethod
    def _clean_summary(cls, v):
        return clean_text(v, max_len=800) or ""

    @field_validator("confidence_reason", mode="after")
    @classmethod
    def _clean_reason(cls, v):
        return clean_text(v, max_len=300) or ""

    @field_validator("mitre_techniques", mode="after")
    @classmethod
    def _valid_attack_ids(cls, v):
        # Allowlist: only real-looking technique IDs survive.
        out = []
        for tid in v:
            tid = tid.strip().upper() if isinstance(tid, str) else ""
            if ATTACK_ID_RE.fullmatch(tid) and tid not in out:
                out.append(tid)
        return out[:MAX_LIST]

    @field_validator("key_evidence", "next_steps", mode="after")
    @classmethod
    def _cap_lists(cls, v):
        return unique_clean(v, MAX_LIST, max_len=300)
