"""Prompt-injection guard: a dedicated classifier scans untrusted alert text (ADR 0008).

Model: meta-llama/llama-prompt-guard-2-86m on Groq. It returns one number, the
probability that the text is a prompt-injection attempt (0.0005 for a normal sshd line,
0.9996 for "ignore all previous instructions...").

What gets scanned: text an attacker can influence - the raw log, username, file path,
and community-written OTX pulse names/tags. The model reads at most 512 tokens, so text
is split into chunks; the highest chunk score counts.

On detection the alert is still triaged (decision: flag, don't block), but:
- the agent sees a `prompt_injection_suspected` signal, and
- a benign/false_positive verdict is overridden to needs_investigation (see graph.py).

Fail soft: if the guard fails, triage continues and the error is recorded.
Scores are cached (same text -> same score), so evaluation re-runs don't spend quota.
Set PROMPT_GUARD=off in .env to disable.
"""

import hashlib
import logging
import os

import groq
from dotenv import load_dotenv

from pipeline.intel.cache import cached_lookup

load_dotenv()

MODEL = "meta-llama/llama-prompt-guard-2-86m"
THRESHOLD = 0.5
MAX_CHUNK_CHARS = 1200  # comfortably under the 512-token limit
GUARD_ERRORS = (RuntimeError, ValueError, groq.GroqError)

logger = logging.getLogger(__name__)


def _enabled():
    return (os.environ.get("PROMPT_GUARD") or "on").strip().lower() not in ("off", "false", "0", "no")


def collect_untrusted_text(alert):
    """Every attacker-influenceable string in the alert, in a stable order."""
    texts = [alert.get("raw_log"), alert.get("user"), alert.get("file_path")]
    intel = alert.get("intel") or {}
    for key in ("otx_ip", "otx_hash"):
        otx = intel.get(key) or {}
        for field in ("pulses", "tags", "malware_families", "adversaries"):
            texts.extend(otx.get(field) or [])
    return [t for t in texts if isinstance(t, str) and t.strip()]


def chunk(texts, max_chars=MAX_CHUNK_CHARS):
    """Join texts with ' | ' into chunks of at most max_chars (long single texts are split)."""
    chunks, current = [], ""
    for t in texts:
        for start in range(0, len(t), max_chars):
            piece = t[start:start + max_chars]
            if current and len(current) + 3 + len(piece) > max_chars:
                chunks.append(current)
                current = piece
            else:
                current = f"{current} | {piece}" if current else piece
    if current:
        chunks.append(current)
    return chunks


def _fetch_score(text):
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY environment variable is not set")
    client = groq.Groq(api_key=api_key, timeout=20, max_retries=3)
    reply = client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": text}])
    return {"score": float(reply.choices[0].message.content.strip())}


def classify(text):
    """Injection probability for one chunk (cached by a hash of the text)."""
    key = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return cached_lookup("prompt_guard", key, lambda _: _fetch_score(text), lambda _, raw: raw["score"])


def scan(alert, classify_fn=classify):
    """Return {"enabled", "score", "suspected", "chunks", "error"} for one alert."""
    if not _enabled():
        return {"enabled": False}
    chunks = chunk(collect_untrusted_text(alert))
    if not chunks:
        return {"enabled": True, "score": 0.0, "suspected": False, "chunks": 0, "error": None}
    try:
        score = max(classify_fn(c) for c in chunks)
    except GUARD_ERRORS as e:
        logger.warning("Prompt guard failed for alert %s: %s", alert.get("alert_id"), e)
        return {"enabled": True, "score": None, "suspected": False, "chunks": len(chunks), "error": str(e)[:200]}
    suspected = score >= THRESHOLD
    if suspected:
        logger.warning("Prompt injection suspected in alert %s (score %.3f)", alert.get("alert_id"), score)
    return {"enabled": True, "score": round(score, 4), "suspected": suspected, "chunks": len(chunks), "error": None}
