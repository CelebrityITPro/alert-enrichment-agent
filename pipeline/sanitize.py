"""Helpers for untrusted text (from logs or community threat intel).

This text will later reach the LLM agent and log files. Trimming it limits how much
attacker-written content gets through and stops newline tricks (fake log lines).
It is NOT a full prompt-injection defence; that comes in Phase 5.
"""

import re

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")  # newlines, tabs, escape codes...
_WHITESPACE = re.compile(r"\s+")


def clean_text(value, max_len=100):
    """Return `value` as a single trimmed line of at most `max_len` chars, or None."""
    if not isinstance(value, str):
        return None
    text = _CONTROL_CHARS.sub(" ", value)
    text = _WHITESPACE.sub(" ", text).strip()
    if not text:
        return None
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def unique_clean(values, limit, max_len=100):
    """Clean each value, drop empties and duplicates (keeping order), keep at most `limit`."""
    out = []
    for v in values:
        c = clean_text(v, max_len)
        if c and c not in out:
            out.append(c)
        if len(out) >= limit:
            break
    return out
