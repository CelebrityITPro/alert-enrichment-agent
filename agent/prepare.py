"""Turn an enriched alert into a compact, cleaned view for the LLM.

Two goals:
1. Less noise and fewer tokens: only the fields an analyst needs (free-tier quotas are small).
2. Defence against prompt injection: every string came from logs or community intel,
   so it is flattened to one line, length-capped, and stripped of < and > so it can't
   close the <alert_data> tags the prompt wraps it in.
"""

from pipeline.sanitize import clean_text

FIELDS = [
    "alert_id", "timestamp", "description", "severity", "rule_id", "rule_groups",
    "mitre_ids", "host", "src_ip", "user", "file_path", "file_sha256",
    "raw_log", "intel", "correlation",
]
MAX_STRING = 300
MAX_RAW_LOG = 500
MAX_LIST = 10


def _clean(value, max_len=MAX_STRING):
    """Recursively clean strings, cap lists, and drop empty values."""
    if isinstance(value, str):
        text = clean_text(value.replace("<", " ").replace(">", " "), max_len=max_len)
        return text
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            c = _clean(v)
            if c not in (None, "", [], {}):
                out[str(k)] = c
        return out
    if isinstance(value, list):
        items = [_clean(v) for v in value[:MAX_LIST]]
        return [i for i in items if i not in (None, "", [], {})]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return clean_text(str(value), max_len=max_len)


def alert_for_llm(alert):
    """Return the cleaned subset of `alert` that is shown to the LLM."""
    view = {}
    for field in FIELDS:
        if field not in alert:
            continue
        max_len = MAX_RAW_LOG if field == "raw_log" else MAX_STRING
        value = _clean(alert[field], max_len=max_len) if isinstance(alert[field], str) else _clean(alert[field])
        if value not in (None, "", [], {}):
            view[field] = value
    return view
