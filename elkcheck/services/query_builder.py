import json
import re


def _normalize_kql_text(kql: str) -> str:
    text = (kql or "").strip()
    if not text:
        return text
    # Make common KQL spacing work with Elasticsearch query_string parser.
    text = re.sub(r"\s*:\s*", ":", text)
    # Normalize logical operators to query_string style.
    text = re.sub(r"\bnot\b", "NOT", text, flags=re.IGNORECASE)
    text = re.sub(r"\band\b", "AND", text, flags=re.IGNORECASE)
    text = re.sub(r"\bor\b", "OR", text, flags=re.IGNORECASE)
    return text


def build_query(monitor):
    mode = monitor.get("query_mode", "json")
    timestamp_field = monitor.get("timestamp_field", "@timestamp")
    window_seconds = int(monitor.get("window_seconds", 60))

    if mode == "kql":
        kql = _normalize_kql_text(monitor.get("query_kql", ""))
        if not kql:
            raise ValueError("KQL mode is enabled but query_kql is empty.")
        base_query = {
            "query_string": {
                "query": kql,
                "default_operator": "AND",
            }
        }
    else:
        raw = monitor.get("query_json", '{"query":{"match_all":{}}}')
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON query: {exc}") from exc
        base_query = parsed.get("query", {"match_all": {}})

    return {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "must": [base_query],
                "filter": [
                    {
                        "range": {
                            timestamp_field: {"gte": f"now-{window_seconds}s", "lte": "now"}
                        }
                    }
                ],
            }
        },
    }

