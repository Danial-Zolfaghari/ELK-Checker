import json

from .es_client import elasticsearch_client, format_transport_error, search_silencing_product_warning
from .query_builder import _normalize_kql_text, build_query


def validate_monitor_query(monitor):
    try:
        mode = monitor.get("query_mode", "json")
        if mode == "json":
            raw = monitor.get("query_json", "")
            if not raw or not str(raw).strip():
                return False, "Query JSON is empty."
            try:
                parsed = json.loads(raw) if isinstance(raw, str) else raw
            except json.JSONDecodeError as exc:
                return False, f"Invalid JSON: {exc}"
            if not isinstance(parsed, dict):
                return False, "Query JSON must be an object."
        elif mode == "kql":
            kql = _normalize_kql_text(monitor.get("query_kql") or "")
            if not kql:
                return False, "KQL query is empty."
        else:
            return False, f"Unknown query_mode: {mode}"

        build_query(monitor)
    except ValueError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, f"Query build error: {exc}"

    host = (monitor.get("host") or "").strip()
    index = (monitor.get("index") or "").strip()
    if not host:
        return False, "Host is required."
    if not index:
        return False, "Index is required."

    try:
        es = elasticsearch_client(
            host,
            monitor.get("username", ""),
            monitor.get("password", ""),
            request_timeout=25,
        )
        body = build_query(monitor)
        search_silencing_product_warning(es, index=index, body=body)
        return True, ""
    except Exception as exc:
        return False, f"Elasticsearch rejected the query: {format_transport_error(exc)}"
