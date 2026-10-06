import pytest

from elkcheck.persistence.security_store import SecurityStore
from elkcheck.services.query_builder import _normalize_kql_text, build_query
from elkcheck.services.rule_engine import evaluate_rules


def test_normalize_kql_text():
    assert _normalize_kql_text("status : 500 and not host : web-1") == "status:500 AND NOT host:web-1"
    assert _normalize_kql_text("  ") == ""


def test_build_json_query_wraps_time_filter():
    monitor = {
        "query_mode": "json",
        "query_json": '{"query":{"term":{"service":"api"}}}',
        "timestamp_field": "@timestamp",
        "window_seconds": 120,
    }
    body = build_query(monitor)
    assert body["size"] == 0
    assert body["track_total_hits"] is True
    assert body["query"]["bool"]["must"][0] == {"term": {"service": "api"}}
    assert body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == "now-120s"


def test_build_kql_query():
    monitor = {
        "query_mode": "kql",
        "query_kql": "status : 500 or status : 503",
        "timestamp_field": "ts",
        "window_seconds": 30,
    }
    body = build_query(monitor)
    query_string = body["query"]["bool"]["must"][0]["query_string"]
    assert query_string["query"] == "status:500 OR status:503"
    assert query_string["default_operator"] == "AND"


def test_empty_kql_is_rejected():
    with pytest.raises(ValueError):
        build_query({"query_mode": "kql", "query_kql": ""})


def test_rule_engine_thresholds_and_volatility():
    rules = {
        "no_hit": {"enabled": False},
        "count_threshold": {"enabled": True, "operator": "gt", "value": 10},
        "volatility": {"enabled": True, "percent": 50},
    }
    alerts = evaluate_rules(rules, current_count=20, previous_count=0, volatility_baseline=10)
    assert "count_threshold_gt" in alerts
    assert "volatility" in alerts


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("192.0.2.1:443", "192.0.2.1"),
        ("::ffff:192.0.2.1", "192.0.2.1"),
        ("203.0.113.5, 10.0.0.1", "203.0.113.5"),
        ("2001:db8::1", "2001:db8::1"),
        ("", "unknown"),
    ],
)
def test_normalize_ip(raw, expected):
    assert SecurityStore.normalize_ip(raw) == expected
