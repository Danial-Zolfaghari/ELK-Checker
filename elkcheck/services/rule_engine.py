def evaluate_rules(rules, current_count, previous_count, volatility_baseline=None):
    rules = rules or {}
    alerts = []

    if rules.get("no_hit", {}).get("enabled", True) and current_count == 0:
        alerts.append("no_hit")

    if rules.get("reverse_hit", {}).get("enabled", False) and current_count > 0:
        alerts.append("reverse_hit")

    count_threshold = rules.get("count_threshold", {})
    if count_threshold.get("enabled", False):
        value = int(count_threshold.get("value", 0))
        operator = count_threshold.get("operator", "gt")
        if operator == "gt" and current_count > value:
            alerts.append("count_threshold_gt")
        if operator == "lt" and current_count < value:
            alerts.append("count_threshold_lt")

    volatility = rules.get("volatility", {})
    if volatility.get("enabled", False) and volatility_baseline is not None:
        pct_threshold = float(volatility.get("percent", 0) or 0)
        if pct_threshold <= 0:
            pass
        else:
            base = float(volatility_baseline)
            change = abs(float(current_count) - base) / max(base, 1.0) * 100.0
            if change >= pct_threshold:
                alerts.append("volatility")

    return alerts
