import time

from .alert_dispatcher import (
    dispatch_error_escalation,
    dispatch_notifications,
    dispatch_recovery_notifications,
)
from .es_client import elasticsearch_client, search_silencing_product_warning
from .query_builder import build_query
from .monitor_resolver import resolve_monitor_connection
from .rule_engine import evaluate_rules


def run_monitor_check(monitor, state_store):
    monitor_id = monitor.get("id", "")

    def _inc_alert_count():
        st_local = state_store.get(monitor_id)
        state_store.update(monitor_id, alert_count=int(st_local.get("alert_count") or 0) + 1)

    try:
        monitor = resolve_monitor_connection(monitor)
        state = state_store.get(monitor_id)
        previous_count = state.get("last_count")

        es = elasticsearch_client(
            monitor["host"],
            monitor.get("username", ""),
            monitor.get("password", ""),
            request_timeout=30,
        )
        query = build_query(monitor)
        result = search_silencing_product_warning(
            es, index=monitor["index"], body=query
        )
        current_count = int(result["hits"]["total"]["value"])

        rules = monitor.get("rules", {})
        volatility = rules.get("volatility", {})
        volatility_baseline = None
        if volatility.get("enabled", False):
            window_minutes = max(1, int(volatility.get("window_minutes", 5) or 5))
            retention = window_minutes * 60
            state_store.append_count_sample(monitor_id, current_count, retention)
            volatility_baseline = state_store.volatility_baseline(monitor_id)

        reasons = evaluate_rules(rules, current_count, previous_count, volatility_baseline)
        prev_reasons = set(state.get("last_rule_reasons") or [])
        curr_reasons = set(reasons)

        status = "healthy"
        if not monitor.get("enabled", True):
            status = "disabled"
        elif reasons:
            status = "alert"
        else:
            status = "ok"

        state_store.update(
            monitor_id,
            previous_count=previous_count,
            last_count=current_count,
            last_rule_reasons=list(curr_reasons),
            status=status,
            connection_ok=True,
            last_error=None,
            consecutive_failures=0,
            error_escalation_sms_sent=False,
            error_escalation_call_sent=False,
            error_escalation_bale_sent=False,
        )

        if reasons:
            cooldown = int(monitor.get("alert_cooldown", 300))
            now = time.time()
            if now - float(state.get("last_alert", 0) or 0) >= cooldown:
                try:
                    dispatch_notifications(monitor, reasons)
                    _inc_alert_count()
                except Exception as alert_exc:
                    state_store.update(
                        monitor_id,
                        last_error=f"Alert dispatch failed: {alert_exc}",
                    )
                state_store.update(monitor_id, last_alert=now)

        recovery_reasons = []
        if rules.get("no_hit", {}).get("notify_on_recovery", False):
            if "no_hit" in prev_reasons and "no_hit" not in curr_reasons:
                recovery_reasons.append("no_hit_recovered")
        if rules.get("reverse_hit", {}).get("notify_on_recovery", False):
            if "reverse_hit" in prev_reasons and "reverse_hit" not in curr_reasons:
                recovery_reasons.append("reverse_hit_recovered")
        if recovery_reasons:
            try:
                dispatch_recovery_notifications(monitor, recovery_reasons)
                _inc_alert_count()
            except Exception as alert_exc:
                state_store.update(
                    monitor_id,
                    last_error=f"Recovery alert dispatch failed: {alert_exc}",
                )

        return {"monitor_id": monitor_id, "count": current_count, "reasons": reasons}
    except Exception as exc:
        try:
            st = state_store.get(monitor_id)
            fails_streak = int(st.get("consecutive_failures") or 0) + 1
            sms_sent = bool(st.get("error_escalation_sms_sent"))
            call_sent = bool(st.get("error_escalation_call_sent"))
            bale_sent = bool(st.get("error_escalation_bale_sent"))
            state_store.update(
                monitor_id,
                connection_ok=False,
                last_error=str(exc),
                status="error",
                errors=int(st.get("errors") or 0) + 1,
                consecutive_failures=fails_streak,
            )
            esc = monitor.get("rules", {}).get("error_escalation", {})
            if esc.get("enabled"):
                sms_n = int(esc.get("sms_after_failures") or 0)
                call_n = int(esc.get("call_after_failures") or 0)
                bale_n = int(esc.get("bale_after_failures") or 0)
                if sms_n > 0 and fails_streak >= sms_n and not sms_sent:
                    try:
                        dispatch_error_escalation(
                            monitor,
                            send_sms=True,
                            send_call=False,
                            send_bale=False,
                            failures=fails_streak,
                            error_text=str(exc),
                        )
                        _inc_alert_count()
                        state_store.update(monitor_id, error_escalation_sms_sent=True)
                    except Exception:
                        pass
                if call_n > 0 and fails_streak >= call_n and not call_sent:
                    try:
                        dispatch_error_escalation(
                            monitor,
                            send_sms=False,
                            send_call=True,
                            send_bale=False,
                            failures=fails_streak,
                            error_text=str(exc),
                        )
                        _inc_alert_count()
                        state_store.update(monitor_id, error_escalation_call_sent=True)
                    except Exception:
                        pass
                if bale_n > 0 and fails_streak >= bale_n and not bale_sent:
                    try:
                        dispatch_error_escalation(
                            monitor,
                            send_sms=False,
                            send_call=False,
                            send_bale=True,
                            failures=fails_streak,
                            error_text=str(exc),
                        )
                        _inc_alert_count()
                        state_store.update(monitor_id, error_escalation_bale_sent=True)
                    except Exception:
                        pass
        except Exception:
            pass
        return {"monitor_id": monitor_id, "error": str(exc)}
