import os

from kavenegar import KavenegarAPI

from elkcheck.persistence.app_settings_store import AppSettingsStore
from elkcheck.persistence.data_paths import data_file
from elkcheck.services.alert_history import get_store


def _app_settings_path():
    return os.getenv("APP_SETTINGS_FILE", data_file("app_settings.json"))


def _bale_bot_url():
    store = AppSettingsStore(path=_app_settings_path())
    store.load()
    return (store.get().get("bale") or {}).get("bot_url", "").strip()


def _bale_render_template(monitor, template, *, reasons=None, failures=0, error_text=""):
    tpl = (template or "").strip()
    if not tpl:
        return None
    name = monitor.get("name", "Monitor")
    reason_text = ", ".join(reasons) if reasons else ""
    out = (
        tpl.replace("{name}", name)
        .replace("{reasons}", reason_text)
        .replace("{failures}", str(int(failures or 0)))
        .replace("{error}", str(error_text or "")[:400])
    )
    return out[:8000]


def _bale_content_rule(monitor, reasons, default_message):
    bale = monitor.get("notifications", {}).get("bale") or {}
    rendered = _bale_render_template(
        monitor, bale.get("message"), reasons=reasons, failures=0, error_text=""
    )
    return rendered


def _bale_content_error(monitor, default_body, failures, error_text):
    bale = monitor.get("notifications", {}).get("bale") or {}
    rendered = _bale_render_template(
        monitor, bale.get("message"), reasons=None, failures=failures, error_text=error_text
    )
    return rendered


def _log(mid, name, kind, channel, status, detail="", reasons=None):
    try:
        get_store().add(
            monitor_id=mid,
            monitor_name=name,
            kind=kind,
            channel=channel,
            status=status,
            detail=detail,
            reasons=reasons,
        )
    except Exception:
        pass


def _format_recipients(recipients):
    vals = [str(x).strip() for x in (recipients or []) if str(x).strip()]
    return ", ".join(vals)


def _compact_error_reason(exc):
    text = str(exc or "").strip().replace("\n", " ")
    if "Caused by" in text:
        text = text.split("Caused by", 1)[-1].strip(" :()")
    if "HTTPSConnectionPool" in text:
        return "Network connection to Kavenegar failed."
    if "Failed to establish a new connection" in text:
        return "Could not establish a new network connection."
    if len(text) > 180:
        text = text[:177] + "..."
    return text or "Unknown error."


def _dispatch_bale_message(monitor, *, content, kind, reasons=None, failures=0, error_text=""):
    notifications = monitor.get("notifications", {})
    bale = notifications.get("bale") or {}
    mid = monitor.get("id", "")
    name = monitor.get("name", "Monitor")
    content_text = str(content or "").strip()

    if not bale.get("enabled"):
        return
    if not content_text:
        _log(
            mid,
            name,
            kind,
            "bale",
            "skipped",
            "Bale message is empty, so nothing was sent.",
            reasons,
        )
        return

    token = (bale.get("token") or "").strip()
    script_name = (bale.get("script_name") or "").strip()
    if not token or not script_name:
        _log(
            mid,
            name,
            kind,
            "bale",
            "skipped",
            "Bale enabled but token or script name is missing.",
            reasons,
        )
        return

    bot_url = _bale_bot_url()
    if not bot_url:
        _log(
            mid,
            name,
            kind,
            "bale",
            "skipped",
            "Bale bot URL is not set (Management → Bale script server).",
            reasons,
        )
        return

    metadata = {}
    rid = bale.get("requester_id")
    if rid is not None:
        metadata["requester_id"] = rid

    try:
        from elkcheck.services.bale_dispatch import send_bale_script_message

        send_bale_script_message(
            bot_url=bot_url,
            script_name=script_name,
            token=token,
            content=content_text,
            metadata=metadata,
        )
    except Exception as exc:
        detail = str(exc)
        if failures:
            detail = f"After {failures} failures: {detail}"
        _log(mid, name, kind, "bale", "failed", detail[:880], reasons)
        return

    ok_detail = "Bale script message sent."
    if failures:
        ok_detail = f"Bale script message sent after {failures} consecutive failures. {error_text}"[:880]
    elif reasons:
        ok_detail = (ok_detail + " Reasons: " + ", ".join(reasons))[:880]
    _log(mid, name, kind, "bale", "success", ok_detail, reasons)


def dispatch_error_escalation(
    monitor,
    *,
    send_sms=False,
    send_call=False,
    send_bale=False,
    failures=0,
    error_text="",
):
    notifications = monitor.get("notifications", {})
    api_key = notifications.get("kavenegar_api_key", "").strip()
    mid = monitor.get("id", "")
    name = monitor.get("name", "Monitor")
    sms_message = str((notifications.get("sms") or {}).get("message") or "").strip()
    call_message = str((notifications.get("call") or {}).get("message") or "").strip()

    need_kavenegar = send_sms or send_call
    if need_kavenegar and not api_key:
        _log(
            mid,
            name,
            "error_escalation",
            "none",
            "skipped",
            "No Kavenegar API key — SMS/call escalation cannot run.",
            None,
        )
    elif need_kavenegar and api_key:
        try:
            api = KavenegarAPI(api_key)
        except Exception as exc:
            _log(
                mid,
                name,
                "error_escalation",
                "sms" if send_sms else "call",
                "failed",
                f"Tried to alert but Kavenegar client could not be created: {exc}",
                None,
            )
            api = None
        if api is not None:
            sms = notifications.get("sms", {})
            if send_sms and sms.get("enabled", True):
                recs = list(sms.get("recipients") or [])
                if not recs:
                    _log(
                        mid,
                        name,
                        "error_escalation",
                        "sms",
                        "skipped",
                        "SMS escalation requested but no SMS recipients.",
                        None,
                    )
                elif not sms_message:
                    _log(
                        mid,
                        name,
                        "error_escalation",
                        "sms",
                        "skipped",
                        "SMS message is empty, so nothing was sent.",
                        None,
                    )
                else:
                    errs = []
                    ok = 0
                    for receptor in recs:
                        try:
                            api.sms_send(
                                {
                                    "receptor": receptor,
                                    "message": sms_message,
                                    "sender": notifications.get("sms_sender", ""),
                                }
                            )
                            ok += 1
                        except Exception as exc:
                            errs.append(exc)
                    if ok and not errs:
                        _log(
                            mid,
                            name,
                            "error_escalation",
                            "sms",
                            "success",
                            (
                                f'SMS message "{sms_message}" was sent to: {_format_recipients(recs)}. '
                                f"(After {failures} consecutive failures.)"
                            )[:880],
                            None,
                        )
                    elif errs:
                        reason = _compact_error_reason(errs[0] if errs else "")
                        base_msg = (
                            f'SMS message "{sms_message}" was supposed to be sent to: {_format_recipients(recs)}, '
                            f"but failed because: {reason}"
                        )
                        if ok > 0:
                            base_msg += f" (Delivered to {ok} recipient(s), some failed.)"
                        _log(
                            mid,
                            name,
                            "error_escalation",
                            "sms",
                            "failed",
                            base_msg[:880],
                            None,
                        )

            call = notifications.get("call", {})
            if send_call and call.get("enabled", False):
                recs = list(call.get("recipients") or [])
                if not recs:
                    _log(
                        mid,
                        name,
                        "error_escalation",
                        "call",
                        "skipped",
                        "Call escalation requested but no call recipients.",
                        None,
                    )
                elif not call_message:
                    _log(
                        mid,
                        name,
                        "error_escalation",
                        "call",
                        "skipped",
                        "Call message is empty, so nothing was sent.",
                        None,
                    )
                else:
                    errs = []
                    ok = 0
                    for receptor in recs:
                        try:
                            api.call_maketts({"receptor": receptor, "message": call_message[:300]})
                            ok += 1
                        except Exception as exc:
                            errs.append(exc)
                    if ok and not errs:
                        _log(
                            mid,
                            name,
                            "error_escalation",
                            "call",
                            "success",
                            f"Voice call placed to {ok} recipient(s) after {failures} consecutive failures.",
                            None,
                        )
                    elif errs:
                        _log(
                            mid,
                            name,
                            "error_escalation",
                            "call",
                            "failed",
                            ("Tried voice call but it failed: " + " | ".join(errs))[:880],
                            None,
                        )

    if send_bale:
        bale_content = _bale_content_error(monitor, "", failures, error_text)
        _dispatch_bale_message(
            monitor,
            content=bale_content,
            kind="error_escalation",
            reasons=None,
            failures=failures,
            error_text=error_text,
        )


def dispatch_notifications(monitor, reasons):
    return _dispatch_rule_notifications(monitor, reasons, kind="rule")


def dispatch_recovery_notifications(monitor, reasons):
    notifications = monitor.get("notifications", {})
    recovery = notifications.get("recovery") or {}
    sms_rec = recovery.get("sms") or {}
    call_rec = recovery.get("call") or {}
    bale_rec = recovery.get("bale") or {}
    return _dispatch_rule_notifications(
        monitor,
        reasons,
        kind="recovery",
        force_sms_enabled=bool(sms_rec.get("enabled", False)),
        force_call_enabled=bool(call_rec.get("enabled", False)),
        force_bale_enabled=bool(bale_rec.get("enabled", False)),
        override_sms_message=str(sms_rec.get("message", "")).strip(),
        override_call_message=str(call_rec.get("message", "")).strip(),
        override_bale_message=str(bale_rec.get("message", "")).strip(),
    )


def _dispatch_rule_notifications(
    monitor,
    reasons,
    *,
    kind="rule",
    force_sms_enabled=None,
    force_call_enabled=None,
    force_bale_enabled=None,
    override_sms_message="",
    override_call_message="",
    override_bale_message="",
):
    notifications = monitor.get("notifications", {})
    api_key = notifications.get("kavenegar_api_key", "").strip()
    mid = monitor.get("id", "")
    name = monitor.get("name", "Monitor")
    reason_text = ", ".join(reasons) if reasons else ""
    sms_cfg_message = str((notifications.get("sms") or {}).get("message") or "").strip()
    call_cfg_message = str((notifications.get("call") or {}).get("message") or "").strip()
    sms_message = override_sms_message or sms_cfg_message
    call_message = override_call_message or call_cfg_message

    try:
        wants_sms = bool((force_sms_enabled if force_sms_enabled is not None else (notifications.get("sms") or {}).get("enabled", True)))
        wants_call = bool((force_call_enabled if force_call_enabled is not None else (notifications.get("call") or {}).get("enabled", False)))
        if api_key:
            try:
                api = KavenegarAPI(api_key)
            except Exception as exc:
                _log(
                    mid,
                    name,
                    kind,
                    "none",
                    "failed",
                    f"Tried rule alert but Kavenegar client could not be created (network/SDK): {exc}",
                    reasons,
                )
                raise

            sms = notifications.get("sms", {})
            sms_enabled = bool(sms.get("enabled", True)) if force_sms_enabled is None else bool(force_sms_enabled)
            if sms_enabled:
                recs = list(sms.get("recipients") or [])
                if not recs:
                    _log(mid, name, kind, "sms", "skipped", "SMS enabled but no recipients configured.", reasons)
                elif not sms_message:
                    _log(mid, name, kind, "sms", "skipped", "SMS message is empty, so nothing was sent.", reasons)
                else:
                    errs = []
                    ok = 0
                    for receptor in recs:
                        try:
                            api.sms_send(
                                {
                                    "receptor": receptor,
                                    "message": sms_message,
                                    "sender": notifications.get("sms_sender", ""),
                                }
                            )
                            ok += 1
                        except Exception as exc:
                            errs.append(f"{receptor}: {exc}")
                    if ok and not errs:
                        _log(
                            mid,
                            name,
                            kind,
                            "sms",
                            "success",
                            (
                                f'SMS message "{sms_message}" was sent to: {_format_recipients(recs)}. '
                                f"Reasons: {reason_text}"
                            )[:880],
                            reasons,
                        )
                    elif errs:
                        reason = _compact_error_reason(errs[0] if errs else "")
                        base_msg = (
                            f'SMS message "{sms_message}" was supposed to be sent to: {_format_recipients(recs)}, '
                            f"but failed because: {reason}"
                        )
                        if ok > 0:
                            base_msg += f" (Delivered to {ok} recipient(s), some failed.)"
                        _log(
                            mid,
                            name,
                            kind,
                            "sms",
                            "failed",
                            base_msg[:880],
                            reasons,
                        )

            call = notifications.get("call", {})
            call_enabled = bool(call.get("enabled", False)) if force_call_enabled is None else bool(force_call_enabled)
            if call_enabled:
                recs = list(call.get("recipients") or [])
                if not recs:
                    _log(mid, name, kind, "call", "skipped", "Voice call enabled but no call recipients.", reasons)
                elif not call_message:
                    _log(mid, name, kind, "call", "skipped", "Call message is empty, so nothing was sent.", reasons)
                else:
                    errs = []
                    ok = 0
                    for receptor in recs:
                        try:
                            api.call_maketts(
                                {
                                    "receptor": receptor,
                                    "message": call_message,
                                }
                            )
                            ok += 1
                        except Exception as exc:
                            errs.append(f"{receptor}: {exc}")
                    if ok and not errs:
                        _log(
                            mid,
                            name,
                            kind,
                            "call",
                            "success",
                            f"Voice call {kind} notification to {ok} recipient(s). Reasons: {reason_text}"[:880],
                            reasons,
                        )
                    elif errs:
                        _log(
                            mid,
                            name,
                            kind,
                            "call",
                            "failed",
                            ("Tried voice call rule alert but it failed: " + " | ".join(errs))[:880],
                            reasons,
                        )
        else:
            if not (wants_sms or wants_call):
                return
            _log(
                mid,
                name,
                kind,
                "none",
                "skipped",
                "No Kavenegar API key — SMS and voice call channels skipped for rule alert.",
                reasons,
            )
    finally:
        bale_enabled = bool((notifications.get("bale") or {}).get("enabled", False))
        if force_bale_enabled is not None:
            bale_enabled = bool(force_bale_enabled)
        if bale_enabled:
            if override_bale_message:
                bale_content = _bale_render_template(monitor, override_bale_message, reasons=reasons)
            else:
                bale_content = _bale_content_rule(monitor, reasons, "")
            _dispatch_bale_message(monitor, content=bale_content, kind=kind, reasons=reasons)
