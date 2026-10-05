import os
import json
import logging
import time
import traceback

from kavenegar import APIException, HTTPException, KavenegarAPI
try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    Console = None
    Live = None
    Table = None
    RICH_AVAILABLE = False

KAVENEGAR_API_KEY = os.getenv("KAVENEGAR_API_KEY", "")
SMS_SENDER = os.getenv("KAVENEGAR_SENDER", "")
CONTACTS = [x.strip() for x in os.getenv("KAVENEGAR_CONTACTS", "").split(",") if x.strip()]

TEST_SMS_ENABLED = False
TEST_CALL_ENABLED = True
TEST_SMS_MESSAGE = "✅ Monitoring service started successfully"
TEST_CALL_MESSAGE = "This is a voice test call from monitoring service."

VERBOSE = True
FETCH_ACCOUNT_INFO = True
CLEAN_CONSOLE = True
USE_RICH_UI = True

WAIT_FOR_FINAL_STATUS = True
POLL_INTERVAL_SEC = 3
POLL_TIMEOUT_SEC = 600

NON_FINAL_STATUSES = frozenset({1, 2, 4})
STOP_STATUSES = frozenset({5, 6, 10, 11, 13, 14, 100})

log = logging.getLogger("kavenegar_test")
_live_line_len = 0
console = Console() if RICH_AVAILABLE else None
SESSION_EVENTS = []
ACCOUNT_INFO = None


def _rich_live_mode() -> bool:
    return USE_RICH_UI and RICH_AVAILABLE and CLEAN_CONSOLE


def _add_event(text: str) -> None:
    SESSION_EVENTS.append(text)
    if len(SESSION_EVENTS) > 20:
        del SESSION_EVENTS[:-20]


def _setup_logging():
    level = logging.DEBUG if VERBOSE else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    if CLEAN_CONSOLE:
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
    if USE_RICH_UI and not RICH_AVAILABLE:
        log.warning("rich is not installed; fallback to plain console output.")
    if _rich_live_mode():
        logging.getLogger().setLevel(logging.WARNING)


def _live_update(text: str) -> None:
    global _live_line_len
    if USE_RICH_UI and RICH_AVAILABLE:
        return
    if not CLEAN_CONSOLE:
        return
    padded = text
    if len(text) < _live_line_len:
        padded = text + (" " * (_live_line_len - len(text)))
    print("\r" + padded, end="", flush=True)
    _live_line_len = len(text)


def _live_clear() -> None:
    global _live_line_len
    if USE_RICH_UI and RICH_AVAILABLE:
        return
    if not CLEAN_CONSOLE or _live_line_len == 0:
        return
    print("\r" + (" " * _live_line_len) + "\r", end="", flush=True)
    _live_line_len = 0


def _poll_table(kind: str, message_id: int, poll_n: int, remaining: int, last_status, last_text, events):
    status_meta = {
        1: ("Queued", "In send queue", "yellow"),
        2: ("Scheduled", "Scheduled", "yellow"),
        4: ("SentToCarrier", "Submitted to carrier", "cyan"),
        5: ("Sent", "Sent", "green"),
        6: ("Failed", "Failed", "red"),
        10: ("Delivered", "Delivered to recipient", "green"),
        11: ("Undelivered", "Not delivered", "red"),
        13: ("Canceled", "Canceled", "red"),
        14: ("Filtered", "Filtered", "red"),
        100: ("Invalid", "Invalid message id or inaccessible", "red"),
    }
    status_int = None
    try:
        if last_status is not None:
            status_int = int(last_status)
    except (TypeError, ValueError):
        status_int = None

    if status_int is None:
        phase = ("Polling", "Checking delivery status", "magenta")
        status_short = "-"
        status_long = "-"
    else:
        eng, fa, color = status_meta.get(status_int, ("Unknown", str(last_text or "-"), "white"))
        status_short = f"[{color}]{status_int} · {eng}[/{color}]"
        status_long = f"{fa}"
        if status_int in STOP_STATUSES:
            phase = ("Final", "Final status reached", "green" if status_int in (5, 10) else "red")
        elif status_int in NON_FINAL_STATUSES:
            phase = ("InTransit", "Still processing delivery", "yellow")
        else:
            phase = ("Unknown", "Status outside expected lifecycle", "white")

    table = Table(title=f"{kind.upper()} status tracker", expand=True)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Message ID", str(message_id))
    table.add_row("Mode", "Voice via sms/status" if kind == "call" else "SMS via sms/status")
    table.add_row("Progress", f"poll #{poll_n} | {remaining}s remaining")
    table.add_row("Status", status_short)
    table.add_row("Meaning", status_long)
    table.add_row("Phase", f"[{phase[2]}]{phase[0]}[/{phase[2]}] | {phase[1]}")
    if ACCOUNT_INFO:
        table.add_row("Credit", _format_credit(ACCOUNT_INFO.get("remaincredit")))
        table.add_row("Account Type", str(ACCOUNT_INFO.get("type", "-")))
    if events:
        table.add_section()
        table.add_row("Recent", "\n".join(events[-6:]))
    return table


def _pretty(data) -> str:
    if isinstance(data, (dict, list)):
        return json.dumps(data, ensure_ascii=False, indent=2, default=str)
    return repr(data)


def _decode_api_exception(exc: APIException) -> str:
    if not exc.args:
        return str(exc)
    first = exc.args[0]
    if isinstance(first, bytes):
        return first.decode("utf-8", errors="replace")
    return str(first)


def _format_credit(credit_raw) -> str:
    try:
        rial = int(credit_raw)
    except (TypeError, ValueError):
        return "-"
    toman = rial // 10
    return f"{rial:,} rial (~{toman:,} toman)"


def _log_request(action: str, contact: str, params: dict) -> None:
    redacted = dict(params)
    msg = redacted.get("message")
    if isinstance(msg, str) and len(msg) > 200:
        redacted["message"] = msg[:200] + f"... ({len(msg)} chars)"
    _add_event(f"{action} -> {contact}")
    if not _rich_live_mode():
        log.debug("[%s] receptor=%s | outgoing params:\n%s", action, contact, _pretty(redacted))


def _log_success(action: str, contact: str, result) -> None:
    _live_clear()
    entry = _first_entry(result) or {}
    _add_event(
        f"{action} OK | receptor={contact} | messageid={entry.get('messageid','-')} | status={entry.get('status','-')}"
    )
    if not _rich_live_mode():
        log.info(
            "[%s] OK | receptor=%s | Kavenegar entries (parsed):\n%s",
            action,
            contact,
            _pretty(result),
        )
        log.debug("[%s] receptor=%s | Python type of entries: %s", action, contact, type(result).__name__)


def _log_failure(action: str, contact: str, exc: BaseException) -> None:
    _live_clear()
    _add_event(f"{action} FAILED | {type(exc).__name__}: {exc}")
    if not _rich_live_mode():
        log.error("[%s] FAILED | receptor=%s | %s: %s", action, contact, type(exc).__name__, exc)
        if isinstance(exc, APIException):
            log.error("[%s] Kavenegar API message: %s", action, _decode_api_exception(exc))
        if VERBOSE:
            log.debug("[%s] traceback:\n%s", action, traceback.format_exc())


def _first_entry(result):
    if isinstance(result, list) and result:
        return result[0]
    if isinstance(result, dict):
        return result
    return None


def _extract_message_id(entry) -> int | None:
    if not entry:
        return None
    mid = entry.get("messageid")
    if mid is None:
        return None
    try:
        return int(mid)
    except (TypeError, ValueError):
        return None


def poll_until_stable(kind: str, message_id: int, receptor: str):
    assert kind in ("call", "sms")
    deadline = time.time() + POLL_TIMEOUT_SEC
    poll_n = 0
    last_row = None
    last_status = None
    last_text = None
    recent_events = list(SESSION_EVENTS)

    _live_clear()
    _add_event(f"{kind} polling start | messageid={message_id} | timeout={POLL_TIMEOUT_SEC}s")
    if not _rich_live_mode():
        log.info(
            "[%s -> sms/status] polling messageid=%s every %ss (timeout %ss)",
            kind,
            message_id,
            POLL_INTERVAL_SEC,
            POLL_TIMEOUT_SEC,
        )

    live = None
    if USE_RICH_UI and RICH_AVAILABLE and CLEAN_CONSOLE:
        live = Live(_poll_table(kind, message_id, 0, int(POLL_TIMEOUT_SEC), None, None, []), console=console, refresh_per_second=4)
        live.start()
    quiet_during_live = live is not None
    try:
        while time.time() < deadline:
            poll_n += 1
            remaining = max(0, int(deadline - time.time()))
            if live:
                live.update(_poll_table(kind, message_id, poll_n, remaining, last_status, last_text, recent_events))
            else:
                _live_update(
                    f"[{kind}] polling messageid={message_id} | try={poll_n} | remaining={remaining}s"
                )
            try:
                entries = api.sms_status({"messageid": message_id})
            except (APIException, HTTPException) as e:
                _live_clear()
                msg = f"poll #{poll_n} API error: {e}"
                recent_events.append(msg)
                _add_event(msg)
                if not quiet_during_live:
                    log.error("[%s -> sms/status] %s", kind, msg)
                    if isinstance(e, APIException):
                        log.error("[%s -> sms/status] %s", kind, _decode_api_exception(e))
                time.sleep(POLL_INTERVAL_SEC)
                continue
            except Exception as e:
                _live_clear()
                msg = f"poll #{poll_n} unexpected: {e}"
                recent_events.append(msg)
                _add_event(msg)
                if not quiet_during_live:
                    log.exception("[%s -> sms/status] %s", kind, msg)
                time.sleep(POLL_INTERVAL_SEC)
                continue

            row = _first_entry(entries)
            if not row:
                _live_clear()
                msg = f"poll #{poll_n} empty entries"
                recent_events.append(msg)
                _add_event(msg)
                if not quiet_during_live:
                    log.warning("[%s -> sms/status] %s for messageid=%s", kind, msg, message_id)
                time.sleep(POLL_INTERVAL_SEC)
                continue

            last_row = row
            st = row.get("status")
            st_text = row.get("statustext")
            try:
                st_int = int(st) if st is not None else None
            except (TypeError, ValueError):
                st_int = None

            if st != last_status or st_text != last_text:
                _live_clear()
                recent_events.append(f"status={st} ({st_text})")
                _add_event(f"{kind} status={st} ({st_text})")
                if not quiet_during_live:
                    log.info(
                        "[%s -> sms/status] transition | poll=%s | messageid=%s | status=%s | statustext=%s",
                        kind,
                        poll_n,
                        message_id,
                        st,
                        st_text,
                    )
                if VERBOSE and not quiet_during_live:
                    log.debug("[%s -> sms/status] full row:\n%s", kind, _pretty(row))
                last_status, last_text = st, st_text

            if st_int is None:
                time.sleep(POLL_INTERVAL_SEC)
                continue

            if st_int in STOP_STATUSES:
                _live_clear()
                recent_events.append(f"final={st_int}")
                _add_event(f"{kind} final={st_int}")
                log.info(
                    "[%s -> sms/status] final status reached (status=%s) for messageid=%s — receptor=%s",
                    kind,
                    st_int,
                    message_id,
                    receptor,
                )
                return last_row

            if st_int not in NON_FINAL_STATUSES:
                _live_clear()
                recent_events.append(f"unknown-stop={st_int}")
                _add_event(f"{kind} unknown-stop={st_int}")
                log.info(
                    "[%s -> sms/status] status %s is outside non-final list; polling is being stopped.",
                    kind,
                    st_int,
                )
                return last_row

            time.sleep(POLL_INTERVAL_SEC)
    finally:
        if live:
            live.stop()

    _live_clear()
    log.error(
        "[%s -> sms/status] timeout after %ss for messageid=%s — last row:\n%s",
        kind,
        POLL_TIMEOUT_SEC,
        message_id,
        _pretty(last_row),
    )
    return last_row


_setup_logging()
api = KavenegarAPI(KAVENEGAR_API_KEY)


def fetch_account_info():
    global ACCOUNT_INFO
    try:
        _live_clear()
        _add_event("Calling account/info")
        if not _rich_live_mode():
            log.info("Calling account/info …")
        info = api.account_info()
        ACCOUNT_INFO = info
        _add_event(f"account/info OK | credit={info.get('remaincredit','-')}")
        if not _rich_live_mode():
            log.info("account/info entries:\n%s", _pretty(info))
        return info
    except APIException as e:
        log.error("account/info APIException: %s", _decode_api_exception(e))
    except HTTPException as e:
        log.error("account/info HTTPException: %s", e)
    if VERBOSE:
        log.debug(traceback.format_exc())
    return None


def send_call(text: str) -> bool:
    ok_any = False
    for contact in CONTACTS:
        params = {"receptor": contact, "message": text}
        _log_request("call_maketts", contact, params)
        try:
            result = api.call_maketts(params)
            _log_success("call_maketts", contact, result)
            ok_any = True
            if WAIT_FOR_FINAL_STATUS:
                entry = _first_entry(result)
                mid = _extract_message_id(entry)
                if mid is not None:
                    final = poll_until_stable("call", mid, contact)
                    log.info("Final call status for messageid=%s:\n%s", mid, _pretty(final))
                else:
                    log.warning("No messageid found in maketts response; polling skipped.")
        except (APIException, HTTPException) as e:
            _log_failure("call_maketts", contact, e)
        except Exception as e:
            _log_failure("call_maketts", contact, e)
    return ok_any


def send_sms(text: str) -> bool:
    for contact in CONTACTS:
        params = {"receptor": contact, "message": text, "sender": SMS_SENDER}
        _log_request("sms_send", contact, params)
        try:
            result = api.sms_send(params)
            _log_success("sms_send", contact, result)
            if WAIT_FOR_FINAL_STATUS:
                entry = _first_entry(result)
                mid = _extract_message_id(entry)
                if mid is not None:
                    final = poll_until_stable("sms", mid, contact)
                    log.info("Final SMS status for messageid=%s:\n%s", mid, _pretty(final))
                else:
                    log.warning("No messageid found in sms_send response; polling skipped.")
            return True
        except (APIException, HTTPException) as e:
            _log_failure("sms_send", contact, e)
        except Exception as e:
            _log_failure("sms_send", contact, e)
    return False


def main():
    _live_clear()
    _add_event("Kavenegar test start")
    if not _rich_live_mode():
        log.info("Kavenegar test — detailed logging (SMS / voice)")

    if FETCH_ACCOUNT_INFO:
        fetch_account_info()

    if TEST_SMS_ENABLED:
        _add_event("--- SMS test ---")
        if not _rich_live_mode():
            log.info("--- SMS test ---")
        if send_sms(TEST_SMS_MESSAGE):
            log.info("SMS test finished: at least one send reported OK by library")
        else:
            log.error("SMS test finished: no successful send")

    if TEST_CALL_ENABLED:
        _add_event("--- Voice (maketts) test ---")
        if not _rich_live_mode():
            log.info("--- Voice (maketts) test ---")
        if send_call(TEST_CALL_MESSAGE):
            log.info("Call test finished: at least one request reported OK by library")
        else:
            log.error("Call test finished: no successful request")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _live_clear()
        log.info("Exit by user")
