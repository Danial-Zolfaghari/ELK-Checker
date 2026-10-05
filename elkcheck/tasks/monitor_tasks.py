from .celery_app import celery_app


def _monitor_check_impl(monitor, app_context_data=None):
    from elkcheck.services.check_executor import run_monitor_check
    from elkcheck.services.state_store import StateStore

    state_store = StateStore()
    return run_monitor_check(monitor, state_store)


if celery_app is not None:
    monitor_check_task = celery_app.task(name="elkcheck.monitor.check")(_monitor_check_impl)
else:
    monitor_check_task = None
