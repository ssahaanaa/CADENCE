"""
scheduler.py — optional automatic scans. Set the SCAN_CRON env var
(standard 5-field cron, e.g. "0 3 * * *" for daily at 03:00 server time)
to enable. Leave it unset and the team just clicks "Run scan" manually.
"""

from __future__ import annotations

import os
from typing import Callable

_scheduler = None


def start_if_configured(trigger_run: Callable[[str], None]):
    """trigger_run(trigger_type) should start a background scan, the same
    way the manual 'Run scan' button does."""
    global _scheduler
    cron = os.environ.get("SCAN_CRON", "").strip()
    if not cron:
        return None

    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        lambda: trigger_run("scheduled"),
        CronTrigger.from_crontab(cron),
        id="cadence_scheduled_scan",
        replace_existing=True,
    )
    _scheduler.start()
    return _scheduler


def shutdown():
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
