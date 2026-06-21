import time
import logging
import threading

import schedule

from scanner import run_scans_for_all_targets
from alerts import send_alerts_for_scan
from database import get_scans

log = logging.getLogger(__name__)


def job():
    log.info("Scheduled scan job starting...")
    results = run_scans_for_all_targets()
    for name, host, scan_id in results:
        if scan_id:
            send_alerts_for_scan(scan_id)
    log.info("Scheduled scan job complete.")


def run_scheduler(interval_days=1, interval_weeks=0):
    if interval_weeks > 0:
        schedule.every(interval_weeks).weeks.do(job)
        log.info("Scheduled scan every %d week(s)", interval_weeks)
    else:
        schedule.every(interval_days).days.do(job)
        log.info("Scheduled scan every %d day(s)", interval_days)

    job()

    while True:
        schedule.run_pending()
        time.sleep(60)


def start_scheduler_thread(interval_days=1, interval_weeks=0, daemon=True):
    t = threading.Thread(
        target=run_scheduler,
        args=(interval_days, interval_weeks),
        daemon=daemon,
    )
    t.start()
    return t
