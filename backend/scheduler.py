""" Minimal in-process scheduler for report subscriptions.

One daemon thread wakes up at the start of every minute and runs the
subscriptions store.claim_due() hands out. The claim is atomic in SQLite,
so several dtrg processes (gunicorn workers) can each run a scheduler
without sending a report twice.
"""

import logging
import threading
import time

from backend import mailer, store

logger = logging.getLogger(__name__)
_started = threading.Event()


def tick(app, job):
    """ Run every due subscription once; returns how many ran """
    ran = 0
    for sub in store.claim_due():
        logger.info(f"Running scheduled report {sub['id']} for {sub['owner']}")
        with app.app_context(), app.test_request_context():
            try:
                job(sub)
            except mailer.MailError as e:
                logger.error(f"Scheduled report {sub['id']} failed: {e}")
            except Exception:  # pylint: disable=broad-except
                logger.exception(f"Scheduled report {sub['id']} failed")
        ran += 1
    return ran


def _loop(app, job):
    while True:
        time.sleep(60 - time.time() % 60 + 1)
        try:
            tick(app, job)
        except Exception:  # pylint: disable=broad-except
            logger.exception("Scheduler tick failed")


def start(app, job):
    if _started.is_set():
        return
    _started.set()
    threading.Thread(target=_loop, args=(app, job), name="dtrg-scheduler", daemon=True).start()
    logger.info(f"Report scheduler started (timezone {store.tz()})")
