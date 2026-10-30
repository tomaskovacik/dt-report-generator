""" Report subscriptions, kept in a SQLite file (DTRG_DATA_DIR/dtrg.sqlite3).

No database server: one file on a volume. Every connection is short-lived
and SQLite's own locking keeps the web requests and the scheduler thread
consistent.
"""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

FREQUENCIES = ("daily", "weekly", "monthly")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS subscriptions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    owner       TEXT NOT NULL,
    owner_name  TEXT,
    projects    TEXT NOT NULL,   -- JSON [{"uuid": ..., "label": ...}]
    recipients  TEXT NOT NULL,   -- JSON ["a@example.com", ...]
    frequency   TEXT NOT NULL,   -- daily | weekly | monthly
    hour        INTEGER NOT NULL,
    weekday     INTEGER,         -- 0 = Monday (weekly)
    day         INTEGER,         -- 1..28 (monthly)
    next_run    TEXT NOT NULL,   -- UTC ISO timestamp
    last_run    TEXT,
    last_status TEXT,
    created     TEXT NOT NULL
)
"""


def data_dir() -> str:
    return os.getenv("DTRG_DATA_DIR") or os.path.join(os.path.dirname(__file__), "..", "data")


def tz():
    return ZoneInfo(os.getenv("DTRG_TIMEZONE") or "UTC")


def _connect():
    os.makedirs(data_dir(), exist_ok=True)
    conn = sqlite3.connect(os.path.join(data_dir(), "dtrg.sqlite3"), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute(_SCHEMA)
    return conn


def _now():
    return datetime.now(timezone.utc)


def next_run(frequency, hour, weekday=None, day=None, after=None):
    """ Next run time (UTC) strictly after `after`, scheduled in DTRG_TIMEZONE """
    after = (after or _now()).astimezone(tz())
    cand = after.replace(hour=hour, minute=0, second=0, microsecond=0)
    if frequency == "daily":
        if cand <= after:
            cand += timedelta(days=1)
    elif frequency == "weekly":
        cand += timedelta(days=(weekday - cand.weekday()) % 7)
        if cand <= after:
            cand += timedelta(days=7)
    elif frequency == "monthly":
        cand = cand.replace(day=day)
        if cand <= after:
            month = cand.month % 12 + 1
            cand = cand.replace(year=cand.year + (cand.month == 12), month=month)
    else:
        raise ValueError(f"unknown frequency {frequency!r}")
    # re-localise so a DST change between now and then keeps the wall-clock hour
    cand = cand.replace(tzinfo=None).replace(tzinfo=tz())
    return cand.astimezone(timezone.utc)


def _row(r):
    d = dict(r)
    d["projects"] = json.loads(d["projects"])
    d["recipients"] = json.loads(d["recipients"])
    return d


def create(owner, owner_name, projects, recipients, frequency, hour, weekday=None, day=None):
    nxt = next_run(frequency, hour, weekday, day)
    with closing(_connect()) as conn, conn:
        cur = conn.execute(
            "INSERT INTO subscriptions (owner, owner_name, projects, recipients, frequency, hour,"
            " weekday, day, next_run, created) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (owner, owner_name, json.dumps(projects), json.dumps(recipients), frequency, hour,
             weekday, day, nxt.isoformat(), _now().isoformat()))
        new_id = cur.lastrowid
    # read back after the commit above, on a fresh connection
    return get(new_id)


def get(sub_id):
    with closing(_connect()) as conn:
        r = conn.execute("SELECT * FROM subscriptions WHERE id = ?", (sub_id,)).fetchone()
    return _row(r) if r else None


def list_for(owner=None):
    """ All subscriptions of `owner`, or every subscription when owner is None """
    with closing(_connect()) as conn:
        if owner is None:
            rows = conn.execute("SELECT * FROM subscriptions ORDER BY id").fetchall()
        else:
            rows = conn.execute("SELECT * FROM subscriptions WHERE owner = ? ORDER BY id", (owner,)).fetchall()
    return [_row(r) for r in rows]


def delete(sub_id):
    with closing(_connect()) as conn, conn:
        conn.execute("DELETE FROM subscriptions WHERE id = ?", (sub_id,))


def claim_due(now=None):
    """ Due subscriptions, each moved to its next slot before it is returned.

    The conditional UPDATE makes the claim atomic, so a subscription runs
    once per slot even if two dtrg processes share the data directory.
    """
    now = now or _now()
    claimed = []
    with closing(_connect()) as conn, conn:
        rows = conn.execute("SELECT * FROM subscriptions WHERE next_run <= ?", (now.isoformat(),)).fetchall()
        for r in rows:
            nxt = next_run(r["frequency"], r["hour"], r["weekday"], r["day"], after=now)
            cur = conn.execute("UPDATE subscriptions SET next_run = ? WHERE id = ? AND next_run = ?",
                               (nxt.isoformat(), r["id"], r["next_run"]))
            if cur.rowcount:
                claimed.append(_row(r))
    return claimed


def record_run(sub_id, status):
    with closing(_connect()) as conn, conn:
        conn.execute("UPDATE subscriptions SET last_run = ?, last_status = ? WHERE id = ?",
                     (_now().isoformat(), status[:500], sub_id))
