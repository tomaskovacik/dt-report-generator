""" dtrg's own secrets (DTRG_SECRET_KEY, DTRG_API_KEY): from the environment or stored.

A key set in the environment (or .env) always wins. One that is not set is
generated on the first start, stored in DTRG_DATA_DIR/dtrg.sqlite3 and
written to the log once; later starts reuse it without logging the value.
DTRG_API_KEY set to an empty string is the explicit opt-out (no access key).
An empty DTRG_SECRET_KEY is never valid, so it is treated as not set.

    python -m backend.keys show     # print the stored keys
    python -m backend.keys reset    # forget them; new ones on the next start
"""

import logging
import os
import secrets
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timezone

from backend import store

logger = logging.getLogger(__name__)

_GENERATORS = {
    "DTRG_SECRET_KEY": lambda: secrets.token_hex(32),
    "DTRG_API_KEY": lambda: secrets.token_urlsafe(32),
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    name    TEXT PRIMARY KEY,
    value   TEXT NOT NULL,
    created TEXT NOT NULL
)
"""


def db_path() -> str:
    return os.path.join(store.data_dir(), "dtrg.sqlite3")


def _connect():
    os.makedirs(store.data_dir(), exist_ok=True)
    conn = sqlite3.connect(db_path(), timeout=30)
    conn.execute(_SCHEMA)
    try:
        # holds secrets now: owner only
        os.chmod(db_path(), 0o600)
    except OSError:
        pass
    return conn


def stored():
    """ {name: (value, created)} of the stored keys """
    with closing(_connect()) as conn:
        return {n: (v, c) for n, v, c in conn.execute("SELECT name, value, created FROM settings")}


def _stored_or_new(name):
    """ The stored value of `name`, generated and stored first if missing; (value, created, new) """
    with closing(_connect()) as conn, conn:
        created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        cur = conn.execute("INSERT OR IGNORE INTO settings (name, value, created) VALUES (?, ?, ?)",
                           (name, _GENERATORS[name](), created))
        value, created = conn.execute("SELECT value, created FROM settings WHERE name = ?",
                                      (name,)).fetchone()
        return value, created, cur.rowcount == 1


def reset(names=None):
    """ Forget stored keys (all, or `names`); returns how many were removed """
    with closing(_connect()) as conn, conn:
        if names:
            return conn.execute(f"DELETE FROM settings WHERE name IN ({','.join('?' * len(names))})",
                                list(names)).rowcount
        return conn.execute("DELETE FROM settings").rowcount


def _missing(name):
    if name == "DTRG_API_KEY":
        return name not in os.environ
    return not os.getenv(name)


def ensure_secrets():
    """ Fill os.environ with every key that is not set: stored, or generated and stored """
    for name in _GENERATORS:
        if not _missing(name):
            continue
        try:
            value, created, new = _stored_or_new(name)
        except (OSError, sqlite3.Error) as e:
            value = _GENERATORS[name]()
            logger.warning(f"{name} is not set and cannot be stored ({db_path()}: {e}); "
                           f"generated for this run only: {value}")
        else:
            if new:
                logger.warning(f"{name} is not set; generated and stored in {db_path()}: {value} "
                               "(shown once; `python -m backend.keys show` prints it again)")
            else:
                logger.info(f"{name} is not set; using the stored one (generated {created})")
        os.environ[name] = value
    if os.environ.get("DTRG_API_KEY") == "":
        logger.warning("DTRG_API_KEY is set to an empty string: /api/v1/* and, without SSO, "
                       "the browser UI are open to anyone who can reach dtrg")


def main(argv):
    command = argv[1] if len(argv) > 1 else ""
    if command == "show":
        keys = stored()
        if not keys:
            print(f"no stored keys in {db_path()}")
        for name, (value, created) in sorted(keys.items()):
            note = "  (not used: set in the environment)" if not _missing(name) else ""
            print(f"{name}={value}  # generated {created}{note}")
        return 0
    if command == "reset":
        removed = reset(argv[2:])
        print(f"removed {removed} stored key(s) from {db_path()}; restart dtrg to generate new ones")
        return 0
    print("usage: python -m backend.keys show | reset [DTRG_API_KEY|DTRG_SECRET_KEY ...]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    # same settings file as the app (DTRG_DATA_DIR may live in .env)
    from dotenv import load_dotenv
    load_dotenv(os.getenv("DTRG_ENV_FILE")
                or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))
    sys.exit(main(sys.argv))
