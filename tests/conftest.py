""" Keep a developer's local .env out of the test run """

import os

# app.py loads .env at import time; point it at an empty file instead
os.environ["DTRG_ENV_FILE"] = os.devnull
os.environ["DTRG_SCHEDULER"] = "false"
# the suite runs with protection explicitly off (DTRG_API_KEY=""); tests that
# need a key set one with monkeypatch
os.environ["DTRG_API_KEY"] = ""
# and with a fixed secret key, so importing app.py never writes ./data
os.environ["DTRG_SECRET_KEY"] = "test-secret-key"
