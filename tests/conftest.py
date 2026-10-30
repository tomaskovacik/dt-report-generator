""" Keep a developer's local .env out of the test run """

import os

# app.py loads .env at import time; point it at an empty file instead
os.environ["DTRG_ENV_FILE"] = os.devnull
os.environ["DTRG_SCHEDULER"] = "false"
