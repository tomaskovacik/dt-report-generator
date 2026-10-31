""" Production server settings (used by the Docker image: `gunicorn app:app`).

One worker process with threads: reports are I/O bound (waiting on DT,
GitHub, Maven Central), a single process keeps one in-memory rate limiter
and one report scheduler, and threads let several 10-60 s reports run at
the same time. Set DTRG_SECRET_KEY anyway so logins survive restarts.
"""

import os

bind = f"{os.getenv('DTRG_HOST', '0.0.0.0')}:{os.getenv('DTRG_PORT', '5000')}"
workers = 1
threads = int(os.getenv("DTRG_THREADS", "8"))
# a combined dashboard for 8 projects can take a few minutes
timeout = int(os.getenv("DTRG_REQUEST_TIMEOUT", "600"))
graceful_timeout = 30
accesslog = "-" if os.getenv("DTRG_ACCESS_LOG", "true").lower() in ["true", "1", "t"] else None
errorlog = "-"
loglevel = "debug" if os.getenv("DTRG_DEBUG", "false").lower() in ["true", "1", "t"] else "info"
# behind nginx / another proxy on the same host
forwarded_allow_ips = os.getenv("DTRG_FORWARDED_ALLOW_IPS", "127.0.0.1")
# gunicorn's runtime control socket (gunicornc) is not used, and its default
# path is not writable in the read-only container
control_socket_disable = True

# access log without OAuth secrets: /auth/callback carries the one-time
# authorization code and state in its query string
import re  # noqa: E402

from gunicorn.glogging import Logger  # noqa: E402

_SENSITIVE_PARAMS = re.compile(
    r"(?i)((?:^|[?&])(?:code|state|session_state|id_token|access_token|client_secret)=)[^&\s\"]*")


class RedactingLogger(Logger):
    """ Gunicorn logger that masks auth parameters in the request line / query """

    def atoms(self, resp, req, environ, request_time):
        atoms = super().atoms(resp, req, environ, request_time)
        for key in ("r", "q", "U"):
            if isinstance(atoms.get(key), str):
                atoms[key] = _SENSITIVE_PARAMS.sub(r"\1***", atoms[key])
        return atoms


logger_class = RedactingLogger
