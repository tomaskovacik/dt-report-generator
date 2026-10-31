""" gunicorn.conf.py: the access log must not carry OAuth secrets """

import runpy


def test_access_log_masks_auth_parameters():
    conf = runpy.run_path("gunicorn.conf.py")
    redact = lambda s: conf["_SENSITIVE_PARAMS"].sub(r"\1***", s)  # noqa: E731
    assert redact("GET /auth/callback?code=1.AYEA-x_y&state=abc&session_state=s HTTP/1.1") == \
        "GET /auth/callback?code=***&state=***&session_state=*** HTTP/1.1"
    assert redact("GET /dashboard?projects=a&projects=b HTTP/1.1") == "GET /dashboard?projects=a&projects=b HTTP/1.1"
    assert redact("GET /x?barcode=1 HTTP/1.1") == "GET /x?barcode=1 HTTP/1.1"  # only whole parameter names
    assert conf["logger_class"].__name__ == "RedactingLogger"
