""" Access control: generated secrets, the access-key login and optional SSO.

Nothing is open by default. A DTRG_SECRET_KEY or DTRG_API_KEY that is not
set is generated and stored (backend/keys.py). Without SSO the
browser UI then asks for DTRG_API_KEY (the same key CI sends to /api/v1/*).
Only DTRG_API_KEY set to an empty string turns protection off. With SSO on,
the access-key form stays available at /auth/key (or /auth/login?nosso) as
a fallback when the identity provider is unavailable.

Single sign-on for the browser UI (OpenID Connect):

Off unless DTRG_OIDC_CLIENT_ID is set. Built for Microsoft Entra ID, but
any OIDC provider works through DTRG_OIDC_METADATA_URL.

When on, every browser route (form, report downloads, dashboard, Swagger
UI) needs a signed-in user. /health and /api/v1/* are left alone: probes
must stay anonymous, and CI keeps authenticating with DTRG_API_KEY.

The login is the authorization-code flow with PKCE and a nonce. Authlib
validates the ID token (signature against the provider's JWKS, issuer,
audience, expiry, nonce). On top of that dtrg pins the Entra tenant (`tid`)
(always, DTRG_OIDC_TENANT_ID is required), and can restrict who gets in with
DTRG_OIDC_ALLOWED_USERS. Restricting access in Entra itself (Enterprise
application -> "Assignment required") is the recommended first line.
"""

import hashlib
import hmac
import logging
import os
from datetime import timedelta
from fnmatch import fnmatch
from urllib.parse import urlencode, urlparse

from authlib.integrations.flask_client import OAuth, OAuthError
from flask import (Blueprint, abort, current_app, jsonify, redirect, render_template, request,
                   session, url_for)

logger = logging.getLogger(__name__)

bp = Blueprint("auth", __name__, url_prefix="/auth")

# Endpoints that never need a browser session
_PUBLIC_PREFIXES = ("/health", "/auth/", "/api/v1/", "/static/", "/favicon.ico")
# Endpoints called from page scripts: answer 401 instead of a login redirect
_AJAX_PATHS = ("/ui/",)
# the last SSO account, sent back as login_hint so the provider can skip its
# account picker; only the username, never a token
_HINT_COOKIE = "dtrg_login_hint"
_HINT_DAYS = 90


def access_key() -> str:
    return os.getenv("DTRG_API_KEY") or ""


def _key_fingerprint(key):
    """ Stored in the session instead of the key; a changed key ends old sessions """
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def key_signed_in() -> bool:
    key = access_key()
    return bool(key) and hmac.compare_digest(session.get("dtrg_key", ""), _key_fingerprint(key))


def enabled() -> bool:
    """ SSO is on when a client id is configured """
    return bool(os.getenv("DTRG_OIDC_CLIENT_ID"))


def _tenant() -> str:
    return os.getenv("DTRG_OIDC_TENANT_ID", "").strip()


def _metadata_url() -> str:
    return os.getenv("DTRG_OIDC_METADATA_URL") or \
        f"https://login.microsoftonline.com/{_tenant()}/v2.0/.well-known/openid-configuration"


def _allowed_patterns() -> list[str]:
    raw = os.getenv("DTRG_OIDC_ALLOWED_USERS", "")
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def user_allowed(claims) -> bool:
    """ Tenant pin + optional DTRG_OIDC_ALLOWED_USERS (emails, *@domain globs) """
    tenant = _tenant()
    if not os.getenv("DTRG_OIDC_METADATA_URL"):
        if claims.get("tid") != tenant:
            logger.warning(f"SSO login rejected: tenant {claims.get('tid')!r} is not {tenant!r}")
            return False
    patterns = _allowed_patterns()
    if not patterns:
        return True
    ident = (claims.get("preferred_username") or claims.get("email") or "").lower()
    if any(fnmatch(ident, p) for p in patterns):
        return True
    logger.warning(f"SSO login rejected: {ident!r} is not in DTRG_OIDC_ALLOWED_USERS")
    return False


def current_user():
    return session.get("user")


def _safe_next(target):
    """ Only same-site relative paths, so ?next= cannot be an open redirect """
    if not target:
        return "/"
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//") \
            or "\\" in target:
        return "/"
    return target


def init_app(app, login_limit=None):
    """ Register the login routes and guard: SSO when configured, else the access key.

    login_limit: optional decorator (a rate limit) for the access-key form POST.
    The access-key form is registered in both modes (/auth/key); without SSO
    it is also /auth/login.
    """
    try:
        hours = float(os.getenv("DTRG_SESSION_HOURS", "8"))
    except ValueError:
        hours = 8
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=hours)
    _init_key_login(app, login_limit, sso=enabled())
    if not enabled():
        app.before_request(_require_key)
        return
    if not os.getenv("DTRG_OIDC_CLIENT_SECRET"):
        raise SystemExit("DTRG_OIDC_CLIENT_ID is set but DTRG_OIDC_CLIENT_SECRET is missing")
    # single tenant only: Entra's multi-tenant endpoints ("organizations",
    # "common") issue tokens whose issuer differs per tenant, and dtrg is an
    # internal tool that should only admit its own directory anyway
    if not os.getenv("DTRG_OIDC_METADATA_URL") and \
            (not _tenant() or _tenant().lower() in ("common", "organizations", "consumers")):
        raise SystemExit("DTRG_OIDC_TENANT_ID must be your Entra tenant ID (Directory ID GUID)")
    oauth = OAuth(app)
    app.extensions["dtrg_sso"] = oauth.register(
        "sso",
        client_id=os.getenv("DTRG_OIDC_CLIENT_ID"),
        client_secret=os.getenv("DTRG_OIDC_CLIENT_SECRET"),
        server_metadata_url=_metadata_url(),
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
    )
    app.register_blueprint(bp)
    app.before_request(_require_login)
    app.context_processor(lambda: {"sso_user": current_user(), "sso_enabled": True})
    logger.info(f"SSO enabled (metadata: {_metadata_url()})")


def _require_login():
    path = request.path
    if path.startswith(_PUBLIC_PREFIXES) or current_user() or key_signed_in():
        return None
    if path.startswith(_AJAX_PATHS):
        return jsonify(error="login required"), 401
    # a form POST cannot be replayed after the login round-trip: back to the form
    target = request.full_path.rstrip("?") if request.method == "GET" else "/"
    return redirect(url_for("auth.login", next=target))


def _init_key_login(app, login_limit, sso):
    """ The access-key form: the browser login without SSO, the fallback with it """
    key_bp = Blueprint("keylogin", __name__, url_prefix="/auth")

    def login():
        """Sign in with the access key (DTRG_API_KEY): the login without SSO, a fallback with it.
        ---
        tags:
          - browser
        responses:
          200:
            description: The sign-in form (wrong key on a POST).
          302:
            description: Signed in, back to the page that asked for it.
        """
        target = _safe_next(request.values.get("next"))
        if request.method == "GET":
            return render_template("login.html", next=target, error=None)
        presented = request.form.get("key", "")
        key = access_key()
        if not key or not hmac.compare_digest(presented.encode("utf-8"), key.encode("utf-8")):
            logger.warning("Browser sign-in rejected: wrong access key")
            return render_template("login.html", next=target, error="Wrong access key"), 401
        session.clear()
        session.permanent = True
        session["dtrg_key"] = _key_fingerprint(key)
        logger.info("Browser sign-in with the access key")
        return redirect(target)

    def logout():
        """Sign out of the browser UI.
        ---
        tags:
          - browser
        responses:
          302:
            description: Back to the sign-in form.
        """
        session.clear()
        return redirect(url_for("keylogin.login"))

    view = login_limit(login) if login_limit else login
    if not sso:
        # first rule wins in url_for: without SSO the form is /auth/login
        key_bp.add_url_rule("/login", "login", view, methods=["GET", "POST"])
        key_bp.add_url_rule("/logout", "logout", logout)
    key_bp.add_url_rule("/key", "login", view, methods=["GET", "POST"])
    key_bp.add_url_rule("/key/logout", "logout", logout)
    app.register_blueprint(key_bp)
    app.context_processor(lambda: {"key_signed_in": key_signed_in()})


def _require_key():
    path = request.path
    if not access_key() or path.startswith(_PUBLIC_PREFIXES) or key_signed_in():
        return None
    if path.startswith(_AJAX_PATHS):
        return jsonify(error="login required"), 401
    target = request.full_path.rstrip("?") if request.method == "GET" else "/"
    return redirect(url_for("keylogin.login", next=target))


def _client():
    return current_app.extensions["dtrg_sso"]


def _redirect_uri():
    return os.getenv("DTRG_OIDC_REDIRECT_URI") or url_for("auth.callback", _external=True)


@bp.route("/login")
def login():
    """Start the SSO login.
    ---
    tags:
      - browser
    responses:
      302:
        description: Redirect to the identity provider.
    """
    target = _safe_next(request.args.get("next"))
    if "nosso" in request.args:
        return redirect(url_for("keylogin.login", next=target))
    session["sso_next"] = target
    hints = {}
    if request.cookies.get(_HINT_COOKIE):
        hints["login_hint"] = request.cookies[_HINT_COOKIE]
    if os.getenv("DTRG_OIDC_DOMAIN_HINT"):
        hints["domain_hint"] = os.getenv("DTRG_OIDC_DOMAIN_HINT")
    return _client().authorize_redirect(_redirect_uri(), **hints)


@bp.route("/callback")
def callback():
    """SSO redirect target.
    ---
    tags:
      - browser
    responses:
      302:
        description: Signed in, back to the page that asked for it.
      403:
        description: Login failed or the user is not allowed.
    """
    try:
        token = _client().authorize_access_token()
    except OAuthError as e:
        logger.warning(f"SSO login failed: {e.error}")
        abort(403)
    claims = token.get("userinfo") or {}
    if not claims or not user_allowed(claims):
        abort(403)
    target = session.pop("sso_next", "/")
    # fresh session on login: nothing from the anonymous session survives
    session.clear()
    session.permanent = True
    session["user"] = {
        "name": claims.get("name") or claims.get("preferred_username"),
        "username": claims.get("preferred_username") or claims.get("email"),
        "oid": claims.get("oid") or claims.get("sub"),
    }
    logger.info(f"SSO login: {session['user']['username']}")
    res = redirect(_safe_next(target))
    if session["user"]["username"]:
        res.set_cookie(_HINT_COOKIE, session["user"]["username"], max_age=_HINT_DAYS * 86400,
                       httponly=True, samesite="Lax", path="/auth/",
                       secure=current_app.config.get("SESSION_COOKIE_SECURE", False))
    return res


@bp.route("/logout")
def logout():
    """Sign out of dtrg and the identity provider.
    ---
    tags:
      - browser
    responses:
      302:
        description: Redirect to the provider's sign-out page.
    """
    session.clear()
    end = (_client().load_server_metadata() or {}).get("end_session_endpoint")
    if not end:
        res = redirect("/")
    else:
        back = os.getenv("DTRG_OIDC_POST_LOGOUT_URI") or url_for("index", _external=True)
        res = redirect(f"{end}?{urlencode({'post_logout_redirect_uri': back})}")
    # signed out on purpose: let the next login pick an account (shared PCs)
    res.delete_cookie(_HINT_COOKIE, path="/auth/")
    return res

