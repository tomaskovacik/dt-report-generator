""" Optional single sign-on for the browser UI (OpenID Connect).

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

import logging
import os
from datetime import timedelta
from fnmatch import fnmatch
from urllib.parse import urlencode, urlparse

from authlib.integrations.flask_client import OAuth, OAuthError
from flask import Blueprint, abort, current_app, jsonify, redirect, request, session, url_for

logger = logging.getLogger(__name__)

bp = Blueprint("auth", __name__, url_prefix="/auth")

# Endpoints that never need a browser session
_PUBLIC_PREFIXES = ("/health", "/auth/", "/api/v1/", "/static/", "/favicon.ico")
# Endpoints called from page scripts: answer 401 instead of a login redirect
_AJAX_PATHS = ("/ui/",)


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


def init_app(app):
    """ Register the client, routes and the login guard (no-op when disabled) """
    if not enabled():
        return
    if not os.getenv("DTRG_SECRET_KEY"):
        logger.warning("SSO is on but DTRG_SECRET_KEY is unset: every restart logs everyone out")
    if not os.getenv("DTRG_OIDC_CLIENT_SECRET"):
        raise SystemExit("DTRG_OIDC_CLIENT_ID is set but DTRG_OIDC_CLIENT_SECRET is missing")
    # single tenant only: Entra's multi-tenant endpoints ("organizations",
    # "common") issue tokens whose issuer differs per tenant, and dtrg is an
    # internal tool that should only admit its own directory anyway
    if not os.getenv("DTRG_OIDC_METADATA_URL") and \
            (not _tenant() or _tenant().lower() in ("common", "organizations", "consumers")):
        raise SystemExit("DTRG_OIDC_TENANT_ID must be your Entra tenant ID (Directory ID GUID)")
    try:
        hours = float(os.getenv("DTRG_SESSION_HOURS", "8"))
    except ValueError:
        hours = 8
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=hours)
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
    if path.startswith(_PUBLIC_PREFIXES) or current_user():
        return None
    if path.startswith(_AJAX_PATHS):
        return jsonify(error="login required"), 401
    # a form POST cannot be replayed after the login round-trip: back to the form
    target = request.full_path.rstrip("?") if request.method == "GET" else "/"
    return redirect(url_for("auth.login", next=target))


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
    session["sso_next"] = _safe_next(request.args.get("next"))
    return _client().authorize_redirect(_redirect_uri())


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
    return redirect(_safe_next(target))


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
        return redirect("/")
    back = os.getenv("DTRG_OIDC_POST_LOGOUT_URI") or url_for("index", _external=True)
    return redirect(f"{end}?{urlencode({'post_logout_redirect_uri': back})}")

