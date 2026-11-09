""" Tests for backend.auth (optional OIDC / Microsoft Entra ID login) """

from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest
from authlib.integrations.flask_client import OAuthError
from flask import Flask
from flask_bootstrap import Bootstrap5
from flask_wtf.csrf import CSRFProtect

from backend import auth

TENANT = "11111111-2222-3333-4444-555555555555"
METADATA = {
    "issuer": f"https://login.microsoftonline.com/{TENANT}/v2.0",
    "authorization_endpoint": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize",
    "token_endpoint": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
    "jwks_uri": f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys",
    "end_session_endpoint": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/logout",
}


def _make_app():
    # the real templates, for the access-key form
    app = Flask(__name__, template_folder="../templates")
    app.config.update(SECRET_KEY="test", TESTING=True, WTF_CSRF_ENABLED=False)
    Bootstrap5(app)
    CSRFProtect(app)
    app.add_url_rule("/", "index", lambda: "form")
    app.add_url_rule("/health", "health", lambda: "ok")
    app.add_url_rule("/api/v1/projects", "api", lambda: "api", methods=["POST"])
    app.add_url_rule("/ui/projects", "ajax", lambda: "[]")
    app.add_url_rule("/reports/get_report", "report", lambda: "zip", methods=["POST"])
    app.add_url_rule("/apidocs/", "docs", lambda: "docs")
    auth.init_app(app)
    return app


@pytest.fixture
def sso_env(monkeypatch):
    monkeypatch.setenv("DTRG_OIDC_CLIENT_ID", "client-id")
    monkeypatch.setenv("DTRG_OIDC_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("DTRG_OIDC_TENANT_ID", TENANT)
    monkeypatch.setenv("DTRG_SECRET_KEY", "x")
    monkeypatch.delenv("DTRG_OIDC_ALLOWED_USERS", raising=False)
    monkeypatch.delenv("DTRG_OIDC_METADATA_URL", raising=False)


@pytest.fixture
def client(sso_env):
    app = _make_app()
    with patch.object(app.extensions["dtrg_sso"], "load_server_metadata", return_value=METADATA):
        with app.test_client() as c:
            yield c


def _claims(**over):
    claims = {"tid": TENANT, "oid": "oid-1", "name": "Jane Doe", "preferred_username": "jane@example.com"}
    claims.update(over)
    return claims


def _login(client, claims=None, next_path="/"):
    client.get(f"/auth/login?next={next_path}")
    with patch.object(client.application.extensions["dtrg_sso"], "authorize_access_token",
                      return_value={"userinfo": claims or _claims()}):
        return client.get("/auth/callback?code=c&state=s")


# disabled

def test_disabled_without_client_id(monkeypatch):
    monkeypatch.delenv("DTRG_OIDC_CLIENT_ID", raising=False)
    app = _make_app()
    assert "dtrg_sso" not in app.extensions
    assert app.test_client().get("/").data == b"form"

def test_client_secret_required(monkeypatch):
    monkeypatch.setenv("DTRG_OIDC_CLIENT_ID", "client-id")
    monkeypatch.delenv("DTRG_OIDC_CLIENT_SECRET", raising=False)
    with pytest.raises(SystemExit):
        _make_app()


# guard

def test_browser_page_redirects_to_login(client):
    res = client.get("/apidocs/")
    assert res.status_code == 302
    assert res.headers["Location"].startswith("/auth/login?next=/apidocs/")

def test_ajax_gets_401_not_redirect(client):
    res = client.get("/ui/projects")
    assert res.status_code == 401
    assert res.get_json() == {"error": "login required"}

def test_form_post_redirects_back_to_form(client):
    res = client.post("/reports/get_report")
    assert res.status_code == 302
    assert res.headers["Location"] == "/auth/login?next=/"

def test_health_and_api_stay_public(client):
    assert client.get("/health").status_code == 200
    assert client.post("/api/v1/projects").status_code == 200


# login flow

def test_login_redirects_to_entra_with_pkce(client):
    res = client.get("/auth/login")
    assert res.status_code == 302
    url = urlparse(res.headers["Location"])
    q = parse_qs(url.query)
    assert url.netloc == "login.microsoftonline.com"
    assert q["client_id"] == ["client-id"]
    assert q["response_type"] == ["code"]
    assert q["code_challenge_method"] == ["S256"] and q["code_challenge"]
    assert q["nonce"] and q["state"]
    assert q["redirect_uri"] == ["http://localhost/auth/callback"]
    assert "openid" in q["scope"][0]

def test_redirect_uri_override(client, monkeypatch):
    monkeypatch.setenv("DTRG_OIDC_REDIRECT_URI", "https://dtrg.internal/auth/callback")
    q = parse_qs(urlparse(client.get("/auth/login").headers["Location"]).query)
    assert q["redirect_uri"] == ["https://dtrg.internal/auth/callback"]

def test_callback_signs_in_and_returns_to_next(client):
    res = _login(client, next_path="/apidocs/")
    assert res.status_code == 302 and res.headers["Location"] == "/apidocs/"
    assert client.get("/apidocs/").data == b"docs"
    with client.session_transaction() as s:
        assert s["user"] == {"name": "Jane Doe", "username": "jane@example.com", "oid": "oid-1"}
        assert s.permanent

def test_open_redirect_blocked(client):
    for evil in ("https://evil.com", "//evil.com", "/\\evil.com"):
        res = _login(client, next_path=evil)
        assert res.headers["Location"] == "/", evil
        client.get("/auth/logout")

def test_foreign_tenant_rejected(client):
    res = _login(client, claims=_claims(tid="99999999-0000-0000-0000-000000000000"))
    assert res.status_code == 403
    assert client.get("/").status_code == 302

@pytest.mark.parametrize("tenant", ["", "organizations", "common"])
def test_concrete_tenant_required(sso_env, monkeypatch, tenant):
    monkeypatch.setenv("DTRG_OIDC_TENANT_ID", tenant)
    with pytest.raises(SystemExit):
        _make_app()

def test_allowed_users_filter(client, monkeypatch):
    monkeypatch.setenv("DTRG_OIDC_ALLOWED_USERS", "*@corp.example, boss@example.com")
    assert _login(client).status_code == 403
    assert _login(client, claims=_claims(preferred_username="Dev@Corp.Example")).status_code == 302

def test_provider_error_is_403(client):
    client.get("/auth/login")
    with patch.object(client.application.extensions["dtrg_sso"], "authorize_access_token",
                      side_effect=OAuthError(error="invalid_grant")):
        assert client.get("/auth/callback?code=bad&state=s").status_code == 403

def test_login_starts_fresh_session(client):
    with client.session_transaction() as s:
        s["planted"] = "attacker"
    _login(client)
    with client.session_transaction() as s:
        assert "planted" not in s

def test_logout_clears_session_and_signs_out_of_entra(client):
    _login(client)
    res = client.get("/auth/logout")
    assert res.headers["Location"].startswith(METADATA["end_session_endpoint"] + "?post_logout_redirect_uri=")
    assert client.get("/").status_code == 302


# login_hint / domain_hint

def test_callback_remembers_the_account_for_login_hint(client):
    res = _login(client)
    cookie = res.headers["Set-Cookie"]
    assert cookie.startswith("dtrg_login_hint=jane@example.com;")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Path=/auth/" in cookie
    client.get("/auth/logout", follow_redirects=False)
    # a later login (e.g. after the session expired) sends it
    client.set_cookie("dtrg_login_hint", "jane@example.com", path="/auth/")
    q = parse_qs(urlparse(client.get("/auth/login").headers["Location"]).query)
    assert q["login_hint"] == ["jane@example.com"]

def test_no_login_hint_without_the_cookie(client):
    q = parse_qs(urlparse(client.get("/auth/login").headers["Location"]).query)
    assert "login_hint" not in q and "domain_hint" not in q

def test_domain_hint(client, monkeypatch):
    monkeypatch.setenv("DTRG_OIDC_DOMAIN_HINT", "example.com")
    q = parse_qs(urlparse(client.get("/auth/login").headers["Location"]).query)
    assert q["domain_hint"] == ["example.com"]

def test_logout_forgets_the_account(client):
    _login(client)
    res = client.get("/auth/logout")
    assert any(h.startswith("dtrg_login_hint=;") for h in res.headers.getlist("Set-Cookie"))


# access-key fallback with SSO on

def test_nosso_goes_to_the_access_key_form(client):
    res = client.get("/auth/login?nosso&next=/apidocs/")
    assert res.status_code == 302 and res.headers["Location"] == "/auth/key?next=/apidocs/"
    page = client.get("/auth/key?next=/apidocs/")
    assert page.status_code == 200 and b"Access key" in page.data
    assert b"Sign in with Microsoft instead" in page.data

def test_access_key_signs_in_with_sso_on(client, monkeypatch):
    monkeypatch.setenv("DTRG_API_KEY", "secret")
    assert client.post("/auth/key", data={"key": "wrong"}).status_code == 401
    assert client.get("/apidocs/").status_code == 302
    res = client.post("/auth/key", data={"key": "secret", "next": "/apidocs/"})
    assert res.headers["Location"] == "/apidocs/"
    assert client.get("/apidocs/").data == b"docs"
    client.get("/auth/key/logout")
    assert client.get("/apidocs/").status_code == 302

def test_empty_api_key_never_opens_the_ui_with_sso_on(client, monkeypatch):
    monkeypatch.setenv("DTRG_API_KEY", "")
    assert client.post("/auth/key", data={"key": ""}).status_code == 401
    assert client.get("/apidocs/").status_code == 302

def test_unauthenticated_pages_still_go_to_microsoft(client):
    assert client.get("/apidocs/").headers["Location"].startswith("/auth/login?next=")
