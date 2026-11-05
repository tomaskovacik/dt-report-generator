""" Generated secrets and the access-key sign-in (browser UI without SSO) """

import logging
import os

import pytest

import app as app_module
from backend import keys


# generated secrets

@pytest.fixture
def data(monkeypatch, tmp_path):
    monkeypatch.setenv("DTRG_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("DTRG_API_KEY", raising=False)
    monkeypatch.delenv("DTRG_SECRET_KEY", raising=False)
    return tmp_path

def test_unset_secrets_are_generated_stored_and_logged_once(data, monkeypatch, caplog):
    with caplog.at_level(logging.INFO, logger="backend.keys"):
        keys.ensure_secrets()
    key, secret = os.environ["DTRG_API_KEY"], os.environ["DTRG_SECRET_KEY"]
    assert len(key) >= 32 and len(secret) == 64
    assert key in caplog.text and secret in caplog.text
    assert {n: v for n, (v, _) in keys.stored().items()} == {"DTRG_API_KEY": key, "DTRG_SECRET_KEY": secret}
    assert oct(os.stat(data / "dtrg.sqlite3").st_mode & 0o777) == "0o600"

    # next start: same keys, values not logged again
    monkeypatch.delenv("DTRG_API_KEY")
    monkeypatch.delenv("DTRG_SECRET_KEY")
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="backend.keys"):
        keys.ensure_secrets()
    assert (os.environ["DTRG_API_KEY"], os.environ["DTRG_SECRET_KEY"]) == (key, secret)
    assert "using the stored one" in caplog.text
    assert key not in caplog.text and secret not in caplog.text

def test_reset_forgets_stored_keys(data, monkeypatch):
    keys.ensure_secrets()
    old = os.environ["DTRG_API_KEY"]
    assert keys.reset(["DTRG_API_KEY"]) == 1
    monkeypatch.delenv("DTRG_API_KEY")
    monkeypatch.delenv("DTRG_SECRET_KEY")
    keys.ensure_secrets()
    assert os.environ["DTRG_API_KEY"] != old
    assert keys.reset() == 2 and keys.stored() == {}

def test_unwritable_data_dir_falls_back_to_a_key_per_run(data, monkeypatch, caplog):
    blocker = data / "file"
    blocker.write_text("")
    monkeypatch.setenv("DTRG_DATA_DIR", str(blocker / "sub"))
    with caplog.at_level(logging.WARNING, logger="backend.keys"):
        keys.ensure_secrets()
    assert len(os.environ["DTRG_API_KEY"]) >= 32
    assert "generated for this run only" in caplog.text

def test_empty_api_key_is_the_explicit_opt_out(data, monkeypatch, caplog):
    monkeypatch.setenv("DTRG_API_KEY", "")
    with caplog.at_level(logging.WARNING, logger="backend.keys"):
        keys.ensure_secrets()
    assert os.environ["DTRG_API_KEY"] == ""
    assert "open to anyone" in caplog.text
    assert "DTRG_API_KEY" not in keys.stored()

def test_empty_secret_key_is_generated(data, monkeypatch):
    monkeypatch.setenv("DTRG_SECRET_KEY", "")
    keys.ensure_secrets()
    assert len(os.environ["DTRG_SECRET_KEY"]) == 64

def test_set_secrets_are_kept_and_not_stored(data, monkeypatch, caplog):
    monkeypatch.setenv("DTRG_API_KEY", "mine")
    monkeypatch.setenv("DTRG_SECRET_KEY", "s")
    with caplog.at_level(logging.INFO, logger="backend.keys"):
        keys.ensure_secrets()
    assert (os.environ["DTRG_API_KEY"], os.environ["DTRG_SECRET_KEY"]) == ("mine", "s")
    assert caplog.text == "" and keys.stored() == {}

def test_cli_show_and_reset(data, capsys):
    keys.ensure_secrets()
    assert keys.main(["keys", "show"]) == 0
    out = capsys.readouterr().out
    assert f"DTRG_API_KEY={os.environ['DTRG_API_KEY']}" in out and "not used" in out
    assert keys.main(["keys", "reset"]) == 0
    assert "removed 2" in capsys.readouterr().out
    assert keys.main(["keys"]) == 2


# access-key sign-in

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("DTRG_API_KEY", "secret")
    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    app_module.limiter.reset()
    with app_module.app.test_client() as c:
        yield c
    app_module.app.config.update(WTF_CSRF_ENABLED=True)
    app_module.limiter.reset()

def test_browser_pages_need_sign_in(client):
    for path in ("/", "/apidocs/", "/dashboard?projects=x", "/projects/x/report"):
        res = client.get(path)
        assert res.status_code == 302, path
        assert res.headers["Location"].startswith("/auth/login?next=")

def test_page_scripts_get_401(client):
    res = client.get("/ui/projects")
    assert res.status_code == 401 and res.get_json() == {"error": "login required"}

def test_probe_and_api_are_not_behind_the_form(client):
    assert client.get("/health").status_code == 200
    # /api/v1/* is checked by require_api_key (header), not redirected
    assert client.post("/api/v1/projects", json={}).status_code == 401

def test_wrong_key_is_rejected(client):
    res = client.post("/auth/login", data={"key": "nope", "next": "/"})
    assert res.status_code == 401 and b"Wrong access key" in res.data
    assert client.get("/").status_code == 302

def test_right_key_signs_in_and_returns_to_next(client, monkeypatch):
    monkeypatch.delenv("DT_URL", raising=False)
    res = client.post("/auth/login", data={"key": "secret", "next": "/apidocs/"})
    assert res.status_code == 302 and res.headers["Location"] == "/apidocs/"
    assert client.get("/").status_code == 200
    assert client.get("/auth/logout").status_code == 302
    assert client.get("/").status_code == 302

def test_next_cannot_leave_the_site(client):
    res = client.post("/auth/login", data={"key": "secret", "next": "//evil.example"})
    assert res.headers["Location"] == "/"

def test_changed_key_ends_old_sessions(client, monkeypatch):
    client.post("/auth/login", data={"key": "secret"})
    monkeypatch.setenv("DTRG_API_KEY", "rotated")
    assert client.get("/").status_code == 302

def test_login_is_rate_limited(client):
    codes = [client.post("/auth/login", data={"key": "nope"}).status_code for _ in range(11)]
    assert codes[:10] == [401] * 10 and codes[10] == 429

def test_empty_key_leaves_the_ui_open(client, monkeypatch):
    monkeypatch.setenv("DTRG_API_KEY", "")
    monkeypatch.delenv("DT_URL", raising=False)
    assert client.get("/").status_code == 200
