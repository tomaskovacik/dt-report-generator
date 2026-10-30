""" Tests for report emails: store, schedule maths, mailer, summary, routes, scheduler """

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

import app as app_module
from backend import mail_summary, mailer, scheduler, store

UUID_A = "00000000-0000-0000-0000-00000000000a"
UUID_B = "00000000-0000-0000-0000-00000000000b"


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("DTRG_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DTRG_TIMEZONE", "Europe/Bratislava")
    monkeypatch.setenv("DTRG_MAIL_BACKEND", "smtp")
    monkeypatch.setenv("DTRG_MAIL_FROM", "dtrg@example.com")
    monkeypatch.setenv("DTRG_MAIL_ALLOWED_RECIPIENTS", "*@example.com, boss@partner.org")
    for k in ("DTRG_API_KEY", "DTRG_OIDC_CLIENT_ID"):
        monkeypatch.delenv(k, raising=False)


# schedule maths

def _utc(*a):
    return datetime(*a, tzinfo=timezone.utc)

def test_next_run_daily_weekly_monthly_in_local_time():
    # 2026-10-30 is a Friday; Bratislava is UTC+1 after the DST switch on 25 Oct
    now = _utc(2026, 10, 30, 8, 0)
    assert store.next_run("daily", 7, after=now) == _utc(2026, 10, 31, 6, 0)
    assert store.next_run("daily", 10, after=now) == _utc(2026, 10, 30, 9, 0)
    assert store.next_run("weekly", 7, weekday=0, after=now) == _utc(2026, 11, 2, 6, 0)
    assert store.next_run("weekly", 10, weekday=4, after=now) == _utc(2026, 10, 30, 9, 0)
    assert store.next_run("monthly", 7, day=1, after=now) == _utc(2026, 11, 1, 6, 0)
    assert store.next_run("monthly", 7, day=1, after=_utc(2026, 12, 2)) == _utc(2027, 1, 1, 6, 0)

def test_next_run_keeps_wall_clock_across_dst():
    # summer time (UTC+2) until 2027-03-28; a 07:00 weekly run lands at 05:00 UTC after it
    assert store.next_run("weekly", 7, weekday=0, after=_utc(2027, 3, 27, 12)) == _utc(2027, 3, 29, 5, 0)


# store

def test_store_crud_and_owner_filter():
    a = store.create("alice@example.com", "Alice", [{"uuid": UUID_A, "label": "api"}], ["a@example.com"], "daily", 7)
    store.create("bob@example.com", "Bob", [{"uuid": UUID_B, "label": "web"}], ["b@example.com"], "weekly", 8, weekday=0)
    assert [s["owner"] for s in store.list_for("alice@example.com")] == ["alice@example.com"]
    assert len(store.list_for()) == 2
    assert store.get(a["id"])["projects"] == [{"uuid": UUID_A, "label": "api"}]
    store.delete(a["id"])
    assert store.get(a["id"]) is None

def test_claim_due_moves_slot_and_claims_once():
    sub = store.create("o", None, [{"uuid": UUID_A, "label": "x"}], ["a@example.com"], "daily", 7)
    due_at = datetime.fromisoformat(sub["next_run"])
    assert store.claim_due(now=_utc(2000, 1, 1)) == []
    claimed = store.claim_due(now=due_at)
    assert [c["id"] for c in claimed] == [sub["id"]]
    assert store.claim_due(now=due_at) == []  # already moved to the next slot
    assert datetime.fromisoformat(store.get(sub["id"])["next_run"]) > due_at
    store.record_run(sub["id"], "sent")
    assert store.get(sub["id"])["last_status"] == "sent"


# mailer

def test_recipients_normalised_and_allowlisted():
    assert mailer.check_recipients("A@Example.com; b@example.com,a@example.com") == ["a@example.com", "b@example.com"]
    assert mailer.check_recipients(["boss@partner.org"]) == ["boss@partner.org"]
    with pytest.raises(mailer.MailError, match="not allowed"):
        mailer.check_recipients(["x@evil.com"])
    with pytest.raises(mailer.MailError, match="Not an email"):
        mailer.check_recipients(["nope"])
    with pytest.raises(mailer.MailError, match="at least one"):
        mailer.check_recipients([])
    with pytest.raises(mailer.MailError, match="At most"):
        mailer.check_recipients([f"u{i}@example.com" for i in range(21)])

def test_mail_disabled_without_allowlist(monkeypatch):
    monkeypatch.setenv("DTRG_MAIL_ALLOWED_RECIPIENTS", "")
    assert not mailer.enabled()
    with pytest.raises(mailer.MailError, match="not configured"):
        mailer.send(["a@example.com"], "s", "<p>x</p>")

def test_smtp_send_starttls_login_and_attachment(monkeypatch):
    monkeypatch.setenv("DTRG_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("DTRG_SMTP_USER", "u")
    monkeypatch.setenv("DTRG_SMTP_PASSWORD", "p")
    server = MagicMock()
    server.__enter__.return_value = server  # like smtplib.SMTP
    with patch.object(mailer.smtplib, "SMTP", return_value=server) as smtp:
        mailer.send(["a@example.com"], "Report", "<p>hi</p>", [("d.html", b"<html>", "text/html")])
    smtp.assert_called_once_with("smtp.example.com", 587, timeout=60)
    s = server
    s.starttls.assert_called_once()
    s.login.assert_called_once_with("u", "p")
    msg = s.send_message.call_args.args[0]
    assert msg["To"] == "a@example.com" and msg["From"] == "dtrg@example.com"
    assert [p.get_filename() for p in msg.iter_attachments()] == ["d.html"]

def test_smtp_failure_is_a_safe_error(monkeypatch):
    with patch.object(mailer.smtplib, "SMTP", side_effect=OSError("connection refused 10.0.0.5")):
        with pytest.raises(mailer.MailError) as e:
            mailer.send(["a@example.com"], "s", "<p>x</p>")
    assert "10.0.0.5" not in str(e.value)

def test_graph_send(monkeypatch):
    monkeypatch.setenv("DTRG_MAIL_BACKEND", "graph")
    monkeypatch.setenv("DTRG_OIDC_TENANT_ID", "t")
    monkeypatch.setenv("DTRG_OIDC_CLIENT_ID", "c")
    monkeypatch.setenv("DTRG_OIDC_CLIENT_SECRET", "s")
    token = MagicMock(status_code=200, json=lambda: {"access_token": "tok"})
    sent = MagicMock(status_code=202)
    with patch.object(mailer.requests, "post", side_effect=[token, sent]) as post:
        mailer.send(["a@example.com"], "Report", "<p>hi</p>", [("d.html", b"<html>", "text/html")])
    assert post.call_args_list[0].args[0] == "https://login.microsoftonline.com/t/oauth2/v2.0/token"
    url, kw = post.call_args_list[1].args[0], post.call_args_list[1].kwargs
    assert url == "https://graph.microsoft.com/v1.0/users/dtrg@example.com/sendMail"
    assert kw["headers"] == {"Authorization": "Bearer tok"}
    msg = kw["json"]["message"]
    assert msg["toRecipients"] == [{"emailAddress": {"address": "a@example.com"}}]
    assert msg["attachments"][0]["contentBytes"] == "PGh0bWw+"

def test_graph_error(monkeypatch):
    monkeypatch.setenv("DTRG_MAIL_BACKEND", "graph")
    for k in ("DTRG_OIDC_TENANT_ID", "DTRG_OIDC_CLIENT_ID", "DTRG_OIDC_CLIENT_SECRET"):
        monkeypatch.setenv(k, "x")
    with patch.object(mailer.requests, "post", side_effect=[MagicMock(status_code=200, json=lambda: {"access_token": "t"}),
                                                           MagicMock(status_code=403, text="denied")]):
        with pytest.raises(mailer.MailError, match="Graph"):
            mailer.send(["a@example.com"], "s", "<p>x</p>")


# summary

def _project(name, kev=False):
    comp = {"name": "tomcat-embed-core", "group": "org.apache.tomcat.embed", "version": "9.0.39",
            "latest": "11.0.27", "platform": "spring-boot"}
    vuln = {"sev": "critical", "id": "CVE-2025-24813", "cves": ["CVE-2025-24813"], "kev": kev, "epss": 0.9,
            "vector": "AV:N", "cvss": 9.8, "title": "Tomcat RCE", "comp": "c1", "fix": "9.0.99", "fixKind": "patch"}
    boot = {"id": "spring-boot", "name": "Spring Boot", "kind": "platform", "current": "2.3.5.RELEASE",
            "target": "4.0.9", "effort": "major", "members": ["c1"],
            "overrides": [{"property": "tomcat.version", "current": "9.0.39", "value": "9.0.121", "effort": "patch",
                           "fixedFindings": 1, "findings": 1, "kevFixed": int(kev), "members": ["c1"],
                           "clearedVulns": {"c1": ["CVE-2025-24813"]}}]}
    return {"name": name, "dtLink": "https://dt/p", "counts": {"CRITICAL": 1, "HIGH": 0},
            "components": {"c1": comp}, "vulns": [vuln], "platforms": [boot]}

def test_summary_numbers_and_quick_fix():
    s = mail_summary.summarize([_project("comm", kev=True), _project("h30")])
    assert s["critical"] == 2 and s["kev_ids"] == 1 and s["p1"] == 2
    assert s["quick_count"] == 2 and s["quick_kev"] == 1
    comm = s["apps"][0]
    assert comm["name"] == "comm" and comm["status"][1] == "Exploited: act now"
    assert comm["top"][0]["label"] == "Spring Boot" and comm["top"][0]["to"] == "4.0.9"
    assert "now: tomcat.version=9.0.121" in s["p1_rows"][0]["libs"][0]
    one = [_project("comm", kev=True)]
    assert mail_summary.subject(mail_summary.title(one, [], 1), mail_summary.summarize(one)) == \
        "[dtrg] Vulnerability report: comm: 1 critical, 0 high, 1 actively exploited"
    assert mail_summary.title(one * 3, [{"name": "WORKTIME"}], 1) == "WORKTIME"
    assert mail_summary.title(one * 3, [], 3) == "3 applications"

def test_email_body_renders_without_scripts():
    s = mail_summary.summarize([_project("comm", kev=True)])
    with app_module.app.test_request_context():
        html = app_module.render_template("email_summary.html", s=s, attachment="d.html", note=None,
                                          generated="now", public_url="https://dtrg.example.com")
    assert "<script" not in html
    assert "tomcat.version" in html and "9.0.121" in html and "CVE-2025-24813" in html
    assert "https://dtrg.example.com" in html


# routes

@pytest.fixture
def client():
    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with app_module.app.test_client() as c:
        yield c
    app_module.app.config.update(WTF_CSRF_ENABLED=True)

def test_mail_config(client):
    body = client.get("/ui/mail").get_json()
    assert body["enabled"] and body["allowed"] == ["*@example.com", "boss@partner.org"]
    assert body["timezone"] == "Europe/Bratislava"

def test_send_now(client):
    with patch.object(app_module, "send_report_email") as send:
        res = client.post("/ui/email", json={"projects": [UUID_A], "recipients": ["a@example.com"]})
    assert res.status_code == 200
    send.assert_called_once_with([UUID_A], ["a@example.com"])

def test_send_now_reports_mail_errors(client):
    with patch.object(app_module, "send_report_email", side_effect=mailer.MailError("Recipient not allowed: x@evil.com")):
        res = client.post("/ui/email", json={"projects": [UUID_A], "recipients": ["x@evil.com"]})
    assert res.status_code == 400 and "not allowed" in res.get_json()["error"]

def test_send_now_rejects_bad_projects(client):
    assert client.post("/ui/email", json={"projects": ["../x"], "recipients": ["a@example.com"]}).status_code == 400

def test_send_report_email_builds_body_and_attachment(client):
    collected = [_project("comm", kev=True)]
    with patch.object(app_module, "_build_dashboard_data", return_value=({"projects": collected, "collections": []}, None)), \
         patch.object(app_module.mailer, "send") as send, app_module.app.test_request_context():
        app_module.send_report_email([UUID_A], ["a@example.com"])
    recipients, subject, html, attachments = send.call_args.args
    assert recipients == ["a@example.com"] and "comm" in subject
    assert attachments[0][0].startswith("dashboard_comm_") and attachments[0][2] == "text/html"
    assert b"const DATA" in attachments[0][1] and "Quick" in html

def test_subscription_lifecycle(client):
    res = client.post("/ui/subscriptions", json={
        "projects": [{"uuid": UUID_A, "label": "comm"}, {"uuid": "bad"}], "recipients": ["a@example.com"],
        "frequency": "weekly", "weekday": 0, "hour": 7})
    assert res.status_code == 200
    sub = res.get_json()
    assert sub["projects"] == [{"uuid": UUID_A, "label": "comm"}]
    assert [s["id"] for s in client.get("/ui/subscriptions").get_json()["items"]] == [sub["id"]]
    with patch.object(app_module, "send_report_email") as send:
        assert client.post(f"/ui/subscriptions/{sub['id']}/run").status_code == 200
    assert send.call_args.args[:2] == ([UUID_A], ["a@example.com"])
    assert store.get(sub["id"])["last_status"] == "sent"
    assert client.delete(f"/ui/subscriptions/{sub['id']}").status_code == 200
    assert client.get("/ui/subscriptions").get_json()["items"] == []

@pytest.mark.parametrize("body,error", [
    ({"recipients": ["a@example.com"], "frequency": "daily", "hour": 7}, "Select at least one project"),
    ({"projects": [{"uuid": UUID_A}], "recipients": ["x@evil.com"], "frequency": "daily", "hour": 7}, "not allowed"),
    ({"projects": [{"uuid": UUID_A}], "recipients": ["a@example.com"], "frequency": "hourly", "hour": 7}, "Pick when"),
    ({"projects": [{"uuid": UUID_A}], "recipients": ["a@example.com"], "frequency": "weekly", "hour": 7}, "Pick when"),
    ({"projects": [{"uuid": UUID_A}], "recipients": ["a@example.com"], "frequency": "monthly", "day": 31, "hour": 7}, "Pick when"),
])
def test_subscription_validation(client, body, error):
    res = client.post("/ui/subscriptions", json=body)
    assert res.status_code == 400 and error in res.get_json()["error"]

def test_other_users_subscriptions_are_invisible(client):
    other = store.create("mallory@example.com", "M", [{"uuid": UUID_A, "label": "x"}], ["m@example.com"], "daily", 7)
    with client.session_transaction() as s:
        s["user"] = {"username": "alice@example.com", "oid": "1", "name": "Alice"}
    assert client.get("/ui/subscriptions").get_json()["items"] == []
    assert client.delete(f"/ui/subscriptions/{other['id']}").status_code == 404
    assert client.post(f"/ui/subscriptions/{other['id']}/run").status_code == 404
    assert store.get(other["id"]) is not None

def test_mutations_need_csrf_token():
    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
    with app_module.app.test_client() as c:
        res = c.post("/ui/email", json={"projects": [UUID_A], "recipients": ["a@example.com"]})
    assert res.status_code == 400


# scheduler

def test_scheduler_tick_runs_due_and_survives_failures():
    s1 = store.create("o", None, [{"uuid": UUID_A, "label": "x"}], ["a@example.com"], "daily", 7)
    s2 = store.create("o", None, [{"uuid": UUID_B, "label": "y"}], ["a@example.com"], "daily", 7)
    calls = []

    def job(sub):
        calls.append(sub["id"])
        if sub["id"] == s1["id"]:
            raise mailer.MailError("smtp down")

    later = datetime.fromisoformat(s1["next_run"])
    with patch.object(store, "_now", return_value=later):
        assert scheduler.tick(app_module.app, job) == 2
    assert sorted(calls) == sorted([s1["id"], s2["id"]])
