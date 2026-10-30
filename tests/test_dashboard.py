""" Tests for backend.dashboard and the dashboard routes """

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

import app as app_module
from backend import dashboard

URL = "https://dt.example.com/api/v1/"
HEADERS = {"X-Api-Key": "k"}


@pytest.fixture(autouse=True)
def _clear_cache():
    dashboard._cache.clear()
    yield
    dashboard._cache.clear()


def _resp(status=200, body=None, headers=None):
    res = MagicMock()
    res.status_code = status
    res.json.return_value = body if body is not None else {}
    res.headers = headers or {}
    res.raise_for_status.side_effect = None if status < 400 else Exception(status)
    return res


def _comp(version="5.3.39", name="spring-web", group="org.springframework", latest="7.0.9"):
    return {"uuid": "c1", "name": name, "group": group, "version": version,
            "purl": f"pkg:maven/{group}/{name}@{version}?type=jar", "latestVersion": latest}


# versions

@pytest.mark.parametrize("a,b,expected", [
    ("1.2.10", "1.2.9", 1),
    ("5.3.39", "5.3.39", 0),
    ("6.0.0", "5.3.50", 1),
    ("2.12.7.1", "2.12.7", 1),
    ("5.2.20.RELEASE", "5.2.20", 0),
    ("4.1.124.Final", "4.1.124", 0),
    ("1.0.0-rc1", "1.0.0", -1),
])
def test_vcmp(a, b, expected):
    assert dashboard.vcmp(a, b) == expected

@pytest.mark.parametrize("version,rng,expected", [
    ("5.3.39", ">= 5.3.0, < 5.3.50", True),
    ("5.3.50", ">= 5.3.0, < 5.3.50", False),
    ("6.2.19", "<= 6.2.19", True),
    ("1.0", "= 1.0", True),
    ("2.0", "< 2", False),
])
def test_in_range(version, rng, expected):
    assert dashboard.in_range(version, rng) is expected

@pytest.mark.parametrize("cur,target,kind", [
    ("9.0.39", "9.0.99", "patch"),
    ("2.3.5.RELEASE", "2.5.12", "minor"),
    ("5.3.39", "7.0.9", "major"),
])
def test_upgrade_kind(cur, target, kind):
    assert dashboard.upgrade_kind(cur, target) == kind


# fix_version

def test_fix_from_github_in_current_line():
    adv = [{"pkg": "org.springframework:spring-web", "range": ">= 5.3.0, < 5.3.40", "fix": "5.3.40"}]
    with patch.object(dashboard, "_ghsa", return_value=adv), \
         patch.object(dashboard, "_is_public", return_value=True):
        fx = dashboard.fix_version(URL, HEADERS, _comp(), {"uuid": "v"}, ["GHSA-x"])
    assert fx == {"fix": "5.3.40", "kind": "patch", "note": None, "assumed": False}

def test_fix_in_later_line_when_current_line_unpatched():
    adv = [
        {"pkg": "org.springframework:spring-web", "range": ">= 5.3.0, <= 5.3.49", "fix": None},
        {"pkg": "org.springframework:spring-web", "range": ">= 6.0.0, < 6.1.14", "fix": "6.1.14"},
    ]
    with patch.object(dashboard, "_ghsa", return_value=adv), \
         patch.object(dashboard, "_is_public", return_value=True):
        fx = dashboard.fix_version(URL, HEADERS, _comp(), {"uuid": "v"}, ["GHSA-x"])
    assert fx["fix"] == "6.1.14"
    assert fx["kind"] == "major"
    assert "5.3.x line" in fx["note"]

def test_commercial_only_fix_falls_back_to_latest_public():
    ranges = [{"type": "CPE", "identity": "cpe", "start": "5.3.0", "startExcl": False,
               "endExcl": "5.3.50", "endIncl": None}]
    with patch.object(dashboard, "_ghsa", return_value=[]), \
         patch.object(dashboard, "_dt_ranges", return_value=ranges), \
         patch.object(dashboard, "_is_public", return_value=False):
        fx = dashboard.fix_version(URL, HEADERS, _comp(), {"uuid": "v"}, [])
    assert fx["fix"] == "7.0.9"
    assert fx["assumed"] is True
    assert "commercial" in fx["note"]

def test_purl_range_preferred_over_cpe():
    ranges = [
        {"type": "PURL", "identity": "pkg:maven/org.springframework/spring-web",
         "start": None, "startExcl": False, "endExcl": "6.0.0", "endIncl": None},
        {"type": "CPE", "identity": "cpe", "start": None, "startExcl": False,
         "endExcl": "5.3.40", "endIncl": None},
    ]
    with patch.object(dashboard, "_dt_ranges", return_value=ranges), \
         patch.object(dashboard, "_is_public", return_value=True):
        fx = dashboard.fix_version(URL, HEADERS, _comp(), {"uuid": "v"}, [])
    assert fx["fix"] == "6.0.0"

def test_no_fix_known():
    with patch.object(dashboard, "_dt_ranges", return_value=[]):
        fx = dashboard.fix_version(URL, HEADERS, _comp(), {"uuid": "v"}, [])
    assert fx["fix"] is None and fx["kind"] == "none"

def test_lookup_errors_never_raise():
    with patch.object(dashboard, "_dt_ranges", side_effect=RuntimeError("boom")):
        fx = dashboard.fix_version(URL, HEADERS, _comp(), {"uuid": "v"}, [])
    assert fx["fix"] is None

def test_enrichment_disabled_skips_external_calls(monkeypatch):
    monkeypatch.setenv("DTRG_DASHBOARD_ENRICH", "false")
    ranges = [{"type": "CPE", "identity": "cpe", "start": None, "startExcl": False,
               "endExcl": "5.3.40", "endIncl": None}]
    with patch.object(dashboard, "_ghsa") as ghsa, \
         patch.object(dashboard, "_is_public") as public, \
         patch.object(dashboard, "_dt_ranges", return_value=ranges):
        fx = dashboard.fix_version(URL, HEADERS, _comp(), {"uuid": "v"}, ["GHSA-x"])
    ghsa.assert_not_called()
    public.assert_not_called()
    assert fx["fix"] == "5.3.40"

def test_ghsa_404_cached_as_empty():
    with patch.object(dashboard.requests, "get", return_value=_resp(404)) as get:
        assert dashboard._ghsa("GHSA-none") == []
        assert dashboard._ghsa("GHSA-none") == []
    assert get.call_count == 1

def test_ghsa_error_not_cached():
    with patch.object(dashboard.requests, "get", return_value=_resp(500)) as get:
        dashboard._ghsa("GHSA-err")
        dashboard._ghsa("GHSA-err")
    assert get.call_count == 2


# build_project / render

def _finding(sev, vuln_id="CVE-2022-22965", kev=False, aliases=None):
    return {
        "component": _comp(),
        "vulnerability": {"uuid": "v-" + vuln_id + sev, "vulnId": vuln_id, "source": "NVD",
                          "severity": sev, "title": "t", "cvssV3BaseScore": 9.8,
                          "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N", "epssScore": 0.9,
                          "isKev": kev, "cwes": [{"cweId": 94, "name": "Code Injection"}],
                          "aliases": aliases or [{"ghsaId": "GHSA-36p3-wjmg-h94x"}]},
    }

def test_build_project_counts_all_and_details_critical_high_kev():
    findings = [_finding("CRITICAL", kev=True), _finding("HIGH", "CVE-2"),
                _finding("MEDIUM", "CVE-3"), _finding("MEDIUM", "CVE-4", kev=True), _finding("LOW", "CVE-5")]
    with patch.object(dashboard.requests, "get",
                      return_value=_resp(body=findings, headers={"X-Total-Count": "5"})), \
         patch.object(dashboard, "fix_version",
                      return_value={"fix": "5.3.18", "kind": "patch", "note": None, "assumed": False}):
        data = dashboard.build_project(URL, HEADERS, "p1", "app 1.0",
                                       direct={("spring-web", "5.3.39"): True})
    assert data["counts"]["CRITICAL"] == 1 and data["counts"]["MEDIUM"] == 2
    assert {v["id"] for v in data["vulns"]} == {"CVE-2022-22965", "CVE-2", "CVE-4"}
    crit = data["vulns"][0]
    assert crit["sev"] == "critical" and crit["kev"] and crit["ghsas"] == ["GHSA-36p3-wjmg-h94x"]
    assert crit["cves"] == ["CVE-2022-22965"]
    assert data["components"]["c1"]["direct"] is True
    assert data["dtLink"] == "https://dt.example.com/projects/p1"

def test_findings_paginates():
    page1 = [_finding("HIGH", f"CVE-{i}") for i in range(500)]
    page2 = [_finding("HIGH", "CVE-last")]
    responses = [_resp(body=page1, headers={"X-Total-Count": "501"}),
                 _resp(body=page2, headers={"X-Total-Count": "501"})]
    with patch.object(dashboard.requests, "get", side_effect=responses) as get:
        assert len(dashboard._findings(URL, HEADERS, "p")) == 501
    assert get.call_args.kwargs["params"]["pageNumber"] == 2

def test_render_embeds_data_and_escapes_script_close():
    project = {"name": "</script><b>x", "uuid": "u", "dtLink": "", "counts": {}, "components": {},
               "vulns": [], "tree": None}
    with tempfile.TemporaryDirectory() as d:
        path = dashboard.render([project], os.path.join(d, "dashboard.html"))
        html = open(path, encoding="utf-8").read()
    assert "/*__DATA__*/null" not in html
    assert "<\\/script><b>x" in html
    assert html.count("</script>") == 1

def test_graph_tree_extracts_pre():
    assert dashboard.graph_tree("<html><pre>Application\n└── a</pre></html>") == "Application\n└── a"
    assert dashboard.graph_tree("") is None


# app integration

@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("DTRG_API_KEY", raising=False)
    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with app_module.app.test_client() as c:
        yield c
    app_module.app.config.update(WTF_CSRF_ENABLED=True)


def _fake_create_report(config, output_dir):
    with open(os.path.join(output_dir, "summary.json"), "w") as f:
        json.dump({"project": {"name": "app", "version": "1.0"}, "components": []}, f)
    return "app 1.0 (29.10.2026)", []


def test_single_report_zip_contains_dashboard(client):
    import zipfile, io
    with patch.object(app_module, "create_report", side_effect=_fake_create_report), \
         patch.object(app_module, "_resolve_params", return_value=(URL, HEADERS, "p1")), \
         patch.object(dashboard, "build_project", return_value={
             "name": "app 1.0", "uuid": "p1", "dtLink": "", "counts": {}, "components": {},
             "vulns": [], "tree": None}) as build:
        res = client.post("/api/v1/reports/get_report", json={"project": "p1"})
    assert res.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(res.data)).namelist()
    assert "dashboard.html" in names and "summary.json" in names
    assert build.call_args.args[3] == "app 1.0"

def test_single_report_survives_dashboard_failure(client):
    import zipfile, io
    with patch.object(app_module, "create_report", side_effect=_fake_create_report), \
         patch.object(app_module, "_resolve_params", side_effect=ConnectionError("down")):
        res = client.post("/api/v1/reports/get_report", json={"project": "p1"})
    assert res.status_code == 200
    assert "dashboard.html" not in zipfile.ZipFile(io.BytesIO(res.data)).namelist()

def test_api_dashboard_combines_projects(client):
    seen = []
    def build(url, headers, project, name, tree, direct=None, graph=None):
        seen.append((project, name, bool(tree), sorted(graph)))
        return {"name": name, "uuid": project, "dtLink": "", "counts": {}, "components": {},
                "vulns": [], "tree": tree}
    comps = {"c1": {"name": "lib", "version": "1", "group": "", "last_version": "", "dependencies": [],
                    "is_direct_dependency": True, "vulnerabilities": [], "severity": ""}}
    loaded = lambda url, headers, project: {  # noqa: E731
        "name": "app-" + project, "info": {"version": "no version"}, "components": comps}
    with patch.object(app_module, "_load_project", side_effect=loaded), \
         patch.object(app_module, "create_report") as create_report, \
         patch.object(app_module, "_resolve_params", return_value=(URL, HEADERS, "a")), \
         patch.object(dashboard, "build_project", side_effect=build):
        res = client.post("/api/v1/reports/dashboard", json={"projects": ["a", "b", "a"]})
    assert res.status_code == 200
    assert res.mimetype == "text/html"
    assert seen == [("a", "app-a", True, ["c1"]), ("b", "app-b", True, ["c1"])]
    assert b'"uuid": "b"' in res.data
    create_report.assert_not_called()  # no docx / xlsx for a dashboard

def test_api_dashboard_requires_list(client):
    res = client.post("/api/v1/reports/dashboard", json={"projects": "a"})
    assert res.status_code == 400

def test_api_dashboard_rejects_empty_and_too_many(client, monkeypatch):
    assert client.post("/api/v1/reports/dashboard", json={"projects": []}).get_json() == \
        {"error": "Select at least one project"}
    monkeypatch.setenv("DTRG_DASHBOARD_MAX_PROJECTS", "2")
    res = client.post("/api/v1/reports/dashboard", json={"projects": ["a", "b", "c"]})
    assert res.get_json() == {"error": "At most 2 projects per dashboard"}

def test_api_dashboard_hides_internal_errors(client):
    with patch.object(app_module, "_resolve_params", side_effect=RuntimeError("secret detail")):
        res = client.post("/api/v1/reports/dashboard", json={"projects": ["a"]})
    assert res.status_code == 400
    assert "secret" not in res.get_json()["error"]

def test_api_dashboard_requires_key_when_set(client, monkeypatch):
    monkeypatch.setenv("DTRG_API_KEY", "secret")
    res = client.post("/api/v1/reports/dashboard", json={"projects": ["a"]})
    assert res.status_code == 401

# browser views

UUID_A = "00000000-0000-0000-0000-00000000000a"
UUID_B = "00000000-0000-0000-0000-00000000000b"


@pytest.fixture
def dt_env(monkeypatch):
    monkeypatch.setenv("DT_URL", "https://dt.example.com")
    monkeypatch.setenv("DT_TOKEN", "t")


def test_ui_projects_trims_dt_fields(client, dt_env):
    dt = [{"uuid": UUID_A, "name": "api", "version": "1.0", "parent": {"name": "WT", "uuid": "x"},
           "tags": [{"name": "java"}], "lastBomImport": 1, "directDependencies": "[huge]",
           "metrics": {"critical": 3, "high": 4, "medium": 0, "low": 1, "components": 99}}]
    with patch.object(app_module, "get_projects", return_value=(json.dumps(dt), 1)) as get:
        res = client.get("/ui/projects?search=api&page=2")
    body = res.get_json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["parent"] == "WT" and item["tags"] == ["java"]
    assert item["metrics"]["critical"] == 3 and "components" not in item["metrics"]
    assert "directDependencies" not in item
    args, kwargs = get.call_args
    assert args == ("https://dt.example.com", "t")
    assert kwargs["search_text"] == "api" and kwargs["page_number"] == 2

def test_ui_projects_needs_dt_config(client, monkeypatch):
    monkeypatch.delenv("DT_URL", raising=False)
    assert client.get("/ui/projects").status_code == 502

def test_ui_projects_upstream_error(client, dt_env):
    with patch.object(app_module, "get_projects", return_value=({"error": "x"}, 0)):
        assert client.get("/ui/projects").status_code == 502

def _fake_build_report(config, output_dir):
    with open(os.path.join(output_dir, "dashboard.html"), "w") as f:
        f.write("<html>dash</html>")
    zip_path = os.path.join(output_dir, "reports.zip")
    with open(zip_path, "wb") as f:
        f.write(b"PK")
    return zip_path, "api 1.0 (29.10.2026)"

def test_view_report_inline(client, dt_env):
    def fake(config, projects, output_dir):
        path = os.path.join(output_dir, "dashboard.html")
        with open(path, "w") as f:
            f.write("<html>dash</html>")
        return path, "dashboard"
    with patch.object(app_module, "_build_dashboard", side_effect=fake) as build, \
         patch.object(app_module, "_build_report") as zip_pipeline:
        res = client.get(f"/projects/{UUID_A}/report")
    assert res.status_code == 200 and res.mimetype == "text/html"
    assert "attachment" not in res.headers.get("Content-Disposition", "")
    assert res.data == b"<html>dash</html>"
    assert build.call_args.args[1] == [UUID_A]
    zip_pipeline.assert_not_called()  # viewing builds no ZIP

def test_download_report_zip(client, dt_env):
    with patch.object(app_module, "_build_report", side_effect=_fake_build_report):
        res = client.get(f"/projects/{UUID_A}/report.zip")
    assert res.status_code == 200 and res.mimetype == "application/zip"
    assert "attachment" in res.headers["Content-Disposition"]
    assert "api_1.0_29.10.2026.zip" in res.headers["Content-Disposition"]

def test_report_failure_shows_error_page(client, dt_env):
    with patch.object(app_module, "_build_dashboard", return_value=(None, ValueError("secret"))):
        res = client.get(f"/projects/{UUID_A}/report")
    assert res.status_code == 502
    assert b"Report generation failed" in res.data and b"secret" not in res.data

def test_report_rejects_non_uuid(client):
    with patch.object(app_module, "_build_report") as build:
        assert client.get("/projects/..%2Fetc/report").status_code == 404
        assert client.get("/projects/abc/report.zip").status_code == 404
    build.assert_not_called()

def test_view_combined_dashboard(client, dt_env):
    def fake(config, projects, output_dir):
        path = os.path.join(output_dir, "dashboard.html")
        with open(path, "w") as f:
            f.write("combined")
        return path, "dashboard"
    with patch.object(app_module, "_build_dashboard", side_effect=fake) as build:
        res = client.get(f"/dashboard?projects={UUID_A}&projects={UUID_B}")
    assert res.status_code == 200 and res.data == b"combined"
    assert build.call_args.args[1] == [UUID_A, UUID_B]

def test_combined_dashboard_user_errors(client, dt_env):
    res = client.get("/dashboard")
    assert res.status_code == 400 and b"Select at least one project" in res.data
    assert client.get("/dashboard?projects=nope").status_code == 400
