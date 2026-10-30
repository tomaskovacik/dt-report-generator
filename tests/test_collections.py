""" Tests for DT collection projects (backend.dt_collections + app wiring) """

import io
import json
import os
import zipfile
from unittest.mock import MagicMock, patch

import pytest

import app as app_module
from backend import dt_collections

URL = "https://dt.example.com/api/v1/"


def _p(uuid, name, logic=None, bom=True, latest=False, tags=(), tag=None):
    return {"uuid": uuid, "name": name, "collectionLogic": logic, "lastBomImport": 1 if bom else None,
            "isLatest": latest, "tags": [{"name": t} for t in tags],
            "collectionTag": {"name": tag} if tag else None}


PROJECTS = {
    "root": _p("root", "WORKTIME", "AGGREGATE_DIRECT_CHILDREN"),
    "api": _p("api", "worktime-api"),
    "db": _p("db", "worktime database", bom=False),
    "imgs": _p("imgs", "worktime docker images", "AGGREGATE_DIRECT_CHILDREN", bom=False),
    "img1": _p("img1", "api image"),
    "plain": _p("plain", "h30listener-api"),
    "latest": _p("latest", "Nextcore", "AGGREGATE_LATEST_VERSION_CHILDREN"),
    "v1": _p("v1", "svc 1.0"), "v2": _p("v2", "svc 2.0", latest=True),
    "tagged": _p("tagged", "Prod", "AGGREGATE_DIRECT_CHILDREN_WITH_TAG", tag="Prod"),
    "t1": _p("t1", "a", tags=["prod"]), "t2": _p("t2", "b", tags=["dev"]),
}
CHILDREN = {"root": ["api", "db", "imgs", "root"], "imgs": ["img1"], "latest": ["v1", "v2"], "tagged": ["t1", "t2"]}


def _fake_get(url, headers=None, params=None, **kw):
    path = url.replace(URL, "")
    res = MagicMock(status_code=200)
    if path.endswith("/children"):
        body = [PROJECTS[c] for c in CHILDREN[path.split("/")[1]]]
        res.headers = {"X-Total-Count": str(len(body))}
    else:
        body = PROJECTS[path.split("/")[1]]
        res.headers = {}
    res.json.return_value = body
    return res


def _expand(uuids):
    with patch.object(dt_collections.requests, "get", side_effect=_fake_get):
        return dt_collections.expand(URL, {}, uuids)


def test_plain_projects_pass_through():
    assert _expand(["plain"]) == (["plain"], [])

def test_direct_children_with_nested_collection_and_no_bom():
    leaves, infos = _expand(["root"])
    assert leaves == ["api", "img1"]  # nested collection expanded, no-BOM child skipped, no self-loop
    assert infos == [{"uuid": "root", "name": "WORKTIME", "logic": "AGGREGATE_DIRECT_CHILDREN", "tag": None,
                      "included": ["worktime-api", "api image"], "skipped": ["worktime database"]}]

def test_latest_version_children_only():
    assert _expand(["latest"])[0] == ["v2"]

def test_tagged_children_only_case_insensitive():
    assert _expand(["tagged"])[0] == ["t1"]

def test_mixed_selection_deduplicates():
    leaves, infos = _expand(["plain", "root", "api"])
    assert leaves == ["plain", "api", "img1"] and [i["name"] for i in infos] == ["WORKTIME"]


# app wiring

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("DT_URL", "https://dt.example.com")
    monkeypatch.setenv("DT_TOKEN", "t")
    monkeypatch.delenv("DTRG_API_KEY", raising=False)
    app_module.app.config.update(TESTING=True)
    with app_module.app.test_client() as c:
        yield c


def _dash(uuid):
    return {"name": PROJECTS[uuid]["name"], "uuid": uuid, "dtLink": "", "counts": {}, "components": {},
            "vulns": [], "tree": None, "platforms": []}


def test_collection_dashboard_expands_and_records_coverage():
    with patch.object(app_module, "_resolve_params", return_value=(URL, {}, "root")), \
         patch.object(dt_collections.requests, "get", side_effect=_fake_get), \
         patch.object(app_module, "_dashboard_project", side_effect=lambda u, h, p: _dash(p)):
        data, err = app_module._build_dashboard_data({}, ["root"], "/tmp")
    assert err is None
    assert [p["uuid"] for p in data["projects"]] == ["api", "img1"]
    assert data["collections"][0]["skipped"] == ["worktime database"]

def test_collection_without_bom_children_is_a_clear_error():
    PROJECTS["empty"] = _p("empty", "CSL", "AGGREGATE_DIRECT_CHILDREN")
    CHILDREN["empty"] = ["db"]
    with patch.object(app_module, "_resolve_params", return_value=(URL, {}, "empty")), \
         patch.object(dt_collections.requests, "get", side_effect=_fake_get):
        data, err = app_module._build_dashboard_data({}, ["empty"], "/tmp")
    assert data is None and app_module._dashboard_user_error(err) == "No projects with a BOM in CSL"

def test_collection_cap(monkeypatch):
    monkeypatch.setenv("DTRG_COLLECTION_MAX_PROJECTS", "1")
    with patch.object(app_module, "_resolve_params", return_value=(URL, {}, "root")), \
         patch.object(dt_collections.requests, "get", side_effect=_fake_get):
        data, err = app_module._build_dashboard_data({}, ["root"], "/tmp")
    assert "At most 1 projects" in str(err)

def test_collection_zip_has_dashboard_and_child_folders(tmp_path):
    def fake_create_report(config, out):
        uuid = config["project"][0]
        for f in ("result.docx", "result.xlsx", "summary.json"):
            open(os.path.join(out, f), "w").write(uuid)
        return f"{uuid} report", {}
    info = {"uuid": "root", "name": "WORKTIME"}
    with patch.object(app_module, "_build_dashboard_data",
                      return_value=({"projects": [_dash("api"), _dash("img1")], "collections": [info]}, None)), \
         patch.object(app_module, "create_report", side_effect=fake_create_report):
        zip_path, name = app_module._build_collection_zip({"project": ["root"]}, str(tmp_path), info)
    names = sorted(zipfile.ZipFile(zip_path).namelist())
    assert names == ["api_image/result.docx", "api_image/result.xlsx", "api_image/summary.json", "dashboard.html",
                     "worktime-api/result.docx", "worktime-api/result.xlsx", "worktime-api/summary.json"]
    assert name.startswith("WORKTIME collection")
    assert b'"collections": [{"uuid": "root"' in zipfile.ZipFile(zip_path).read("dashboard.html")

def test_build_report_routes_collections_to_collection_zip(tmp_path):
    with patch.object(app_module, "_collection_of", return_value={"uuid": "root", "name": "WORKTIME"}), \
         patch.object(app_module, "_build_collection_zip", return_value=("z", "n")) as coll, \
         patch.object(app_module, "create_report") as single:
        assert app_module._build_report({"project": ["root"]}, str(tmp_path)) == ("z", "n")
    single.assert_not_called()
    coll.assert_called_once()

def test_project_list_marks_collections(client):
    dt = [dict(PROJECTS["root"], metrics={}), dict(PROJECTS["tagged"], metrics={}), dict(PROJECTS["api"], metrics={})]
    with patch.object(app_module, "get_projects", return_value=(json.dumps(dt), 3)):
        items = client.get("/ui/projects").get_json()["items"]
    assert [i["collection"] for i in items] == ["all direct children", "children tagged Prod", None]
