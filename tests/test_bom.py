""" Tests for backend.bom and the dashboard's platform / ownership analysis """

from unittest.mock import MagicMock, patch

import pytest

from backend import bom, dashboard


@pytest.fixture(autouse=True)
def _clear():
    bom._cache.clear()
    dashboard._cache.clear()
    yield
    bom._cache.clear()
    dashboard._cache.clear()


def _pom(body, parent=""):
    return f"""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">{parent}{body}</project>"""


POMS = {
    "org/example/platform-bom/1.0/platform-bom-1.0.pom": _pom("""
      <properties><tomcat.version>9.0.39</tomcat.version><jackson-bom.version>2.11.3</jackson-bom.version></properties>
      <dependencyManagement><dependencies>
        <dependency><groupId>org.apache.tomcat.embed</groupId><artifactId>tomcat-embed-core</artifactId><version>${tomcat.version}</version></dependency>
        <dependency><groupId>org.example</groupId><artifactId>platform-core</artifactId><version>${project.version}</version></dependency>
        <dependency><groupId>com.fasterxml.jackson</groupId><artifactId>jackson-bom</artifactId><version>${jackson-bom.version}</version><type>pom</type><scope>import</scope></dependency>
      </dependencies></dependencyManagement>"""),
    "com/fasterxml/jackson/jackson-bom/2.11.3/jackson-bom-2.11.3.pom": _pom("""
      <dependencyManagement><dependencies>
        <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version.databind}</version></dependency>
      </dependencies></dependencyManagement>""",
      parent="<parent><groupId>com.fasterxml.jackson</groupId><artifactId>jackson-parent</artifactId><version>2.11</version></parent>"),
    "com/fasterxml/jackson/jackson-parent/2.11/jackson-parent-2.11.pom": _pom(
        "<properties><jackson.version.databind>2.11.3</jackson.version.databind></properties>"),
}


def _fake_get(url, timeout=None, **kw):
    path = url.replace(bom.CENTRAL, "")
    res = MagicMock()
    res.status_code = 200 if path in POMS else 404
    res.text = POMS.get(path, "")
    return res


def test_managed_versions_resolves_properties_imports_and_parents():
    with patch.object(bom.requests, "get", side_effect=_fake_get):
        found = bom.managed_versions("org.example", "platform-bom", "1.0", {
            ("org.apache.tomcat.embed", "tomcat-embed-core"),
            ("org.example", "platform-core"),
            ("com.fasterxml.jackson.core", "jackson-databind"),
            ("not", "managed"),
        })
    assert found == {
        ("org.apache.tomcat.embed", "tomcat-embed-core"): "9.0.39",
        ("org.example", "platform-core"): "1.0",
        ("com.fasterxml.jackson.core", "jackson-databind"): "2.11.3",
    }

def test_import_boms_fetched_only_when_needed():
    with patch.object(bom.requests, "get", side_effect=_fake_get) as get:
        bom.managed_versions("org.example", "platform-bom", "1.0",
                             {("org.apache.tomcat.embed", "tomcat-embed-core")})
    assert all("jackson" not in c.args[0] for c in get.call_args_list)

def test_release_versions_filters_milestones():
    meta = "<metadata><versioning><versions><version>2.3.5.RELEASE</version><version>3.0.0-M1</version>" \
           "<version>3.0.0</version><version>3.1.0-RC2</version></versions></versioning></metadata>"
    res = MagicMock(status_code=200, text=meta)
    with patch.object(bom.requests, "get", return_value=res):
        assert bom.release_versions("g", "a") == ["2.3.5.RELEASE", "3.0.0"]


# ownership

def _node(name, deps=(), direct=False, group="g", version="1"):
    return {"name": name, "group": group, "version": version, "dependencies": list(deps),
            "is_direct_dependency": direct}

def test_paths_skip_app_module_and_find_shortest_route():
    graph = {
        "app": _node("my-app", ["web", "mail"], direct=True),
        "web": _node("spring-boot-starter-web", ["st"]),
        "st": _node("spring-boot-starter-tomcat", ["tc"]),
        "tc": _node("tomcat-embed-core"),
        "mail": _node("mail", ["tc"]),
    }
    assert dashboard.top_level(graph) == {"web", "mail"}
    paths = dashboard.dependency_paths(graph, ["tc", "web", "missing"])
    assert paths["tc"] == ["mail"]
    assert paths["web"] == [] and paths["missing"] == []

def test_many_direct_deps_used_as_is():
    graph = {k: _node(k, direct=True) for k in "abc"}
    graph["d"] = _node("d")
    graph["a"]["dependencies"] = ["d"]
    assert dashboard.top_level(graph) == {"a", "b", "c"}
    assert dashboard.dependency_paths(graph, ["d"])["d"] == ["a"]


# platforms

def _comp(name, group, version):
    return {"name": name, "group": group, "version": version, "purl": f"pkg:maven/{group}/{name}@{version}"}

def test_spring_boot_platform_picks_lowest_release_clearing_findings():
    comps = {
        "tc": _comp("tomcat-embed-core", "org.apache.tomcat.embed", "9.0.39"),
        "own": _comp("tomcat-embed-core-override", "x", "1"),  # not pinned by Boot -> not a member
    }
    vuln = {"uuid": "v1"}
    checks = {"tc": [(vuln, ["GHSA-1"], "9.0.99")], "own": [(vuln, [], None)]}
    ships = {"2.3.5.RELEASE": "9.0.39", "2.3.12.RELEASE": "9.0.46", "2.7.18": "9.0.83", "3.0.13": "10.1.16"}

    def managed(group, artifact, version, wanted):
        return {("org.apache.tomcat.embed", "tomcat-embed-core"): ships[version]}

    def affected(url, headers, comp, v, ghsa_ids, version):
        return dashboard.vcmp(version, "9.0.80") < 0  # fixed from 9.0.80 on

    with patch.object(dashboard.bom, "managed_versions", side_effect=managed), \
         patch.object(dashboard.bom, "release_versions", return_value=list(ships)), \
         patch.object(dashboard, "is_affected", side_effect=affected):
        pl = dashboard.spring_boot_platform("u", {}, "2.3.5.RELEASE", comps, checks)
    assert pl["members"] == ["tc"]
    assert pl["target"] == "2.7.18" and pl["allFixed"] and pl["effort"] == "minor"
    assert pl["memberTargets"]["tc"] == {"version": "9.0.83", "fixed": True}
    assert pl["inLine"] is None

def test_spring_boot_platform_reports_best_effort_and_same_major_option():
    comps = {"tc": _comp("tomcat-embed-core", "org.apache.tomcat.embed", "9.0.39"),
             "jd": _comp("jackson-databind", "com.fasterxml.jackson.core", "2.11.3")}
    checks = {"tc": [({"uuid": "a"}, [], "11.0.1")], "jd": [({"uuid": "b"}, [], None)]}
    ships = {"2.3.5.RELEASE": ("9.0.39", "2.11.3"), "2.7.18": ("9.0.83", "2.13.5"), "3.0.13": ("10.1.16", "2.14.3"),
             "4.0.1": ("11.0.2", "2.20.0"), "4.1.0": ("11.0.9", "2.21.0")}

    def managed(group, artifact, version, wanted):
        tc, jd = ships[version]
        return {("org.apache.tomcat.embed", "tomcat-embed-core"): tc, ("com.fasterxml.jackson.core", "jackson-databind"): jd}

    def affected(url, headers, comp, v, ghsa_ids, version):
        return comp["name"] == "jackson-databind" or dashboard.vcmp(version, "11.0.1") < 0

    with patch.object(dashboard.bom, "managed_versions", side_effect=managed), \
         patch.object(dashboard.bom, "release_versions", return_value=list(ships)), \
         patch.object(dashboard, "is_affected", side_effect=affected):
        pl = dashboard.spring_boot_platform("u", {}, "2.3.5.RELEASE", comps, checks)
    assert pl["target"] == "4.0.1"  # lowest release with the best achievable result
    assert not pl["allFixed"] and pl["fixedFindings"] == 1 and pl["unfixable"] == 1
    assert pl["inLine"] == {"version": "2.7.18", "fixedFindings": 0}

def test_family_platforms_group_version_aligned_libraries():
    comps = {"a": _comp("spring-web", "org.springframework", "5.3.39"),
             "b": _comp("spring-core", "org.springframework", "5.3.39"),
             "c": _comp("jackson-databind", "com.fasterxml.jackson.core", "2.19.1"),
             "d": _comp("guava", "com.google.guava", "18.0")}
    fixes = {"a": "6.0.0", "b": "7.0.9", "c": "2.21.7", "d": "33.0"}
    fam = dashboard.family_platforms(comps, fixes, exclude=set())
    assert [(f["name"], f["target"], f["effort"], sorted(f["members"])) for f in fam] == \
        [("Spring Framework", "7.0.9", "major", ["a", "b"])]  # single-member Jackson is not a family

def test_is_affected_uses_github_ranges_then_dt_ranges():
    comp = _comp("spring-web", "org.springframework", "5.3.39")
    adv = [{"pkg": "org.springframework:spring-web", "range": ">= 5.3.0, < 5.3.40", "fix": "5.3.40"}]
    with patch.object(dashboard, "_ghsa", return_value=adv):
        assert dashboard.is_affected("u", {}, comp, {"uuid": "v"}, ["G"], "5.3.39") is True
        assert dashboard.is_affected("u", {}, comp, {"uuid": "v"}, ["G"], "6.0.0") is False
    cpe = [{"type": "CPE", "identity": "c", "start": "6.0.0", "startExcl": False, "endExcl": "6.0.31", "endIncl": None}]
    with patch.object(dashboard, "_dt_ranges", return_value=cpe):
        assert dashboard.is_affected("u", {}, comp, {"uuid": "v"}, [], "6.0.5") is True
        assert dashboard.is_affected("u", {}, comp, {"uuid": "v"}, [], "6.1.0") is False
    with patch.object(dashboard, "_dt_ranges", return_value=[]):
        assert dashboard.is_affected("u", {}, comp, {"uuid": "v"}, [], "6.1.0") is None
