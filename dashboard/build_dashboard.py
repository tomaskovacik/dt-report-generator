#!/usr/bin/env python3
"""Build a single-page vulnerability dashboard from Dependency-Track.

Usage:
    DT_URL=... DT_TOKEN=... python build_dashboard.py OUT.html name=uuid [name=uuid ...]
    python build_dashboard.py --from-json OUT.json OUT.html     # re-render only

Pulls findings straight from DT (VEX-suppressed findings excluded, matching the
DT UI), enriches critical/high ones with the first patched version from the
GitHub Advisory DB (via `gh auth token`) and DT's affected-version ranges, and
embeds each project's dtrg dependency tree (graph.html) and direct-dependency
flags (summary.json) when an unpacked dtrg report folder named <name> is found
under DASHBOARD_REPORTS_DIR (default: current directory).
"""
import html
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

DT_URL = os.environ.get("DT_URL", "").rstrip("/")
DT = requests.Session()
DT.headers["X-Api-Key"] = os.environ.get("DT_TOKEN", "")
GH = requests.Session()
try:
    GH.headers["Authorization"] = "Bearer " + subprocess.check_output(["gh", "auth", "token"], text=True).strip()
except Exception:
    print("warning: no gh token, GitHub advisory lookups are rate-limited", file=sys.stderr)
GH.headers["Accept"] = "application/vnd.github+json"

HERE = Path(__file__).resolve().parent
# where dtrg report folders (<name>/graph.html, <name>/summary.json) are looked up, any depth
REPORTS = Path(os.environ.get("DASHBOARD_REPORTS_DIR", ".")).resolve()
CACHE = REPORTS / ".dashboard-cache.json"
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED"]


# ---------- versions ----------
def vkey(v):
    """Lenient version key: numeric segments compared as ints, qualifiers below release."""
    out = []
    for p in re.split(r"[.\-+_]", str(v or "")):
        if p.isdigit():
            out.append((1, int(p), ""))
        elif p.lower() in ("final", "release", "ga", ""):
            continue
        else:
            m = re.match(r"(\d+)(.*)", p)
            if m:
                out.append((1, int(m.group(1)), ""))
                out.append((0, 0, m.group(2).lower()))
            else:
                out.append((0, 0, p.lower()))
    while out and out[-1] == (1, 0, ""):
        out.pop()
    return out


def vcmp(a, b):
    ka, kb = vkey(a), vkey(b)
    return (ka > kb) - (ka < kb)


def in_range(version, rng):
    """GHSA range syntax: '>= 1.0, < 1.2.3' / '= 1.0' / '< 2'."""
    for cond in filter(None, (c.strip() for c in (rng or "").split(","))):
        m = re.match(r"(>=|<=|>|<|=)\s*(.+)", cond)
        if not m:
            continue
        op, val = m.groups()
        c = vcmp(version, val)
        if not {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "=": c == 0}[op]:
            return False
    return True


# ---------- DT ----------
def dt_get(path, **params):
    r = DT.get(f"{DT_URL}/api/v1/{path}", params=params, timeout=120)
    r.raise_for_status()
    return r


def findings(uuid):
    out, page = [], 1
    while True:
        r = dt_get(f"finding/project/{uuid}", suppressed="false", pageSize=500, pageNumber=page)
        batch = r.json()
        out += batch
        if not batch or len(out) >= int(r.headers.get("X-Total-Count", len(out))):
            return out
        page += 1


# ---------- fix version lookup ----------
cache = json.loads(CACHE.read_text()) if CACHE.exists() else {}


def ghsa(gid):
    if gid not in cache:
        for attempt in range(3):
            r = GH.get(f"https://api.github.com/advisories/{gid}", timeout=30)
            if r.status_code == 200:
                cache[gid] = [
                    {"pkg": v["package"]["name"], "eco": v["package"]["ecosystem"],
                     "range": v.get("vulnerable_version_range"), "fix": v.get("first_patched_version")}
                    for v in r.json().get("vulnerabilities", [])
                ]
                break
            if r.status_code == 404:
                cache[gid] = []
                break
            time.sleep(2 * (attempt + 1))
        else:
            return []
    return cache[gid]


def dt_ranges(vuln_uuid):
    key = "dt2:" + vuln_uuid
    if key not in cache:
        try:
            cache[key] = [
                {"type": a.get("identityType"), "identity": a.get("identity"),
                 "start": a.get("versionStartIncluding") or a.get("versionStartExcluding"),
                 "startExcl": bool(a.get("versionStartExcluding")),
                 "endExcl": a.get("versionEndExcluding"), "endIncl": a.get("versionEndIncluding")}
                for a in dt_get(f"vulnerability/{vuln_uuid}").json().get("affectedComponents", [])
                if a.get("versionType") == "RANGE"
            ]
        except requests.HTTPError:
            cache[key] = []
    return cache[key]


def pkg_names(comp):
    g, n = comp.get("group") or "", comp["name"]
    return {n, f"{g}:{n}", f"{g}/{n}"} if g else {n}


def is_public(comp, version):
    """Is this release downloadable from the public registry? (EOL lines of Spring/Tomcat
    often get CVE fixes only in commercial builds that never reach Maven Central.)"""
    purl = comp.get("purl") or ""
    key = f"pub:{purl.split('@')[0]}@{version}"
    if key not in cache:
        g, n = comp.get("group") or "", comp["name"]
        if purl.startswith("pkg:maven/"):
            url = f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{n}/{version}/{n}-{version}.pom"
        elif purl.startswith("pkg:npm/"):
            url = f"https://registry.npmjs.org/{(g + '/' if g else '') + n}/{version}"
        else:
            return None
        try:
            cache[key] = requests.head(url, timeout=20, allow_redirects=True).status_code == 200 if "maven" in url \
                else requests.get(url, timeout=20).status_code == 200
        except requests.RequestException:
            return None
    return cache[key]


def fix_candidates(comp, vuln, ghsa_ids):
    """-> (in_line_fix | None, [later fixes > version]), from GitHub advisories, else DT/NVD ranges."""
    version = comp.get("version") or ""
    names = pkg_names(comp)
    in_line, later, affected_known = None, set(), False
    for gid in ghsa_ids:
        for v in ghsa(gid):
            if v["pkg"] not in names:
                continue
            if v["fix"] and vcmp(v["fix"], version) > 0:
                later.add(v["fix"])
            if in_range(version, v["range"]):
                affected_known = True
                in_line = in_line or v["fix"]
    if affected_known:
        return in_line, sorted(later, key=vkey)
    base = (comp.get("purl") or "").split("@")[0]
    ranges = dt_ranges(vuln["uuid"])
    purl_ranges = [a for a in ranges if a["type"] == "PURL" and a["identity"] == base]
    for a in purl_ranges or [a for a in ranges if a["type"] == "CPE"]:
        if a["endExcl"] and vcmp(a["endExcl"], version) > 0:
            later.add(a["endExcl"])
        if a["start"] and vcmp(version, a["start"]) < (1 if a["startExcl"] else 0):
            continue
        end = a["endExcl"] or a["endIncl"]
        if end and (vcmp(version, end) < 0 or (a["endIncl"] and vcmp(version, end) == 0)):
            in_line = in_line or a["endExcl"]
    return in_line, sorted(later, key=vkey)


def line(v, parts):
    nums = []
    for k in vkey(v):
        if k[0] != 1:
            break
        nums.append(k[1])
    return tuple(nums[:parts])


def upgrade_kind(cur, target):
    if line(target, 1) != line(cur, 1):
        return "major"
    return "patch" if line(target, 2) == line(cur, 2) else "minor"


def fix_version(comp, vuln, ghsa_ids):
    """-> dict(fix, kind, note). kind: patch | minor | major | none."""
    version = comp.get("version") or ""
    in_line, later = fix_candidates(comp, vuln, ghsa_ids)
    note, private = None, []
    ordered = ([in_line] if in_line else []) + [v for v in later if v != in_line]
    for cand in ordered:
        pub = is_public(comp, cand)
        if pub is False and comp.get("purl", "").startswith("pkg:maven/") and is_public(comp, cand + "-jre"):
            cand, pub = cand + "-jre", True
        if pub is False:
            private.append(cand)
            continue
        if private:
            note = f"{', '.join(private)} fixes it only in a commercial / extended-support build"
        elif in_line is None:
            note = f"no fix released for the {'.'.join(map(str, line(version, 2)))}.x line"
        return {"fix": cand, "kind": upgrade_kind(version, cand), "note": note, "assumed": False}
    latest = comp.get("latestVersion")
    if private and latest and all(vcmp(latest, p) > 0 for p in private):
        return {"fix": latest, "kind": upgrade_kind(version, latest), "assumed": True,
                "note": f"{', '.join(private)} fixes it only in a commercial build; latest public {latest} should include the fix"}
    return {"fix": None, "kind": "none", "assumed": False,
            "note": "fix only in commercial build " + ", ".join(private) if private else "no fixed version published yet"}


# ---------- build ----------
def direct_deps(name):
    """(name, version) -> is direct dependency, from dtrg's summary.json."""
    for p in sorted(REPORTS.glob(f"**/{name}/summary.json"), reverse=True):
        return {(c["name"], c["version"]): bool(c.get("isDirectDependency")) for c in json.loads(p.read_text())["components"]}
    return {}


def tree_html(name):
    for p in sorted(REPORTS.glob(f"**/{name}/graph.html"), reverse=True):
        m = re.search(r"<pre>(.*?)</pre>", p.read_text(), re.S)
        if m:
            return m.group(1)
    return None


def build(name, uuid):
    raw = findings(uuid)
    counts = {s: 0 for s in SEV_ORDER}
    vulns, comps = [], {}
    jobs = []
    for f in raw:
        v, c = f["vulnerability"], f["component"]
        sev = v.get("severity") or "UNASSIGNED"
        counts[sev] = counts.get(sev, 0) + 1
        if sev not in ("CRITICAL", "HIGH") and not v.get("isKev"):
            continue
        aliases = v.get("aliases") or []
        cves = sorted({a["cveId"] for a in aliases if a.get("cveId")} | ({v["vulnId"]} if v["vulnId"].startswith("CVE-") else set()))
        ghsas = sorted({a["ghsaId"] for a in aliases if a.get("ghsaId")} | ({v["vulnId"]} if v["vulnId"].startswith("GHSA-") else set()))
        jobs.append((f, cves, ghsas))

    with ThreadPoolExecutor(8) as ex:
        fixes = list(ex.map(lambda j: fix_version(j[0]["component"], j[0]["vulnerability"], j[2]), jobs))

    direct = direct_deps(name)
    for (f, cves, ghsas), fx in zip(jobs, fixes):
        v, c = f["vulnerability"], f["component"]
        key = c["uuid"]
        comp = comps.setdefault(key, {
            "name": c["name"], "group": c.get("group") or "", "version": c.get("version") or "",
            "latest": c.get("latestVersion"), "purl": c.get("purl"),
            "direct": direct.get((c["name"], c.get("version") or "")),
        })
        cvss = v.get("cvssV3BaseScore") or v.get("cvssV2BaseScore")
        vulns.append({
            "sev": (v.get("severity") or "UNASSIGNED").lower(), "id": v["vulnId"], "source": v["source"],
            "cves": cves, "ghsas": ghsas,
            "title": v.get("title") or (v.get("description") or "").split("\n")[0][:180],
            "cvss": cvss, "vector": v.get("cvssV3Vector"), "epss": v.get("epssScore"),
            "epssPct": v.get("epssPercentile"), "kev": bool(v.get("isKev")),
            "cwes": [{"id": w["cweId"], "name": w.get("name", "")} for w in v.get("cwes") or []],
            "comp": key, "fix": fx["fix"], "fixKind": fx["kind"], "fixNote": fx["note"], "fixAssumed": fx["assumed"],
        })
    vulns.sort(key=lambda x: (x["sev"] != "critical", -(x["cvss"] or 0)))
    return {"name": name, "uuid": uuid, "dtLink": f"{DT_URL}/projects/{uuid}",
            "counts": counts, "components": comps, "vulns": vulns, "tree": tree_html(name)}


def render(data, out):
    page = (HERE / "dashboard_template.html").read_text()
    page = page.replace("/*__DATA__*/null", json.dumps(data).replace("</", "<\\/"))
    Path(out).write_text(page)
    Path(out).with_suffix(".json").write_text(json.dumps(data, indent=1))
    print("wrote", out)


def main():
    args = sys.argv[1:]
    if args and args[0] == "--from-json":
        # re-render the page from previously fetched data, no DT access needed
        render(json.loads(Path(args[1]).read_text()), args[2])
        return
    out, pairs = args[0], [a.split("=", 1) for a in args[1:]]
    projects = [build(n, u) for n, u in pairs]
    CACHE.write_text(json.dumps(cache))
    for p in projects:
        kinds = {}
        for v in p["vulns"]:
            kinds[v["fixKind"]] = kinds.get(v["fixKind"], 0) + 1
        print(p["name"], {k: v for k, v in p["counts"].items() if v}, "libs:", len(p["components"]), "fix kinds:", kinds)
    render({"generated": time.strftime("%Y-%m-%d %H:%M"), "dt": DT_URL, "projects": projects}, out)


if __name__ == "__main__":
    main()
