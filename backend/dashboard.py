""" Management dashboard: one self-contained HTML page across DT projects.

For every project it pulls the findings straight from DT (VEX-suppressed
ones excluded, matching the DT UI), keeps critical / high / KEV findings in
detail and works out the version that fixes each one:

1. GitHub Advisory DB `first_patched_version` for the range that contains
   the current version (falls back to a fix in a later release line);
2. DT's affected-version ranges (PURL first, then NVD CPE ranges);
3. every candidate is checked on Maven Central / npm, because EOL lines of
   Spring / Tomcat / ... often get CVE fixes only in commercial builds that
   never reach the public registry.

The enrichment is best effort: any lookup error just leaves the fix empty,
it never fails the report. Set DTRG_DASHBOARD_ENRICH=false to skip the
GitHub / registry calls entirely (air-gapped installs); DTRG_GITHUB_TOKEN
raises the GitHub API rate limit from 60 to 5000 requests per hour.
"""

import json
import logging
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from backend._http import requests
from backend.param_validators import http_timeout, verify_tls

logger = logging.getLogger(__name__)

DASHBOARD_TEMPLATE = os.path.join(os.path.dirname(__file__), "..", "reports", "dashboard.html")
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED"]
_GITHUB_API = "https://api.github.com/advisories/"
_EXTERNAL_TIMEOUT = 20

# Process-wide cache for advisory / registry lookups. Advisories and
# published releases change rarely, and the same libraries show up across
# most projects of one organisation, so this keeps repeated reports fast.
_cache = {}
_cache_lock = threading.Lock()


def enrich_enabled() -> bool:
    """ Whether to call GitHub / public registries for fix versions """
    return os.getenv("DTRG_DASHBOARD_ENRICH", "true").lower() in ["true", "1", "t"]


def _cached(key, fn):
    with _cache_lock:
        if key in _cache:
            return _cache[key]
    value = fn()
    if value is not None:
        with _cache_lock:
            _cache[key] = value
    return value


# ---------- versions ----------
def _numeric_prefix(version):
    nums = []
    for part in re.split(r"[.\-+_]", str(version or "")):
        match = re.match(r"(\d+)", part)
        if not match:
            break
        nums.append(int(match.group(1)))
        if match.group(1) != part:
            break
    return nums


_RELEASE_WORDS = ("final", "release", "ga", "")


def vkey(version):
    """ Lenient sort key: numeric prefix (zero padded), then qualifiers.

    "5.2.20.RELEASE" == "5.2.20", "1.0.0-rc1" < "1.0.0" < "1.0.0.1".
    """
    nums = _numeric_prefix(version)
    rest = re.split(r"[.\-+_]", str(version or ""))[len(nums):]
    quals = [q.lower() for q in rest if q.lower() not in _RELEASE_WORDS]
    padded = tuple(nums + [0] * (8 - len(nums))) if len(nums) <= 8 else tuple(nums)
    # a version with no qualifier (or only RELEASE / Final) is the release
    # and sorts above its own pre-releases (rc / beta / M1 ...)
    return (padded, (1,) if not quals else (0, *quals))


def vcmp(a, b):
    """ -1 / 0 / 1 comparison of two version strings """
    ka, kb = vkey(a), vkey(b)
    return (ka > kb) - (ka < kb)


def in_range(version, rng):
    """ GHSA range syntax: '>= 1.0, < 1.2.3' / '= 1.0' / '< 2' """
    for cond in filter(None, (c.strip() for c in (rng or "").split(","))):
        match = re.match(r"(>=|<=|>|<|=)\s*(.+)", cond)
        if not match:
            continue
        op, val = match.groups()
        c = vcmp(version, val)
        if not {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "=": c == 0}[op]:
            return False
    return True


def _line(version, parts):
    return tuple(_numeric_prefix(version)[:parts])


def upgrade_kind(current, target):
    """ patch (same major.minor) / minor (same major) / major """
    if _line(target, 1) != _line(current, 1):
        return "major"
    return "patch" if _line(target, 2) == _line(current, 2) else "minor"


# ---------- lookups ----------
def _ghsa(ghsa_id):
    def fetch():
        headers = {"Accept": "application/vnd.github+json"}
        if os.getenv("DTRG_GITHUB_TOKEN"):
            headers["Authorization"] = "Bearer " + os.getenv("DTRG_GITHUB_TOKEN")
        try:
            res = requests.get(_GITHUB_API + ghsa_id, headers=headers, timeout=_EXTERNAL_TIMEOUT)
        except requests.RequestException as e:
            logger.warning(f"GitHub advisory lookup failed for {ghsa_id}: {e}")
            return None
        if res.status_code == 404:
            return []
        if res.status_code != 200:
            logger.warning(f"GitHub advisory lookup for {ghsa_id} returned {res.status_code}")
            return None
        return [
            {"pkg": v["package"]["name"], "range": v.get("vulnerable_version_range"),
             "fix": v.get("first_patched_version")}
            for v in res.json().get("vulnerabilities") or [] if v.get("package")
        ]
    return _cached("ghsa:" + ghsa_id, fetch) or []


def _dt_ranges(url, headers, vuln_uuid):
    def fetch():
        try:
            res = requests.get(f"{url}vulnerability/{vuln_uuid}", headers=headers,
                               verify=verify_tls(), timeout=http_timeout())
            res.raise_for_status()
        except requests.RequestException as e:
            logger.warning(f"DT vulnerability lookup failed for {vuln_uuid}: {e}")
            return None
        return [
            {"type": a.get("identityType"), "identity": a.get("identity"),
             "start": a.get("versionStartIncluding") or a.get("versionStartExcluding"),
             "startExcl": bool(a.get("versionStartExcluding")),
             "endExcl": a.get("versionEndExcluding"), "endIncl": a.get("versionEndIncluding")}
            for a in res.json().get("affectedComponents") or []
            if a.get("versionType") == "RANGE"
        ]
    return _cached(f"dt:{url}:{vuln_uuid}", fetch) or []


def _is_public(comp, version):
    """ True / False when the release is (not) on the public registry, None = unknown """
    purl = comp.get("purl") or ""
    group, name = comp.get("group") or "", comp["name"]
    if purl.startswith("pkg:maven/"):
        check = lambda: requests.get(  # noqa: E731
            f"https://repo1.maven.org/maven2/{group.replace('.', '/')}/{name}/{version}/{name}-{version}.pom",
            timeout=_EXTERNAL_TIMEOUT, stream=True)
    elif purl.startswith("pkg:npm/"):
        check = lambda: requests.get(  # noqa: E731
            f"https://registry.npmjs.org/{(group + '/' if group else '') + name}/{version}",
            timeout=_EXTERNAL_TIMEOUT)
    else:
        return None

    def fetch():
        try:
            res = check()
            res.close()
        except requests.RequestException:
            return None
        return res.status_code == 200 if res.status_code in (200, 404) else None
    return _cached(f"pub:{purl.split('@')[0]}@{version}", fetch)


def _pkg_names(comp):
    group, name = comp.get("group") or "", comp["name"]
    return {name, f"{group}:{name}", f"{group}/{name}"} if group else {name}


def fix_candidates(url, headers, comp, vuln, ghsa_ids):
    """ -> (fix in the current line or None, [later fixes > version]) """
    version = comp.get("version") or ""
    names = _pkg_names(comp)
    in_line, later, affected_known = None, set(), False
    if enrich_enabled():
        for gid in ghsa_ids:
            for adv in _ghsa(gid):
                if adv["pkg"] not in names:
                    continue
                if adv["fix"] and vcmp(adv["fix"], version) > 0:
                    later.add(adv["fix"])
                if in_range(version, adv["range"]):
                    affected_known = True
                    in_line = in_line or adv["fix"]
    if affected_known:
        return in_line, sorted(later, key=vkey)
    base = (comp.get("purl") or "").split("@")[0]
    ranges = _dt_ranges(url, headers, vuln["uuid"])
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


def fix_version(url, headers, comp, vuln, ghsa_ids):
    """ -> {fix, kind (patch|minor|major|none), note, assumed} """
    version = comp.get("version") or ""
    try:
        in_line, later = fix_candidates(url, headers, comp, vuln, ghsa_ids)
    except Exception as e:  # enrichment must never break the report
        logger.warning(f"Fix lookup failed for {comp.get('name')}: {e}")
        return {"fix": None, "kind": "none", "note": None, "assumed": False}
    private, note = [], None
    for cand in ([in_line] if in_line else []) + [v for v in later if v != in_line]:
        public = _is_public(comp, cand) if enrich_enabled() else None
        if public is False and (comp.get("purl") or "").startswith("pkg:maven/") \
                and _is_public(comp, cand + "-jre"):
            cand, public = cand + "-jre", True
        if public is False:
            private.append(cand)
            continue
        if private:
            note = f"{', '.join(private)} fixes it only in a commercial / extended-support build"
        elif in_line is None:
            note = f"no fix released for the {'.'.join(map(str, _line(version, 2)))}.x line"
        return {"fix": cand, "kind": upgrade_kind(version, cand), "note": note, "assumed": False}
    latest = comp.get("latestVersion")
    if private and latest and all(vcmp(latest, p) > 0 for p in private):
        return {"fix": latest, "kind": upgrade_kind(version, latest), "assumed": True,
                "note": f"{', '.join(private)} fixes it only in a commercial build; "
                        f"latest public {latest} should include the fix"}
    return {"fix": None, "kind": "none", "assumed": False,
            "note": ("fix only in commercial build " + ", ".join(private)) if private
            else "no fixed version published yet"}


# ---------- DT ----------
def _findings(url, headers, project):
    out, page = [], 1
    while True:
        res = requests.get(f"{url}finding/project/{project}", headers=headers,
                           params={"suppressed": "false", "pageSize": 500, "pageNumber": page},
                           verify=verify_tls(), timeout=http_timeout())
        res.raise_for_status()
        batch = res.json()
        out += batch
        if not batch or len(out) >= int(res.headers.get("X-Total-Count", len(out))):
            return out
        page += 1


def graph_tree(graph_html):
    """ The <pre> body of dtrg's graph.html, for embedding """
    match = re.search(r"<pre>(.*?)</pre>", graph_html or "", re.S)
    return match.group(1) if match else None


def build_project(url, headers, project, name, tree=None, direct=None):
    """ Collect one project's dashboard data.

    url/headers come from param_validators (url ends in /api/v1/), `tree` is
    graph_tree() output, `direct` maps (name, version) -> is direct dependency.
    """
    logger.info(f"Collecting dashboard data for {name}")
    raw = _findings(url, headers, project)
    counts = {s: 0 for s in SEV_ORDER}
    jobs = []
    for f in raw:
        vuln = f["vulnerability"]
        sev = vuln.get("severity") or "UNASSIGNED"
        counts[sev] = counts.get(sev, 0) + 1
        if sev not in ("CRITICAL", "HIGH") and not vuln.get("isKev"):
            continue
        aliases = vuln.get("aliases") or []
        vid = vuln.get("vulnId") or ""
        cves = sorted({a["cveId"] for a in aliases if a.get("cveId")}
                      | ({vid} if vid.startswith("CVE-") else set()))
        ghsas = sorted({a["ghsaId"] for a in aliases if a.get("ghsaId")}
                       | ({vid} if vid.startswith("GHSA-") else set()))
        jobs.append((f, cves, ghsas))

    with ThreadPoolExecutor(8) as ex:
        fixes = list(ex.map(
            lambda j: fix_version(url, headers, j[0]["component"], j[0]["vulnerability"], j[2]), jobs))

    comps, vulns = {}, []
    for (f, cves, ghsas), fx in zip(jobs, fixes):
        vuln, comp = f["vulnerability"], f["component"]
        comps.setdefault(comp["uuid"], {
            "name": comp["name"], "group": comp.get("group") or "", "version": comp.get("version") or "",
            "latest": comp.get("latestVersion"), "purl": comp.get("purl"),
            "direct": (direct or {}).get((comp["name"], comp.get("version") or "")),
        })
        vulns.append({
            "sev": (vuln.get("severity") or "UNASSIGNED").lower(), "id": vuln.get("vulnId"),
            "source": vuln.get("source"), "cves": cves, "ghsas": ghsas,
            "title": vuln.get("title") or (vuln.get("description") or "").split("\n")[0][:180],
            "cvss": vuln.get("cvssV3BaseScore") or vuln.get("cvssV2BaseScore"),
            "vector": vuln.get("cvssV3Vector"), "epss": vuln.get("epssScore"),
            "epssPct": vuln.get("epssPercentile"), "kev": bool(vuln.get("isKev")),
            "cwes": [{"id": w["cweId"], "name": w.get("name", "")} for w in vuln.get("cwes") or []],
            "comp": comp["uuid"], "fix": fx["fix"], "fixKind": fx["kind"],
            "fixNote": fx["note"], "fixAssumed": fx["assumed"],
        })
    vulns.sort(key=lambda x: (x["sev"] != "critical", -(x["cvss"] or 0)))
    return {"name": name, "uuid": project,
            "dtLink": f"{url.split('/api/v1/')[0]}/projects/{project}",
            "counts": counts, "components": comps, "vulns": vulns, "tree": tree}


def direct_map(summary):
    """ (name, version) -> isDirectDependency, from a summary.json dict """
    return {(c.get("name"), c.get("version")): bool(c.get("isDirectDependency"))
            for c in (summary or {}).get("components") or []}


def render(projects, path):
    """ Write the dashboard page for already collected projects to `path` """
    with open(DASHBOARD_TEMPLATE, encoding="utf-8") as f:
        page = f.read()
    data = {"generated": datetime.now().strftime("%Y-%m-%d %H:%M"), "projects": projects}
    # "</" escaped so project data can never close the inline <script>
    page = page.replace("/*__DATA__*/null", json.dumps(data).replace("</", "<\\/"))
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
    return path
