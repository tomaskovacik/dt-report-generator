""" DT collection projects: which child projects a collection report covers.

A collection project (collectionLogic != NONE) has no BOM of its own; DT
aggregates its children. The report follows the same setting:

- AGGREGATE_DIRECT_CHILDREN           every active direct child
- AGGREGATE_LATEST_VERSION_CHILDREN   children marked "latest version"
- AGGREGATE_DIRECT_CHILDREN_WITH_TAG  children carrying the collection tag

Children that are collections themselves are expanded the same way.
Children without a BOM yet have nothing to report and are listed as skipped.
"""

import logging
import os

from backend._http import requests
from backend.param_validators import http_timeout, verify_tls

logger = logging.getLogger(__name__)

LOGIC_LABELS = {
    "AGGREGATE_DIRECT_CHILDREN": "all direct children",
    "AGGREGATE_LATEST_VERSION_CHILDREN": "children marked as latest version",
    "AGGREGATE_DIRECT_CHILDREN_WITH_TAG": "children tagged",
}
_MAX_DEPTH = 5


def max_projects() -> int:
    """ Cap on projects one collection report may expand to """
    try:
        return max(1, int(os.getenv("DTRG_COLLECTION_MAX_PROJECTS", "30")))
    except ValueError:
        return 30


def is_collection(project) -> bool:
    return (project.get("collectionLogic") or "NONE") != "NONE"


def _get(url, headers, path, params=None):
    res = requests.get(url + path, headers=headers, params=params,
                       verify=verify_tls(), timeout=http_timeout())
    res.raise_for_status()
    return res


def _children(url, headers, uuid):
    out, page = [], 1
    while True:
        res = _get(url, headers, f"project/{uuid}/children",
                   {"excludeInactive": "true", "pageSize": 100, "pageNumber": page})
        batch = res.json() or []
        out += batch
        if not batch or len(out) >= int(res.headers.get("X-Total-Count", len(out))):
            return out
        page += 1


def _label(p):
    return " ".join(x for x in (p.get("name"), p.get("version")) if x)


def _matches(logic, tag, child):
    if logic == "AGGREGATE_LATEST_VERSION_CHILDREN":
        return bool(child.get("isLatest"))
    if logic == "AGGREGATE_DIRECT_CHILDREN_WITH_TAG":
        return tag in {(t.get("name") or "").lower() for t in child.get("tags") or []}
    return True


def expand(url, headers, project_uuids):
    """ -> (leaf uuids, [collection info]) for a list of selected projects.

    Plain projects pass through unchanged. Each collection contributes its
    reportable descendants; the info records what was included and skipped
    so the report can say what it covers.
    """
    leaves, infos = [], []

    def add(uuid):
        if uuid not in leaves:
            leaves.append(uuid)

    for uuid in project_uuids:
        project = _get(url, headers, f"project/{uuid}").json()
        if not is_collection(project):
            add(uuid)
            continue
        info = {"uuid": uuid, "name": _label(project), "logic": project["collectionLogic"],
                "tag": (project.get("collectionTag") or {}).get("name"),
                "included": [], "skipped": []}
        _walk(url, headers, project, info, add, {uuid}, 0)
        infos.append(info)
    return leaves, infos


def _walk(url, headers, project, info, add, seen, depth):
    logic = project.get("collectionLogic")
    tag = ((project.get("collectionTag") or {}).get("name") or "").lower()
    for child in _children(url, headers, project["uuid"]):
        if child["uuid"] in seen or not _matches(logic, tag, child):
            continue
        seen.add(child["uuid"])
        if is_collection(child):
            if depth < _MAX_DEPTH:
                # the nested collection's own logic decides its children
                _walk(url, headers, child, info, add, seen, depth + 1)
            continue
        if not child.get("lastBomImport"):
            info["skipped"].append(_label(child))
            continue
        info["included"].append(_label(child))
        add(child["uuid"])
