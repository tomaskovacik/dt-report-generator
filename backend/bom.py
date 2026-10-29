""" Maven BOM resolution: which library versions a platform release ships.

Used by the dashboard to turn "tomcat-embed-core is vulnerable" into
"upgrade Spring Boot to 2.7.18, which ships tomcat 9.0.83". Only the
pieces needed for that: <properties> (with parent inheritance),
<dependencyManagement> entries and `import`-scoped BOMs, resolved lazily so
a lookup for tomcat never downloads the Jackson BOM.
"""

import logging
import re
import threading
import xml.etree.ElementTree as ET

from backend._http import requests

logger = logging.getLogger(__name__)

CENTRAL = "https://repo1.maven.org/maven2/"
_TIMEOUT = 20
_RELEASE_RE = re.compile(r"^\d+\.\d+\.\d+(\.RELEASE)?$")
_PROP_RE = re.compile(r"\$\{([^}]+)\}")

_cache = {}
_lock = threading.Lock()


def _get_text(url):
    with _lock:
        if url in _cache:
            return _cache[url]
    try:
        res = requests.get(url, timeout=_TIMEOUT)
    except requests.RequestException as e:
        logger.warning(f"Maven Central lookup failed for {url}: {e}")
        return None
    text = res.text if res.status_code == 200 else None
    if res.status_code in (200, 404):
        with _lock:
            _cache[url] = text
    return text


def _pom_url(group, artifact, version):
    return f"{CENTRAL}{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom"


def _strip_ns(root):
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def _child(el, name):
    found = el.find(name) if el is not None else None
    return (found.text or "").strip() if found is not None and found.text else ""


class _Pom:
    """ Parsed POM: own coordinates, merged properties, managed deps, imports """

    def __init__(self, group, artifact, version, depth=0):
        self.group, self.artifact, self.version = group, artifact, version
        self.props, self.managed, self.imports = {}, {}, []
        text = _get_text(_pom_url(group, artifact, version))
        if not text:
            return
        try:
            root = _strip_ns(ET.fromstring(text))
        except ET.ParseError:
            logger.warning(f"Unparseable POM {group}:{artifact}:{version}")
            return
        parent = root.find("parent")
        if parent is not None and depth < 4:
            ppom = _load(_child(parent, "groupId"), _child(parent, "artifactId"),
                         _child(parent, "version"), depth + 1)
            self.props.update(ppom.props)
        props = root.find("properties")
        for p in list(props) if props is not None else []:
            if isinstance(p.tag, str):
                self.props[p.tag] = (p.text or "").strip()
        self.props.update({"project.version": version, "project.groupId": group,
                           "version": version, "revision": self.props.get("revision", version)})
        for dep in root.findall("dependencyManagement/dependencies/dependency"):
            g, a = self._resolve(_child(dep, "groupId")), self._resolve(_child(dep, "artifactId"))
            v = self._resolve(_child(dep, "version"))
            if not (g and a and v):
                continue
            if _child(dep, "scope") == "import" and _child(dep, "type") == "pom":
                self.imports.append((g, a, v))
            else:
                self.managed.setdefault((g, a), v)

    def _resolve(self, value, rounds=5):
        for _ in range(rounds):
            if "${" not in value:
                return value
            value = _PROP_RE.sub(lambda m: self.props.get(m.group(1), m.group(0)), value)
        return value if "${" not in value else ""


def _load(group, artifact, version, depth=0):
    key = ("pom", group, artifact, version)
    with _lock:
        if key in _cache:
            return _cache[key]
    pom = _Pom(group, artifact, version, depth)
    with _lock:
        _cache[key] = pom
    return pom


def managed_versions(group, artifact, version, wanted):
    """ {(group, artifact): version} for the `wanted` coordinates a BOM pins """
    wanted = set(wanted)
    found, seen = {}, set()
    queue = [(group, artifact, version)]
    while queue and wanted - found.keys():
        coords = queue.pop(0)
        if coords in seen:
            continue
        seen.add(coords)
        pom = _load(*coords)
        for key in wanted - found.keys():
            if key in pom.managed:
                found[key] = pom.managed[key]
        queue.extend(pom.imports)
    return found


def release_versions(group, artifact):
    """ All plain release versions of an artifact on Maven Central """
    text = _get_text(f"{CENTRAL}{group.replace('.', '/')}/{artifact}/maven-metadata.xml")
    if not text:
        return []
    try:
        root = _strip_ns(ET.fromstring(text))
    except ET.ParseError:
        return []
    return [v.text.strip() for v in root.iter("version") if v.text and _RELEASE_RE.match(v.text.strip())]
