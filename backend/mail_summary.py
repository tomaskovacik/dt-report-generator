""" Static (no JavaScript) summary of dashboard data, for email bodies.

Mail clients strip scripts, so the interactive dashboard travels as an
attachment and this module computes what the executive summary shows:
headline numbers, per-app status, upgrades needed, Spring Boot quick fixes
and the P1 list. Priority rules mirror the dashboard page.
"""

KIND_RANK = {"patch": 0, "minor": 1, "major": 2, "none": 3}


def prio(v):
    if v["kev"] or (v.get("epss") or 0) >= 0.10:
        return 1
    if (v["sev"] == "critical" and "AV:N" in (v.get("vector") or "")) or (v.get("epss") or 0) >= 0.01:
        return 2
    return 3


def _platform_of(p, comp):
    pid = comp.get("platform")
    return next((pl for pl in p.get("platforms") or [] if pl["id"] == pid), None) if pid else None


def _quick(p, safe_only=False):
    boot = next((pl for pl in p.get("platforms") or [] if pl["id"] == "spring-boot"), None)
    out = (boot or {}).get("overrides") or []
    return [o for o in out if o["effort"] == "patch"] if safe_only else out


def summarize(projects):
    ch = lambda v: v["sev"] in ("critical", "high")  # noqa: E731
    apps = []
    for p in projects:
        vs = p["vulns"]
        c = [v for v in vs if ch(v)]
        hard = [v for v in c if v.get("fixKind") in ("major", "none")]
        kev_ids = {(v["cves"] or [v["id"]])[0] for v in vs if v["kev"]}
        share = len(hard) / len(c) if c else 0
        libs = {}
        for v in c:
            comp = p["components"][v["comp"]]
            pl = _platform_of(p, comp)
            key = "pl:" + pl["id"] if pl else v["comp"]
            entry = libs.setdefault(key, {
                "label": pl["name"] if pl else comp["name"],
                "from": pl["current"] if pl else comp["version"],
                "to": (pl["target"] if pl else comp.get("latest")) or "?",
                "kind": pl["effort"] if pl else None, "n": 0, "platform": bool(pl)})
            entry["n"] += 1
            if not pl and v.get("fix") and (entry["kind"] is None or
                                            KIND_RANK[v["fixKind"]] > KIND_RANK[entry["kind"]]):
                entry["kind"] = v["fixKind"]
        for entry in libs.values():
            entry["kind"] = entry["kind"] or "none"
        top = sorted(libs.values(), key=lambda e: (not e["platform"], KIND_RANK[e["kind"]] < 2, -e["n"]))[:3]
        if kev_ids:
            status = ("critical", "Exploited: act now")
        elif share >= 0.4:
            status = ("serious", "Platform upgrade required")
        else:
            status = ("warning", "Dependency updates")
        apps.append({
            "name": p["name"], "link": p.get("dtLink"), "critical": p["counts"].get("CRITICAL", 0),
            "high": p["counts"].get("HIGH", 0), "kev": len(kev_ids),
            "p1": sum(1 for v in vs if prio(v) == 1), "share": round(share * 100), "status": status,
            "top": top, "quick": _quick(p), "components": p["components"],
        })
    apps.sort(key=lambda a: (-a["kev"], -a["p1"], -a["critical"]))

    all_v = [v for p in projects for v in p["vulns"]]
    chv = [v for v in all_v if ch(v)]
    hard = [v for v in chv if v.get("fixKind") in ("major", "none")]
    safe = [o for p in projects for o in _quick(p, safe_only=True)]

    p1 = {}
    for p in projects:
        for v in p["vulns"]:
            if prio(v) != 1:
                continue
            key = (p["name"], (v["cves"] or [v["id"]])[0])
            row = p1.setdefault(key, {"app": p["name"], "id": key[1], "sev": v["sev"], "kev": v["kev"],
                                      "epss": v.get("epss"), "cvss": v.get("cvss"), "title": v["title"], "libs": []})
            comp = p["components"][v["comp"]]
            pl = _platform_of(p, comp)
            fix = f"{pl['name']} {pl['target']}" if pl and pl.get("target") else v.get("fix") or "no fix"
            quick = next((o for o in _quick(p) if v["id"] in (o.get("clearedVulns") or {}).get(v["comp"], [])), None)
            lib = f"{comp['name']} {comp['version']} → {fix}" + (f" (now: {quick['property']}={quick['value']})" if quick else "")
            if lib not in row["libs"]:
                row["libs"].append(lib)
    p1_rows = sorted(p1.values(), key=lambda r: (not r["kev"], -(r["epss"] or 0)))

    return {
        "apps": apps,
        "critical": sum(1 for v in all_v if v["sev"] == "critical"),
        "high": sum(1 for v in all_v if v["sev"] == "high"),
        "kev_ids": len({(v["cves"] or [v["id"]])[0] for v in all_v if v["kev"]}),
        "kev_findings": sum(1 for v in all_v if v["kev"]),
        "p1": sum(1 for v in all_v if prio(v) == 1),
        "hard_pct": round(100 * len(hard) / max(1, len(chv))),
        "easy_pct": 100 - round(100 * len(hard) / max(1, len(chv))) if chv else 0,
        "quick_count": len(safe),
        "quick_fixed": sum(o["fixedFindings"] for o in safe),
        "quick_kev": sum(o["kevFixed"] for o in safe),
        "p1_rows": p1_rows[:15], "p1_more": max(0, len(p1_rows) - 15),
    }


def title(projects, collections, selected):
    """ What the report is about: the collection, the single app, or a count """
    if len(collections) == 1 and selected == 1:
        return collections[0]["name"]
    return projects[0]["name"] if len(projects) == 1 else f"{len(projects)} applications"


def subject(title_, s):
    kev = f", {s['kev_ids']} actively exploited" if s["kev_ids"] else ""
    return f"[dtrg] Vulnerability report: {title_}: {s['critical']} critical, {s['high']} high{kev}"
