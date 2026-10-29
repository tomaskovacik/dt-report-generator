# Management dashboard

`build_dashboard.py` turns Dependency-Track findings for one or more projects into a single
self-contained HTML page aimed at management: what is actively exploited, what to fix first,
and how much of it needs a framework upgrade rather than a patch bump.

What goes into the page:

- **Executive summary**: a generated verdict, KPIs (critical, high, CISA KEV, P1, share needing a major upgrade) and a per-app risk table with the libraries driving the risk.
- **Bar chart**: all findings by severity, every app stacked together.
- **Fix first (P1)**: KEV findings (any severity) and EPSS ≥ 10%.
- **Upgrade plan**: one row per library, with the minimum version that fixes all its critical/high/KEV findings and the effort (patch / minor / major / no fix). It flags fixes that ship only in commercial builds.
- **Vulnerability table**: CVE (NVD link), GHSA (GitHub advisory link), CVSS + vector, EPSS, CWE links, fixed-in version, current vs. latest version.
- **Dependency trees**: taken from dtrg's `graph.html`.

Priorities: **P1** = KEV or EPSS ≥ 10%. **P2** = critical with network attack vector, or EPSS ≥ 1%. **P3** = remaining critical/high.

Fix versions come from the GitHub Advisory DB (`first_patched_version`, via `gh auth token`), falling back
to DT's affected-version ranges (NVD CPE). Each candidate is checked on Maven Central / npm. When a fix
exists only in a commercial build (e.g. Spring 5.3.x / 6.2.x OSS EOL lines), the page says so and
points at the newest public release instead.

## Usage

Requirements: `requests` (already in requirements.txt), and optionally the `gh` CLI, logged in, for the higher GitHub API rate limit.
The DT API key needs `VIEW_PORTFOLIO` and `VIEW_VULNERABILITY`.

```bash
export DT_URL=https://dt.example.com DT_TOKEN=odt_...
# optional: folder with unpacked dtrg reports (<name>/graph.html, <name>/summary.json)
export DASHBOARD_REPORTS_DIR=./reports-out

python dashboard/build_dashboard.py dashboard.html \
    app-api=<project-uuid> app-web=<project-uuid>

# re-render after template changes, without DT access (uses dashboard.json written next to the html)
python dashboard/build_dashboard.py --from-json dashboard.json dashboard.html
```

Outbound calls: DT, `api.github.com/advisories`, `repo1.maven.org`, `registry.npmjs.org`.
Lookups are cached in `.dashboard-cache.json` in `DASHBOARD_REPORTS_DIR`.
