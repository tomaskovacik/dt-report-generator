# dt-report-generator (dtrg) <img width="30" src="./static/icon.svg"/>
## Main information
Tool for create reports from [Dependency Track](https://dependencytrack.org/) in Word (.docx) and Excel (.xlsx) formats.\
More information about tool and how to use it can be found in the articles on habr [1](https://habr.com/ru/articles/860536/), [2](https://habr.com/ru/articles/900276/) (rus).
## Getting started
### Installation and start
Configuration lives in a `.env` file next to `app.py` (real environment variables win over it):
```
cp .env.example .env    # set DT_URL and DT_TOKEN, optionally SSO / API key
```
№1. Python
```
git clone <this repo>
pip install --upgrade pip
pip install -r requirements.txt
python ./app.py
```
№2. Docker
```
docker pull ghcr.io/tomaskovacik/dt-report-generator:management-dashboard
docker run --name dtrg -d --restart unless-stopped -p 5000:5000 --env-file .env \
    ghcr.io/tomaskovacik/dt-report-generator:management-dashboard
```
Or with Docker Compose (uses the published image, hardened: read-only root filesystem, no capabilities):
```
cp .env.example .env    # fill in DT_URL / DT_TOKEN / DTRG_SECRET_KEY
docker compose up -d    # DTRG_TAG=management-dashboard to follow the branch, --build to build locally
```
Image tags (built by `.github/workflows/publish.yml` after pytest; vulnerability scanning is done by GitHub code scanning (CodeQL), Dependabot and secret scanning): `:<branch>` and `:sha-<commit>` on every push to `main` / `management-dashboard`; `:<version>` and `:latest` for a version tag (`git tag v.2.3.0 && git push --tags`), which also creates a GitHub release. In `.env` for the container use `DTRG_HOST=0.0.0.0`.
### Usage
1. Open [localhost:5000](http://localhost:5000). The start page lists the Dependency-Track projects with their critical / high / medium / low counts, newest BOM first. Search by name, or paste a project UUID.
2. **Show report** opens the project's management dashboard in a new tab.
3. **ZIP** downloads the full report: `result.docx`, `result.xlsx`, `summary.json`, `graph.html` and `dashboard.html`.
4. Tick several projects (up to 8) and click **Show combined dashboard** for one page covering all of them.

The DT URL and API key are never entered in the browser. They come from `DT_URL` / `DT_TOKEN` in `.env`. The version-diff report is available through the API (`/api/v1/reports/diff`, see below).

### Management dashboard
Every report ZIP now also has a `dashboard.html`. It is a self-contained page (no external scripts) written for people who need the "how bad is it and what do we do" answer, not the raw finding list:

- **Executive summary**: a generated verdict, KPIs (critical, high, actively exploited per CISA KEV, P1 count, share of findings that need a major upgrade) and a per-app status table with the libraries causing the most risk.
- **Bar chart** of all findings by severity, with the apps stacked (table view included).
- **Fix first (P1)**: KEV findings of any severity plus EPSS ≥ 10%. **P2** = critical and network-reachable, or EPSS ≥ 1%. **P3** = the rest of critical/high.
- **Upgrade plan**: what to upgrade, not just which jar is vulnerable.
  - **Spring Boot apps**: libraries whose version comes from Spring Boot's dependency management (Tomcat, Jackson, Spring Framework, Hibernate, …) are grouped under one *Spring Boot X → Y* row. Y is the lowest Boot release (latest patch of a minor line) whose bundled versions fall outside the vulnerable ranges, read from `spring-boot-dependencies` on Maven Central. Each bundled library shows the version Y ships and whether that clears it. The row also says how far staying on the current major gets you.
  - **Quick fixes without upgrading Spring Boot**: Boot reads each bundled library's version from a build property (`tomcat.version`, `jackson-bom.version`, `spring-framework.version`, …). For every such property the dashboard finds the lowest value that clears the findings without leaving the line your Boot release supports: Spring projects on the same minor (5.2.x), everything else on the same major (Tomcat 9.x for Boot 2.x, never the jakarta-based 10/11). It shows how many findings and KEVs each override fixes and marks patch-level ones *safe* and minor ones *test first*. Ready-to-paste Maven `<properties>` and Gradle `ext[...]` snippets are included.
  - **Library families** released together (Spring Framework, Spring Security, Jackson, Tomcat, Netty, Hibernate, …) collapse into one row with the version that fixes all members.
  - **Everything else**: the minimum version that fixes all its critical/high/KEV findings, effort (patch / minor / major / no fix), latest version, and *via …*, the chain of your own dependencies that pulls the library in.
- **Vulnerability table**: CVE (NVD link), GHSA (GitHub advisory link), CVSS + vector, EPSS, CWE links, fixed-in version. Filterable and searchable.
- **Dependency tree** from `graph.html`.

Fix versions come from the GitHub Advisory DB (`first_patched_version`) and DT's affected-version ranges (incl. NVD CPE ranges). Each candidate is checked on Maven Central / npm. When the only fix for your release line is a commercial build (typical for Spring / Tomcat EOL lines), the page says so and suggests the newest public release instead. These lookups are best effort: if they fail, the fix column stays empty and the report is still produced. Set `DTRG_DASHBOARD_ENRICH=false` on air-gapped installs. The DT API key needs `VIEW_PORTFOLIO` and `VIEW_VULNERABILITY`.

### Reports by email
With mail configured (see the *Reports by email* block in `.env.example`) the start page gets:
- an **Email** button per project, plus **Email…** / **Schedule…** for the ticked projects (one combined report);
- **Scheduled reports**: daily, weekly or monthly at a chosen hour (`DTRG_TIMEZONE`), with *Send now* and *Delete*. With SSO on, each user sees and manages only their own schedules. Without SSO the list is shared.

The email body is a static summary (verdict, KPIs, per-app status, Spring Boot quick fixes with the `<properties>` snippet, the P1 list), because mail clients strip JavaScript. The full interactive dashboard is attached as one HTML file. Sending works over **SMTP** or **Microsoft Graph** (`Mail.Send` application permission; it can reuse the SSO app registration). Recipients must match `DTRG_MAIL_ALLOWED_RECIPIENTS`. Schedules are stored in a SQLite file in `DTRG_DATA_DIR` (`/data` in the image; `docker-compose.yml` mounts a volume there).

### Single sign-on (Microsoft Entra ID)
The browser UI can require a Microsoft login (OpenID Connect, authorization code + PKCE). It is off by default. When it is on, the form, downloads, dashboard and Swagger UI need a signed-in user. `/health` stays open for probes, and `/api/v1/*` keeps using `DTRG_API_KEY` for CI.

1. In the Entra admin center go to **App registrations → New registration**:
   - Supported account types: *Accounts in this organizational directory only*.
   - Redirect URI: platform **Web**, `http://localhost:5000/auth/callback`. Use your real `https://<host>/auth/callback` when running behind a proxy.
2. **Certificates & secrets → New client secret**, and copy the *Value*.
3. Note the **Application (client) ID** and **Directory (tenant) ID** on the Overview page.
4. Recommended: **Enterprise applications → dtrg → Properties → Assignment required = Yes**, then add the allowed users / groups under *Users and groups*. Everyone else is stopped by Entra before reaching dtrg.

```
export DTRG_OIDC_TENANT_ID="<directory-tenant-id>"
export DTRG_OIDC_CLIENT_ID="<application-client-id>"
export DTRG_OIDC_CLIENT_SECRET="<client-secret-value>"
export DTRG_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"  # keep sessions across restarts
# optional extra filter inside dtrg
export DTRG_OIDC_ALLOWED_USERS="*@example.com,contractor@partner.com"
```
Behind a TLS proxy also set `DTRG_SECURE_COOKIES=true` and `DTRG_OIDC_REDIRECT_URI=https://<host>/auth/callback`. Other OIDC providers (Keycloak, Okta, Google) work through `DTRG_OIDC_METADATA_URL`.

## CI usage
For pipelines a JSON API is exposed alongside the form. It returns the same ZIP, but does not need a browser session and is suitable for `curl` from a build job.

Generate a report:
```
curl -fSL -o report.zip \
    -H "X-DTRG-Key: $DTRG_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"project":"<uuid>"}' \
    http://dtrg.internal:5000/api/v1/reports/get_report
```
List projects to look up a UUID:
```
curl -fsSL \
    -H "X-DTRG-Key: $DTRG_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{}' \
    http://dtrg.internal:5000/api/v1/projects | jq '.[] | {name, version, uuid}'
```
Need to filter or paginate? Pass `searchText`, `pageSize` and `pageNumber` in the JSON body. Total matches come back in the `X-Total-Count` response header. Without those fields the endpoint returns the full list as before.

Diff between two versions of the same project:
```
curl -fSL -o diff.zip \
    -H "X-DTRG-Key: $DTRG_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"projectA":"<old-uuid>","projectB":"<new-uuid>"}' \
    http://dtrg.internal:5000/api/v1/reports/diff
```
Combined management dashboard for several projects (returns `dashboard.html`, not a ZIP):
```
curl -fSL -o dashboard.html \
    -H "X-DTRG-Key: $DTRG_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"projects":["<uuid-1>","<uuid-2>","<uuid-3>"]}' \
    http://dtrg.internal:5000/api/v1/reports/dashboard
```

The diff ZIP contains `result.xlsx` (sheets: General information, Added, Removed, Common) and `summary.json` (`kind: "diff"`). Common entries surface both component versions and both VEX states so a CVE that travelled with a library upgrade is visible.

### Working with `summary.json`

Every ZIP (single report or diff) carries a machine-readable `summary.json` alongside the docx/xlsx so CI can post-process without parsing Office files. Versioned via `schemaVersion: 1`. Below are jq one-liners on top of an `unzip -p report.zip summary.json` pipe.

**Single report** (`kind` absent / not `"diff"`):
```bash
# All vulnerable components
unzip -p report.zip summary.json | jq '.components[] | {name, version, severity}'

# Fail CI if any critical or high vuln is present
unzip -p report.zip summary.json \
  | jq -e '[.components[].vulnerabilities[] | select(.severity == "critical" or .severity == "high")] | length == 0'

# List CVEs in CISA KEV (must-fix)
unzip -p report.zip summary.json \
  | jq '.components[].vulnerabilities[] | select(.isKev) | .id'

# CVEs with EPSS > 50% (high exploitation probability)
unzip -p report.zip summary.json \
  | jq '.components[].vulnerabilities[] | select((.epss // 0) > 0.5) | {id, epss, cvss}'
```

**Diff report** (`.kind == "diff"`):
```bash
# Fail CI if a new critical CVE appeared in B
unzip -p diff.zip summary.json \
  | jq -e '[.diff.added[] | select(.severity == "critical")] | length == 0'

# What was fixed going A -> B
unzip -p diff.zip summary.json \
  | jq '.diff.removed[] | {component, vulnerability, severity}'

# CVEs that "travelled" with a library upgrade (still vulnerable, version bumped)
unzip -p diff.zip summary.json \
  | jq '.diff.common[] | select(.versionChanged) | {component, from: .componentVersionA, to: .componentVersionB, vulnerability}'

# VEX changes between snapshots (e.g. CVE marked false_positive in newer)
unzip -p diff.zip summary.json \
  | jq '.diff.common[] | select(.analysisStateA != .analysisStateB)
                       | {component, vulnerability, was: .analysisStateA, now: .analysisStateB}'
```

Notes:

- `url` and `token` can be omitted from the request body when `DT_URL` and `DT_TOKEN` are set in the dtrg environment.
- The endpoints are open by default. When the service is reachable beyond a trusted network, set `DTRG_API_KEY` so requests must present the same key in the `X-DTRG-Key` (or `Authorization: Bearer ...`) header.
- Errors come back as `{"error": "..."}` with a non-200 status, never as a redirect.
- These endpoints are deliberately CSRF-exempt (CI tooling has no session). The form endpoints (`/reports/get_report`, `/projects/get_all`) keep CSRF protection on; rely on `DTRG_API_KEY` and network controls for `/api/v1/*`.
- The full OpenAPI spec is served at [`/apispec.json`](http://localhost:5000/apispec.json) and the Swagger UI at [`/apidocs/`](http://localhost:5000/apidocs/), so you can explore request shapes and try calls from the browser.

## Advanced usage
You can set environment variable. A couple of examples: \
\
№1. dtrg as a service
```
export DT_URL="http://evil.com"
export DT_TOKEN="some_special_token"
```
№2. Vulnerability prioritization or enrichment
You must beside deploy [CVE-PaaS](https://github.com/denimoll/CVE-PaaS) tool. dtrg batches all CVE ids of a project into a single `POST /v1/cve` call (chunks of 50 transparently), so even projects with hundreds of CVEs add only a few CVE-PaaS round-trips. The enrichment surfaces CVSS, EPSS, KEV / PoC / Nuclei flags - directly in the `Additional info` column of the Excel report and as fields in `summary.json`. If CVE-PaaS is unreachable or returns an error, dtrg logs a warning and continues to render the report **without** enrichment instead of failing the run.
```
export CVEPAAS_URL="http://evil.com"
# optional: when CVE-PaaS is started with CVE_PAAS_API_KEY set
export DTRG_CVEPAAS_KEY="cvepaas-secret"
```
№3. Custom port
```
export DTRG_PORT=5252
```
When use docker run container with this command:
```
docker run --name dtrg -d -p $DTRG_PORT:5000 ghcr.io/denimoll/dt-report-generator
```
№4. Show VEX-suppressed findings
By default dtrg honours VEX: a finding marked in DT as `resolved`, `resolved_with_pedigree`, `false_positive` or `not_affected` is dropped from the report so it matches what the DT UI shows. Set the variable below to keep them in the output and see their analysis state in the `All issues` sheet.
```
export DTRG_INCLUDE_SUPPRESSED=true
```
№5. Restrict which DT instances dtrg will fetch
When dtrg accepts the DT URL from the form / API, set an allowlist so it cannot be pointed at arbitrary internal hosts (SSRF mitigation). Empty (default) keeps the previous behaviour. Patterns are comma-separated; `*.example.com` matches subdomains.
```
export DTRG_ALLOWED_HOSTS="dt.example.com,*.dt.example.com"
```

All environment variables:
* DT_URL - DT address
* DT_TOKEN - DT API key
* DTRG_PORT - dtrg port
* DTRG_HOST - bind address (default: 0.0.0.0)
* DTRG_DEBUG - dtrg (Flask) debug mode. Refuses to start when combined with a non-loopback DTRG_HOST unless DTRG_DEBUG_ALLOW_REMOTE=true is set, because the Werkzeug debugger can be used for remote code execution.
* DTRG_DEBUG_ALLOW_REMOTE - explicit override that allows DTRG_DEBUG=true together with a non-loopback DTRG_HOST. Use only in trusted networks.
* DTRG_VERIFY_TLS - verify TLS certificate of DT and CVE-PaaS (default: true; set to false only for self-signed test instances)
* DTRG_HTTP_TIMEOUT - timeout in seconds for outbound HTTP calls to DT and CVE-PaaS (default: 120)
* DTRG_SECRET_KEY - Flask secret key used to sign session cookies and CSRF tokens for the form endpoints (`/`, `/reports/get_report`, `/projects/get_all`). Set a stable value when running multiple workers or behind a reverse proxy so tokens stay valid across restarts. If unset, a random key is generated on each start.
* DTRG_SECURE_COOKIES - when `true`, the session cookie is sent only over HTTPS (`Secure` flag). Default `false` so local `http://localhost` dev keeps working. Turn on for any deployment behind TLS.
* DTRG_API_KEY - shared secret required on the /api/v1/* endpoints. When unset (default) those endpoints are open and only network controls protect them; when set, callers must present the same value in an `X-DTRG-Key` or `Authorization: Bearer ...` header.
* DTRG_API_RATE_LIMIT - per-IP rate limit applied to /api/v1/* (default `60/minute`). Empty disables enforcement. Format follows [Flask-Limiter notation](https://flask-limiter.readthedocs.io/en/stable/configuration.html#rate-limit-string-notation): e.g. `30/minute`, `1000/hour`, `5/second`.
* DTRG_ALLOWED_HOSTS - comma-separated SSRF allowlist for the DT URL. When set, only listed hosts are accepted from the form / API (`*.example.com` matches subdomains). Default empty = no restriction (suitable for on-prem). Use this when running dtrg as a public service.
* DTRG_CVEPAAS_KEY - optional CVE-PaaS API key. When set, dtrg adds an `X-API-Key` header to every CVE-PaaS request. Match the value of `CVE_PAAS_API_KEY` configured on the CVE-PaaS side.
* DTRG_INCLUDE_SUPPRESSED - when `true`, vulnerabilities that DT considers suppressed via VEX (state `resolved` / `resolved_with_pedigree` / `false_positive` / `not_affected`) are still rendered in the report with their analysis state in the `All issues` sheet. Default `false`, which matches the DT UI.
* DTRG_GRAPH_DEPTH - max depth of the dependency graph traversal. Direct dependencies are level 1, their children level 2, etc. The level of each component is shown in column G of the `Vulnerable dependencies` sheet; components beyond the depth limit show an empty cell. Default 3.
* DTRG_PROJECTS_PAGE_SIZE - page size for the form's project dropdown. Projects are loaded lazily as the user scrolls or types into the search box, so this controls how many DT projects are fetched per round-trip. Default 50. Does not affect `/api/v1/projects` (which still returns the full list by default).
* DTRG_DASHBOARD_ENRICH - when `true` (default), the dashboard looks up fix versions on `api.github.com/advisories`, `repo1.maven.org` and `registry.npmjs.org`. Set `false` for air-gapped installs; fix versions then come from DT's affected-version ranges only.
* DTRG_GITHUB_TOKEN - optional GitHub token for the advisory lookups (rate limit 60 → 5000 requests/hour). Any token works; it needs no scopes.
* DTRG_DASHBOARD_MAX_PROJECTS - max projects per combined dashboard (default and maximum 8, the number of distinct chart colors).
* DTRG_OIDC_CLIENT_ID - turns on SSO for the browser UI (see [Single sign-on](#single-sign-on-microsoft-entra-id)). Requires DTRG_OIDC_CLIENT_SECRET and DTRG_OIDC_TENANT_ID.
* DTRG_OIDC_CLIENT_SECRET - client secret of the Entra app registration.
* DTRG_OIDC_TENANT_ID - Entra Directory (tenant) ID. Only users of this tenant can sign in (`tid` claim is checked); multi-tenant values like `organizations` are refused.
* DTRG_OIDC_ALLOWED_USERS - optional comma-separated allowlist of usernames / emails, glob patterns allowed (`*@example.com`). Empty = everyone the identity provider lets through.
* DTRG_OIDC_REDIRECT_URI - override the callback URL (default derived from the request, e.g. `http://localhost:5000/auth/callback`). Set it when dtrg runs behind a reverse proxy.
* DTRG_OIDC_POST_LOGOUT_URI - where Entra sends the browser after sign-out (default: the dtrg start page).
* DTRG_OIDC_METADATA_URL - OIDC discovery URL for a non-Microsoft provider. Replaces the Entra tenant check.
* DTRG_SESSION_HOURS - how long a login lasts (default 8).
* CVEPAAS_URL - [CVE-PaaS](https://github.com/denimoll/CVE-PaaS) address
## Development
Tests live under `tests/` and run with pytest:
```
pip install -r requirements-dev.txt
pytest -q
```
The same suite runs on every push/PR via `.github/workflows/tests.yml`.
## Roadmap
Planned functionality:
- [x] *Project search*. Simplify the search for projects via the provided link and token.
- [x] *Dependency tree*. Export the tree with vulnerable components marked.
- [x] *Release policy*. Create release rules and publish Docker images.
- [x] *Reports*. Add a text to docx when 0 vulns.
- [x] *Dashboards with overview information*. Visualize data in the form of various graphs for visual analysis.
- [x] *Icon*. Create an icon for tool and add a favicon.
- [x] *Secure use as a service*. Add the ability to define trusted addresses (SSRF exclusion) or disable URL and token selection by setting default values.
- [x] *Vulnerability prioritization*. Implement logic that will help assess which vulnerabilities require priority fixing.
- [x] *Docs*. Add a documentation or just more info in readme.md for advansed settings (like custom port, use specific version and etc.)
- [x] *VEX support*. Honour CycloneDX analysis state from DT so suppressed findings are dropped (or surfaced via DTRG_INCLUDE_SUPPRESSED) in the report.
- [x] *Tests*. Smoke/unit tests for validators, severity merge, graph traversal, VEX filter and the API auth paths, run on every PR.
- [x] *Optimization*. Project dropdown is lazy-loaded via select2 ajax with debounced search. Page size controlled by `DTRG_PROJECTS_PAGE_SIZE`.
- [x] *Graph*. Configurable traversal depth via `DTRG_GRAPH_DEPTH`; per-component level surfaced in the report.
- [x] *Specification*. OpenAPI 2.0 spec served at `/apispec.json`; Swagger UI at `/apidocs/`.

- [x] *Quick wins (2.1.0)*. `summary.json` bundled in the report ZIP; multi-arch Docker (`linux/amd64`+`linux/arm64`); CI matrix Python 3.11/3.12/3.13; per-request env in `GetReportForm`.

- [x] *Diff between project versions (2.1.0)*. New endpoints `/reports/diff` and `/api/v1/reports/diff`; checkbox on the form reveals the second project select. ZIP carries `result.xlsx` + `summary.json` describing what was added, removed or stayed common.

- [x] *Hardening (2.2.0)*. Baseline security headers on every response (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`); session cookie pinned to `HttpOnly` + `SameSite=Lax` with opt-in `Secure` via `DTRG_SECURE_COOKIES`; transient 5xx from DT / CVE-PaaS retried through a shared `requests.Session`; dependencies, base image and GitHub Actions refreshed to current stable; the release workflow now blocks on a Trivy scan of the image before it is pushed. CSP / HSTS stay with the TLS-terminating proxy.

### CVE-PaaS collaboration
Caching is intentionally out of scope here — CVE-PaaS owns it on its side.
- [x] *Graceful degradation*. CVE-PaaS errors / timeouts no longer abort the report; dtrg logs a warning and continues without enrichment for that batch.
- [x] *Batch endpoint*. dtrg now calls `POST /v1/cve` once per project (in chunks of 50 ids) instead of per-vulnerability GETs.
- [x] *Wider enrichment*. CVSS, EPSS and the KEV / PoC / Nuclei flags from CVE-PaaS land in the `Additional info` column and in `summary.json`.
- [x] *CVE-PaaS auth*. `DTRG_CVEPAAS_KEY` env attaches `X-API-Key` to every CVE-PaaS call.

### On demand
Pulled out of the active list — pick up only when there is a concrete trigger.
- [x] *Rate limiting* on `/api/v1/*`. Per-IP cap via Flask-Limiter, controlled by `DTRG_API_RATE_LIMIT` (default `60/minute`).
- [x] *SSRF allowlist* for the user-supplied DT URL. `DTRG_ALLOWED_HOSTS` (comma-separated, supports `*.subdomain` wildcards). Empty by default - on-prem keeps the old "any host" behaviour.
