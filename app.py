""" Main logic dependency track report generator """

import os

from dotenv import load_dotenv

# DT_URL / DT_TOKEN and the rest of the DTRG_* settings live in .env next to
# app.py (or the file named by DTRG_ENV_FILE). Loaded before the backend
# imports because some of them read the environment at import time. Real
# environment variables win over the file.
load_dotenv(os.getenv("DTRG_ENV_FILE")
            or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# pylint: disable=wrong-import-position
import hmac
import json
import logging
import re
import secrets
import shutil
import tempfile
import zipfile
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    Response,
    after_this_request,
    jsonify,
    render_template,
    request,
    send_file,
)
from flasgger import Swagger
from flask_bootstrap import Bootstrap5
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

from backend import auth, dashboard, dt_collections, mail_summary, mailer, scheduler, store
from backend.dependency_graph import get_graph
from backend.param_validators import projects_page_size
from backend.projects import get_projects
from backend.reports import (
    DIFF_ERROR_CROSS_PROJECT_PREFIX,
    DIFF_ERROR_SAME_PROJECT,
    _load_project,
    _resolve_params,
    create_diff_report,
    create_report,
)

# Logging setup
logging.basicConfig(
    format="%(asctime)s - [%(levelname)s] [%(name)s] %(message)s",
    # set here, not only under __main__, so gunicorn workers log at INFO too
    level=logging.DEBUG if os.getenv("DTRG_DEBUG", "False").lower() in ["true", "1", "t"] else logging.INFO,
)
logger = logging.getLogger(__name__)

__version__ = "3.0.0"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("DTRG_SECRET_KEY") or secrets.token_hex(16)
# HTTPS-only session cookie. Opt-in via env to keep local HTTP dev working
# (when set, the browser refuses to send the cookie over http:// and CSRF
# breaks during a local form submit).
app.config["SESSION_COOKIE_SECURE"] = os.getenv(
    "DTRG_SECURE_COOKIES", "false").lower() in ["true", "1", "t"]
# Defaults already, declared explicitly so a future Flask change in
# defaults does not silently weaken them.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
bootstrap = Bootstrap5(app)
csrf = CSRFProtect(app)

# Rate limit on /api/v1/* only. Empty DTRG_API_RATE_LIMIT disables.
# Form routes / probes / Swagger are not limited.
_API_RATE_LIMIT = os.getenv("DTRG_API_RATE_LIMIT", "60/minute").strip()
limiter = Limiter(get_remote_address, app=app, default_limits=[],
                  storage_uri="memory://")


@app.errorhandler(429)
def _ratelimit_json(err):
    """ Return JSON for /api/v1/* clients (default Flask-Limiter is HTML) """
    if request.path.startswith("/api/v1/"):
        return jsonify(error="rate_limited", description=str(err.description)), 429
    return err


def _api_limit():
    """ Decorator that applies the configured rate limit, or no-op when empty """
    if not _API_RATE_LIMIT:
        return lambda view: view
    return limiter.limit(_API_RATE_LIMIT)


@app.after_request
def _security_headers(response):
    """ Baseline security headers on every response.

    HSTS and CSP belong on the TLS-terminating proxy in front of dtrg
    (they need site-wide policy decisions); the three here are zero-config
    defensive defaults that cost nothing and tighten common browser quirks.
    """
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response

# OpenAPI / Swagger UI at /apidocs/, raw spec at /apispec.json.
swagger = Swagger(app, config={
    "headers": [],
    "specs": [{
        "endpoint": "apispec",
        "route": "/apispec.json",
        "rule_filter": lambda rule: True,
        "model_filter": lambda tag: True,
    }],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/",
}, template={
    "swagger": "2.0",
    "info": {
        "title": "dt-report-generator API",
        "description": "Generate Dependency-Track reports from a browser form "
                       "or from CI. The /api/v1/* endpoints are JSON, "
                       "CSRF-exempt, and gated by DTRG_API_KEY when set.",
        "version": "1.0",
    },
    "securityDefinitions": {
        "ApiKey": {
            "type": "apiKey",
            "in": "header",
            "name": "X-DTRG-Key",
            "description": "DTRG_API_KEY value. Required only if the env var is set.",
        },
        "Bearer": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "'Bearer <DTRG_API_KEY>'. Alternative to X-DTRG-Key.",
        },
    },
})

# Optional Microsoft Entra ID / OIDC login for the browser UI (DTRG_OIDC_*)
auth.init_app(app)


def _presented_api_key():
    """ Pull the dtrg API key from X-DTRG-Key or Authorization: Bearer ... """
    header = request.headers.get("X-DTRG-Key")
    if header:
        return header
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return ""

def require_api_key(view):
    """ Gate a route on DTRG_API_KEY when the env var is set """
    @wraps(view)
    def wrapper(*args, **kwargs):
        expected = os.getenv("DTRG_API_KEY") or ""
        if expected:
            presented = _presented_api_key()
            if not presented or not hmac.compare_digest(presented, expected):
                logger.warning("API call rejected: invalid or missing DTRG_API_KEY")
                return jsonify(error="unauthorized"), 401
        return view(*args, **kwargs)
    return wrapper


# PROBES
@app.route("/health", methods=["GET"])
def health():
    """Liveness/readiness probe.
    ---
    tags:
      - probe
    produces:
      - application/json
    responses:
      200:
        description: Service is up. Returns the running version.
        schema:
          type: object
          properties:
            status:
              type: string
              example: ok
            version:
              type: string
              example: 2.0.0
    """
    return jsonify(status="ok", version=__version__)


@app.route("/favicon.ico", methods=["GET"])
def favicon():
    """Browser tab icon.
    ---
    tags:
      - probe
    responses:
      200:
        description: SVG icon.
    """
    return app.send_static_file("favicon.svg")


# INDEX PAGE
def _dt_configured():
    return bool(os.getenv("DT_URL") and os.getenv("DT_TOKEN"))

@app.route("/", methods=["GET"])
def index():
    """Project list with links to each project's report.
    ---
    tags:
      - browser
    produces:
      - text/html
    responses:
      200:
        description: HTML page listing the DT projects.
    """
    return render_template("index.html",
        dt_configured=_dt_configured(),
        dt_url=(os.getenv("DT_URL") or "").split("/api/v")[0],
        max_projects=dashboard_max_projects(),
        page_size=projects_page_size())


# REPORTS GROUP
def _create_zip(output_dir, with_graph=False):
    """ Bundle the rendered files inside output_dir into reports.zip """
    logger.info("Creating ZIP archive with report files")
    zip_path = os.path.join(output_dir, "reports.zip")
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for file in ["result.docx", "result.xlsx", "summary.json", "dashboard.html"]:
                src = os.path.join(output_dir, file)
                if os.path.exists(src):
                    zipf.write(src, arcname=file)
            if with_graph:
                zipf.write(os.path.join(output_dir, "graph.html"), arcname="graph.html")
        logger.info("ZIP archive created successfully")
        return zip_path
    except OSError as e:
        logger.error(f"Error while creating ZIP: {e}")
        return None

def _redact(form_data):
    """ Drop secret-bearing fields from form data before logging """
    return {k: ("<redacted>" if k in {"token", "csrf_token"} else v)
            for k, v in form_data.items()}

def _new_output_dir():
    """ Create a unique output directory for a single report request """
    return tempfile.mkdtemp(prefix="dtrg-")

def _safe_download_name(report):
    """ Sanitize the report-name string before it lands in Content-Disposition.

    `report` is built from the DT project name + version + date. The DT
    project name is operator-controlled but flows from an external system,
    so we run it through werkzeug's secure_filename to drop any path
    separators or odd unicode before sending it as a header.
    """
    safe = secure_filename(f"{report}.zip")
    return safe or "report.zip"

# Generic message returned to clients when report generation fails. The
# actual exception is logged; we do not surface its str() to keep
# CodeQL py/stack-trace-exposure happy and to avoid accidental leaks
# when validators evolve to embed contextual data.
_GENERIC_REPORT_FAILURE = "Report generation failed. Check server logs for details."


def _diff_user_error(err):
    """ Return a safe-to-surface message for diff input errors, else None.

    create_diff_report raises ValueError with one of two known prefixes
    when the operator picks two of the same project or two unrelated
    projects. Those messages are dtrg-controlled strings (no external
    data interpolation beyond DT project names) and are explicitly
    designed for the end user to read. Everything else falls back to
    the generic message so we do not leak internal exception detail.
    """
    if not isinstance(err, Exception):
        return None
    msg = str(err)
    if msg == DIFF_ERROR_SAME_PROJECT:
        return msg
    if msg.startswith(DIFF_ERROR_CROSS_PROJECT_PREFIX):
        return msg
    return None

def _project_label(output_dir, fallback):
    """ "name version" from the summary.json create_report just wrote """
    try:
        with open(os.path.join(output_dir, "summary.json"), encoding="utf-8") as f:
            summary = json.load(f)
    except (OSError, ValueError):
        return fallback, {}
    project = summary.get("project") or {}
    version = project.get("version")
    if version == "no version":  # create_report's placeholder for unversioned projects
        version = None
    label = " ".join(x for x in (project.get("name"), version) if x)
    return label or fallback, summary

def _collect_dashboard_project(url, headers, project, output_dir, graph=None):
    """ Dashboard data for one project whose dtrg report sits in output_dir """
    label, summary = _project_label(output_dir, project)
    tree = None
    graph_path = os.path.join(output_dir, "graph.html")
    if os.path.exists(graph_path):
        with open(graph_path, encoding="utf-8") as f:
            tree = dashboard.graph_tree(f.read())
    return dashboard.build_project(url, headers, project, label, tree,
                                   dashboard.direct_map(summary), graph=graph)

def _add_dashboard(config, output_dir, graph=None):
    """ Best effort: drop dashboard.html next to the report, never fail it """
    try:
        url, headers, project = _resolve_params(config)
        data = _collect_dashboard_project(url, headers, project, output_dir, graph)
        dashboard.render([data], os.path.join(output_dir, "dashboard.html"))
    except Exception as e:  # pylint: disable=broad-except
        logger.warning(f"Dashboard generation skipped: {e}")

def _collection_of(config):
    """ The collection info when config's project is a DT collection, else None """
    try:
        url, headers, project = _resolve_params(config)
        _, infos = dt_collections.expand(url, headers, [project])
    except Exception:  # pylint: disable=broad-except
        return None  # the regular pipeline reports the problem
    return infos[0] if infos else None

def _build_collection_zip(config, output_dir, info):
    """ ZIP for a collection: combined dashboard.html + one report folder per child """
    data, err = _build_dashboard_data(config, [info["uuid"]], output_dir)
    if err is not None:
        return None, err
    dashboard.render(data["projects"], os.path.join(output_dir, "dashboard.html"), data["collections"])
    zip_path = os.path.join(output_dir, "reports.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(os.path.join(output_dir, "dashboard.html"), arcname="dashboard.html")
        for i, project in enumerate(data["projects"]):
            sub = os.path.join(output_dir, f"child{i}")
            os.makedirs(sub)
            report, components = create_report({**config, "project": [project["uuid"]]}, sub)
            if not isinstance(report, str):
                logger.warning(f"Collection child {project['name']} skipped: {report}")
                continue
            if components:
                _create_graph(components, sub)
            folder = secure_filename(project["name"]) or f"project{i}"
            for file in ("result.docx", "result.xlsx", "summary.json", "graph.html"):
                if os.path.exists(os.path.join(sub, file)):
                    zipf.write(os.path.join(sub, file), arcname=f"{folder}/{file}")
    return zip_path, f"{info['name']} collection ({datetime.now().strftime('%d.%m.%Y')})"

def _build_report(config, output_dir):
    """ Run create_report + graph + dashboard + zip and return (zip_path, name_or_error) """
    collection = _collection_of(config)
    if collection:
        return _build_collection_zip(config, output_dir, collection)
    report, components = create_report(config, output_dir)
    if not isinstance(report, str):
        return None, report
    with_graph = _create_graph(components, output_dir) if components else False
    _add_dashboard(config, output_dir, components)
    zip_path = _create_zip(output_dir, with_graph)
    if not zip_path:
        return None, "Failed to build report archive"
    return zip_path, report

def _build_diff(config_a, config_b, output_dir):
    """ Run create_diff_report + zip and return (zip_path, name_or_error) """
    report, _ = create_diff_report(config_a, config_b, output_dir)
    if not isinstance(report, str):
        return None, report
    zip_path = _create_zip(output_dir, with_graph=False)
    if not zip_path:
        return None, "Failed to build report archive"
    return zip_path, report

@app.route("/api/v1/reports/get_report", methods=["POST"])
@csrf.exempt
@_api_limit()
@require_api_key
def get_report_api():
    """Generate a DT report and return it as a ZIP.
    ---
    tags:
      - api
    security:
      - ApiKey: []
      - Bearer: []
    consumes:
      - application/json
    produces:
      - application/zip
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - project
          properties:
            url:
              type: string
              description: DT instance URL. Optional when DT_URL is set.
              example: https://dependencytrack.example.com
            token:
              type: string
              description: DT API key. Optional when DT_TOKEN is set.
            project:
              type: string
              description: DT project UUID.
              example: 00000000-0000-0000-0000-000000000000
    responses:
      200:
        description: ZIP archive with result.docx, result.xlsx, summary.json, graph.html and dashboard.html.
      400:
        description: Validation error (missing field or upstream rejected).
        schema:
          type: object
          properties:
            error:
              type: string
      401:
        description: DTRG_API_KEY is set and the request did not present it.
        schema:
          type: object
          properties:
            error:
              type: string
              example: unauthorized
    """
    logger.info("Received API request to generate report")
    body = request.get_json(silent=True) or {}
    if not body and request.form:
        body = request.form.to_dict(flat=True)
    config = {k: [str(body[k])] for k in ("url", "token", "project") if body.get(k)}
    logger.debug(f"API report request: {_redact(config)}")

    output_dir = _new_output_dir()

    @after_this_request
    def _cleanup(response):
        response.call_on_close(lambda: shutil.rmtree(output_dir, ignore_errors=True))
        return response

    zip_path, report = _build_report(config, output_dir)
    if not zip_path:
        logger.error(f"API report generation failed: {report}")
        return jsonify(error=_GENERIC_REPORT_FAILURE), 400
    return send_file(zip_path, as_attachment=True,
                     download_name=_safe_download_name(report),
                     mimetype="application/zip")

@app.route("/api/v1/reports/diff", methods=["POST"])
@csrf.exempt
@_api_limit()
@require_api_key
def get_diff_report_api():
    """Generate a diff report between two DT projects and return it as a ZIP.
    ---
    tags:
      - api
    security:
      - ApiKey: []
      - Bearer: []
    consumes:
      - application/json
    produces:
      - application/zip
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - projectA
            - projectB
          properties:
            url:
              type: string
              description: DT instance URL. Optional when DT_URL is set.
            token:
              type: string
              description: DT API key. Optional when DT_TOKEN is set.
            projectA:
              type: string
              description: Baseline DT project UUID.
              example: 00000000-0000-0000-0000-000000000001
            projectB:
              type: string
              description: Comparison DT project UUID; diff is "from A to B".
              example: 00000000-0000-0000-0000-000000000002
    responses:
      200:
        description: ZIP archive with the diff result.xlsx and summary.json.
      400:
        description: Validation error (missing field or upstream rejected).
        schema:
          type: object
          properties:
            error:
              type: string
      401:
        description: DTRG_API_KEY is set and the request did not present it.
        schema:
          type: object
          properties:
            error:
              type: string
              example: unauthorized
    """
    logger.info("Received API request to generate diff report")
    body = request.get_json(silent=True) or {}
    if not body and request.form:
        body = request.form.to_dict(flat=True)
    base = {k: [str(body[k])] for k in ("url", "token") if body.get(k)}
    config_a = dict(base)
    config_b = dict(base)
    if body.get("projectA"):
        config_a["project"] = [str(body["projectA"])]
    if body.get("projectB"):
        config_b["project"] = [str(body["projectB"])]
    logger.debug(f"API diff request: {_redact(config_a)} vs {_redact(config_b)}")

    output_dir = _new_output_dir()

    @after_this_request
    def _cleanup(response):
        response.call_on_close(lambda: shutil.rmtree(output_dir, ignore_errors=True))
        return response

    zip_path, report = _build_diff(config_a, config_b, output_dir)
    if not zip_path:
        logger.error(f"API diff report generation failed: {report}")
        return jsonify(
            error=_diff_user_error(report) or _GENERIC_REPORT_FAILURE), 400
    return send_file(zip_path, as_attachment=True,
                     download_name=_safe_download_name(report),
                     mimetype="application/zip")


# DASHBOARD GROUP
def dashboard_max_projects() -> int:
    """ Cap on projects per combined dashboard (the chart palette has 8 hues) """
    try:
        return max(1, min(int(os.getenv("DTRG_DASHBOARD_MAX_PROJECTS", "8")), 8))
    except ValueError:
        return 8

def _project_ids(values):
    """ Form sends "name version (uuid)", API sends bare UUIDs """
    out = []
    for raw in values or []:
        match = re.search(r"\(([^()]+)\)\s*$", str(raw))
        pid = match.group(1) if match else str(raw).strip()
        if pid and pid not in out:
            out.append(pid)
    return out

def _build_dashboard(config, projects, output_dir):
    """ One combined page for several projects -> (html_path, name_or_error) """
    data, err = _build_dashboard_data(config, projects, output_dir)
    if err is not None:
        return None, err
    path = dashboard.render(data["projects"], os.path.join(output_dir, "dashboard.html"), data["collections"])
    name = data["collections"][0]["name"] if len(data["collections"]) == 1 and len(projects) == 1 else "dashboard"
    return path, f"{name} {datetime.now().strftime('%d.%m.%Y')}"

def _dashboard_project(url, headers, project):
    """ Dashboard data straight from DT, without rendering docx / xlsx / ZIP """
    data = _load_project(url, headers, project)
    components = data["components"]
    version = data["info"].get("version")
    label = " ".join(x for x in (data["name"], None if version == "no version" else version) if x) or project
    graph = get_graph(components) if components else None
    tree = dashboard.graph_tree(render_template("graph.html", graph=graph)) if graph else None
    return dashboard.build_project(url, headers, project, label, tree, graph=components)

def _build_dashboard_data(config, projects, output_dir):
    """ -> ({"projects": [...], "collections": [...]}, None) or (None, error).

    Selected collection projects are expanded into their children (per the
    collection logic set in DT), so a schedule follows changes made in DT.
    """
    if not projects:
        return None, ValueError("Select at least one project")
    if len(projects) > dashboard_max_projects():
        return None, ValueError(f"At most {dashboard_max_projects()} projects per dashboard")
    try:
        url, headers, _ = _resolve_params({**config, "project": [projects[0]]})
        leaves, collections = dt_collections.expand(url, headers, projects)
        if not leaves:
            return None, ValueError(f"No projects with a BOM in {', '.join(c['name'] for c in collections)}")
        limit = dt_collections.max_projects() if collections else dashboard_max_projects()
        if len(leaves) > limit:
            return None, ValueError(f"At most {limit} projects per dashboard ({len(leaves)} selected)")
        collected = [_dashboard_project(url, headers, project) for project in leaves]
    except (ValueError, ConnectionError) as e:
        return None, e
    except Exception as e:  # pylint: disable=broad-except
        logger.exception("Dashboard generation failed")
        return None, e
    return {"projects": collected, "collections": collections}, None

def _dashboard_user_error(err):
    """ Input errors that are safe and useful to show to the user """
    msg = str(err) if isinstance(err, ValueError) else ""
    if msg == "Select at least one project" or msg.startswith(("At most ", "No projects with a BOM")):
        return msg
    return None

def _send_dashboard(path, name):
    return send_file(path, as_attachment=True, mimetype="text/html",
                     download_name=secure_filename(f"{name}.html") or "dashboard.html")

@app.route("/api/v1/reports/dashboard", methods=["POST"])
@csrf.exempt
@_api_limit()
@require_api_key
def get_dashboard_api():
    """Generate one combined management dashboard for several DT projects.
    ---
    tags:
      - api
    security:
      - ApiKey: []
      - Bearer: []
    consumes:
      - application/json
    produces:
      - text/html
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - projects
          properties:
            url:
              type: string
              description: DT instance URL. Optional when DT_URL is set.
            token:
              type: string
              description: DT API key. Optional when DT_TOKEN is set.
            projects:
              type: array
              items:
                type: string
              description: DT project UUIDs (up to DTRG_DASHBOARD_MAX_PROJECTS, default 8).
              example: ["00000000-0000-0000-0000-000000000001"]
    responses:
      200:
        description: Self-contained dashboard.html.
      400:
        description: Validation error (missing field or upstream rejected).
        schema:
          type: object
          properties:
            error:
              type: string
      401:
        description: DTRG_API_KEY is set and the request did not present it.
    """
    logger.info("Received API request to generate dashboard")
    body = request.get_json(silent=True) or {}
    config = {k: [str(body[k])] for k in ("url", "token") if body.get(k)}
    projects = body.get("projects")
    if not isinstance(projects, list):
        return jsonify(error="projects must be a list of project UUIDs"), 400

    output_dir = _new_output_dir()

    @after_this_request
    def _cleanup(response):
        response.call_on_close(lambda: shutil.rmtree(output_dir, ignore_errors=True))
        return response

    path, name = _build_dashboard(config, _project_ids(projects), output_dir)
    if not path:
        logger.error(f"API dashboard generation failed: {name}")
        return jsonify(error=_dashboard_user_error(name) or _GENERIC_REPORT_FAILURE), 400
    return _send_dashboard(path, name)


# BROWSER VIEWS
# The start page lists DT projects; these GET routes back its buttons. DT
# URL and token always come from the environment (.env), never the browser.
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

def _temp_output_dir():
    """ Per-request output directory, removed once the response is sent """
    output_dir = _new_output_dir()

    @after_this_request
    def _cleanup(response):
        response.call_on_close(lambda: shutil.rmtree(output_dir, ignore_errors=True))
        return response
    return output_dir

def _error_page(message, status):
    return render_template("error.html", message=message), status

def _list_item(project):
    metrics = project.get("metrics") or {}
    return {
        "uuid": project.get("uuid"),
        "name": project.get("name"),
        "version": project.get("version"),
        "parent": (project.get("parent") or {}).get("name"),
        "tags": [t.get("name") for t in project.get("tags") or [] if t.get("name")],
        "classifier": project.get("classifier"),
        "lastBomImport": project.get("lastBomImport"),
        "hasChildren": bool(project.get("hasChildren")),
        "collection": dt_collections.LOGIC_LABELS.get(project.get("collectionLogic") or "", None)
        and (dt_collections.LOGIC_LABELS[project["collectionLogic"]]
             + (f" {(project.get('collectionTag') or {}).get('name')}"
                if project["collectionLogic"] == "AGGREGATE_DIRECT_CHILDREN_WITH_TAG" else "")),
        "metrics": {k: metrics.get(k) for k in
                    ("critical", "high", "medium", "low", "unassigned", "inheritedRiskScore")},
    }

@app.route("/ui/projects", methods=["GET"])
def ui_projects():
    """Project page data for the start page (needs DT_URL / DT_TOKEN in the environment).
    ---
    tags:
      - browser
    produces:
      - application/json
    parameters:
      - in: query
        name: search
        type: string
      - in: query
        name: page
        type: integer
    responses:
      200:
        description: '{"items": [...], "total": n, "pageSize": n}'
      502:
        description: DT is not configured or the request to DT failed.
    """
    if not _dt_configured():
        return jsonify(error="DT_URL and DT_TOKEN are not set"), 502
    try:
        page = max(int(request.args.get("page", "1")), 1)
    except ValueError:
        page = 1
    page_size = projects_page_size()
    body, total = get_projects(os.getenv("DT_URL"), os.getenv("DT_TOKEN"),
                               search_text=request.args.get("search", ""),
                               page_size=page_size, page_number=page)
    if isinstance(body, dict):
        return jsonify(body), 502
    return jsonify(items=[_list_item(p) for p in json.loads(body)], total=total, pageSize=page_size)

@app.route("/projects/<project>/report", methods=["GET"])
def view_report(project):
    """Open one project's dashboard (HTML) in the browser.
    ---
    tags:
      - browser
    produces:
      - text/html
    parameters:
      - in: path
        name: project
        required: true
        type: string
    responses:
      200:
        description: dashboard.html, inline.
      502:
        description: Report generation failed.
    """
    if not _UUID_RE.match(project):
        return _error_page("Unknown project.", 404)
    # dashboard only: no docx / xlsx / ZIP for a page that is just viewed
    path, name = _build_dashboard({}, [project], _temp_output_dir())
    if not path:
        logger.error(f"Report view failed: {name}")
        return _error_page(_GENERIC_REPORT_FAILURE, 502)
    return send_file(path, mimetype="text/html")

@app.route("/projects/<project>/report.zip", methods=["GET"])
def download_report(project):
    """Download one project's report ZIP (docx, xlsx, summary.json, graph, dashboard).
    ---
    tags:
      - browser
    produces:
      - application/zip
    parameters:
      - in: path
        name: project
        required: true
        type: string
    responses:
      200:
        description: ZIP archive.
      502:
        description: Report generation failed.
    """
    if not _UUID_RE.match(project):
        return _error_page("Unknown project.", 404)
    output_dir = _temp_output_dir()
    zip_path, report = _build_report({"project": [project]}, output_dir)
    if not zip_path:
        logger.error(f"Report download failed: {report}")
        return _error_page(_GENERIC_REPORT_FAILURE, 502)
    return send_file(zip_path, as_attachment=True, mimetype="application/zip",
                     download_name=_safe_download_name(report))

@app.route("/dashboard", methods=["GET"])
def view_dashboard():
    """Open one combined dashboard for several projects (?projects=<uuid>&projects=<uuid>).
    ---
    tags:
      - browser
    produces:
      - text/html
    parameters:
      - in: query
        name: projects
        type: array
        items:
          type: string
        collectionFormat: multi
    responses:
      200:
        description: Combined dashboard.html, inline.
      400:
        description: No / too many / malformed project ids.
    """
    projects = _project_ids(request.args.getlist("projects"))
    if not all(_UUID_RE.match(p) for p in projects):
        return _error_page("Unknown project.", 400)
    path, name = _build_dashboard({}, projects, _temp_output_dir())
    if not path:
        logger.error(f"Combined dashboard failed: {name}")
        user_error = _dashboard_user_error(name)
        return _error_page(user_error or _GENERIC_REPORT_FAILURE, 400 if user_error else 502)
    return send_file(path, mimetype="text/html")


# EMAIL GROUP
# Reports by mail, now or on a schedule. Mail clients strip JavaScript, so
# the body is a static summary and the interactive dashboard is attached.
def send_report_email(projects, recipients, note=None):
    """ Build the dashboard for `projects` and mail it; raises mailer.MailError """
    recipients = mailer.check_recipients(recipients)
    output_dir = _new_output_dir()
    try:
        data, err = _build_dashboard_data({}, projects, output_dir)
        if err is not None:
            logger.error(f"Report for email failed: {err}")
            raise mailer.MailError(_dashboard_user_error(err) or _GENERIC_REPORT_FAILURE)
        collected, collections = data["projects"], data["collections"]
        path = dashboard.render(collected, os.path.join(output_dir, "dashboard.html"), collections)
        stamp = datetime.now().strftime("%Y-%m-%d")
        title = mail_summary.title(collected, collections, len(projects))
        attachment = secure_filename(f"dashboard_{title}_{stamp}.html") or "dashboard.html"
        summary = mail_summary.summarize(collected)
        html = render_template("email_summary.html", s=summary, attachment=attachment, note=note,
                               collections=collections, title=title,
                               generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
                               public_url=os.getenv("DTRG_PUBLIC_URL"))
        with open(path, "rb") as f:
            mailer.send(recipients, mail_summary.subject(title, summary), html,
                        [(attachment, f.read(), "text/html")])
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)

def _owner():
    """ Subscriptions belong to the signed-in user; without SSO they are shared """
    user = auth.current_user()
    return (user["username"] or user["oid"], user.get("name")) if user else ("shared", None)

def _json_error(message, status=400):
    return jsonify(error=message), status

@app.route("/ui/mail", methods=["GET"])
def ui_mail_config():
    """Mail settings the start page needs (no secrets).
    ---
    tags:
      - browser
    responses:
      200:
        description: '{"enabled": bool, "defaultRecipient": str, "allowed": [...], "timezone": str}'
    """
    user = auth.current_user() or {}
    return jsonify(enabled=mailer.enabled(), backend=mailer.backend(), allowed=mailer._allowed(),
                   defaultRecipient=user.get("username") or "", timezone=str(store.tz()),
                   maxProjects=dashboard_max_projects())

@app.route("/ui/email", methods=["POST"])
def ui_send_email():
    """Email a report now: {"projects": [uuid, ...], "recipients": [email, ...]}.
    ---
    tags:
      - browser
    responses:
      200:
        description: Sent.
      400:
        description: Not configured, recipient not allowed, or report failed.
    """
    body = request.get_json(silent=True) or {}
    projects = _project_ids(body.get("projects") if isinstance(body.get("projects"), list) else [])
    if not projects or not all(_UUID_RE.match(p) for p in projects):
        return _json_error("Select at least one project")
    try:
        send_report_email(projects, body.get("recipients") or [])
    except mailer.MailError as e:
        return _json_error(str(e))
    return jsonify(ok=True)

def _sub_view(sub):
    return {k: sub[k] for k in ("id", "owner_name", "projects", "recipients", "frequency", "hour",
                                "weekday", "day", "next_run", "last_run", "last_status")}

@app.route("/ui/subscriptions", methods=["GET"])
def ui_list_subscriptions():
    """The signed-in user's report subscriptions (all of them when SSO is off).
    ---
    tags:
      - browser
    responses:
      200:
        description: '{"items": [...]}'
    """
    return jsonify(items=[_sub_view(s) for s in store.list_for(_owner()[0])])

@app.route("/ui/subscriptions", methods=["POST"])
def ui_create_subscription():
    """Create a scheduled report.
    ---
    tags:
      - browser
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            projects: {type: array, items: {type: object}, description: '[{"uuid", "label"}]'}
            recipients: {type: array, items: {type: string}}
            frequency: {type: string, enum: [daily, weekly, monthly]}
            hour: {type: integer, description: 0-23 in DTRG_TIMEZONE}
            weekday: {type: integer, description: 0 = Monday (weekly)}
            day: {type: integer, description: 1-28 (monthly)}
    responses:
      200:
        description: The new subscription.
      400:
        description: Invalid input.
    """
    if not mailer.enabled():
        return _json_error("Email is not configured on this dtrg instance")
    body = request.get_json(silent=True) or {}
    projects = []
    for p in body.get("projects") or []:
        uuid = str((p or {}).get("uuid") or "")
        if _UUID_RE.match(uuid) and uuid not in [x["uuid"] for x in projects]:
            projects.append({"uuid": uuid, "label": str(p.get("label") or uuid)[:200]})
    if not projects:
        return _json_error("Select at least one project")
    if len(projects) > dashboard_max_projects():
        return _json_error(f"At most {dashboard_max_projects()} projects per report")
    try:
        recipients = mailer.check_recipients(body.get("recipients") or [])
    except mailer.MailError as e:
        return _json_error(str(e))
    frequency = body.get("frequency")
    try:
        hour = int(body.get("hour", 7))
        weekday = int(body["weekday"]) if frequency == "weekly" else None
        day = int(body["day"]) if frequency == "monthly" else None
    except (KeyError, TypeError, ValueError):
        return _json_error("Pick when to send it")
    if frequency not in store.FREQUENCIES or not 0 <= hour <= 23 \
            or (weekday is not None and not 0 <= weekday <= 6) or (day is not None and not 1 <= day <= 28):
        return _json_error("Pick when to send it")
    owner, owner_name = _owner()
    sub = store.create(owner, owner_name, projects, recipients, frequency, hour, weekday, day)
    logger.info(f"Subscription {sub['id']} created by {owner}")
    return jsonify(_sub_view(sub))

def _own_subscription(sub_id):
    sub = store.get(sub_id)
    return sub if sub and sub["owner"] == _owner()[0] else None

@app.route("/ui/subscriptions/<int:sub_id>", methods=["DELETE"])
def ui_delete_subscription(sub_id):
    """Delete one of your subscriptions.
    ---
    tags:
      - browser
    responses:
      200:
        description: Deleted.
      404:
        description: Not found or not yours.
    """
    if not _own_subscription(sub_id):
        return _json_error("Not found", 404)
    store.delete(sub_id)
    return jsonify(ok=True)

@app.route("/ui/subscriptions/<int:sub_id>/run", methods=["POST"])
def ui_run_subscription(sub_id):
    """Send one of your subscriptions right now (the schedule is unchanged).
    ---
    tags:
      - browser
    responses:
      200:
        description: Sent.
      400:
        description: Sending failed.
      404:
        description: Not found or not yours.
    """
    sub = _own_subscription(sub_id)
    if not sub:
        return _json_error("Not found", 404)
    try:
        run_subscription(sub)
    except mailer.MailError as e:
        return _json_error(str(e))
    return jsonify(ok=True)

def run_subscription(sub):
    """ Send a subscription's report and record the outcome """
    try:
        send_report_email([p["uuid"] for p in sub["projects"]], sub["recipients"],
                          note=f"Scheduled report ({sub['frequency']})"
                               + ("" if sub["owner"] == "shared" else f" set up by {sub['owner_name'] or sub['owner']}") + ".")
    except mailer.MailError as e:
        store.record_run(sub["id"], f"failed: {e}")
        raise
    except Exception as e:
        store.record_run(sub["id"], "failed: internal error")
        logger.exception(f"Subscription {sub['id']} failed")
        raise mailer.MailError(_GENERIC_REPORT_FAILURE) from e
    store.record_run(sub["id"], "sent")


# the scheduler sends due subscriptions; off when mail is not configured,
# in tests, and in the Werkzeug reloader's parent process
if mailer.enabled() and os.getenv("DTRG_SCHEDULER", "true").lower() in ["true", "1", "t"] \
        and not (os.getenv("DTRG_DEBUG", "").lower() in ["true", "1", "t"] and os.getenv("WERKZEUG_RUN_MAIN") != "true"):
    scheduler.start(app, run_subscription)


# PROJECTS GROUP
@app.route("/api/v1/projects", methods=["POST"])
@csrf.exempt
@_api_limit()
@require_api_key
def get_all_projects_api():
    """List Dependency-Track projects.
    ---
    tags:
      - api
    security:
      - ApiKey: []
      - Bearer: []
    consumes:
      - application/json
    produces:
      - application/json
    parameters:
      - in: body
        name: body
        required: false
        schema:
          type: object
          properties:
            url:
              type: string
              description: DT instance URL. Optional when DT_URL is set.
            token:
              type: string
              description: DT API key. Optional when DT_TOKEN is set.
            searchText:
              type: string
              description: Optional substring filter forwarded to DT.
            pageSize:
              type: integer
              description: |
                Optional. Number of projects per page (default returns
                everything DT has up to 99999 to preserve previous CI
                behaviour).
            pageNumber:
              type: integer
              description: Optional. 1-based page number (default 1).
    responses:
      200:
        description: |
          JSON array of DT project objects (forwarded from DT). The
          X-Total-Count response header carries the total number of
          projects matching the search.
      400:
        description: Missing url/token or non-integer pagination.
        schema:
          type: object
          properties:
            error:
              type: string
      401:
        description: DTRG_API_KEY is set and the request did not present it.
      502:
        description: Upstream DT request failed.
        schema:
          type: object
          properties:
            error:
              type: string
    """
    body = request.get_json(silent=True) or {}
    if not body and request.form:
        body = request.form.to_dict(flat=True)
    url = os.getenv("DT_URL") or body.get("url") or ""
    token = os.getenv("DT_TOKEN") or body.get("token") or ""
    if not url or not token:
        return jsonify(error="url and token are required"), 400

    search_text = str(body.get("searchText") or "")
    try:
        page_size = int(body["pageSize"]) if body.get("pageSize") else 99999
        page_number = max(int(body["pageNumber"]) if body.get("pageNumber") else 1, 1)
    except (ValueError, TypeError):
        return jsonify(error="pageSize and pageNumber must be integers"), 400

    logger.debug(f"API projects request for: {url} "
                 f"(page={page_number}, size={page_size}, search={search_text!r})")
    result, total = get_projects(url, token,
                                 search_text=search_text,
                                 page_size=page_size,
                                 page_number=page_number)
    if isinstance(result, dict):
        return jsonify(result), 502
    response = Response(result, mimetype="application/json")
    response.headers["X-Total-Count"] = str(total)
    return response


# GRAPH GROUP
def _create_graph(components, output_dir):
    """ Render the dependency graph HTML into output_dir """
    logger.info("Generating graph from components")
    graph = get_graph(components)
    if graph:
        rendered = render_template("graph.html", graph=graph)
        with open(os.path.join(output_dir, "graph.html"), "w", encoding="utf-8") as f:
            f.write(rendered)
        logger.info("Graph HTML saved successfully")
        return True
    logger.warning("Graph data was empty; skipping HTML generation")
    return False


if __name__ == "__main__":
    debug_mode = os.getenv("DTRG_DEBUG", "False").lower() in ["true", "1", "t"]
    port = int(os.getenv("DTRG_PORT", "5000"))
    host = os.getenv("DTRG_HOST", "0.0.0.0")
    allow_remote_debug = os.getenv("DTRG_DEBUG_ALLOW_REMOTE", "False").lower() in [
        "true", "1", "t"
    ]

    # Werkzeug debugger exposes a remote code execution path via the PIN
    # console. Refuse to combine debug mode with a non-loopback bind unless
    # operators explicitly opt in.
    if debug_mode and host not in ("127.0.0.1", "localhost") and not allow_remote_debug:
        raise SystemExit(
            "DTRG_DEBUG=true is unsafe with a non-loopback DTRG_HOST. "
            "Set DTRG_HOST=127.0.0.1 or DTRG_DEBUG_ALLOW_REMOTE=true to confirm."
        )

    # Set logging level based on debug mode
    log_level = logging.DEBUG if debug_mode else logging.INFO
    logging.getLogger().setLevel(log_level)
    logger.info(f"Starting app on {host}:{port} with debug={debug_mode}")

    app.run(host=host, port=port, debug=debug_mode)
