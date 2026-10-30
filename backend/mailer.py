""" Outbound email for reports: SMTP or Microsoft Graph, chosen in the env.

DTRG_MAIL_BACKEND=smtp   DTRG_SMTP_HOST / _PORT / _USER / _PASSWORD,
                         DTRG_SMTP_SECURITY=starttls|ssl|none
DTRG_MAIL_BACKEND=graph  app-only Graph sendMail as DTRG_MAIL_FROM; the Entra
                         app needs the Mail.Send application permission.
                         DTRG_GRAPH_TENANT_ID / _CLIENT_ID / _CLIENT_SECRET
                         default to the DTRG_OIDC_* values.

Reports carry vulnerability details of internal systems, so every
recipient must match DTRG_MAIL_ALLOWED_RECIPIENTS (comma-separated, globs
such as *@example.com). With the allowlist empty nothing is sent.
"""

import base64
import logging
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from fnmatch import fnmatch

from backend._http import requests

logger = logging.getLogger(__name__)

MAX_RECIPIENTS = 20
_EMAIL_RE = re.compile(r"^[^@\s,;<>\"']+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class MailError(Exception):
    """ Safe to show to the user """


def backend() -> str:
    return (os.getenv("DTRG_MAIL_BACKEND") or "").strip().lower()


def enabled() -> bool:
    return backend() in ("smtp", "graph") and bool(os.getenv("DTRG_MAIL_FROM")) and bool(_allowed())


def _allowed():
    raw = os.getenv("DTRG_MAIL_ALLOWED_RECIPIENTS", "")
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def check_recipients(recipients):
    """ Normalise and validate; raises MailError naming the first bad address """
    if isinstance(recipients, str):
        recipients = re.split(r"[,;\s]+", recipients)
    out = []
    for r in recipients or []:
        r = (r or "").strip().lower()
        if not r or r in out:
            continue
        if not _EMAIL_RE.match(r):
            raise MailError(f"Not an email address: {r}")
        if not any(fnmatch(r, p) for p in _allowed()):
            raise MailError(f"Recipient not allowed: {r} (see DTRG_MAIL_ALLOWED_RECIPIENTS)")
        out.append(r)
    if not out:
        raise MailError("Add at least one recipient")
    if len(out) > MAX_RECIPIENTS:
        raise MailError(f"At most {MAX_RECIPIENTS} recipients")
    return out


def send(recipients, subject, html, attachments=()):
    """ attachments: [(filename, bytes, mime type)] """
    if not enabled():
        raise MailError("Email is not configured on this dtrg instance")
    recipients = check_recipients(recipients)
    sender = os.getenv("DTRG_MAIL_FROM")
    if backend() == "graph":
        _send_graph(sender, recipients, subject, html, attachments)
    else:
        _send_smtp(sender, recipients, subject, html, attachments)
    logger.info(f"Report mail '{subject}' sent to {len(recipients)} recipient(s) via {backend()}")


def _send_smtp(sender, recipients, subject, html, attachments):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, ", ".join(recipients), subject
    msg.set_content("This report is HTML; open it in a mail client that shows HTML, "
                    "or open the attached dashboard in a browser.")
    msg.add_alternative(html, subtype="html")
    for name, data, mime in attachments:
        maintype, subtype = mime.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    host = os.getenv("DTRG_SMTP_HOST") or "localhost"
    security = (os.getenv("DTRG_SMTP_SECURITY") or "starttls").lower()
    port = int(os.getenv("DTRG_SMTP_PORT") or (465 if security == "ssl" else 587 if security == "starttls" else 25))
    context = ssl.create_default_context()
    try:
        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, context=context, timeout=60)
        else:
            server = smtplib.SMTP(host, port, timeout=60)
        with server:
            if security == "starttls":
                server.starttls(context=context)
            if os.getenv("DTRG_SMTP_USER"):
                server.login(os.getenv("DTRG_SMTP_USER"), os.getenv("DTRG_SMTP_PASSWORD") or "")
            server.send_message(msg)
    except (OSError, smtplib.SMTPException) as e:
        logger.error(f"SMTP send failed: {e}")
        raise MailError("Sending the email failed (SMTP). Check server logs for details.") from e


def _graph_token():
    tenant = os.getenv("DTRG_GRAPH_TENANT_ID") or os.getenv("DTRG_OIDC_TENANT_ID")
    client = os.getenv("DTRG_GRAPH_CLIENT_ID") or os.getenv("DTRG_OIDC_CLIENT_ID")
    secret = os.getenv("DTRG_GRAPH_CLIENT_SECRET") or os.getenv("DTRG_OIDC_CLIENT_SECRET")
    if not (tenant and client and secret):
        raise MailError("Graph mail needs a tenant id, client id and client secret")
    res = requests.post(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", data={
        "grant_type": "client_credentials", "client_id": client, "client_secret": secret,
        "scope": "https://graph.microsoft.com/.default"}, timeout=30)
    if res.status_code != 200:
        logger.error(f"Graph token request failed: {res.status_code} {res.text[:300]}")
        raise MailError("Sending the email failed (Microsoft Graph sign-in). Check server logs.")
    return res.json()["access_token"]


def _send_graph(sender, recipients, subject, html, attachments):
    try:
        token = _graph_token()
        body = {"message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": html},
            "toRecipients": [{"emailAddress": {"address": r}} for r in recipients],
            "attachments": [{
                "@odata.type": "#microsoft.graph.fileAttachment", "name": name, "contentType": mime,
                "contentBytes": base64.b64encode(data).decode()} for name, data, mime in attachments],
        }, "saveToSentItems": True}
        res = requests.post(f"https://graph.microsoft.com/v1.0/users/{sender}/sendMail",
                            headers={"Authorization": f"Bearer {token}"}, json=body, timeout=60)
    except requests.RequestException as e:
        logger.error(f"Graph send failed: {e}")
        raise MailError("Sending the email failed (Microsoft Graph). Check server logs.") from e
    if res.status_code != 202:
        logger.error(f"Graph sendMail returned {res.status_code}: {res.text[:300]}")
        raise MailError("Sending the email failed (Microsoft Graph). Check server logs.")
