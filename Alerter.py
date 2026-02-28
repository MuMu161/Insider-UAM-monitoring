"""
alerter.py — Alert Engine for UAM IDS Server

Sends notifications to your security team when an incident is raised.
Supports: Email (SMTP), Slack (webhook), Generic Webhook (Teams, SIEM, etc.)

All alerting is configurable via environment variables in config.py.
"""

import json
import logging
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional

import requests
from sqlalchemy.orm import Session

import config
from models import Incident, AlertLog

log = logging.getLogger("alerter")

# Severity → colour for visual alerts
SEVERITY_COLOR = {
    "CRITICAL": "#FF0000",   # Red
    "HIGH":     "#FF6600",   # Orange
    "MEDIUM":   "#FFCC00",   # Yellow
    "LOW":      "#00AA00",   # Green
}

SEVERITY_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH":     "⚠️",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}


# ─────────────────────────────────────────────
# SHOULD WE ALERT?
# ─────────────────────────────────────────────
def _should_alert(incident: Incident, db: Session) -> bool:
    """
    Check if we should send an alert for this incident.
    Rules:
      1. Incident severity must meet minimum threshold
      2. Must not be in cooldown period (already alerted recently)
      3. Alert not already sent for this incident (unless escalated)
    """
    # Severity check
    severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_rank = severity_rank.get(config.ALERT_MIN_SEVERITY, 1)
    inc_rank = severity_rank.get(incident.severity, 0)
    if inc_rank < min_rank:
        return False

    # Already alerted and not escalated
    if incident.alert_sent:
        return False

    # Cooldown check — look at recent alert logs for this incident
    cooldown_cutoff = datetime.utcnow() - timedelta(minutes=config.ALERT_COOLDOWN_MIN)
    recent_alert = (
        db.query(AlertLog)
        .filter(
            AlertLog.incident_id == incident.id,
            AlertLog.sent_at >= cooldown_cutoff,
            AlertLog.success == True,
        )
        .first()
    )
    if recent_alert:
        return False

    return True


# ─────────────────────────────────────────────
# LOG ALERT RESULT
# ─────────────────────────────────────────────
def _log_alert(
    db:          Session,
    incident_id: int,
    channel:     str,
    recipient:   str,
    subject:     str,
    success:     bool,
    error_msg:   str = "",
):
    entry = AlertLog(
        incident_id = incident_id,
        channel     = channel,
        recipient   = recipient,
        subject     = subject,
        success     = success,
        error_msg   = error_msg,
    )
    db.add(entry)


# ─────────────────────────────────────────────
# FORMAT ALERT CONTENT
# ─────────────────────────────────────────────
def _format_subject(incident: Incident) -> str:
    emoji = SEVERITY_EMOJI.get(incident.severity, "⚠️")
    return (
        f"{emoji} UAM IDS [{incident.severity}] - "
        f"{incident.username}@{incident.hostname} - Incident #{incident.id}"
    )


def _format_html_body(incident: Incident) -> str:
    color  = SEVERITY_COLOR.get(incident.severity, "#888888")
    emoji  = SEVERITY_EMOJI.get(incident.severity, "⚠️")
    flags  = ", ".join(incident.trigger_flags or []) or "N/A"
    time_s = incident.opened_at.strftime("%Y-%m-%d %H:%M UTC")

    html = f"""
    <html><body style="font-family:Arial,sans-serif; max-width:700px;">
    <div style="background:{color};color:white;padding:16px;border-radius:8px 8px 0 0;">
        <h2 style="margin:0;">{emoji} UAM IDS Alert — {incident.severity}</h2>
        <p style="margin:4px 0 0 0;">Incident #{incident.id} | {time_s}</p>
    </div>
    <div style="border:1px solid {color};padding:16px;border-radius:0 0 8px 8px;">
        <table style="width:100%;border-collapse:collapse;">
            <tr>
                <td style="padding:8px;font-weight:bold;width:140px;">User</td>
                <td style="padding:8px;">{incident.username}</td>
            </tr>
            <tr style="background:#f5f5f5;">
                <td style="padding:8px;font-weight:bold;">Hostname</td>
                <td style="padding:8px;">{incident.hostname}</td>
            </tr>
            <tr>
                <td style="padding:8px;font-weight:bold;">Severity</td>
                <td style="padding:8px;"><strong style="color:{color};">{incident.severity}</strong></td>
            </tr>
            <tr style="background:#f5f5f5;">
                <td style="padding:8px;font-weight:bold;">Risk Score</td>
                <td style="padding:8px;">{incident.incident_score:.1f} / 100</td>
            </tr>
            <tr>
                <td style="padding:8px;font-weight:bold;">Rules Fired</td>
                <td style="padding:8px;">{flags}</td>
            </tr>
        </table>
        <hr style="border:1px solid #ddd;margin:16px 0;">
        <h3 style="color:#333;">Narrative</h3>
        <pre style="background:#f8f8f8;padding:12px;border-radius:4px;white-space:pre-wrap;font-size:13px;">{incident.narrative}</pre>
        <hr style="border:1px solid #ddd;margin:16px 0;">
        <p style="color:#666;font-size:12px;">
            This alert was generated automatically by the UAM Insider Threat Detection System.<br>
            Log in to the analyst dashboard to investigate and update this incident.<br>
            Status: {incident.status} | Updated: {incident.updated_at.strftime('%Y-%m-%d %H:%M UTC')}
        </p>
    </div>
    </body></html>
    """
    return html


def _format_plain_body(incident: Incident) -> str:
    flags = ", ".join(incident.trigger_flags or []) or "N/A"
    return f"""
UAM IDS ALERT — {incident.severity}
Incident #{incident.id} | {incident.opened_at.strftime('%Y-%m-%d %H:%M UTC')}

User:       {incident.username}
Hostname:   {incident.hostname}
Severity:   {incident.severity}
Risk Score: {incident.incident_score:.1f} / 100
Status:     {incident.status}
Rules:      {flags}

NARRATIVE:
{incident.narrative}

---
This alert was generated automatically by the UAM Insider Threat Detection System.
    """.strip()


# ─────────────────────────────────────────────
# EMAIL ALERT
# ─────────────────────────────────────────────
def _send_email(incident: Incident, db: Session) -> bool:
    if not config.ALERT_EMAIL_ENABLED:
        return False

    recipients = [r.strip() for r in config.ALERT_EMAIL_TO.split(",") if r.strip()]
    subject    = _format_subject(incident)

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = config.SMTP_FROM
        msg["To"]      = ", ".join(recipients)

        msg.attach(MIMEText(_format_plain_body(incident), "plain"))
        msg.attach(MIMEText(_format_html_body(incident),  "html"))

        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(config.SMTP_USER, config.SMTP_PASS)
            server.sendmail(config.SMTP_FROM, recipients, msg.as_string())

        log.info(f"Email alert sent for incident #{incident.id} to {recipients}")
        _log_alert(db, incident.id, "email", ", ".join(recipients), subject, True)
        return True

    except Exception as e:
        log.error(f"Email alert failed for incident #{incident.id}: {e}")
        _log_alert(db, incident.id, "email", ", ".join(recipients), subject, False, str(e))
        return False


# ─────────────────────────────────────────────
# SLACK ALERT
# ─────────────────────────────────────────────
def _send_slack(incident: Incident, db: Session) -> bool:
    if not config.ALERT_SLACK_ENABLED or not config.SLACK_WEBHOOK_URL:
        return False

    color = SEVERITY_COLOR.get(incident.severity, "#888888")
    emoji = SEVERITY_EMOJI.get(incident.severity, "⚠️")
    flags = ", ".join(incident.trigger_flags or []) or "N/A"

    payload = {
        "text": f"{emoji} *UAM IDS Alert — {incident.severity}*",
        "attachments": [
            {
                "color": color,
                "fields": [
                    {"title": "User",       "value": incident.username,                  "short": True},
                    {"title": "Hostname",   "value": incident.hostname,                  "short": True},
                    {"title": "Severity",   "value": incident.severity,                  "short": True},
                    {"title": "Risk Score", "value": f"{incident.incident_score:.1f}/100","short": True},
                    {"title": "Rules Fired","value": flags,                              "short": False},
                ],
                "footer": f"Incident #{incident.id} | {incident.opened_at.strftime('%Y-%m-%d %H:%M UTC')}",
                "fallback": f"UAM Alert [{incident.severity}] {incident.username}@{incident.hostname}",
            }
        ],
    }

    try:
        resp = requests.post(config.SLACK_WEBHOOK_URL, json=payload, timeout=10)
        resp.raise_for_status()
        log.info(f"Slack alert sent for incident #{incident.id}")
        _log_alert(db, incident.id, "slack", config.SLACK_WEBHOOK_URL,
                   f"Slack: {incident.severity} incident #{incident.id}", True)
        return True

    except Exception as e:
        log.error(f"Slack alert failed for incident #{incident.id}: {e}")
        _log_alert(db, incident.id, "slack", config.SLACK_WEBHOOK_URL,
                   f"Slack: incident #{incident.id}", False, str(e))
        return False


# ─────────────────────────────────────────────
# GENERIC WEBHOOK (Teams, SIEM, PagerDuty, etc.)
# ─────────────────────────────────────────────
def _send_webhook(incident: Incident, db: Session) -> bool:
    if not config.ALERT_WEBHOOK_ENABLED or not config.ALERT_WEBHOOK_URL:
        return False

    payload = {
        "incident_id":    incident.id,
        "severity":       incident.severity,
        "status":         incident.status,
        "username":       incident.username,
        "hostname":       incident.hostname,
        "incident_score": incident.incident_score,
        "trigger_flags":  incident.trigger_flags,
        "narrative":      incident.narrative,
        "opened_at":      incident.opened_at.isoformat(),
        "updated_at":     incident.updated_at.isoformat(),
        "source":         "UAM_IDS",
    }

    try:
        resp = requests.post(
            config.ALERT_WEBHOOK_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        log.info(f"Webhook alert sent for incident #{incident.id}")
        _log_alert(db, incident.id, "webhook", config.ALERT_WEBHOOK_URL,
                   f"Webhook: incident #{incident.id}", True)
        return True

    except Exception as e:
        log.error(f"Webhook alert failed for incident #{incident.id}: {e}")
        _log_alert(db, incident.id, "webhook", config.ALERT_WEBHOOK_URL,
                   f"Webhook: incident #{incident.id}", False, str(e))
        return False


# ─────────────────────────────────────────────
# MAIN ALERT DISPATCHER
# ─────────────────────────────────────────────
def process_alerts(db: Session) -> int:
    """
    Check for un-alerted incidents and send notifications.
    Returns number of alerts sent.
    """
    alerts_sent = 0

    pending = (
        db.query(Incident)
        .filter(
            Incident.status.in_(["OPEN", "INVESTIGATING"]),
            Incident.alert_sent == False,
        )
        .all()
    )

    for incident in pending:
        if not _should_alert(incident, db):
            continue

        sent_any = False

        # Try all configured channels
        if config.ALERT_EMAIL_ENABLED:
            ok = _send_email(incident, db)
            sent_any = sent_any or ok

        if config.ALERT_SLACK_ENABLED:
            ok = _send_slack(incident, db)
            sent_any = sent_any or ok

        if config.ALERT_WEBHOOK_ENABLED:
            ok = _send_webhook(incident, db)
            sent_any = sent_any or ok

        if sent_any:
            incident.alert_sent    = True
            incident.alert_channel = ",".join(filter(None, [
                "email"   if config.ALERT_EMAIL_ENABLED   else "",
                "slack"   if config.ALERT_SLACK_ENABLED   else "",
                "webhook" if config.ALERT_WEBHOOK_ENABLED else "",
            ]))
            alerts_sent += 1

    try:
        db.commit()
    except Exception as e:
        log.error(f"Alert DB commit failed: {e}")
        db.rollback()

    if alerts_sent:
        log.info(f"Alerts sent: {alerts_sent}")

    return alerts_sent
