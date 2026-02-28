"""
server.py — UAM IDS Main Server
================================
Flask application providing:
  1. Collector API  — receives payloads from agents
  2. Analyst API    — REST endpoints for dashboard / SOC tools
  3. Background scheduler — runs correlator + alerter every 60 seconds

Quick Start:
  pip install -r requirements.txt
  python server.py

Environment variables (see config.py for full list):
  UAM_DB_URL        — database connection string
  UAM_AGENT_APIKEY  — API key for agents
  UAM_ANALYST_APIKEY— API key for analysts
  UAM_HMAC_SECRET   — HMAC signing secret (must match agent's AGENT_SECRET)
"""

import hashlib
import hmac
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
from collections import Counter

from flask import Flask, request, jsonify, g
from sqlalchemy import func, desc, text

import config
from models import (
    Agent, Payload, Incident, RiskScore, Watchlist, AlertLog, CorrelationRule,
    get_engine, get_session_factory, init_db, Base
)
from correlator import run_correlation, purge_old_payloads, BUILTIN_RULES
from alerter import process_alerts

# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────
logging.basicConfig(
    level   = getattr(logging, config.LOG_LEVEL, logging.INFO),
    format  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers= [
        logging.StreamHandler(),
        logging.FileHandler(config.LOG_FILE),
    ],
)
log = logging.getLogger("server")

# ─────────────────────────────────────────────
# DB SETUP
# ─────────────────────────────────────────────
engine         = get_engine(config.DB_URL)
SessionFactory = get_session_factory(engine)
init_db(engine)

# ─────────────────────────────────────────────
# FLASK APP
# ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = config.SECRET_KEY


def get_db():
    """Return a DB session for this request context."""
    if "db" not in g:
        g.db = SessionFactory()
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


# ─────────────────────────────────────────────
# AUTHENTICATION DECORATORS
# ─────────────────────────────────────────────
def require_agent_key(f):
    """Decorator: requires X-API-KEY header matching AGENT_API_KEY."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-KEY", "")
        if key != config.AGENT_API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def require_analyst_key(f):
    """Decorator: requires X-ANALYST-KEY header matching ANALYST_API_KEY."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-ANALYST-KEY", "")
        if key != config.ANALYST_API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
# HMAC SIGNATURE VERIFICATION
# ─────────────────────────────────────────────
def _verify_hmac(body: bytes, signature_header: str) -> bool:
    """Verify HMAC-SHA256 payload signature from agent."""
    if not config.VERIFY_HMAC:
        return True
    if not signature_header:
        return False
    try:
        expected = hmac.new(
            config.HMAC_SECRET.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature_header)
    except Exception:
        return False


# ─────────────────────────────────────────────
# PAYLOAD VALIDATOR
# ─────────────────────────────────────────────
REQUIRED_FIELDS = [
    "agent_id", "hostname", "timestamp", "schema_version",
    "session", "risk_intelligence",
]

def _validate_payload(data: dict) -> tuple[bool, str]:
    """Basic validation of incoming agent payload."""
    for field in REQUIRED_FIELDS:
        if field not in data:
            return False, f"Missing required field: {field}"
    if data.get("schema_version") not in ("3.0", "2.0"):
        return False, f"Unsupported schema version: {data.get('schema_version')}"
    return True, ""


# ─────────────────────────────────────────────
# ════════════════════════════════════════════
#   COLLECTOR API — for agents
# ════════════════════════════════════════════
# ─────────────────────────────────────────────

@app.route("/api/logs", methods=["POST"])
@require_agent_key
def collect_payload():
    """
    POST /api/logs
    Receives a JSON payload from an agent, stores it, updates agent record.

    Headers required:
      X-API-KEY           — agent API key
      X-PAYLOAD-SIGNATURE — HMAC-SHA256 of request body (optional if VERIFY_HMAC=false)
    """
    raw_body = request.get_data()

    # HMAC check
    sig = request.headers.get("X-PAYLOAD-SIGNATURE", "")
    if config.VERIFY_HMAC and not _verify_hmac(raw_body, sig):
        log.warning(f"HMAC verification failed from {request.remote_addr}")
        return jsonify({"error": "Invalid payload signature"}), 403

    try:
        data = json.loads(raw_body)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON"}), 400

    # Validate
    ok, err = _validate_payload(data)
    if not ok:
        return jsonify({"error": err}), 400

    db = get_db()

    try:
        agent_id = data["agent_id"]
        hostname = data.get("hostname", "unknown")
        username = data.get("session", {}).get("user", "unknown")
        os_name  = data.get("os", "unknown")
        os_ver   = data.get("os_version", "")
        ip       = data.get("ip", request.remote_addr)

        # Agent timestamp
        try:
            agent_ts = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
        except Exception:
            agent_ts = datetime.utcnow()

        # Risk data
        risk = data.get("risk_intelligence", {})
        rule_score      = float(risk.get("rule_score", 0))
        deviation_score = float(risk.get("deviation_score", 0))
        agent_risk_score= float(risk.get("agent_risk_score", 0))
        flags           = risk.get("rule_based_flags", [])
        is_off_hours    = bool(data.get("session", {}).get("is_off_hours", False))

        # ── UPSERT AGENT ──
        agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
        if agent:
            agent.hostname      = hostname
            agent.username      = username
            agent.os            = os_name
            agent.os_version    = os_ver
            agent.ip            = ip
            agent.last_seen     = datetime.utcnow()
            agent.total_payloads += 1
        else:
            agent = Agent(
                agent_id      = agent_id,
                hostname      = hostname,
                username      = username,
                os            = os_name,
                os_version    = os_ver,
                ip            = ip,
                total_payloads= 1,
            )
            db.add(agent)
            log.info(f"New agent registered: {hostname} ({username})")

        # ── STORE PAYLOAD ──
        # Remove screenshot to save DB space (store separately if needed)
        data_to_store = {k: v for k, v in data.items() if k != "screenshot_b64"}

        payload = Payload(
            agent_id        = agent_id,
            agent_timestamp = agent_ts,
            schema_version  = data.get("schema_version", "3.0"),
            rule_score      = rule_score,
            deviation_score = deviation_score,
            agent_risk_score= agent_risk_score,
            flags           = flags,
            raw             = data_to_store,
            ip              = ip,
            is_off_hours    = is_off_hours,
        )
        db.add(payload)
        db.commit()

        return jsonify({"status": "ok", "received": len(raw_body)}), 200

    except Exception as e:
        log.error(f"Payload processing error: {e}", exc_info=True)
        db.rollback()
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/health", methods=["GET"])
def health_check():
    """GET /api/health — public endpoint for uptime monitoring."""
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()}), 200


# ─────────────────────────────────────────────
# ════════════════════════════════════════════
#   ANALYST API — for security team
# ════════════════════════════════════════════
# ─────────────────────────────────────────────

# ── DASHBOARD SUMMARY ──────────────────────

@app.route("/api/analyst/summary", methods=["GET"])
@require_analyst_key
def analyst_summary():
    """
    GET /api/analyst/summary
    High-level dashboard statistics.
    """
    db = get_db()
    now = datetime.utcnow()

    total_agents   = db.query(func.count(Agent.id)).scalar()
    active_agents  = db.query(func.count(Agent.id)).filter(
        Agent.last_seen >= now - timedelta(minutes=5)).scalar()
    open_incidents = db.query(func.count(Incident.id)).filter(
        Incident.status.in_(["OPEN", "INVESTIGATING"])).scalar()
    critical_inc   = db.query(func.count(Incident.id)).filter(
        Incident.status.in_(["OPEN", "INVESTIGATING"]),
        Incident.severity == "CRITICAL").scalar()
    high_inc       = db.query(func.count(Incident.id)).filter(
        Incident.status.in_(["OPEN", "INVESTIGATING"]),
        Incident.severity == "HIGH").scalar()
    payloads_24h   = db.query(func.count(Payload.id)).filter(
        Payload.received_at >= now - timedelta(hours=24)).scalar()

    # Top risky agents (last 24h)
    top_risky = (
        db.query(Agent.hostname, Agent.username, func.max(Payload.agent_risk_score).label("max_score"))
        .join(Payload, Agent.agent_id == Payload.agent_id)
        .filter(Payload.received_at >= now - timedelta(hours=24))
        .group_by(Agent.hostname, Agent.username)
        .order_by(desc("max_score"))
        .limit(5)
        .all()
    )

    return jsonify({
        "total_agents":    total_agents,
        "active_agents":   active_agents,
        "open_incidents":  open_incidents,
        "critical_incidents": critical_inc,
        "high_incidents":  high_inc,
        "payloads_24h":    payloads_24h,
        "top_risky_agents": [
            {"hostname": r.hostname, "username": r.username, "max_score": round(r.max_score, 1)}
            for r in top_risky
        ],
        "server_time": now.isoformat(),
    })


# ── AGENTS ─────────────────────────────────

@app.route("/api/analyst/agents", methods=["GET"])
@require_analyst_key
def list_agents():
    """
    GET /api/analyst/agents?page=1&limit=50&search=username
    List all agents with last seen, status, risk.
    """
    db     = get_db()
    page   = int(request.args.get("page", 1))
    limit  = min(int(request.args.get("limit", 50)), 200)
    search = request.args.get("search", "").strip()
    offset = (page - 1) * limit
    now    = datetime.utcnow()

    q = db.query(Agent)
    if search:
        q = q.filter(
            (Agent.username.ilike(f"%{search}%")) |
            (Agent.hostname.ilike(f"%{search}%"))
        )

    total  = q.count()
    agents = q.order_by(desc(Agent.last_seen)).offset(offset).limit(limit).all()

    result = []
    for a in agents:
        # Last risk score
        last_score = (
            db.query(Payload.agent_risk_score)
            .filter(Payload.agent_id == a.agent_id)
            .order_by(desc(Payload.received_at))
            .scalar()
        ) or 0.0

        open_inc = db.query(func.count(Incident.id)).filter(
            Incident.agent_id == a.agent_id,
            Incident.status.in_(["OPEN", "INVESTIGATING"])
        ).scalar()

        result.append({
            "agent_id":       a.agent_id,
            "hostname":       a.hostname,
            "username":       a.username,
            "os":             a.os,
            "ip":             a.ip,
            "first_seen":     a.first_seen.isoformat(),
            "last_seen":      a.last_seen.isoformat(),
            "is_online":      (now - a.last_seen).total_seconds() < 300,
            "total_payloads": a.total_payloads,
            "last_risk_score":round(last_score, 1),
            "open_incidents": open_inc,
        })

    return jsonify({"agents": result, "total": total, "page": page, "limit": limit})


@app.route("/api/analyst/agents/<agent_id>", methods=["GET"])
@require_analyst_key
def get_agent(agent_id):
    """GET /api/analyst/agents/<agent_id> — Detailed agent view."""
    db    = get_db()
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        return jsonify({"error": "Agent not found"}), 404

    # Risk trend (last 24 hourly buckets)
    risk_trend = (
        db.query(RiskScore)
        .filter(RiskScore.agent_id == agent_id)
        .order_by(desc(RiskScore.hour_bucket))
        .limit(24)
        .all()
    )

    # Recent incidents
    incidents = (
        db.query(Incident)
        .filter(Incident.agent_id == agent_id)
        .order_by(desc(Incident.opened_at))
        .limit(10)
        .all()
    )

    return jsonify({
        "agent": {
            "agent_id":       agent.agent_id,
            "hostname":       agent.hostname,
            "username":       agent.username,
            "os":             agent.os,
            "os_version":     agent.os_version,
            "ip":             agent.ip,
            "first_seen":     agent.first_seen.isoformat(),
            "last_seen":      agent.last_seen.isoformat(),
            "total_payloads": agent.total_payloads,
            "notes":          agent.notes,
        },
        "risk_trend": [
            {
                "hour":         r.hour_bucket.isoformat(),
                "max_score":    round(r.max_score, 1),
                "avg_score":    round(r.avg_score, 1),
                "payload_count":r.payload_count,
                "top_flags":    r.top_flags,
            }
            for r in reversed(risk_trend)
        ],
        "incidents": [_incident_to_dict(i) for i in incidents],
    })


@app.route("/api/analyst/agents/<agent_id>/payloads", methods=["GET"])
@require_analyst_key
def get_agent_payloads(agent_id):
    """
    GET /api/analyst/agents/<agent_id>/payloads?page=1&limit=20&min_score=50
    Retrieve recent payloads for an agent. Full raw JSON included.
    """
    db        = get_db()
    page      = int(request.args.get("page", 1))
    limit     = min(int(request.args.get("limit", 20)), 100)
    min_score = float(request.args.get("min_score", 0))
    offset    = (page - 1) * limit

    q = db.query(Payload).filter(Payload.agent_id == agent_id)
    if min_score > 0:
        q = q.filter(Payload.agent_risk_score >= min_score)

    total    = q.count()
    payloads = q.order_by(desc(Payload.received_at)).offset(offset).limit(limit).all()

    return jsonify({
        "payloads": [
            {
                "id":               p.id,
                "received_at":      p.received_at.isoformat(),
                "agent_timestamp":  p.agent_timestamp.isoformat() if p.agent_timestamp else None,
                "agent_risk_score": round(p.agent_risk_score, 1),
                "rule_score":       round(p.rule_score, 1),
                "deviation_score":  round(p.deviation_score, 1),
                "flags":            p.flags,
                "is_off_hours":     p.is_off_hours,
                "raw":              p.raw,
            }
            for p in payloads
        ],
        "total": total, "page": page, "limit": limit,
    })


# ── INCIDENTS ──────────────────────────────

def _incident_to_dict(i: Incident) -> dict:
    return {
        "id":              i.id,
        "agent_id":        i.agent_id,
        "hostname":        i.hostname,
        "username":        i.username,
        "severity":        i.severity,
        "status":          i.status,
        "incident_score":  round(i.incident_score, 1),
        "trigger_flags":   i.trigger_flags,
        "narrative":       i.narrative,
        "analyst_notes":   i.analyst_notes,
        "alert_sent":      i.alert_sent,
        "alert_channel":   i.alert_channel,
        "opened_at":       i.opened_at.isoformat(),
        "updated_at":      i.updated_at.isoformat(),
        "closed_at":       i.closed_at.isoformat() if i.closed_at else None,
    }


@app.route("/api/analyst/incidents", methods=["GET"])
@require_analyst_key
def list_incidents():
    """
    GET /api/analyst/incidents?status=OPEN&severity=HIGH&page=1&limit=50
    List incidents with filters.
    """
    db       = get_db()
    page     = int(request.args.get("page", 1))
    limit    = min(int(request.args.get("limit", 50)), 200)
    status   = request.args.get("status", "")
    severity = request.args.get("severity", "")
    search   = request.args.get("search", "").strip()
    offset   = (page - 1) * limit

    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status.upper())
    if severity:
        q = q.filter(Incident.severity == severity.upper())
    if search:
        q = q.filter(
            (Incident.username.ilike(f"%{search}%")) |
            (Incident.hostname.ilike(f"%{search}%"))
        )

    total     = q.count()
    incidents = q.order_by(desc(Incident.updated_at)).offset(offset).limit(limit).all()

    return jsonify({
        "incidents": [_incident_to_dict(i) for i in incidents],
        "total": total, "page": page, "limit": limit,
    })


@app.route("/api/analyst/incidents/<int:incident_id>", methods=["GET"])
@require_analyst_key
def get_incident(incident_id):
    """GET /api/analyst/incidents/<id> — Full incident detail."""
    db       = get_db()
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        return jsonify({"error": "Incident not found"}), 404
    return jsonify(_incident_to_dict(incident))


@app.route("/api/analyst/incidents/<int:incident_id>", methods=["PATCH"])
@require_analyst_key
def update_incident(incident_id):
    """
    PATCH /api/analyst/incidents/<id>
    Update incident status or analyst notes.

    Body (JSON):
      status       — OPEN / INVESTIGATING / CLOSED / FALSE_POSITIVE
      analyst_notes— free text
    """
    db       = get_db()
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    data = request.get_json() or {}

    if "status" in data:
        new_status = data["status"].upper()
        allowed = {"OPEN", "INVESTIGATING", "CLOSED", "FALSE_POSITIVE"}
        if new_status not in allowed:
            return jsonify({"error": f"Invalid status. Choose from: {allowed}"}), 400
        incident.status = new_status
        if new_status in ("CLOSED", "FALSE_POSITIVE"):
            incident.closed_at = datetime.utcnow()
        log.info(f"Incident #{incident_id} status → {new_status}")

    if "analyst_notes" in data:
        incident.analyst_notes = data["analyst_notes"]

    if "severity" in data:
        new_sev = data["severity"].upper()
        if new_sev in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            incident.severity = new_sev

    incident.updated_at = datetime.utcnow()
    db.commit()

    return jsonify({"status": "updated", "incident": _incident_to_dict(incident)})


# ── WATCHLIST ──────────────────────────────

@app.route("/api/analyst/watchlist", methods=["GET"])
@require_analyst_key
def list_watchlist():
    """GET /api/analyst/watchlist — All watchlist entries."""
    db      = get_db()
    entries = db.query(Watchlist).all()
    return jsonify({
        "watchlist": [
            {
                "id":          w.id,
                "username":    w.username,
                "hostname":    w.hostname,
                "reason":      w.reason,
                "score_boost": w.score_boost,
                "added_at":    w.added_at.isoformat(),
                "added_by":    w.added_by,
                "is_active":   w.is_active,
            }
            for w in entries
        ]
    })


@app.route("/api/analyst/watchlist", methods=["POST"])
@require_analyst_key
def add_to_watchlist():
    """
    POST /api/analyst/watchlist
    Add a user to the watchlist.

    Body: { "username": "jsmith", "hostname": "", "reason": "...", "score_boost": 20 }
    """
    db   = get_db()
    data = request.get_json() or {}

    if not data.get("username"):
        return jsonify({"error": "username is required"}), 400

    existing = db.query(Watchlist).filter(Watchlist.username == data["username"]).first()
    if existing:
        existing.is_active   = True
        existing.reason      = data.get("reason", existing.reason)
        existing.score_boost = float(data.get("score_boost", existing.score_boost))
        db.commit()
        return jsonify({"status": "updated", "id": existing.id})

    entry = Watchlist(
        username    = data["username"],
        hostname    = data.get("hostname", ""),
        reason      = data.get("reason", ""),
        score_boost = float(data.get("score_boost", config.WATCHLIST_SCORE_BOOST)),
        added_by    = data.get("added_by", "analyst"),
    )
    db.add(entry)
    db.commit()
    log.info(f"Added {data['username']} to watchlist")
    return jsonify({"status": "added", "id": entry.id}), 201


@app.route("/api/analyst/watchlist/<int:entry_id>", methods=["DELETE"])
@require_analyst_key
def remove_from_watchlist(entry_id):
    """DELETE /api/analyst/watchlist/<id> — Remove from watchlist."""
    db    = get_db()
    entry = db.query(Watchlist).filter(Watchlist.id == entry_id).first()
    if not entry:
        return jsonify({"error": "Not found"}), 404
    entry.is_active = False
    db.commit()
    return jsonify({"status": "removed"})


# ── AGENT NOTES ────────────────────────────

@app.route("/api/analyst/agents/<agent_id>/notes", methods=["PATCH"])
@require_analyst_key
def update_agent_notes(agent_id):
    """PATCH /api/analyst/agents/<agent_id>/notes — Update analyst notes on an agent."""
    db    = get_db()
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    data = request.get_json() or {}
    agent.notes = data.get("notes", agent.notes)
    db.commit()
    return jsonify({"status": "updated"})


# ── FLAG STATISTICS ────────────────────────

@app.route("/api/analyst/stats/flags", methods=["GET"])
@require_analyst_key
def flag_statistics():
    """
    GET /api/analyst/stats/flags?hours=24
    Returns top triggered flags across all agents in the given time window.
    """
    db    = get_db()
    hours = int(request.args.get("hours", 24))
    since = datetime.utcnow() - timedelta(hours=hours)

    payloads = (
        db.query(Payload.flags)
        .filter(Payload.received_at >= since, Payload.flags != None)
        .all()
    )

    all_flags = []
    for (flags,) in payloads:
        if flags:
            all_flags.extend(flags)

    counts = Counter(all_flags)
    return jsonify({
        "hours": hours,
        "total_flags": len(all_flags),
        "top_flags": [
            {"flag": f, "count": c}
            for f, c in counts.most_common(20)
        ]
    })


@app.route("/api/analyst/stats/risk_timeline", methods=["GET"])
@require_analyst_key
def risk_timeline():
    """
    GET /api/analyst/stats/risk_timeline?agent_id=...&hours=24
    Returns hourly risk score trend for an agent (or all agents).
    """
    db       = get_db()
    agent_id = request.args.get("agent_id", "")
    hours    = int(request.args.get("hours", 24))
    since    = datetime.utcnow() - timedelta(hours=hours)

    q = db.query(RiskScore).filter(RiskScore.hour_bucket >= since)
    if agent_id:
        q = q.filter(RiskScore.agent_id == agent_id)

    rows = q.order_by(RiskScore.hour_bucket.asc()).all()

    return jsonify({
        "timeline": [
            {
                "hour":         r.hour_bucket.isoformat(),
                "agent_id":     r.agent_id,
                "max_score":    round(r.max_score, 1),
                "avg_score":    round(r.avg_score, 1),
                "payload_count":r.payload_count,
                "top_flags":    r.top_flags,
            }
            for r in rows
        ]
    })


# ── CORRELATION RULES ──────────────────────

@app.route("/api/analyst/rules", methods=["GET"])
@require_analyst_key
def list_rules():
    """GET /api/analyst/rules — View all built-in correlation rules."""
    return jsonify({"rules": BUILTIN_RULES})


# ── MANUAL CORRELATION TRIGGER ─────────────

@app.route("/api/analyst/correlate_now", methods=["POST"])
@require_analyst_key
def correlate_now():
    """POST /api/analyst/correlate_now — Manually trigger correlation engine."""
    db = get_db()
    try:
        count = run_correlation(db)
        process_alerts(db)
        return jsonify({"status": "ok", "incidents_affected": count})
    except Exception as e:
        log.error(f"Manual correlation failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# ════════════════════════════════════════════
#   BACKGROUND SCHEDULER
#   Runs correlator + alerter every N seconds
# ════════════════════════════════════════════
# ─────────────────────────────────────────────

def _background_scheduler():
    """Runs in a separate daemon thread. Calls correlator + alerter on a fixed interval."""
    log.info(f"Background scheduler started (interval={config.CORRELATOR_INTERVAL_SEC}s)")
    purge_counter = 0

    while True:
        time.sleep(config.CORRELATOR_INTERVAL_SEC)
        try:
            db = SessionFactory()
            run_correlation(db)
            process_alerts(db)

            # Purge old payloads once per hour (every 60 scheduler ticks)
            purge_counter += 1
            if purge_counter >= 60:
                purge_old_payloads(db)
                purge_counter = 0

            db.close()
        except Exception as e:
            log.error(f"Scheduler error: {e}", exc_info=True)


def start_scheduler():
    t = threading.Thread(target=_background_scheduler, daemon=True, name="Scheduler")
    t.start()
    log.info("Background scheduler thread started.")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    start_scheduler()
    log.info(f"UAM IDS Server starting on {config.HOST}:{config.PORT}")
    app.run(
        host  = config.HOST,
        port  = config.PORT,
        debug = config.DEBUG,
        use_reloader = False,   # Must be False when using background threads
    )
