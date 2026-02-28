"""
correlator.py — Correlation Engine for UAM IDS Server

This is the "detective" — it runs every 60 seconds, looks at the last
few hours of data per agent, and decides whether an incident should be
opened, escalated, or closed.

Key concepts:
  - Time windows: 5min / 1hr / 8hr / 24hr / 7day
  - Incident score accumulates on bad signals, decays on clean periods
  - Narrative: plain-English explanation of why an incident was raised
  - Peer comparison: is this user behaving unusually vs. their colleagues?
"""

import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import List, Optional

from sqlalchemy.orm import Session

import config
from models import Agent, Payload, Incident, RiskScore, Watchlist

log = logging.getLogger("correlator")

# ─────────────────────────────────────────────
# BUILT-IN CORRELATION RULES
# Each rule defines what pattern triggers an incident.
# ─────────────────────────────────────────────
BUILTIN_RULES = [
    {
        "rule_id":        "R01_DATA_EXFIL_USB",
        "name":           "Data Exfiltration via USB",
        "description":    "Sensitive file copied to USB + large network upload in same session",
        "severity":       "CRITICAL",
        "time_window_min": 60,
        "required_flags": ["SENSITIVE_FILE_COPIED_TO_USB"],
        "also_any_flags": ["LARGE_UPLOAD_AFTER_HOURS", "USB_INSERT_WITH_LARGE_UPLOAD"],
        "min_occurrences": 1,
        "score_threshold": 40,
    },
    {
        "rule_id":        "R02_IMPOSSIBLE_TRAVEL",
        "name":           "Impossible Travel Detected",
        "description":    "Login from two geographically impossible locations",
        "severity":       "CRITICAL",
        "time_window_min": 120,
        "required_flags": ["IMPOSSIBLE_TRAVEL_DETECTED"],
        "also_any_flags": [],
        "min_occurrences": 1,
        "score_threshold": 40,
    },
    {
        "rule_id":        "R03_C2_BEACONING",
        "name":           "C2 Beaconing + Credential Theft",
        "description":    "Regular C2-like network beaconing combined with credential access",
        "severity":       "CRITICAL",
        "time_window_min": 30,
        "required_flags": ["C2_BEACONING_DETECTED"],
        "also_any_flags": ["CLIPBOARD_CREDENTIAL_PATTERN", "SUSPICIOUS_PROCESS"],
        "min_occurrences": 1,
        "score_threshold": 55,
    },
    {
        "rule_id":        "R04_DNS_TUNNEL_EXFIL",
        "name":           "DNS Tunneling Data Exfiltration",
        "description":    "DNS tunneling pattern detected with active data movement",
        "severity":       "HIGH",
        "time_window_min": 60,
        "required_flags": ["DNS_TUNNEL_PATTERN"],
        "also_any_flags": ["LARGE_UPLOAD_AFTER_HOURS", "PERSONAL_CLOUD_LARGE_TRANSFER"],
        "min_occurrences": 2,
        "score_threshold": 28,
    },
    {
        "rule_id":        "R05_BULK_EMAIL_OFFHOURS",
        "name":           "Bulk Email Exfiltration After Hours",
        "description":    "Mass external email sending outside work hours",
        "severity":       "HIGH",
        "time_window_min": 120,
        "required_flags": ["BULK_EXTERNAL_EMAIL"],
        "also_any_flags": ["LARGE_EMAIL_ATTACHMENT", "OFF_HOURS_FILE_ACCESS"],
        "min_occurrences": 1,
        "score_threshold": 30,
    },
    {
        "rule_id":        "R06_PRIV_ESC_LATERAL",
        "name":           "Privilege Escalation + Lateral Tools",
        "description":    "Privilege escalation combined with suspicious hacking tools",
        "severity":       "HIGH",
        "time_window_min": 30,
        "required_flags": ["PRIVILEGE_ESCALATION_DETECTED"],
        "also_any_flags": ["SUSPICIOUS_PROCESS", "PROCESS_FROM_TEMP_DIR"],
        "min_occurrences": 1,
        "score_threshold": 25,
    },
    {
        "rule_id":        "R07_SLOW_BURN_OFFHOURS",
        "name":           "Repeated Off-Hours Access Pattern",
        "description":    "Multiple off-hours sessions with file access over several days",
        "severity":       "MEDIUM",
        "time_window_min": 7 * 24 * 60,   # 7 days
        "required_flags": ["OFF_HOURS_FILE_ACCESS"],
        "also_any_flags": [],
        "min_occurrences": 3,
        "score_threshold": 15,
    },
    {
        "rule_id":        "R08_CLOUD_PERSONAL_LARGE",
        "name":           "Large Personal Cloud Upload",
        "description":    "Repeated large uploads to personal cloud services",
        "severity":       "HIGH",
        "time_window_min": 60,
        "required_flags": ["PERSONAL_CLOUD_LARGE_TRANSFER"],
        "also_any_flags": ["LARGE_CLOUD_SYNC_UPLOAD", "USB_INSERT_WITH_LARGE_UPLOAD"],
        "min_occurrences": 1,
        "score_threshold": 25,
    },
    {
        "rule_id":        "R09_CREDENTIAL_THEFT",
        "name":           "Credential Theft Attempt",
        "description":    "Credential-like content in clipboard with suspicious processes",
        "severity":       "HIGH",
        "time_window_min": 30,
        "required_flags": ["CLIPBOARD_CREDENTIAL_PATTERN"],
        "also_any_flags": ["SUSPICIOUS_PROCESS", "PROCESS_FROM_TEMP_DIR", "MULTIPLE_FAILED_LOGONS"],
        "min_occurrences": 1,
        "score_threshold": 30,
    },
    {
        "rule_id":        "R10_MASS_PRINT_OFFHOURS",
        "name":           "Mass Printing After Hours",
        "description":    "Large print job outside work hours — possible document theft",
        "severity":       "MEDIUM",
        "time_window_min": 60,
        "required_flags": ["HIGH_VOLUME_PRINTING"],
        "also_any_flags": ["OFF_HOURS_FILE_ACCESS"],
        "min_occurrences": 1,
        "score_threshold": 20,
    },
    {
        "rule_id":        "R11_BOT_AUTOMATED",
        "name":           "Automated / Bot-Like Activity",
        "description":    "Robotic input pattern with large upload — possible automation exfil",
        "severity":       "HIGH",
        "time_window_min": 30,
        "required_flags": ["BOT_LIKE_INPUT_PATTERN"],
        "also_any_flags": ["LARGE_UPLOAD_AFTER_HOURS", "PERSONAL_CLOUD_LARGE_TRANSFER"],
        "min_occurrences": 1,
        "score_threshold": 35,
    },
    {
        "rule_id":        "R12_KNOWN_BAD_FILE",
        "name":           "Known Malicious File Detected",
        "description":    "File with known-bad hash found on endpoint",
        "severity":       "CRITICAL",
        "time_window_min": 5,
        "required_flags": ["KNOWN_BAD_FILE_HASH"],
        "also_any_flags": [],
        "min_occurrences": 1,
        "score_threshold": 0,
    },
    {
        "rule_id":        "R13_VPN_OFFHOURS_UPLOAD",
        "name":           "VPN After Hours with Large Upload",
        "description":    "Off-hours VPN session combined with large data transfer",
        "severity":       "MEDIUM",
        "time_window_min": 120,
        "required_flags": ["VPN_OFF_HOURS"],
        "also_any_flags": ["LARGE_UPLOAD_AFTER_HOURS", "PERSONAL_CLOUD_LARGE_TRANSFER"],
        "min_occurrences": 1,
        "score_threshold": 18,
    },
]

# Severity → numeric weight mapping (for score accumulation)
SEVERITY_WEIGHT = {
    "CRITICAL": 40,
    "HIGH":     25,
    "MEDIUM":   15,
    "LOW":       5,
}

# Severity rank (for upgrading incidents)
SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
RANK_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}


# ─────────────────────────────────────────────
# HELPER: pull recent payloads for an agent
# ─────────────────────────────────────────────
def _get_recent_payloads(db: Session, agent_id: str, minutes: int) -> List[Payload]:
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    return (
        db.query(Payload)
        .filter(Payload.agent_id == agent_id, Payload.received_at >= cutoff)
        .order_by(Payload.received_at.asc())
        .all()
    )


def _get_all_flags(payloads: List[Payload]) -> List[str]:
    """Flatten all flags from a list of payloads."""
    flags = []
    for p in payloads:
        if p.flags:
            flags.extend(p.flags)
    return flags


def _flag_count(flags: List[str], target: str) -> int:
    return flags.count(target)


def _any_flag_present(flags: List[str], flag_list: List[str]) -> bool:
    return any(f in flags for f in flag_list)


# ─────────────────────────────────────────────
# INCIDENT SCORE CALCULATION
# ─────────────────────────────────────────────
def _calculate_incident_score(
    payloads:      List[Payload],
    matched_rules: List[dict],
    watchlist_boost: float = 0.0,
) -> float:
    """
    Accumulates risk score from:
    1. Average agent risk score across recent payloads
    2. Bonus for each correlation rule that fired
    3. Watchlist boost if user is on the watchlist
    """
    if not payloads:
        return 0.0

    avg_agent_score = sum(p.agent_risk_score for p in payloads) / len(payloads)
    rule_bonus = sum(SEVERITY_WEIGHT.get(r["severity"], 15) for r in matched_rules)
    total = min(100.0, avg_agent_score + rule_bonus + watchlist_boost)
    return round(total, 2)


# ─────────────────────────────────────────────
# INCIDENT SCORE DECAY
# ─────────────────────────────────────────────
def _apply_decay(incident: Incident) -> float:
    """
    Reduce score for incidents with no new evidence.
    Score decays by SCORE_DECAY_FACTOR every SCORE_DECAY_INTERVAL_H hours.
    """
    if not incident.updated_at:
        return incident.incident_score

    hours_since_update = (datetime.utcnow() - incident.updated_at).total_seconds() / 3600
    decay_periods = int(hours_since_update / config.SCORE_DECAY_INTERVAL_H)

    if decay_periods <= 0:
        return incident.incident_score

    decayed = incident.incident_score * (config.SCORE_DECAY_FACTOR ** decay_periods)
    return round(max(0.0, decayed), 2)


# ─────────────────────────────────────────────
# NARRATIVE BUILDER
# ─────────────────────────────────────────────
def _build_narrative(
    agent:         Agent,
    payloads:      List[Payload],
    matched_rules: List[dict],
    all_flags:     List[str],
) -> str:
    """Produces a human-readable description of what happened."""
    lines = []
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    lines.append(f"Incident generated at {now_str}")
    lines.append(f"User: {agent.username} | Host: {agent.hostname} | OS: {agent.os}")
    lines.append(f"Last seen IP: {agent.ip}")
    lines.append("")

    if matched_rules:
        lines.append("TRIGGERED RULES:")
        for r in matched_rules:
            lines.append(f"  [{r['severity']}] {r['name']}: {r['description']}")

    lines.append("")

    # Flag frequency summary
    flag_counts = Counter(all_flags)
    if flag_counts:
        lines.append("SIGNAL SUMMARY (flags observed in time window):")
        for flag, count in flag_counts.most_common(10):
            lines.append(f"  {flag}: {count}x")

    lines.append("")

    # Off-hours?
    offhours_payloads = [p for p in payloads if p.is_off_hours]
    if offhours_payloads:
        lines.append(f"NOTE: {len(offhours_payloads)} of {len(payloads)} check-ins occurred OUTSIDE work hours.")

    lines.append("")
    lines.append(f"Risk score: {_calculate_incident_score(payloads, matched_rules):.1f}/100")
    lines.append("Analyst action required: Review evidence payloads and investigate user activity.")

    return "\n".join(lines)


# ─────────────────────────────────────────────
# RULE MATCHING
# ─────────────────────────────────────────────
def _evaluate_rules(
    agent_id: str,
    db:       Session,
) -> List[dict]:
    """
    For each built-in rule, check if the agent's recent data matches.
    Returns list of matched rule dicts.
    """
    matched = []

    for rule in BUILTIN_RULES:
        window = rule["time_window_min"]
        payloads = _get_recent_payloads(db, agent_id, window)
        if not payloads:
            continue

        all_flags  = _get_all_flags(payloads)
        max_score  = max(p.agent_risk_score for p in payloads)

        # Score threshold check
        if max_score < rule["score_threshold"]:
            continue

        # Required flags — must all appear at least min_occurrences times
        required_ok = all(
            _flag_count(all_flags, f) >= rule["min_occurrences"]
            for f in rule["required_flags"]
        )
        if not required_ok:
            continue

        # Also-any flags — at least one must be present (if list is non-empty)
        also_any = rule.get("also_any_flags", [])
        if also_any and not _any_flag_present(all_flags, also_any):
            continue

        matched.append(rule)

    return matched


# ─────────────────────────────────────────────
# HOURLY RISK SCORE ROLLUP
# ─────────────────────────────────────────────
def _update_risk_score_rollup(agent: Agent, payloads: List[Payload], db: Session):
    """Store hourly aggregated risk scores for trend analysis."""
    if not payloads:
        return

    hour_bucket = datetime.utcnow().replace(minute=0, second=0, microsecond=0)

    existing = (
        db.query(RiskScore)
        .filter(RiskScore.agent_id == agent.agent_id, RiskScore.hour_bucket == hour_bucket)
        .first()
    )

    scores = [p.agent_risk_score for p in payloads]
    all_flags = _get_all_flags(payloads)
    top_flags = [f for f, _ in Counter(all_flags).most_common(5)]

    if existing:
        existing.max_score     = max(existing.max_score, max(scores))
        existing.avg_score     = sum(scores) / len(scores)
        existing.payload_count = len(payloads)
        existing.top_flags     = top_flags
    else:
        db.add(RiskScore(
            agent_id      = agent.agent_id,
            hour_bucket   = hour_bucket,
            max_score     = max(scores),
            avg_score     = sum(scores) / len(scores),
            payload_count = len(payloads),
            top_flags     = top_flags,
        ))


# ─────────────────────────────────────────────
# MAIN CORRELATOR — called every N seconds
# ─────────────────────────────────────────────
def run_correlation(db: Session) -> int:
    """
    Main correlation loop. Called by background scheduler.
    Returns number of incidents created or updated.
    """
    log.info("Correlation run started.")
    incident_count = 0

    # Load watchlist for fast lookup
    watchlist = {
        w.username: w.score_boost
        for w in db.query(Watchlist).filter(Watchlist.is_active == True).all()
    }

    # Process each active agent
    agents = db.query(Agent).filter(Agent.is_active == True).all()

    for agent in agents:
        try:
            matched_rules = _evaluate_rules(agent.agent_id, db)

            # Update risk score rollup (always, even if no rules matched)
            recent_payloads = _get_recent_payloads(db, agent.agent_id, 60)
            _update_risk_score_rollup(agent, recent_payloads, db)

            if not matched_rules:
                # No rules matched — apply decay to any open incidents
                open_incidents = (
                    db.query(Incident)
                    .filter(
                        Incident.agent_id == agent.agent_id,
                        Incident.status.in_(["OPEN", "INVESTIGATING"]),
                    )
                    .all()
                )
                for inc in open_incidents:
                    new_score = _apply_decay(inc)
                    if new_score < config.INCIDENT_SCORE_LOW and inc.status == "OPEN":
                        inc.status = "CLOSED"
                        inc.closed_at = datetime.utcnow()
                        log.info(f"Auto-closed incident #{inc.id} (score decayed to {new_score:.1f})")
                    else:
                        inc.incident_score = new_score
                continue

            # Rules matched — get the widest window for context
            max_window = max(r["time_window_min"] for r in matched_rules)
            context_payloads = _get_recent_payloads(db, agent.agent_id, max_window)
            all_flags = _get_all_flags(context_payloads)

            # Watchlist boost
            wl_boost = watchlist.get(agent.username, 0.0)

            # Calculate incident score
            inc_score = _calculate_incident_score(context_payloads, matched_rules, wl_boost)

            # Determine severity (highest matched rule, or score-based)
            highest_severity = max(
                matched_rules,
                key=lambda r: SEVERITY_RANK.get(r["severity"], 0)
            )["severity"]

            # Override based on score
            if inc_score >= config.INCIDENT_SCORE_CRITICAL:
                highest_severity = "CRITICAL"
            elif inc_score >= config.INCIDENT_SCORE_HIGH:
                highest_severity = max(highest_severity, "HIGH",
                                       key=lambda s: SEVERITY_RANK.get(s, 0))

            rule_ids    = [r["rule_id"] for r in matched_rules]
            evidence    = [p.id for p in context_payloads[-20:]]  # last 20 payload IDs
            narrative   = _build_narrative(agent, context_payloads, matched_rules, all_flags)

            # Check for existing open incident
            existing_incident = (
                db.query(Incident)
                .filter(
                    Incident.agent_id == agent.agent_id,
                    Incident.status.in_(["OPEN", "INVESTIGATING"]),
                )
                .order_by(Incident.opened_at.desc())
                .first()
            )

            if existing_incident:
                # UPDATE existing incident
                existing_incident.incident_score = max(existing_incident.incident_score, inc_score)
                existing_incident.updated_at     = datetime.utcnow()
                existing_incident.narrative      = narrative
                existing_incident.evidence       = list(set(existing_incident.evidence or []) | set(evidence))
                existing_incident.trigger_flags  = list(set(existing_incident.trigger_flags or []) | set(rule_ids))

                # Escalate severity if needed
                old_rank = SEVERITY_RANK.get(existing_incident.severity, 0)
                new_rank = SEVERITY_RANK.get(highest_severity, 0)
                if new_rank > old_rank:
                    log.info(f"Escalating incident #{existing_incident.id}: "
                             f"{existing_incident.severity} → {highest_severity}")
                    existing_incident.severity = highest_severity
                    existing_incident.alert_sent = False  # re-alert on escalation

                incident_count += 1

            else:
                # CREATE new incident
                inc = Incident(
                    agent_id      = agent.agent_id,
                    hostname      = agent.hostname,
                    username      = agent.username,
                    severity      = highest_severity,
                    status        = "OPEN",
                    incident_score= inc_score,
                    narrative     = narrative,
                    trigger_flags = rule_ids,
                    evidence      = evidence,
                    alert_sent    = False,
                )
                db.add(inc)
                log.info(
                    f"NEW incident for {agent.username}@{agent.hostname} "
                    f"[{highest_severity}] score={inc_score:.1f} rules={rule_ids}"
                )
                incident_count += 1

        except Exception as e:
            log.error(f"Correlator error for agent {agent.agent_id}: {e}", exc_info=True)
            continue

    try:
        db.commit()
    except Exception as e:
        log.error(f"Correlator DB commit failed: {e}")
        db.rollback()

    log.info(f"Correlation run complete. Incidents created/updated: {incident_count}")
    return incident_count


# ─────────────────────────────────────────────
# OLD DATA PURGE
# ─────────────────────────────────────────────
def purge_old_payloads(db: Session):
    """Delete payloads older than PAYLOAD_RETENTION_DAYS."""
    cutoff = datetime.utcnow() - timedelta(days=config.PAYLOAD_RETENTION_DAYS)
    deleted = db.query(Payload).filter(Payload.received_at < cutoff).delete()
    db.commit()
    if deleted:
        log.info(f"Purged {deleted} old payloads (older than {config.PAYLOAD_RETENTION_DAYS} days).")
