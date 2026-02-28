"""
config.py — Central configuration for UAM IDS Server
All settings can be overridden via environment variables.
Copy this file as-is and set environment variables for production.
"""

import os

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────
# PostgreSQL (recommended for production):
#   postgresql://user:password@localhost:5432/uam_ids
# SQLite (for testing/small deployments):
#   sqlite:///uam_ids.db
DB_URL = os.getenv("UAM_DB_URL", "sqlite:///uam_ids.db")

# ─────────────────────────────────────────────
# SERVER
# ─────────────────────────────────────────────
HOST        = os.getenv("UAM_HOST", "0.0.0.0")
PORT        = int(os.getenv("UAM_PORT", "5000"))
DEBUG       = os.getenv("UAM_DEBUG", "false").lower() == "true"

# Secret key for Flask session (change this!)
SECRET_KEY  = os.getenv("UAM_SECRET_KEY", "CHANGE_THIS_SECRET_KEY_IN_PRODUCTION")

# ─────────────────────────────────────────────
# AGENT AUTHENTICATION
# ─────────────────────────────────────────────
# API key agents must send in X-API-KEY header
AGENT_API_KEY   = os.getenv("UAM_AGENT_APIKEY", "CHANGE_THIS_AGENT_API_KEY")

# HMAC secret for payload signature verification (must match agent's AGENT_SECRET)
HMAC_SECRET     = os.getenv("UAM_HMAC_SECRET", "CHANGE_THIS_HMAC_SECRET")

# Set to False during initial rollout to accept all agents even without valid HMAC
VERIFY_HMAC     = os.getenv("UAM_VERIFY_HMAC", "true").lower() == "true"

# ─────────────────────────────────────────────
# ANALYST API AUTHENTICATION
# ─────────────────────────────────────────────
# Simple API key for analyst dashboard / REST API access
ANALYST_API_KEY = os.getenv("UAM_ANALYST_APIKEY", "CHANGE_THIS_ANALYST_KEY")

# ─────────────────────────────────────────────
# RISK SCORING THRESHOLDS
# ─────────────────────────────────────────────
# Incident score needed to trigger alert (0–100)
INCIDENT_SCORE_LOW      = float(os.getenv("UAM_SCORE_LOW",      "30"))
INCIDENT_SCORE_MEDIUM   = float(os.getenv("UAM_SCORE_MEDIUM",   "50"))
INCIDENT_SCORE_HIGH     = float(os.getenv("UAM_SCORE_HIGH",     "70"))
INCIDENT_SCORE_CRITICAL = float(os.getenv("UAM_SCORE_CRITICAL", "85"))

# Incident score decays every 4 hours of clean behaviour
SCORE_DECAY_FACTOR      = float(os.getenv("UAM_DECAY_FACTOR", "0.85"))
SCORE_DECAY_INTERVAL_H  = float(os.getenv("UAM_DECAY_HOURS",  "4"))

# Watchlist users get this bonus added to their score
WATCHLIST_SCORE_BOOST   = float(os.getenv("UAM_WATCHLIST_BOOST", "20"))

# ─────────────────────────────────────────────
# CORRELATION ENGINE
# ─────────────────────────────────────────────
# How often the correlation engine runs (seconds)
CORRELATOR_INTERVAL_SEC = int(os.getenv("UAM_CORRELATOR_INTERVAL", "60"))

# Maximum days to keep raw payloads in DB (older = purged)
PAYLOAD_RETENTION_DAYS  = int(os.getenv("UAM_PAYLOAD_RETENTION", "90"))

# ─────────────────────────────────────────────
# ALERTING — Email
# ─────────────────────────────────────────────
ALERT_EMAIL_ENABLED  = os.getenv("UAM_EMAIL_ENABLED", "false").lower() == "true"
SMTP_HOST            = os.getenv("UAM_SMTP_HOST",     "smtp.gmail.com")
SMTP_PORT            = int(os.getenv("UAM_SMTP_PORT", "587"))
SMTP_USER            = os.getenv("UAM_SMTP_USER",     "")
SMTP_PASS            = os.getenv("UAM_SMTP_PASS",     "")
SMTP_FROM            = os.getenv("UAM_SMTP_FROM",     "uam-ids@company.com")
ALERT_EMAIL_TO       = os.getenv("UAM_ALERT_EMAIL_TO","security@company.com")  # comma-separated

# ─────────────────────────────────────────────
# ALERTING — Slack
# ─────────────────────────────────────────────
ALERT_SLACK_ENABLED  = os.getenv("UAM_SLACK_ENABLED", "false").lower() == "true"
SLACK_WEBHOOK_URL    = os.getenv("UAM_SLACK_WEBHOOK", "")

# ─────────────────────────────────────────────
# ALERTING — Generic Webhook (Teams, SIEM, etc.)
# ─────────────────────────────────────────────
ALERT_WEBHOOK_ENABLED = os.getenv("UAM_WEBHOOK_ENABLED", "false").lower() == "true"
ALERT_WEBHOOK_URL     = os.getenv("UAM_WEBHOOK_URL",     "")

# ─────────────────────────────────────────────
# ALERTING — Minimum severity to trigger alert
# ─────────────────────────────────────────────
# Only incidents at or above this severity will send notifications
# Options: LOW, MEDIUM, HIGH, CRITICAL
ALERT_MIN_SEVERITY = os.getenv("UAM_ALERT_MIN_SEVERITY", "HIGH")

# Cooldown: don't re-alert for same incident within N minutes
ALERT_COOLDOWN_MIN = int(os.getenv("UAM_ALERT_COOLDOWN", "30"))

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────
LOG_LEVEL = os.getenv("UAM_LOG_LEVEL", "INFO")
LOG_FILE  = os.getenv("UAM_LOG_FILE",  "uam_server.log")
