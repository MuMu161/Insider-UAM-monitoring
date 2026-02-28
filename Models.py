"""
models.py — Database models for UAM IDS Server
Uses SQLAlchemy ORM with PostgreSQL (or SQLite for dev)
"""

from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean,
    DateTime, Text, JSON, ForeignKey, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()


# ─────────────────────────────────────────────
# AGENTS — one row per monitored endpoint
# ─────────────────────────────────────────────
class Agent(Base):
    __tablename__ = "agents"

    id             = Column(Integer, primary_key=True)
    agent_id       = Column(String(64), unique=True, nullable=False, index=True)
    hostname       = Column(String(255))
    username       = Column(String(255))
    os             = Column(String(64))
    os_version     = Column(String(255))
    ip             = Column(String(64))
    first_seen     = Column(DateTime, default=datetime.utcnow)
    last_seen      = Column(DateTime, default=datetime.utcnow)
    is_active      = Column(Boolean, default=True)
    total_payloads = Column(Integer, default=0)
    notes          = Column(Text, default="")           # analyst notes

    payloads   = relationship("Payload",   back_populates="agent", lazy="dynamic")
    incidents  = relationship("Incident",  back_populates="agent", lazy="dynamic")
    risk_scores = relationship("RiskScore", back_populates="agent", lazy="dynamic")

    def __repr__(self):
        return f"<Agent {self.hostname} ({self.username})>"


# ─────────────────────────────────────────────
# PAYLOADS — raw data from every agent check-in
# ─────────────────────────────────────────────
class Payload(Base):
    __tablename__ = "payloads"

    id              = Column(Integer, primary_key=True)
    agent_id        = Column(String(64), ForeignKey("agents.agent_id"), nullable=False)
    received_at     = Column(DateTime, default=datetime.utcnow, index=True)
    agent_timestamp = Column(DateTime)
    schema_version  = Column(String(16))
    rule_score      = Column(Float, default=0.0)
    deviation_score = Column(Float, default=0.0)
    agent_risk_score = Column(Float, default=0.0)
    flags           = Column(JSON, default=list)        # list of flag names
    raw             = Column(JSON)                      # full payload JSON
    ip              = Column(String(64))
    is_off_hours    = Column(Boolean, default=False)

    agent = relationship("Agent", back_populates="payloads")

    __table_args__ = (
        Index("ix_payloads_agent_received", "agent_id", "received_at"),
    )

    def __repr__(self):
        return f"<Payload agent={self.agent_id} score={self.agent_risk_score}>"


# ─────────────────────────────────────────────
# RISK SCORES — rolling hourly risk per agent
# Used by correlation engine for trend analysis
# ─────────────────────────────────────────────
class RiskScore(Base):
    __tablename__ = "risk_scores"

    id              = Column(Integer, primary_key=True)
    agent_id        = Column(String(64), ForeignKey("agents.agent_id"), nullable=False)
    hour_bucket     = Column(DateTime, nullable=False)   # truncated to hour
    max_score       = Column(Float, default=0.0)
    avg_score       = Column(Float, default=0.0)
    payload_count   = Column(Integer, default=0)
    top_flags       = Column(JSON, default=list)

    agent = relationship("Agent", back_populates="risk_scores")

    __table_args__ = (
        Index("ix_risk_agent_hour", "agent_id", "hour_bucket"),
    )


# ─────────────────────────────────────────────
# INCIDENTS — correlated alerts raised by server
# ─────────────────────────────────────────────
class Incident(Base):
    __tablename__ = "incidents"

    id              = Column(Integer, primary_key=True)
    agent_id        = Column(String(64), ForeignKey("agents.agent_id"), nullable=False)
    hostname        = Column(String(255))
    username        = Column(String(255))
    opened_at       = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at      = Column(DateTime, default=datetime.utcnow)
    closed_at       = Column(DateTime, nullable=True)

    severity        = Column(String(16), default="MEDIUM")  # LOW / MEDIUM / HIGH / CRITICAL
    status          = Column(String(16), default="OPEN")    # OPEN / INVESTIGATING / CLOSED / FALSE_POSITIVE
    incident_score  = Column(Float, default=0.0)
    narrative       = Column(Text, default="")              # human-readable summary
    trigger_flags   = Column(JSON, default=list)            # flags that triggered this
    evidence        = Column(JSON, default=list)            # list of payload IDs
    analyst_notes   = Column(Text, default="")
    alert_sent      = Column(Boolean, default=False)
    alert_channel   = Column(String(64), default="")        # email / slack / webhook

    agent = relationship("Agent", back_populates="incidents")

    def __repr__(self):
        return f"<Incident #{self.id} {self.severity} {self.status} agent={self.agent_id}>"


# ─────────────────────────────────────────────
# CORRELATION RULES — configurable rule table
# Admins can enable/disable/tune rules via API
# ─────────────────────────────────────────────
class CorrelationRule(Base):
    __tablename__ = "correlation_rules"

    id              = Column(Integer, primary_key=True)
    rule_id         = Column(String(64), unique=True)
    name            = Column(String(255))
    description     = Column(Text)
    enabled         = Column(Boolean, default=True)
    severity        = Column(String(16), default="HIGH")
    time_window_min = Column(Integer, default=60)           # look-back window in minutes
    required_flags  = Column(JSON, default=list)            # flags that must appear
    min_occurrences = Column(Integer, default=1)            # how many times
    score_threshold = Column(Float, default=0.0)            # min agent_risk_score
    created_at      = Column(DateTime, default=datetime.utcnow)


# ─────────────────────────────────────────────
# ALERT LOG — record of every notification sent
# ─────────────────────────────────────────────
class AlertLog(Base):
    __tablename__ = "alert_logs"

    id          = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    sent_at     = Column(DateTime, default=datetime.utcnow)
    channel     = Column(String(64))    # email / slack / webhook
    recipient   = Column(String(255))
    subject     = Column(String(512))
    success     = Column(Boolean, default=True)
    error_msg   = Column(Text, default="")


# ─────────────────────────────────────────────
# WATCHLIST — flag specific users for extra scrutiny
# ─────────────────────────────────────────────
class Watchlist(Base):
    __tablename__ = "watchlist"

    id          = Column(Integer, primary_key=True)
    username    = Column(String(255), unique=True, index=True)
    hostname    = Column(String(255), default="")
    reason      = Column(Text, default="")
    added_at    = Column(DateTime, default=datetime.utcnow)
    added_by    = Column(String(255), default="admin")
    is_active   = Column(Boolean, default=True)
    score_boost = Column(Float, default=20.0)   # add this to their risk score


# ─────────────────────────────────────────────
# DB SETUP HELPERS
# ─────────────────────────────────────────────
def get_engine(db_url: str):
    return create_engine(db_url, pool_pre_ping=True, echo=False)


def get_session_factory(engine):
    return sessionmaker(bind=engine)


def init_db(engine):
    """Create all tables if they don't exist."""
    Base.metadata.create_all(engine)
    print("[DB] Tables created / verified.")M
