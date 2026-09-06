"""
Core detection logic: scoring, rules, and the final decision.

This module has NO FastAPI or CLI code in it on purpose. Both main.py
(the API) and replay.py (the offline replay tool) import from here so
that replaying an event can never produce a different answer than the
live system did — they are calling the exact same functions.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from pydantic import BaseModel, Field


# ============================================================
# Event schema
# ============================================================

class NetworkEvent(BaseModel):
    event_id: str
    source: str
    timestamp: datetime
    ip_address: str
    action: str
    duration: Optional[float] = None
    confidence_score: float = Field(ge=0.0, le=1.0)


# ============================================================
# Helpers
# ============================================================

def ensure_utc(dt: datetime) -> datetime:
    """Normalize any datetime (naive or aware) to UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ============================================================
# ML-style scoring
# ============================================================

def calculate_ml_score(event: NetworkEvent, model: dict) -> float:
    """
    Deterministic, hand-tuned scoring function (not a trained model).
    Weights live in model.json so they can be tuned without a code
    change. Kept intentionally simple and explainable.
    """
    score = model["base_score"]

    action_scores = model["action_scores"]
    score += action_scores.get(event.action, model["default_action_score"])

    duration = event.duration or 0.0
    if duration >= model["duration_threshold"]:
        score += model["duration_score"]

    score += event.confidence_score * model["confidence_weight"]

    return round(max(0.0, min(1.0, score)), 4)


# ============================================================
# Rule 1: repeated failed logins
# ============================================================

def check_failed_login_rule(event: NetworkEvent, events_collection, window_minutes: int = 10, threshold: int = 5):
    """
    Flags an IP that has more than `threshold` failed logins within
    `window_minutes` minutes, counting up to and including this event.
    """
    if event.action != "failed_login":
        return False, 0

    event_time = ensure_utc(event.timestamp)
    window_start = event_time - timedelta(minutes=window_minutes)

    count = events_collection.count_documents({
        "ip_address": event.ip_address,
        "action": "failed_login",
        "timestamp": {"$gte": window_start, "$lte": event_time},
    })

    return count > threshold, count


# ============================================================
# Rule 2: high-rate activity from a single IP (brute force / scanning)
# ============================================================

def check_high_rate_rule(event: NetworkEvent, events_collection, window_seconds: int = 60, threshold: int = 20):
    """
    Flags an IP producing an unusually high number of events of any
    kind in a short window — catches brute-force and scanning activity
    that a single-action rule like failed-login misses (e.g. rapid
    'allowed' probes across many endpoints).
    """
    event_time = ensure_utc(event.timestamp)
    window_start = event_time - timedelta(seconds=window_seconds)

    count = events_collection.count_documents({
        "ip_address": event.ip_address,
        "timestamp": {"$gte": window_start, "$lte": event_time},
    })

    return count > threshold, count


# ============================================================
# Combine rule + ML signals into one decision
# ============================================================

def make_decision(rule_triggered: bool, ml_score: float, model: dict) -> str:
    alert_threshold = model["alert_threshold"]
    review_threshold = model["review_threshold"]

    if rule_triggered or ml_score >= alert_threshold:
        return "alert"

    if ml_score >= review_threshold:
        return "pending_review"

    return "no_alert"
