from fastapi import FastAPI
from pydantic import BaseModel, Field
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
from typing import Optional
from pathlib import Path
import json


app = FastAPI(title="Cybersecurity Anomaly Detection System")


# ============================================================
# MongoDB
# ============================================================

client = MongoClient("mongodb://localhost:27017/")
db = client["cybersecurity_db"]

events_collection = db["events"]
alerts_collection = db["alerts"]
audit_collection = db["audit_logs"]

# event_id must be unique
events_collection.create_index("event_id", unique=True)


# ============================================================
# Load local pre-trained model
# ============================================================

MODEL_PATH = Path(__file__).parent / "model.json"


def load_model():
    with open(MODEL_PATH, "r") as file:
        return json.load(file)


MODEL = load_model()


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
    confidence_score: float = Field(
        ge=0.0,
        le=1.0
    )


# ============================================================
# Helper: convert datetime to UTC
# ============================================================

def ensure_utc(dt: datetime) -> datetime:

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


# ============================================================
# ML scoring
# ============================================================

def calculate_ml_score(event: NetworkEvent) -> float:

    score = MODEL["base_score"]

    action_scores = MODEL["action_scores"]

    score += action_scores.get(
        event.action,
        MODEL["default_action_score"]
    )

    duration = event.duration or 0.0

    if duration >= MODEL["duration_threshold"]:
        score += MODEL["duration_score"]

    score += (
        event.confidence_score
        * MODEL["confidence_weight"]
    )

    # Keep score between 0 and 1
    score = max(0.0, min(1.0, score))

    return round(score, 4)


# ============================================================
# Rule detection
# ============================================================

def check_failed_login_rule(event: NetworkEvent):

    if event.action != "failed_login":
        return False, 0

    event_time = ensure_utc(event.timestamp)

    ten_minutes_ago = event_time - timedelta(
        minutes=10
    )

    count = events_collection.count_documents({
        "ip_address": event.ip_address,
        "action": "failed_login",
        "timestamp": {
            "$gte": ten_minutes_ago,
            "$lte": event_time
        }
    })

    triggered = count > 5

    return triggered, count


# ============================================================
# Combine rule + ML signals
# ============================================================

def make_decision(rule_triggered: bool, ml_score: float):

    alert_threshold = MODEL["alert_threshold"]
    review_threshold = MODEL["review_threshold"]

    if rule_triggered and ml_score >= alert_threshold:
        return "alert"

    if rule_triggered or ml_score >= alert_threshold:
        return "alert"

    if ml_score >= review_threshold:
        return "pending_review"

    return "no_alert"


# ============================================================
# Home
# ============================================================

@app.get("/")
def home():

    return {
        "message": "Cybersecurity Anomaly Detection System"
    }


# ============================================================
# Event ingestion
# ============================================================

@app.post("/ingest")
def ingest_event(event: NetworkEvent):

    event.timestamp = ensure_utc(event.timestamp)

    # --------------------------------------------------------
    # Duplicate event protection
    # --------------------------------------------------------

    existing_event = events_collection.find_one({
        "event_id": event.event_id
    })

    if existing_event:

        existing_audit = audit_collection.find_one({
            "event_id": event.event_id
        })

        return {
            "status": "duplicate",
            "message": "Event already exists",
            "event_id": event.event_id,
            "decision": (
                existing_audit["decision"]
                if existing_audit
                else "already_processed"
            )
        }

    # --------------------------------------------------------
    # Store normalized event
    # --------------------------------------------------------

    event_data = event.model_dump()

    event_data["timestamp"] = event.timestamp
    event_data["received_at"] = datetime.now(
        timezone.utc
    )

    events_collection.insert_one(event_data)

    # --------------------------------------------------------
    # State before decision
    # --------------------------------------------------------

    active_alerts_before = alerts_collection.count_documents({
        "status": "active"
    })

    # --------------------------------------------------------
    # Rule detection
    # --------------------------------------------------------

    rule_triggered, failed_login_count = (
        check_failed_login_rule(event)
    )

    rules_triggered = []

    if rule_triggered:

        rules_triggered.append(
            "more_than_5_failed_logins_in_10_minutes"
        )

    # --------------------------------------------------------
    # ML detection
    # --------------------------------------------------------

    ml_score = calculate_ml_score(event)

    # --------------------------------------------------------
    # Final decision
    # --------------------------------------------------------

    decision = make_decision(
        rule_triggered,
        ml_score
    )

    # --------------------------------------------------------
    # State after decision
    # --------------------------------------------------------

    alert_id = None

    if decision == "alert":

        # Prevent duplicate active alerts for the same
        # event and anomaly type.
        existing_alert = alerts_collection.find_one({
            "event_id": event.event_id,
            "alert_type": "cybersecurity_anomaly"
        })

        if not existing_alert:

            alert_document = {
                "event_id": event.event_id,
                "ip_address": event.ip_address,
                "alert_type": "cybersecurity_anomaly",
                "status": "active",
                "decision": decision,
                "rule_count": failed_login_count,
                "ml_score": ml_score,
                "created_at": datetime.now(
                    timezone.utc
                )
            }

            result = alerts_collection.insert_one(
                alert_document
            )

            alert_id = str(result.inserted_id)

    active_alerts_after = alerts_collection.count_documents({
        "status": "active"
    })

    # --------------------------------------------------------
    # Audit reason
    # --------------------------------------------------------

    reason = {
        "rules_triggered": rules_triggered,
        "failed_login_count": failed_login_count,
        "ml_score": ml_score,
        "decision": decision
    }

    # --------------------------------------------------------
    # Audit trail
    # --------------------------------------------------------

    audit_document = {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "decision": decision,
        "reason": reason,
        "state_before": {
            "active_alerts": active_alerts_before
        },
        "state_after": {
            "active_alerts": active_alerts_after
        },
        "alert_id": alert_id,
        "created_at": datetime.now(
            timezone.utc
        )
    }

    audit_collection.insert_one(
        audit_document
    )

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return {
        "status": "success",
        "message": "Event ingested successfully",
        "event_id": event.event_id,
        "decision": decision,
        "ml_score": ml_score,
        "rule_triggered": rule_triggered,
        "failed_login_count": failed_login_count
    }


# ============================================================
# Get alerts
# ============================================================

@app.get("/alerts")
def get_alerts():

    alerts = list(
        alerts_collection.find(
            {},
            {"_id": 0}
        )
    )

    return {
        "status": "success",
        "count": len(alerts),
        "alerts": alerts
    }


# ============================================================
# Get audit trail
# ============================================================

@app.get("/audit")
def get_audit():

    audits = list(
        audit_collection.find(
            {},
            {"_id": 0}
        ).sort("timestamp", 1)
    )

    return {
        "status": "success",
        "count": len(audits),
        "audit_logs": audits
    }


# ============================================================
# Get audit record for a specific event
# ============================================================

@app.get("/audit/{event_id}")
def get_event_audit(event_id: str):

    audit = audit_collection.find_one(
        {"event_id": event_id},
        {"_id": 0}
    )

    if not audit:

        return {
            "status": "not_found",
            "event_id": event_id
        }

    return {
        "status": "success",
        "audit": audit
    }