import json
import logging
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from pymongo import MongoClient
from pymongo.errors import PyMongoError

import config
from detection import (
    NetworkEvent,
    calculate_ml_score,
    check_failed_login_rule,
    check_high_rate_rule,
    ensure_utc,
    make_decision,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("anomaly_detector")

app = FastAPI(title="Cybersecurity Anomaly Detection System")


# ============================================================
# MongoDB
# ============================================================

client = MongoClient(config.MONGO_URI)
db = client[config.DB_NAME]

events_collection = db["events"]
alerts_collection = db["alerts"]
audit_collection = db["audit_logs"]

events_collection.create_index("event_id", unique=True)
events_collection.create_index([("ip_address", 1), ("action", 1), ("timestamp", 1)])
alerts_collection.create_index("event_id")
audit_collection.create_index("event_id")
audit_collection.create_index("timestamp")


# ============================================================
# Load local scoring model
# ============================================================

def load_model() -> dict:
    with open(config.MODEL_PATH, "r") as file:
        return json.load(file)


MODEL = load_model()


# ============================================================
# Auth
# ============================================================

def require_api_key(x_api_key: str = Header(default="")):
    """
    Minimal shared-secret auth for the ingestion endpoint. Anyone who
    can write to /ingest can write false entries into the audit trail,
    so this endpoint should never be left open.
    """
    if x_api_key != config.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ============================================================
# Error handling
# ============================================================

@app.exception_handler(PyMongoError)
def mongo_error_handler(request, exc):
    logger.exception("Database error")
    return JSONResponse(
        status_code=503,
        content={"status": "error", "message": "Database temporarily unavailable"},
    )


@app.exception_handler(json.JSONDecodeError)
def model_error_handler(request, exc):
    logger.exception("Model file error")
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "Internal configuration error"},
    )


# ============================================================
# Home / health
# ============================================================

@app.get("/")
def home():
    return {"message": "Cybersecurity Anomaly Detection System"}


@app.get("/health")
def health():
    try:
        client.admin.command("ping")
        db_status = "ok"
    except PyMongoError:
        db_status = "unreachable"

    return {
        "status": "ok" if db_status == "ok" else "degraded",
        "database": db_status,
    }


# ============================================================
# Event ingestion
# ============================================================

@app.post("/ingest", dependencies=[Depends(require_api_key)])
def ingest_event(event: NetworkEvent):
    event.timestamp = ensure_utc(event.timestamp)

    # --------------------------------------------------------
    # Duplicate event protection
    # --------------------------------------------------------
    existing_event = events_collection.find_one({"event_id": event.event_id})

    if existing_event:
        existing_audit = audit_collection.find_one({"event_id": event.event_id})
        return {
            "status": "duplicate",
            "message": "Event already exists",
            "event_id": event.event_id,
            "decision": existing_audit["decision"] if existing_audit else "already_processed",
        }

    # --------------------------------------------------------
    # Store normalized event
    # --------------------------------------------------------
    event_data = event.model_dump()
    event_data["timestamp"] = event.timestamp
    event_data["received_at"] = datetime.now(timezone.utc)
    events_collection.insert_one(event_data)

    # --------------------------------------------------------
    # State before decision
    # --------------------------------------------------------
    active_alerts_before = alerts_collection.count_documents({"status": "active"})

    # --------------------------------------------------------
    # Rule detection
    # --------------------------------------------------------
    failed_login_triggered, failed_login_count = check_failed_login_rule(
        event,
        events_collection,
        window_minutes=config.FAILED_LOGIN_WINDOW_MINUTES,
        threshold=config.FAILED_LOGIN_THRESHOLD,
    )

    high_rate_triggered, high_rate_count = check_high_rate_rule(
        event,
        events_collection,
        window_seconds=config.HIGH_RATE_WINDOW_SECONDS,
        threshold=config.HIGH_RATE_THRESHOLD,
    )

    rules_triggered = []
    if failed_login_triggered:
        rules_triggered.append(
            f"more_than_{config.FAILED_LOGIN_THRESHOLD}_failed_logins_in_{config.FAILED_LOGIN_WINDOW_MINUTES}min"
        )
    if high_rate_triggered:
        rules_triggered.append(
            f"more_than_{config.HIGH_RATE_THRESHOLD}_events_in_{config.HIGH_RATE_WINDOW_SECONDS}s"
        )

    rule_triggered = failed_login_triggered or high_rate_triggered

    # --------------------------------------------------------
    # ML-style scoring
    # --------------------------------------------------------
    ml_score = calculate_ml_score(event, MODEL)

    # --------------------------------------------------------
    # Final decision
    # --------------------------------------------------------
    decision = make_decision(rule_triggered, ml_score, MODEL)

    # --------------------------------------------------------
    # Create alert if needed
    # --------------------------------------------------------
    alert_id = None
    if decision == "alert":
        existing_alert = alerts_collection.find_one({
            "event_id": event.event_id,
            "alert_type": "cybersecurity_anomaly",
        })

        if not existing_alert:
            alert_document = {
                "event_id": event.event_id,
                "ip_address": event.ip_address,
                "alert_type": "cybersecurity_anomaly",
                "status": "active",
                "decision": decision,
                "rules_triggered": rules_triggered,
                "failed_login_count": failed_login_count,
                "high_rate_count": high_rate_count,
                "ml_score": ml_score,
                "created_at": datetime.now(timezone.utc),
            }
            result = alerts_collection.insert_one(alert_document)
            alert_id = str(result.inserted_id)

    active_alerts_after = alerts_collection.count_documents({"status": "active"})

    # --------------------------------------------------------
    # Audit trail
    # --------------------------------------------------------
    reason = {
        "rules_triggered": rules_triggered,
        "failed_login_count": failed_login_count,
        "high_rate_count": high_rate_count,
        "ml_score": ml_score,
        "decision": decision,
    }

    audit_document = {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "decision": decision,
        "reason": reason,
        "state_before": {"active_alerts": active_alerts_before},
        "state_after": {"active_alerts": active_alerts_after},
        "alert_id": alert_id,
        "created_at": datetime.now(timezone.utc),
    }

    audit_collection.insert_one(audit_document)

    logger.info(
        "event_id=%s decision=%s ml_score=%s rules=%s",
        event.event_id, decision, ml_score, rules_triggered,
    )

    return {
        "status": "success",
        "message": "Event ingested successfully",
        "event_id": event.event_id,
        "decision": decision,
        "ml_score": ml_score,
        "rules_triggered": rules_triggered,
        "failed_login_count": failed_login_count,
        "high_rate_count": high_rate_count,
    }


# ============================================================
# Get alerts (paginated)
# ============================================================

@app.get("/alerts")
def get_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
):
    total = alerts_collection.count_documents({})
    alerts = list(
        alerts_collection.find({}, {"_id": 0})
        .sort("created_at", -1)
        .skip(skip)
        .limit(limit)
    )

    return {
        "status": "success",
        "total": total,
        "count": len(alerts),
        "skip": skip,
        "limit": limit,
        "alerts": alerts,
    }


# ============================================================
# Get audit trail (paginated)
# ============================================================

@app.get("/audit")
def get_audit(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
):
    total = audit_collection.count_documents({})
    audits = list(
        audit_collection.find({}, {"_id": 0})
        .sort("timestamp", 1)
        .skip(skip)
        .limit(limit)
    )

    return {
        "status": "success",
        "total": total,
        "count": len(audits),
        "skip": skip,
        "limit": limit,
        "audit_logs": audits,
    }


# ============================================================
# Get audit record for a specific event
# ============================================================

@app.get("/audit/{event_id}")
def get_event_audit(event_id: str):
    audit = audit_collection.find_one({"event_id": event_id}, {"_id": 0})

    if not audit:
        raise HTTPException(status_code=404, detail=f"No audit record for event_id '{event_id}'")

    return {"status": "success", "audit": audit}
