import sys
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
import json
from pathlib import Path


# ------------------------------------------------------------
# MongoDB connection
# ------------------------------------------------------------

client = MongoClient("mongodb://localhost:27017/")
db = client["cybersecurity_db"]

events_collection = db["events"]
audit_collection = db["audit_logs"]


# ------------------------------------------------------------
# Load local model
# ------------------------------------------------------------

MODEL_PATH = Path(__file__).parent / "model.json"

with open(MODEL_PATH, "r") as file:
    MODEL = json.load(file)


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def ensure_utc(dt):

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def calculate_ml_score(event):

    score = MODEL["base_score"]

    score += MODEL["action_scores"].get(
        event["action"],
        MODEL["default_action_score"]
    )

    duration = event.get("duration") or 0.0

    if duration >= MODEL["duration_threshold"]:
        score += MODEL["duration_score"]

    score += (
        event["confidence_score"]
        * MODEL["confidence_weight"]
    )

    return round(
        max(0.0, min(1.0, score)),
        4
    )


# ------------------------------------------------------------
# Replay
# ------------------------------------------------------------

def replay_event(event_id):

    event = events_collection.find_one({
        "event_id": event_id
    })

    if not event:

        print(
            f"Event '{event_id}' was not found."
        )

        return

    event_time = ensure_utc(
        event["timestamp"]
    )

    ten_minutes_ago = (
        event_time - timedelta(minutes=10)
    )

    failed_login_count = (
        events_collection.count_documents({
            "ip_address": event["ip_address"],
            "action": "failed_login",
            "timestamp": {
                "$gte": ten_minutes_ago,
                "$lte": event_time
            }
        })
    )

    rule_triggered = (
        event["action"] == "failed_login"
        and failed_login_count > 5
    )

    ml_score = calculate_ml_score(event)

    if (
        rule_triggered
        and ml_score >= MODEL["alert_threshold"]
    ):
        decision = "alert"

    elif (
        rule_triggered
        or ml_score >= MODEL["alert_threshold"]
    ):
        decision = "alert"

    elif ml_score >= MODEL["review_threshold"]:
        decision = "pending_review"

    else:
        decision = "no_alert"

    original_audit = audit_collection.find_one({
        "event_id": event_id
    })

    original_decision = (
        original_audit["decision"]
        if original_audit
        else None
    )

    print("\n========== REPLAY RESULT ==========")

    print(f"Event ID: {event_id}")
    print(f"Original decision: {original_decision}")
    print(f"Replayed decision: {decision}")
    print(f"ML score: {ml_score}")
    print(
        f"Failed login count: "
        f"{failed_login_count}"
    )

    print(
        f"Deterministic match: "
        f"{original_decision == decision}"
    )

    print("===================================\n")


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

if len(sys.argv) != 3 or sys.argv[1] != "--event-id":

    print(
        "Usage: python replay.py "
        "--event-id <event_id>"
    )

    sys.exit(1)


event_id = sys.argv[2]

replay_event(event_id)