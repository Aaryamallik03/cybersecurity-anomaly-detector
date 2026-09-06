import json
import sys

from pymongo import MongoClient

import config
from detection import (
    NetworkEvent,
    calculate_ml_score,
    check_failed_login_rule,
    check_high_rate_rule,
    ensure_utc,
    make_decision,
)

client = MongoClient(config.MONGO_URI)
db = client[config.DB_NAME]

events_collection = db["events"]
audit_collection = db["audit_logs"]

with open(config.MODEL_PATH, "r") as file:
    MODEL = json.load(file)


def replay_event(event_id: str):
    raw_event = events_collection.find_one({"event_id": event_id})

    if not raw_event:
        print(f"Event '{event_id}' was not found.")
        return

    # Rebuild a NetworkEvent so replay uses the exact same validated
    # shape and the exact same functions the live API used.
    event = NetworkEvent(
        event_id=raw_event["event_id"],
        source=raw_event["source"],
        timestamp=ensure_utc(raw_event["timestamp"]),
        ip_address=raw_event["ip_address"],
        action=raw_event["action"],
        duration=raw_event.get("duration"),
        confidence_score=raw_event["confidence_score"],
    )

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

    rule_triggered = failed_login_triggered or high_rate_triggered
    ml_score = calculate_ml_score(event, MODEL)
    decision = make_decision(rule_triggered, ml_score, MODEL)

    original_audit = audit_collection.find_one({"event_id": event_id})
    original_decision = original_audit["decision"] if original_audit else None

    print("\n========== REPLAY RESULT ==========")
    print(f"Event ID: {event_id}")
    print(f"Original decision:  {original_decision}")
    print(f"Replayed decision:  {decision}")
    print(f"ML score:           {ml_score}")
    print(f"Failed login count: {failed_login_count}")
    print(f"High-rate count:    {high_rate_count}")
    print(f"Deterministic match: {original_decision == decision}")
    print("===================================\n")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--event-id":
        print("Usage: python replay.py --event-id <event_id>")
        sys.exit(1)

    replay_event(sys.argv[2])
