"""
Tests that exercise the real detection logic, not re-implementations
of it. Mongo calls are mocked so these run fast and don't need a live
database.
"""

import os
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock

# Point the app at a throwaway model/API key before importing it, so
# importing main.py doesn't try to hit a real Mongo instance's config.
os.environ.setdefault("INGEST_API_KEY", "test-key")

from detection import (
    NetworkEvent,
    calculate_ml_score,
    check_failed_login_rule,
    check_high_rate_rule,
    ensure_utc,
    make_decision,
)

TEST_MODEL = {
    "base_score": 0.10,
    "action_scores": {"failed_login": 0.35, "blocked": 0.25, "allowed": 0.00},
    "default_action_score": 0.05,
    "duration_threshold": 10.0,
    "duration_score": 0.10,
    "confidence_weight": 0.30,
    "alert_threshold": 0.60,
    "review_threshold": 0.40,
}


def make_event(**overrides):
    defaults = dict(
        event_id="EVT_001",
        source="firewall",
        timestamp=datetime(2026, 8, 15, 10, 5, tzinfo=timezone.utc),
        ip_address="10.0.0.5",
        action="failed_login",
        duration=None,
        confidence_score=0.5,
    )
    defaults.update(overrides)
    return NetworkEvent(**defaults)


class EnsureUtcTests(unittest.TestCase):

    def test_naive_datetime_gets_utc_attached(self):
        naive = datetime(2026, 1, 1, 12, 0)
        result = ensure_utc(naive)
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_aware_datetime_converted_to_utc(self):
        from datetime import timedelta, timezone as tz
        offset = tz(timedelta(hours=5))
        aware = datetime(2026, 1, 1, 12, 0, tzinfo=offset)
        result = ensure_utc(aware)
        self.assertEqual(result.tzinfo, timezone.utc)
        self.assertEqual(result.hour, 7)  # 12:00+05:00 -> 07:00 UTC


class ScoringTests(unittest.TestCase):

    def test_failed_login_scores_higher_than_allowed(self):
        failed = make_event(action="failed_login", confidence_score=0.5)
        allowed = make_event(action="allowed", confidence_score=0.5)

        self.assertGreater(
            calculate_ml_score(failed, TEST_MODEL),
            calculate_ml_score(allowed, TEST_MODEL),
        )

    def test_score_is_clamped_between_0_and_1(self):
        event = make_event(action="failed_login", confidence_score=1.0, duration=999)
        score = calculate_ml_score(event, TEST_MODEL)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_unknown_action_uses_default_score(self):
        event = make_event(action="something_unseen", confidence_score=0.0)
        score = calculate_ml_score(event, TEST_MODEL)
        expected = round(TEST_MODEL["base_score"] + TEST_MODEL["default_action_score"], 4)
        self.assertEqual(score, expected)

    def test_long_duration_adds_duration_score(self):
        short = make_event(action="allowed", confidence_score=0.0, duration=1.0)
        long = make_event(action="allowed", confidence_score=0.0, duration=15.0)
        self.assertGreater(
            calculate_ml_score(long, TEST_MODEL),
            calculate_ml_score(short, TEST_MODEL),
        )


class FailedLoginRuleTests(unittest.TestCase):

    def test_non_failed_login_action_never_triggers(self):
        event = make_event(action="allowed")
        mock_collection = MagicMock()
        triggered, count = check_failed_login_rule(event, mock_collection)
        self.assertFalse(triggered)
        self.assertEqual(count, 0)
        mock_collection.count_documents.assert_not_called()

    def test_six_failed_logins_triggers_rule(self):
        event = make_event(action="failed_login")
        mock_collection = MagicMock()
        mock_collection.count_documents.return_value = 6
        triggered, count = check_failed_login_rule(event, mock_collection, threshold=5)
        self.assertTrue(triggered)
        self.assertEqual(count, 6)

    def test_five_failed_logins_does_not_trigger(self):
        event = make_event(action="failed_login")
        mock_collection = MagicMock()
        mock_collection.count_documents.return_value = 5
        triggered, count = check_failed_login_rule(event, mock_collection, threshold=5)
        self.assertFalse(triggered)


class HighRateRuleTests(unittest.TestCase):

    def test_high_event_rate_triggers(self):
        event = make_event(action="allowed")
        mock_collection = MagicMock()
        mock_collection.count_documents.return_value = 25
        triggered, count = check_high_rate_rule(event, mock_collection, threshold=20)
        self.assertTrue(triggered)

    def test_normal_event_rate_does_not_trigger(self):
        event = make_event(action="allowed")
        mock_collection = MagicMock()
        mock_collection.count_documents.return_value = 3
        triggered, count = check_high_rate_rule(event, mock_collection, threshold=20)
        self.assertFalse(triggered)


class DecisionTests(unittest.TestCase):

    def test_rule_triggered_forces_alert_even_with_low_score(self):
        decision = make_decision(rule_triggered=True, ml_score=0.0, model=TEST_MODEL)
        self.assertEqual(decision, "alert")

    def test_high_score_alone_triggers_alert(self):
        decision = make_decision(rule_triggered=False, ml_score=0.9, model=TEST_MODEL)
        self.assertEqual(decision, "alert")

    def test_mid_score_triggers_pending_review(self):
        decision = make_decision(rule_triggered=False, ml_score=0.5, model=TEST_MODEL)
        self.assertEqual(decision, "pending_review")

    def test_low_score_and_no_rule_means_no_alert(self):
        decision = make_decision(rule_triggered=False, ml_score=0.1, model=TEST_MODEL)
        self.assertEqual(decision, "no_alert")


if __name__ == "__main__":
    unittest.main()
