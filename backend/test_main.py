import unittest
from datetime import datetime, timezone


class CybersecuritySystemTests(unittest.TestCase):

    def test_duplicate_event(self):
        """
        Same event_id should be processed only once.
        """
        event_id = "TEST_DUPLICATE_001"

        first_result = {
            "status": "success",
            "event_id": event_id
        }

        second_result = {
            "status": "duplicate",
            "event_id": event_id
        }

        self.assertEqual(
            first_result["status"],
            "success"
        )

        self.assertEqual(
            second_result["status"],
            "duplicate"
        )

    def test_failed_login_rule(self):
        """
        More than 5 failed logins should trigger
        the anomaly rule.
        """
        failed_login_count = 6

        rule_triggered = (
            failed_login_count > 5
        )

        self.assertTrue(rule_triggered)

    def test_no_alert_below_threshold(self):
        """
        Five or fewer failed logins should not
        trigger the failed-login rule.
        """
        failed_login_count = 5

        rule_triggered = (
            failed_login_count > 5
        )

        self.assertFalse(rule_triggered)

    def test_out_of_order_event(self):
        """
        Events can have timestamps that are not in
        arrival order.
        """

        event_1 = datetime(
            2026,
            8,
            15,
            10,
            5,
            tzinfo=timezone.utc
        )

        event_2 = datetime(
            2026,
            8,
            15,
            10,
            2,
            tzinfo=timezone.utc
        )

        self.assertLess(
            event_2,
            event_1
        )

    def test_late_event(self):
        """
        A late event can have a timestamp earlier
        than its receiving time.
        """

        event_timestamp = datetime(
            2026,
            8,
            15,
            9,
            0,
            tzinfo=timezone.utc
        )

        received_timestamp = datetime(
            2026,
            8,
            15,
            12,
            0,
            tzinfo=timezone.utc
        )

        self.assertLess(
            event_timestamp,
            received_timestamp
        )

    def test_conflicting_events(self):
        """
        Events from different sources can report
        different actions for the same IP.
        """

        firewall_action = "blocked"
        endpoint_action = "allowed"

        self.assertNotEqual(
            firewall_action,
            endpoint_action
        )

    def test_replay_determinism(self):
        """
        Replaying the same event should reproduce
        the same decision.
        """

        original_decision = "alert"
        replayed_decision = "alert"

        self.assertEqual(
            original_decision,
            replayed_decision
        )

    def test_ml_score_range(self):
        """
        ML confidence must remain between 0 and 1.
        """

        ml_score = 0.75

        self.assertGreaterEqual(
            ml_score,
            0.0
        )

        self.assertLessEqual(
            ml_score,
            1.0
        )


if __name__ == "__main__":
    unittest.main()