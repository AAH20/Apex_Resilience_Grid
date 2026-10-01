"""TDD tests for predictive maintenance, anomaly detection, and auto-remediation."""
import time
import pytest
from src.grid.predictive import (
    HealthMetricTracker,
    AnomalyDetector,
    RemediationAction,
    AutoRemediator,
    PredictiveMaintenanceEngine,
)


# ── HealthMetricTracker tests ──────────────────────────────────────────

class TestHealthMetricTracker:
    def test_records_metric_values(self):
        tracker = HealthMetricTracker("GEN-1")
        tracker.record(95.0)
        tracker.record(90.0)
        assert len(tracker.get_history()) == 2

    def test_maintains_max_history(self):
        tracker = HealthMetricTracker("GEN-1", max_history=3)
        for i in range(5):
            tracker.record(float(i))
        history = tracker.get_history()
        assert len(history) == 3
        assert history == [2.0, 3.0, 4.0]

    def test_get_trend_positive_slope(self):
        tracker = HealthMetricTracker("GEN-1")
        for i in range(10):
            tracker.record(float(i))
        trend = tracker.get_trend()
        assert trend > 0

    def test_get_trend_negative_slope(self):
        tracker = HealthMetricTracker("GEN-1")
        for i in range(10):
            tracker.record(float(10 - i))
        trend = tracker.get_trend()
        assert trend < 0

    def test_get_trend_flat(self):
        tracker = HealthMetricTracker("GEN-1")
        for _ in range(5):
            tracker.record(50.0)
        trend = tracker.get_trend()
        assert abs(trend) < 0.001

    def test_predict_time_to_failure(self):
        tracker = HealthMetricTracker("GEN-1")
        # Health declining from 100 at rate of -2 per reading
        for i in range(10):
            tracker.record(100.0 - 2.0 * i)
        ttf = tracker.predict_time_to_failure(failure_threshold=50.0)
        assert ttf is not None
        assert ttf > 0

    def test_predict_time_to_failure_already_below(self):
        tracker = HealthMetricTracker("GEN-1")
        tracker.record(30.0)
        ttf = tracker.predict_time_to_failure(failure_threshold=50.0)
        assert ttf == 0.0

    def test_predict_time_to_failure_improving(self):
        tracker = HealthMetricTracker("GEN-1")
        # Health improving - no failure predicted
        for i in range(10):
            tracker.record(50.0 + 2.0 * i)
        ttf = tracker.predict_time_to_failure(failure_threshold=30.0)
        assert ttf is None

    def test_empty_history_trend_is_zero(self):
        tracker = HealthMetricTracker("GEN-1")
        assert tracker.get_trend() == 0.0


# ── AnomalyDetector tests ──────────────────────────────────────────────

class TestAnomalyDetector:
    def test_detects_zscore_anomaly(self):
        detector = AnomalyDetector(method="zscore", threshold=2.0)
        for i in range(20):
            detector.add_reading(100.0)
        assert detector.is_anomaly(200.0) is True

    def test_no_anomaly_for_normal_values(self):
        detector = AnomalyDetector(method="zscore", threshold=3.0)
        for i in range(20):
            detector.add_reading(100.0)
        assert detector.is_anomaly(101.0) is False

    def test_iqr_method_detects_anomaly(self):
        detector = AnomalyDetector(method="iqr", threshold=1.5)
        for i in range(20):
            detector.add_reading(100.0)
        assert detector.is_anomaly(200.0) is True

    def test_get_stats_returns_correct_values(self):
        detector = AnomalyDetector(method="zscore")
        for val in [10.0, 20.0, 30.0, 40.0, 50.0]:
            detector.add_reading(val)
        stats = detector.get_stats()
        assert stats["count"] == 5
        assert stats["mean"] == 30.0
        assert stats["min"] == 10.0
        assert stats["max"] == 50.0

    def test_empty_detector_no_anomaly(self):
        detector = AnomalyDetector()
        assert detector.is_anomaly(999.0) is False

    def test_threshold_affects_detection(self):
        detector = AnomalyDetector(method="zscore", threshold=1.0)
        for i in range(20):
            detector.add_reading(100.0)
        # With low threshold, moderate deviation is anomaly
        assert detector.is_anomaly(110.0) is True

    def test_zscore_calculation(self):
        detector = AnomalyDetector(method="zscore", threshold=2.0)
        for val in [0.0, 0.0, 0.0, 0.0, 10.0]:
            detector.add_reading(val)
        # Mean=2, StdDev=4, zscore of 10 = (10-2)/4 = 2.0
        assert detector.is_anomaly(10.0) is True


# ── RemediationAction tests ────────────────────────────────────────────

class TestRemediationAction:
    def test_execute_calls_action(self):
        called = []
        action = RemediationAction("restart", lambda: called.append(True))
        action.execute()
        assert called == [True]

    def test_can_execute_no_cooldown(self):
        action = RemediationAction("restart", lambda: None, cooldown=0.0)
        action.execute()
        assert action.can_execute() is True

    def test_can_execute_respects_cooldown(self):
        action = RemediationAction("restart", lambda: None, cooldown=10.0)
        action.execute()
        assert action.can_execute() is False

    def test_cooldown_expires(self):
        action = RemediationAction("restart", lambda: None, cooldown=0.01)
        action.execute()
        time.sleep(0.02)
        assert action.can_execute() is True

    def test_execution_count_tracked(self):
        action = RemediationAction("restart", lambda: None)
        action.execute()
        action.execute()
        assert action.execution_count == 2


# ── AutoRemediator tests ──────────────────────────────────────────────

class TestAutoRemediator:
    def test_registers_action(self):
        rem = AutoRemediator()
        action = RemediationAction("restart", lambda: None)
        rem.register_action(action)
        assert len(rem._actions) == 1

    def test_executes_action_on_anomaly(self):
        rem = AutoRemediator()
        executed = []
        action = RemediationAction("restart", lambda: executed.append(True))
        rem.register_action(action)
        rem.on_anomaly("GEN-1", anomaly_score=5.0)
        assert executed == [True]

    def test_respects_cooldown(self):
        rem = AutoRemediator()
        executed = []
        action = RemediationAction("restart", lambda: executed.append(True), cooldown=10.0)
        rem.register_action(action)
        rem.on_anomaly("GEN-1", anomaly_score=5.0)
        rem.on_anomaly("GEN-1", anomaly_score=5.0)
        assert len(executed) == 1

    def test_action_history_tracked(self):
        rem = AutoRemediator()
        action = RemediationAction("restart", lambda: None)
        rem.register_action(action)
        rem.on_anomaly("GEN-1", anomaly_score=5.0)
        history = rem.get_action_history()
        assert len(history) == 1
        assert history[0]["component_id"] == "GEN-1"

    def test_multiple_actions_executed(self):
        rem = AutoRemediator()
        executed = []
        rem.register_action(RemediationAction("restart", lambda: executed.append("restart")))
        rem.register_action(RemediationAction("scale", lambda: executed.append("scale")))
        rem.on_anomaly("GEN-1", anomaly_score=5.0)
        assert "restart" in executed
        assert "scale" in executed

    def test_no_actions_registered(self):
        rem = AutoRemediator()
        # Should not raise
        rem.on_anomaly("GEN-1", anomaly_score=5.0)
        assert rem.get_action_history() == []

    def test_history_includes_anomaly_score(self):
        rem = AutoRemediator()
        rem.register_action(RemediationAction("restart", lambda: None))
        rem.on_anomaly("GEN-1", anomaly_score=7.5)
        history = rem.get_action_history()
        assert history[0]["anomaly_score"] == 7.5


# ── PredictiveMaintenanceEngine tests ─────────────────────────────────

class TestPredictiveMaintenanceEngine:
    def test_register_component(self):
        engine = PredictiveMaintenanceEngine()
        engine.register_component("GEN-1")
        assert "GEN-1" in engine._trackers

    def test_record_metric_triggers_anomaly_detection(self):
        engine = PredictiveMaintenanceEngine()
        engine.register_component("GEN-1")
        # Establish baseline
        for _ in range(20):
            engine.record_metric("GEN-1", 100.0)
        # Anomalous reading
        engine.record_metric("GEN-1", 200.0)
        anomalies = engine.check_anomalies("GEN-1")
        assert len(anomalies) > 0

    def test_get_maintenance_schedule(self):
        engine = PredictiveMaintenanceEngine()
        engine.register_component("GEN-1")
        # Declining health trend
        for i in range(10):
            engine.record_metric("GEN-1", 100.0 - 3.0 * i)
        schedule = engine.get_maintenance_schedule()
        assert len(schedule) > 0
        assert schedule[0]["component_id"] == "GEN-1"

    def test_run_cycle_detects_issues(self):
        engine = PredictiveMaintenanceEngine()
        engine.register_component("GEN-1")
        for i in range(10):
            engine.record_metric("GEN-1", 100.0 - 5.0 * i)
        issues = engine.run_cycle()
        assert isinstance(issues, list)

    def test_engine_integrates_all_components(self):
        engine = PredictiveMaintenanceEngine()
        engine.register_component("GEN-1")
        engine.record_metric("GEN-1", 95.0)
        assert "GEN-1" in engine._trackers
        assert "GEN-1" in engine._detectors

    def test_unknown_component_raises(self):
        engine = PredictiveMaintenanceEngine()
        with pytest.raises(KeyError):
            engine.record_metric("UNKNOWN", 100.0)

    def test_maintenance_priority_ordering(self):
        engine = PredictiveMaintenanceEngine()
        engine.register_component("GEN-1")
        engine.register_component("GEN-2")
        # GEN-1 declining faster
        for i in range(10):
            engine.record_metric("GEN-1", 100.0 - 5.0 * i)
            engine.record_metric("GEN-2", 100.0 - 1.0 * i)
        schedule = engine.get_maintenance_schedule()
        assert len(schedule) == 2
        # GEN-1 should be higher priority (lower time-to-failure)
        assert schedule[0]["component_id"] == "GEN-1"

    def test_healthy_component_not_in_schedule(self):
        engine = PredictiveMaintenanceEngine()
        engine.register_component("GEN-1")
        # Stable healthy readings
        for _ in range(10):
            engine.record_metric("GEN-1", 95.0)
        schedule = engine.get_maintenance_schedule()
        assert len(schedule) == 0

    def test_anomaly_callback_invoked(self):
        engine = PredictiveMaintenanceEngine()
        anomalies_detected = []
        engine.register_component("GEN-1", on_anomaly=lambda cid, score: anomalies_detected.append((cid, score)))
        for _ in range(20):
            engine.record_metric("GEN-1", 100.0)
        engine.record_metric("GEN-1", 200.0)
        assert len(anomalies_detected) > 0
        assert anomalies_detected[0][0] == "GEN-1"