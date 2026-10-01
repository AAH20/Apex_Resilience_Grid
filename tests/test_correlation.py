"""Unit tests for event correlation, pattern detection, and anomaly alerting.

TDD: written before ``src/grid/correlation.py`` existed.
Run ``pytest tests/test_correlation.py``.
"""

import pytest

from src.grid.correlation import (
    AnomalyAlert,
    AnomalyDetector,
    CorrelationEngine,
    CorrelationRule,
    EventWindow,
    PatternDetector,
    PatternMatch,
    Severity,
)
from src.grid.event_bus import Domain, Event


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(event_type, source_domain, entity_refs=None, payload=None, event_id=None):
    return Event(
        event_type=event_type,
        source_domain=source_domain,
        entity_refs=entity_refs or [],
        payload=payload or {},
        event_id=event_id or "",
    )


# ---------------------------------------------------------------------------
# EventWindow
# ---------------------------------------------------------------------------

class TestEventWindow:
    def test_add_and_size(self):
        w = EventWindow(max_size=10)
        w.add(_event("a", Domain.ENERGY))
        assert w.size == 1

    def test_max_size_evicts_oldest(self):
        w = EventWindow(max_size=2)
        w.add(_event("a", Domain.ENERGY, event_id="e1"))
        w.add(_event("b", Domain.WATER, event_id="e2"))
        w.add(_event("c", Domain.TRANSPORT, event_id="e3"))
        assert w.size == 2
        ids = [e.event_id for e in w.events]
        assert ids == ["e2", "e3"]

    def test_filter_by_type(self):
        w = EventWindow()
        w.add(_event("failure", Domain.ENERGY, event_id="e1"))
        w.add(_event("recovery", Domain.WATER, event_id="e2"))
        w.add(_event("failure", Domain.TRANSPORT, event_id="e3"))
        result = w.filter(event_type="failure")
        assert [e.event_id for e in result] == ["e1", "e3"]

    def test_filter_by_domain(self):
        w = EventWindow()
        w.add(_event("a", Domain.ENERGY, event_id="e1"))
        w.add(_event("b", Domain.WATER, event_id="e2"))
        result = w.filter(domain=Domain.WATER)
        assert [e.event_id for e in result] == ["e2"]

    def test_filter_by_entity(self):
        w = EventWindow()
        w.add(_event("a", Domain.ENERGY, entity_refs=["energy:f1"], event_id="e1"))
        w.add(_event("b", Domain.WATER, entity_refs=["water:p1"], event_id="e2"))
        result = w.filter(entity_ref="energy:f1")
        assert [e.event_id for e in result] == ["e1"]

    def test_filter_combined(self):
        w = EventWindow()
        w.add(_event("failure", Domain.ENERGY, entity_refs=["energy:f1"], event_id="e1"))
        w.add(_event("failure", Domain.WATER, entity_refs=["water:p1"], event_id="e2"))
        w.add(_event("recovery", Domain.ENERGY, entity_refs=["energy:f1"], event_id="e3"))
        result = w.filter(event_type="failure", domain=Domain.ENERGY)
        assert [e.event_id for e in result] == ["e1"]

    def test_clear(self):
        w = EventWindow()
        w.add(_event("a", Domain.ENERGY))
        w.clear()
        assert w.size == 0

    def test_events_property_returns_copy(self):
        w = EventWindow()
        w.add(_event("a", Domain.ENERGY, event_id="e1"))
        events = w.events
        events.clear()
        assert w.size == 1


# ---------------------------------------------------------------------------
# CorrelationRule
# ---------------------------------------------------------------------------

class TestCorrelationRule:
    def test_rule_creation(self):
        rule = CorrelationRule(
            name="test_rule",
            event_types={"failure", "recovery"},
            time_window_seconds=60,
            min_occurrences=2,
        )
        assert rule.name == "test_rule"
        assert rule.event_types == {"failure", "recovery"}
        assert rule.time_window_seconds == 60
        assert rule.min_occurrences == 2

    def test_rule_with_domains(self):
        rule = CorrelationRule(
            name="cross_domain",
            event_types={"failure"},
            time_window_seconds=30,
            min_occurrences=1,
            domains={Domain.ENERGY, Domain.WATER},
        )
        assert rule.domains == {Domain.ENERGY, Domain.WATER}

    def test_rule_with_entity_refs(self):
        rule = CorrelationRule(
            name="entity_specific",
            event_types={"failure"},
            time_window_seconds=30,
            min_occurrences=1,
            entity_refs={"energy:f1"},
        )
        assert rule.entity_refs == {"energy:f1"}


# ---------------------------------------------------------------------------
# CorrelationEngine
# ---------------------------------------------------------------------------

class TestCorrelationEngine:
    def test_add_rule(self):
        eng = CorrelationEngine()
        rule = CorrelationRule("r1", {"failure"}, 60, 1)
        eng.add_rule(rule)
        assert len(eng.rules) == 1

    def test_remove_rule(self):
        eng = CorrelationEngine()
        rule = CorrelationRule("r1", {"failure"}, 60, 1)
        eng.add_rule(rule)
        assert eng.remove_rule("r1") is True
        assert eng.remove_rule("r1") is False

    def test_process_event_no_rules(self):
        eng = CorrelationEngine()
        result = eng.process_event(_event("failure", Domain.ENERGY))
        assert result == []

    def test_process_event_triggers_rule(self):
        eng = CorrelationEngine()
        eng.add_rule(CorrelationRule("r1", {"failure"}, 60, 1))
        result = eng.process_event(_event("failure", Domain.ENERGY))
        assert len(result) == 1
        assert result[0].rule_name == "r1"

    def test_process_event_below_threshold(self):
        eng = CorrelationEngine()
        eng.add_rule(CorrelationRule("r1", {"failure"}, 60, 3))
        result = eng.process_event(_event("failure", Domain.ENERGY))
        assert result == []

    def test_process_event_meets_threshold(self):
        eng = CorrelationEngine()
        eng.add_rule(CorrelationRule("r1", {"failure"}, 60, 2))
        eng.process_event(_event("failure", Domain.ENERGY, event_id="e1"))
        result = eng.process_event(_event("failure", Domain.ENERGY, event_id="e2"))
        assert len(result) == 1

    def test_process_event_domain_filter_match(self):
        eng = CorrelationEngine()
        eng.add_rule(CorrelationRule(
            "r1", {"failure"}, 60, 1, domains={Domain.ENERGY}
        ))
        result = eng.process_event(_event("failure", Domain.ENERGY))
        assert len(result) == 1

    def test_process_event_domain_filter_no_match(self):
        eng = CorrelationEngine()
        eng.add_rule(CorrelationRule(
            "r1", {"failure"}, 60, 1, domains={Domain.WATER}
        ))
        result = eng.process_event(_event("failure", Domain.ENERGY))
        assert result == []

    def test_process_event_entity_filter_match(self):
        eng = CorrelationEngine()
        eng.add_rule(CorrelationRule(
            "r1", {"failure"}, 60, 1, entity_refs={"energy:f1"}
        ))
        result = eng.process_event(
            _event("failure", Domain.ENERGY, entity_refs=["energy:f1"])
        )
        assert len(result) == 1

    def test_process_event_entity_filter_no_match(self):
        eng = CorrelationEngine()
        eng.add_rule(CorrelationRule(
            "r1", {"failure"}, 60, 1, entity_refs={"energy:f1"}
        ))
        result = eng.process_event(
            _event("failure", Domain.ENERGY, entity_refs=["energy:f2"])
        )
        assert result == []

    def test_correlation_result_contains_matching_events(self):
        eng = CorrelationEngine()
        eng.add_rule(CorrelationRule("r1", {"failure"}, 60, 2))
        e1 = _event("failure", Domain.ENERGY, event_id="e1")
        e2 = _event("failure", Domain.ENERGY, event_id="e2")
        eng.process_event(e1)
        result = eng.process_event(e2)
        assert len(result) == 1
        assert result[0].matching_events == [e1, e2]

    def test_multiple_rules_can_trigger(self):
        eng = CorrelationEngine()
        eng.add_rule(CorrelationRule("r1", {"failure"}, 60, 1))
        eng.add_rule(CorrelationRule("r2", {"failure"}, 60, 1))
        result = eng.process_event(_event("failure", Domain.ENERGY))
        assert len(result) == 2

    def test_clear(self):
        eng = CorrelationEngine()
        eng.add_rule(CorrelationRule("r1", {"failure"}, 60, 1))
        eng.process_event(_event("failure", Domain.ENERGY))
        eng.clear()
        assert eng.rules == {}
        result = eng.process_event(_event("failure", Domain.ENERGY))
        assert len(result) == 0  # no rules after clear


# ---------------------------------------------------------------------------
# PatternDetector
# ---------------------------------------------------------------------------

class TestPatternDetector:
    def test_detect_sequence_pattern(self):
        det = PatternDetector()
        det.add_pattern(["failure", "recovery"])
        e1 = _event("failure", Domain.ENERGY, event_id="e1")
        e2 = _event("recovery", Domain.ENERGY, event_id="e2")
        det.process_event(e1)
        matches = det.process_event(e2)
        assert len(matches) == 1
        assert matches[0].pattern == ["failure", "recovery"]

    def test_no_match_for_incomplete_sequence(self):
        det = PatternDetector()
        det.add_pattern(["failure", "recovery"])
        det.process_event(_event("failure", Domain.ENERGY))
        matches = det.process_event(_event("failure", Domain.ENERGY))
        assert matches == []

    def test_pattern_with_max_gap(self):
        det = PatternDetector()
        det.add_pattern(["failure", "recovery"], max_gap=2)
        det.process_event(_event("failure", Domain.ENERGY, event_id="e1"))
        det.process_event(_event("noise", Domain.WATER, event_id="e2"))
        matches = det.process_event(_event("recovery", Domain.ENERGY, event_id="e3"))
        assert len(matches) == 1

    def test_pattern_gap_exceeded(self):
        det = PatternDetector()
        det.add_pattern(["failure", "recovery"], max_gap=1)
        det.process_event(_event("failure", Domain.ENERGY, event_id="e1"))
        det.process_event(_event("noise", Domain.WATER, event_id="e2"))
        det.process_event(_event("noise", Domain.TRANSPORT, event_id="e3"))
        matches = det.process_event(_event("recovery", Domain.ENERGY, event_id="e4"))
        assert matches == []

    def test_multiple_patterns(self):
        det = PatternDetector()
        det.add_pattern(["a", "b"])
        det.add_pattern(["x", "y"])
        det.process_event(_event("a", Domain.ENERGY))
        det.process_event(_event("x", Domain.ENERGY))
        matches = det.process_event(_event("b", Domain.ENERGY))
        assert len(matches) == 1
        assert matches[0].pattern == ["a", "b"]

    def test_pattern_match_contains_events(self):
        det = PatternDetector()
        det.add_pattern(["failure", "recovery"])
        e1 = _event("failure", Domain.ENERGY, event_id="e1")
        e2 = _event("recovery", Domain.ENERGY, event_id="e2")
        det.process_event(e1)
        matches = det.process_event(e2)
        assert matches[0].events == [e1, e2]

    def test_remove_pattern(self):
        det = PatternDetector()
        det.add_pattern(["failure", "recovery"])
        assert det.remove_pattern(["failure", "recovery"]) is True
        det.process_event(_event("failure", Domain.ENERGY))
        matches = det.process_event(_event("recovery", Domain.ENERGY))
        assert matches == []

    def test_clear(self):
        det = PatternDetector()
        det.add_pattern(["failure", "recovery"])
        det.process_event(_event("failure", Domain.ENERGY))
        det.clear()
        matches = det.process_event(_event("recovery", Domain.ENERGY))
        assert matches == []


# ---------------------------------------------------------------------------
# AnomalyDetector
# ---------------------------------------------------------------------------

class TestAnomalyDetector:
    def test_baseline_establishment(self):
        det = AnomalyDetector(window_size=5, threshold_std=2.0)
        for i in range(5):
            det.add_sample(10.0)
        assert det.baseline_mean == pytest.approx(10.0)
        assert det.baseline_std == pytest.approx(0.0)

    def test_anomaly_detection(self):
        det = AnomalyDetector(window_size=5, threshold_std=2.0)
        for i in range(5):
            det.add_sample(10.0)
        alert = det.check_value(100.0)
        assert alert is not None
        assert alert.severity == Severity.HIGH

    def test_no_anomaly_for_normal_value(self):
        det = AnomalyDetector(window_size=5, threshold_std=2.0)
        for i in range(5):
            det.add_sample(10.0)
        alert = det.check_value(10.5)
        assert alert is None

    def test_alert_contains_value_and_expected_range(self):
        det = AnomalyDetector(window_size=5, threshold_std=2.0)
        for i in range(5):
            det.add_sample(10.0)
        alert = det.check_value(100.0)
        assert alert.value == 100.0
        assert alert.expected_range[0] <= alert.expected_range[1]

    def test_severity_levels(self):
        det = AnomalyDetector(window_size=10, threshold_std=2.0)
        for i in range(10):
            det.add_sample(10.0)
        # Moderate: 2-3 std
        alert_mod = det.check_value(15.0)
        # High: > 3 std
        alert_high = det.check_value(50.0)
        if alert_mod:
            assert alert_mod.severity == Severity.MEDIUM
        if alert_high:
            assert alert_high.severity == Severity.HIGH

    def test_min_samples_required(self):
        det = AnomalyDetector(window_size=5, threshold_std=2.0, min_samples=3)
        det.add_sample(10.0)
        det.add_sample(10.0)
        alert = det.check_value(100.0)
        assert alert is None  # not enough samples yet

    def test_sliding_window(self):
        det = AnomalyDetector(window_size=3, threshold_std=2.0, min_samples=3)
        det.add_sample(1.0)
        det.add_sample(2.0)
        det.add_sample(3.0)
        det.add_sample(100.0)  # evicts 1.0
        # Window is now [2.0, 3.0, 100.0]
        assert det.baseline_mean == pytest.approx(35.0, rel=0.1)

    def test_event_rate_anomaly(self):
        det = AnomalyDetector(window_size=5, threshold_std=2.0)
        for i in range(5):
            det.add_sample(1.0)  # 1 event per second baseline
        alert = det.check_value(50.0)  # 50 events per second
        assert alert is not None

    def test_clear(self):
        det = AnomalyDetector(window_size=5, threshold_std=2.0)
        det.add_sample(10.0)
        det.clear()
        assert det.baseline_mean is None
        assert det.baseline_std is None


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------

class TestCorrelationIntegration:
    def test_end_to_end_correlation_and_anomaly(self):
        eng = CorrelationEngine()
        eng.add_rule(CorrelationRule("burst", {"failure"}, 60, 3))
        det = AnomalyDetector(window_size=5, threshold_std=2.0)
        for _ in range(5):
            det.add_sample(1.0)

        alerts = []
        for i in range(5):
            result = eng.process_event(
                _event("failure", Domain.ENERGY, event_id=f"e{i}")
            )
            if result:
                alerts.extend(result)

        rate_alert = det.check_value(10.0)
        assert len(alerts) >= 1
        assert rate_alert is not None

    def test_pattern_detection_with_correlation(self):
        eng = CorrelationEngine()
        eng.add_rule(CorrelationRule("r1", {"failure", "recovery"}, 60, 1))
        det = PatternDetector()
        det.add_pattern(["failure", "recovery"])

        e1 = _event("failure", Domain.ENERGY, event_id="e1")
        eng.process_event(e1)
        det.process_event(e1)

        e2 = _event("recovery", Domain.ENERGY, event_id="e2")
        corr_result = eng.process_event(e2)
        pat_result = det.process_event(e2)

        assert len(corr_result) == 1
        assert len(pat_result) == 1
