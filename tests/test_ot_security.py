"""TDD tests for OT security: anomaly detection, protocol analysis, incident response."""
import pytest
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from grid.ot_security import (
    OTAnomalyDetector,
    ProtocolAnalyzer,
    IncidentResponsePlaybook,
    IncidentResponseOrchestrator,
    ModbusFrame,
    DNP3Frame,
    ProtocolAnomaly,
    Incident,
    IncidentSeverity,
    IncidentStatus,
    ResponseAction,
    ProtocolAnomalyType,
)


# ── OT Anomaly Detector tests ──────────────────────────────────────────

class TestOTAnomalyDetector:
    def test_learn_baseline(self):
        detector = OTAnomalyDetector()
        detector.learn_baseline("PLC-001", "temperature", [50.0, 51.0, 49.0, 50.5, 50.2])
        stats = detector.get_baseline_stats("PLC-001", "temperature")
        assert stats is not None
        assert stats["mean"] == pytest.approx(50.14, rel=0.01)
        assert stats["min"] == 49.0
        assert stats["max"] == 51.0

    def test_get_baseline_stats_unknown_returns_none(self):
        detector = OTAnomalyDetector()
        assert detector.get_baseline_stats("UNKNOWN", "temp") is None

    def test_detect_stuck_value(self):
        detector = OTAnomalyDetector()
        for _ in range(3):
            result = detector.detect_stuck_value("PLC-001", "temperature", 50.0)
            assert result is None
        result = detector.detect_stuck_value("PLC-001", "temperature", 50.0)
        assert result is not None
        assert result.anomaly_type == ProtocolAnomalyType.STUCK_VALUE

    def test_no_stuck_value_for_changing_readings(self):
        detector = OTAnomalyDetector()
        values = [50.0, 51.0, 52.0, 53.0, 54.0]
        for v in values:
            result = detector.detect_stuck_value("PLC-001", "temperature", v)
            assert result is None

    def test_detect_out_of_range_high(self):
        detector = OTAnomalyDetector()
        result = detector.detect_out_of_range("PLC-001", "temperature", 95.0, 10.0, 90.0)
        assert result is not None
        assert result.anomaly_type == ProtocolAnomalyType.OUT_OF_RANGE

    def test_detect_out_of_range_low(self):
        detector = OTAnomalyDetector()
        result = detector.detect_out_of_range("PLC-001", "temperature", 5.0, 10.0, 90.0)
        assert result is not None
        assert result.anomaly_type == ProtocolAnomalyType.OUT_OF_RANGE

    def test_no_out_of_range_within_bounds(self):
        detector = OTAnomalyDetector()
        result = detector.detect_out_of_range("PLC-001", "temperature", 50.0, 10.0, 90.0)
        assert result is None

    def test_detect_baseline_deviation(self):
        detector = OTAnomalyDetector()
        detector.learn_baseline("PLC-001", "temperature", [50.0, 51.0, 49.0, 50.5, 50.2])
        result = detector.detect_baseline_deviation("PLC-001", "temperature", 80.0)
        assert result is not None
        assert result.anomaly_type == ProtocolAnomalyType.BASELINE_DEVIATION

    def test_no_baseline_deviation_for_normal_value(self):
        detector = OTAnomalyDetector()
        detector.learn_baseline("PLC-001", "temperature", [50.0, 51.0, 49.0, 50.5, 50.2])
        result = detector.detect_baseline_deviation("PLC-001", "temperature", 50.5)
        assert result is None


# ── Protocol Analyzer tests ────────────────────────────────────────────

class TestProtocolAnalyzer:
    def test_parse_modbus_frame(self):
        analyzer = ProtocolAnalyzer()
        frame_data = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
        frame = analyzer.parse_modbus_frame(frame_data)
        assert frame.transaction_id == 1
        assert frame.protocol_id == 0
        assert frame.unit_id == 1
        assert frame.function_code == 3
        assert frame.data == bytes([0x00, 0x00, 0x00, 0x0A])

    def test_parse_modbus_frame_invalid_length(self):
        analyzer = ProtocolAnalyzer()
        with pytest.raises(ValueError):
            analyzer.parse_modbus_frame(bytes([0x00, 0x01]))

    def test_validate_modbus_frame_valid(self):
        analyzer = ProtocolAnalyzer()
        frame = ModbusFrame(transaction_id=1, protocol_id=0, unit_id=1, function_code=3, data=bytes([0x00, 0x00, 0x00, 0x0A]), raw=b"")
        anomalies = analyzer.validate_modbus_frame(frame)
        assert len(anomalies) == 0

    def test_validate_modbus_frame_invalid_function_code(self):
        analyzer = ProtocolAnalyzer()
        frame = ModbusFrame(transaction_id=1, protocol_id=0, unit_id=1, function_code=99, data=bytes([0x00, 0x00, 0x00, 0x0A]), raw=b"")
        anomalies = analyzer.validate_modbus_frame(frame)
        assert len(anomalies) > 0
        assert anomalies[0].anomaly_type == ProtocolAnomalyType.INVALID_FUNCTION_CODE

    def test_parse_dnp3_frame(self):
        analyzer = ProtocolAnalyzer()
        frame_data = bytes([0x05, 0x64, 0x08, 0xC4, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00])
        frame = analyzer.parse_dnp3_frame(frame_data)
        assert frame.source == 2
        assert frame.destination == 1
        assert frame.control == 0xC4

    def test_detect_unusual_commands(self):
        analyzer = ProtocolAnalyzer()
        history = [3, 4, 3, 4, 3]
        result = analyzer.detect_unusual_commands("PLC-001", 7, history)
        assert result is not None
        assert result.anomaly_type == ProtocolAnomalyType.UNUSUAL_COMMAND

    def test_no_unusual_commands_for_normal(self):
        analyzer = ProtocolAnalyzer()
        history = [3, 4, 3, 4, 3]
        result = analyzer.detect_unusual_commands("PLC-001", 3, history)
        assert result is None


# ── Incident Response tests ────────────────────────────────────────────

class TestIncidentResponse:
    def test_create_incident(self):
        orchestrator = IncidentResponseOrchestrator()
        incident = orchestrator.create_incident(IncidentSeverity.HIGH, "Temperature breach", "PLC-001")
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.description == "Temperature breach"
        assert incident.source == "PLC-001"
        assert incident.status == IncidentStatus.OPEN

    def test_respond_to_incident(self):
        playbook = IncidentResponsePlaybook()
        playbook.add_action(IncidentSeverity.HIGH, ResponseAction.ISOLATE_DEVICE)
        orchestrator = IncidentResponseOrchestrator(playbook)
        incident = orchestrator.create_incident(IncidentSeverity.HIGH, "Temperature breach", "PLC-001")
        actions = orchestrator.respond_to_incident(incident.incident_id)
        assert len(actions) > 0
        assert ResponseAction.ISOLATE_DEVICE in actions

    def test_escalate_incident(self):
        orchestrator = IncidentResponseOrchestrator()
        incident = orchestrator.create_incident(IncidentSeverity.MEDIUM, "Minor issue", "PLC-001")
        orchestrator.escalate_incident(incident.incident_id)
        assert orchestrator.get_incident_status(incident.incident_id) == IncidentStatus.ESCALATED

    def test_resolve_incident(self):
        orchestrator = IncidentResponseOrchestrator()
        incident = orchestrator.create_incident(IncidentSeverity.HIGH, "Issue", "PLC-001")
        orchestrator.resolve_incident(incident.incident_id)
        assert orchestrator.get_incident_status(incident.incident_id) == IncidentStatus.RESOLVED

    def test_get_incident_status_unknown_raises(self):
        orchestrator = IncidentResponseOrchestrator()
        with pytest.raises(ValueError):
            orchestrator.get_incident_status("nonexistent")

    def test_playbook_add_action(self):
        playbook = IncidentResponsePlaybook()
        playbook.add_action(IncidentSeverity.CRITICAL, ResponseAction.BLOCK_IP)
        actions = playbook.get_actions(IncidentSeverity.CRITICAL)
        assert ResponseAction.BLOCK_IP in actions

    def test_playbook_get_actions_empty(self):
        playbook = IncidentResponsePlaybook()
        actions = playbook.get_actions(IncidentSeverity.LOW)
        assert len(actions) == 0
