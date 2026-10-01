"""TDD tests for SCADA/ICS integration: monitoring, OT/IT integration, anomaly detection."""
import pytest
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from grid.scada import (
    SCADADevice,
    SCADAReading,
    Alarm,
    AnomalyEvent,
    OTNetworkSegment,
    ITNetworkSegment,
    SCADAMonitor,
    AnomalyDetector,
    OTITGateway,
    SCADASystem,
    DeviceStatus,
    AlarmSeverity,
    AnomalyType,
    ProtocolType,
)


# ── SCADADevice tests ──────────────────────────────────────────────────

class TestSCADADevice:
    def test_device_creation_with_defaults(self):
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-zone-1",
        )
        assert device.device_id == "PLC-001"
        assert device.device_type == "plc"
        assert device.protocol == ProtocolType.MODBUS
        assert device.network_segment == "ot-zone-1"
        assert device.status == DeviceStatus.ONLINE
        assert device.last_seen is None

    def test_device_creation_with_custom_status(self):
        device = SCADADevice(
            device_id="RTU-001",
            device_type="rtu",
            protocol=ProtocolType.DNP3,
            network_segment="ot-zone-2",
            status=DeviceStatus.DEGRADED,
        )
        assert device.status == DeviceStatus.DEGRADED

    def test_device_status_transition(self):
        device = SCADADevice(
            device_id="SENS-001",
            device_type="sensor",
            protocol=ProtocolType.OPC_UA,
            network_segment="ot-zone-1",
        )
        device.status = DeviceStatus.FAULT
        assert device.status == DeviceStatus.FAULT
        device.status = DeviceStatus.ONLINE
        assert device.status == DeviceStatus.ONLINE


# ── SCADAReading tests ─────────────────────────────────────────────────

class TestSCADAReading:
    def test_reading_creation(self):
        reading = SCADAReading(
            device_id="PLC-001",
            tag="temperature",
            value=75.5,
            unit="celsius",
            timestamp=1000.0,
        )
        assert reading.device_id == "PLC-001"
        assert reading.tag == "temperature"
        assert reading.value == 75.5
        assert reading.unit == "celsius"
        assert reading.timestamp == 1000.0
        assert reading.quality == "good"

    def test_reading_quality_bad(self):
        reading = SCADAReading(
            device_id="PLC-001",
            tag="pressure",
            value=0.0,
            unit="bar",
            timestamp=1000.0,
            quality="bad",
        )
        assert reading.quality == "bad"


# ── SCADAMonitor tests ─────────────────────────────────────────────────

class TestSCADAMonitor:
    def test_add_device(self):
        monitor = SCADAMonitor()
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-zone-1",
        )
        monitor.add_device(device)
        assert "PLC-001" in monitor.devices
        assert monitor.devices["PLC-001"].device_type == "plc"

    def test_add_duplicate_device_raises(self):
        monitor = SCADAMonitor()
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-zone-1",
        )
        monitor.add_device(device)
        with pytest.raises(ValueError, match="already exists"):
            monitor.add_device(device)

    def test_set_threshold(self):
        monitor = SCADAMonitor()
        monitor.set_threshold("PLC-001", "temperature", low=10.0, high=90.0)
        assert monitor._thresholds["PLC-001"]["temperature"] == (10.0, 90.0)

    def test_collect_reading_stores_reading(self):
        monitor = SCADAMonitor()
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-zone-1",
        )
        monitor.add_device(device)
        reading = SCADAReading(
            device_id="PLC-001",
            tag="temperature",
            value=50.0,
            unit="celsius",
            timestamp=1000.0,
        )
        monitor.collect_reading(reading)
        assert len(monitor.readings["PLC-001"]) == 1
        assert monitor.readings["PLC-001"][0].value == 50.0

    def test_collect_reading_unknown_device_raises(self):
        monitor = SCADAMonitor()
        reading = SCADAReading(
            device_id="UNKNOWN",
            tag="temperature",
            value=50.0,
            unit="celsius",
            timestamp=1000.0,
        )
        with pytest.raises(ValueError, match="Unknown device"):
            monitor.collect_reading(reading)

    def test_threshold_breach_triggers_alarm(self):
        monitor = SCADAMonitor()
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-zone-1",
        )
        monitor.add_device(device)
        monitor.set_threshold("PLC-001", "temperature", low=10.0, high=90.0)
        reading = SCADAReading(
            device_id="PLC-001",
            tag="temperature",
            value=95.0,
            unit="celsius",
            timestamp=1000.0,
        )
        alarms = monitor.collect_reading(reading)
        assert len(alarms) == 1
        assert alarms[0].severity == AlarmSeverity.HIGH
        assert alarms[0].device_id == "PLC-001"

    def test_no_alarm_within_threshold(self):
        monitor = SCADAMonitor()
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-zone-1",
        )
        monitor.add_device(device)
        monitor.set_threshold("PLC-001", "temperature", low=10.0, high=90.0)
        reading = SCADAReading(
            device_id="PLC-001",
            tag="temperature",
            value=50.0,
            unit="celsius",
            timestamp=1000.0,
        )
        alarms = monitor.collect_reading(reading)
        assert len(alarms) == 0

    def test_critical_alarm_for_extreme_breach(self):
        monitor = SCADAMonitor()
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-zone-1",
        )
        monitor.add_device(device)
        monitor.set_threshold("PLC-001", "temperature", low=10.0, high=90.0)
        reading = SCADAReading(
            device_id="PLC-001",
            tag="temperature",
            value=150.0,
            unit="celsius",
            timestamp=1000.0,
        )
        alarms = monitor.collect_reading(reading)
        assert len(alarms) == 1
        assert alarms[0].severity == AlarmSeverity.CRITICAL

    def test_acknowledge_alarm(self):
        monitor = SCADAMonitor()
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-zone-1",
        )
        monitor.add_device(device)
        monitor.set_threshold("PLC-001", "temperature", low=10.0, high=90.0)
        reading = SCADAReading(
            device_id="PLC-001",
            tag="temperature",
            value=95.0,
            unit="celsius",
            timestamp=1000.0,
        )
        alarms = monitor.collect_reading(reading)
        alarm_id = alarms[0].alarm_id
        monitor.acknowledge_alarm(alarm_id)
        assert monitor.alarms[0].acknowledged is True

    def test_acknowledge_nonexistent_alarm_raises(self):
        monitor = SCADAMonitor()
        with pytest.raises(ValueError, match="Unknown alarm"):
            monitor.acknowledge_alarm("nonexistent")

    def test_get_device_status(self):
        monitor = SCADAMonitor()
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-zone-1",
        )
        monitor.add_device(device)
        assert monitor.get_device_status("PLC-001") == DeviceStatus.ONLINE

    def test_get_device_status_unknown_raises(self):
        monitor = SCADAMonitor()
        with pytest.raises(ValueError, match="Unknown device"):
            monitor.get_device_status("UNKNOWN")


# ── AnomalyDetector tests ──────────────────────────────────────────────

class TestAnomalyDetector:
    def test_detect_threshold_breach_high(self):
        detector = AnomalyDetector()
        result = detector.detect_threshold_breach("PLC-001", "temp", 95.0, 10.0, 90.0)
        assert result is not None
        assert result.anomaly_type == AnomalyType.THRESHOLD_BREACH
        assert result.device_id == "PLC-001"

    def test_detect_threshold_breach_low(self):
        detector = AnomalyDetector()
        result = detector.detect_threshold_breach("PLC-001", "temp", 5.0, 10.0, 90.0)
        assert result is not None
        assert result.anomaly_type == AnomalyType.THRESHOLD_BREACH

    def test_no_threshold_breach_within_range(self):
        detector = AnomalyDetector()
        result = detector.detect_threshold_breach("PLC-001", "temp", 50.0, 10.0, 90.0)
        assert result is None

    def test_detect_rate_of_change_anomaly(self):
        detector = AnomalyDetector(window_size=5)
        # Seed with normal readings
        for i in range(5):
            detector.add_reading(SCADAReading(
                device_id="PLC-001",
                tag="pressure",
                value=50.0 + i * 0.1,
                unit="bar",
                timestamp=float(i),
            ))
        # Sudden spike
        result = detector.add_reading(SCADAReading(
            device_id="PLC-001",
            tag="pressure",
            value=80.0,
            unit="bar",
            timestamp=5.0,
        ))
        assert result is not None
        assert result.anomaly_type == AnomalyType.RATE_OF_CHANGE

    def test_no_rate_of_change_anomaly_for_gradual_change(self):
        detector = AnomalyDetector(window_size=5)
        for i in range(6):
            result = detector.add_reading(SCADAReading(
                device_id="PLC-001",
                tag="pressure",
                value=50.0 + i * 0.5,
                unit="bar",
                timestamp=float(i),
            ))
        assert result is None

    def test_detect_pattern_deviation(self):
        detector = AnomalyDetector(window_size=20)
        # Seed with consistent readings around 50, last one close to test value
        for i in range(19):
            detector.add_reading(SCADAReading(
                device_id="PLC-001",
                tag="flow",
                value=50.0,
                unit="L/min",
                timestamp=float(i),
            ))
        detector.add_reading(SCADAReading(
            device_id="PLC-001",
            tag="flow",
            value=74.0,
            unit="L/min",
            timestamp=19.0,
        ))
        # Deviation from pattern (close to last value, far from mean)
        result = detector.add_reading(SCADAReading(
            device_id="PLC-001",
            tag="flow",
            value=75.0,
            unit="L/min",
            timestamp=20.0,
        ))
        assert result is not None
        assert result.anomaly_type == AnomalyType.PATTERN_DEVIATION

    def test_no_pattern_deviation_for_normal_variation(self):
        detector = AnomalyDetector(window_size=10)
        for i in range(10):
            detector.add_reading(SCADAReading(
                device_id="PLC-001",
                tag="flow",
                value=50.0 + (i % 3) * 0.5,
                unit="L/min",
                timestamp=float(i),
            ))
        result = detector.add_reading(SCADAReading(
            device_id="PLC-001",
            tag="flow",
            value=51.0,
            unit="L/min",
            timestamp=10.0,
        ))
        assert result is None

    def test_communication_loss_detection(self):
        detector = AnomalyDetector()
        # Simulate no readings for a long time
        result = detector.detect_communication_loss("PLC-001", last_seen=time.time() - 300, threshold=60)
        assert result is not None
        assert result.anomaly_type == AnomalyType.COMMUNICATION_LOSS

    def test_no_communication_loss_when_recent(self):
        detector = AnomalyDetector()
        result = detector.detect_communication_loss("PLC-001", last_seen=time.time(), threshold=60)
        assert result is None


# ── OTITGateway tests ──────────────────────────────────────────────────

class TestOTITGateway:
    def test_add_ot_segment(self):
        gateway = OTITGateway()
        segment = OTNetworkSegment(segment_id="ot-1", name="OT Zone 1", zone="Level 1")
        gateway.add_ot_segment(segment)
        assert "ot-1" in gateway.ot_segments

    def test_add_it_segment(self):
        gateway = OTITGateway()
        segment = ITNetworkSegment(segment_id="it-1", name="IT Zone 1", zone="Level 4")
        gateway.add_it_segment(segment)
        assert "it-1" in gateway.it_segments

    def test_data_diode_allows_ot_to_it(self):
        gateway = OTITGateway()
        gateway.enable_data_diode()
        data = {"sensor": "temperature", "value": 75.0}
        result = gateway.transmit_ot_to_it(data)
        assert result["sensor"] == "temperature"
        assert result["value"] == 75.0
        assert result["direction"] == "ot_to_it"

    def test_data_diode_blocks_it_to_ot(self):
        gateway = OTITGateway()
        gateway.enable_data_diode()
        data = {"command": "set_setpoint", "value": 100.0}
        with pytest.raises(PermissionError, match="Data diode"):
            gateway.transmit_it_to_ot(data)

    def test_data_diode_disabled_allows_bidirectional(self):
        gateway = OTITGateway()
        gateway.disable_data_diode()
        data = {"command": "set_setpoint", "value": 100.0}
        result = gateway.transmit_it_to_ot(data)
        assert result["command"] == "set_setpoint"
        assert result["direction"] == "it_to_ot"

    def test_protocol_translation_modbus_to_opcua(self):
        gateway = OTITGateway()
        gateway._protocol_mappings[ProtocolType.MODBUS] = ProtocolType.OPC_UA
        result = gateway.translate_protocol(ProtocolType.MODBUS)
        assert result == ProtocolType.OPC_UA

    def test_protocol_translation_unmapped_returns_original(self):
        gateway = OTITGateway()
        result = gateway.translate_protocol(ProtocolType.DNP3)
        assert result == ProtocolType.DNP3


# ── SCADASystem integration tests ──────────────────────────────────────

class TestSCADASystem:
    def test_register_device(self):
        system = SCADASystem()
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-zone-1",
        )
        system.register_device(device)
        assert "PLC-001" in system.monitor.devices

    def test_process_reading_returns_alarms_and_anomalies(self):
        system = SCADASystem()
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-zone-1",
        )
        system.register_device(device)
        system.monitor.set_threshold("PLC-001", "temperature", low=10.0, high=90.0)
        reading = SCADAReading(
            device_id="PLC-001",
            tag="temperature",
            value=95.0,
            unit="celsius",
            timestamp=1000.0,
        )
        result = system.process_reading(reading)
        assert "alarms" in result
        assert "anomalies" in result
        assert len(result["alarms"]) >= 1

    def test_get_system_health(self):
        system = SCADASystem()
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-zone-1",
        )
        system.register_device(device)
        health = system.get_system_health()
        assert "total_devices" in health
        assert "online_devices" in health
        assert "active_alarms" in health
        assert health["total_devices"] == 1
        assert health["online_devices"] == 1

    def test_get_system_health_with_offline_device(self):
        system = SCADASystem()
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-zone-1",
            status=DeviceStatus.OFFLINE,
        )
        system.register_device(device)
        health = system.get_system_health()
        assert health["online_devices"] == 0
        assert health["total_devices"] == 1

    def test_end_to_end_ot_it_integration(self):
        system = SCADASystem()
        # Set up OT segment
        ot_segment = OTNetworkSegment(segment_id="ot-1", name="OT Zone 1", zone="Level 1")
        system.gateway.add_ot_segment(ot_segment)
        # Set up IT segment
        it_segment = ITNetworkSegment(segment_id="it-1", name="IT Zone 1", zone="Level 4")
        system.gateway.add_it_segment(it_segment)
        # Enable data diode
        system.gateway.enable_data_diode()
        # Register device and process reading
        device = SCADADevice(
            device_id="PLC-001",
            device_type="plc",
            protocol=ProtocolType.MODBUS,
            network_segment="ot-1",
        )
        system.register_device(device)
        reading = SCADAReading(
            device_id="PLC-001",
            tag="temperature",
            value=75.0,
            unit="celsius",
            timestamp=1000.0,
        )
        result = system.process_reading(reading)
        assert "alarms" in result
        # Transmit data OT->IT
        data = {"device": "PLC-001", "tag": "temperature", "value": 75.0}
        transmitted = system.gateway.transmit_ot_to_it(data)
        assert transmitted["direction"] == "ot_to_it"
