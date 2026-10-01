"""SCADA/ICS integration: industrial control system monitoring, OT/IT integration, anomaly detection."""
import time
import uuid
import statistics
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Enums ──────────────────────────────────────────────────────────────

class DeviceStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    FAULT = "fault"


class AlarmSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnomalyType(str, Enum):
    THRESHOLD_BREACH = "threshold_breach"
    RATE_OF_CHANGE = "rate_of_change"
    PATTERN_DEVIATION = "pattern_deviation"
    COMMUNICATION_LOSS = "communication_loss"


class ProtocolType(str, Enum):
    MODBUS = "modbus"
    DNP3 = "dnp3"
    OPC_UA = "opc_ua"
    IEC_60870 = "iec_60870"
    MQTT = "mqtt"


# ── Data classes ───────────────────────────────────────────────────────

@dataclass
class SCADADevice:
    device_id: str
    device_type: str
    protocol: ProtocolType
    network_segment: str
    status: DeviceStatus = DeviceStatus.ONLINE
    last_seen: Optional[float] = None


@dataclass
class SCADAReading:
    device_id: str
    tag: str
    value: float
    unit: str
    timestamp: float
    quality: str = "good"


@dataclass
class Alarm:
    alarm_id: str
    device_id: str
    tag: str
    severity: AlarmSeverity
    message: str
    timestamp: float
    acknowledged: bool = False


@dataclass
class AnomalyEvent:
    anomaly_id: str
    device_id: str
    tag: str
    anomaly_type: AnomalyType
    description: str
    timestamp: float
    value: float = 0.0


@dataclass
class OTNetworkSegment:
    segment_id: str
    name: str
    zone: str


@dataclass
class ITNetworkSegment:
    segment_id: str
    name: str
    zone: str


# ── SCADAMonitor ───────────────────────────────────────────────────────

class SCADAMonitor:
    """Monitors SCADA devices, collects readings, and triggers alarms."""

    def __init__(self):
        self.devices: dict[str, SCADADevice] = {}
        self.readings: dict[str, list[SCADAReading]] = {}
        self.alarms: list[Alarm] = []
        self._thresholds: dict[str, dict[str, tuple[float, float]]] = {}

    def add_device(self, device: SCADADevice) -> None:
        if device.device_id in self.devices:
            raise ValueError(f"Device {device.device_id} already exists")
        self.devices[device.device_id] = device
        self.readings.setdefault(device.device_id, [])

    def set_threshold(self, device_id: str, tag: str, low: float, high: float) -> None:
        self._thresholds.setdefault(device_id, {})[tag] = (low, high)

    def collect_reading(self, reading: SCADAReading) -> list[Alarm]:
        if reading.device_id not in self.devices:
            raise ValueError(f"Unknown device: {reading.device_id}")
        self.readings.setdefault(reading.device_id, []).append(reading)
        self.devices[reading.device_id].last_seen = reading.timestamp
        return self._check_thresholds(reading)

    def _check_thresholds(self, reading: SCADAReading) -> list[Alarm]:
        alarms = []
        device_thresholds = self._thresholds.get(reading.device_id, {})
        if reading.tag not in device_thresholds:
            return alarms
        low, high = device_thresholds[reading.tag]
        if reading.value > high:
            severity = AlarmSeverity.CRITICAL if reading.value > high * 1.5 else AlarmSeverity.HIGH
            alarm = Alarm(
                alarm_id=str(uuid.uuid4()),
                device_id=reading.device_id,
                tag=reading.tag,
                severity=severity,
                message=f"{reading.tag} high: {reading.value} > {high}",
                timestamp=reading.timestamp,
            )
            self.alarms.append(alarm)
            alarms.append(alarm)
        elif reading.value < low:
            severity = AlarmSeverity.CRITICAL if reading.value < low * 0.5 else AlarmSeverity.LOW
            alarm = Alarm(
                alarm_id=str(uuid.uuid4()),
                device_id=reading.device_id,
                tag=reading.tag,
                severity=severity,
                message=f"{reading.tag} low: {reading.value} < {low}",
                timestamp=reading.timestamp,
            )
            self.alarms.append(alarm)
            alarms.append(alarm)
        return alarms

    def acknowledge_alarm(self, alarm_id: str) -> None:
        for alarm in self.alarms:
            if alarm.alarm_id == alarm_id:
                alarm.acknowledged = True
                return
        raise ValueError(f"Unknown alarm: {alarm_id}")

    def get_device_status(self, device_id: str) -> DeviceStatus:
        if device_id not in self.devices:
            raise ValueError(f"Unknown device: {device_id}")
        return self.devices[device_id].status


# ── AnomalyDetector ────────────────────────────────────────────────────

class AnomalyDetector:
    """Detects anomalies in SCADA readings using statistical methods."""

    def __init__(self, window_size: int = 10, rate_threshold: float = 5.0, deviation_factor: float = 3.0):
        self.window_size = window_size
        self.rate_threshold = rate_threshold
        self.deviation_factor = deviation_factor
        self._readings: dict[str, list[SCADAReading]] = {}

    def add_reading(self, reading: SCADAReading) -> Optional[AnomalyEvent]:
        key = f"{reading.device_id}:{reading.tag}"
        self._readings.setdefault(key, []).append(reading)
        # Keep only the last window_size readings
        if len(self._readings[key]) > self.window_size:
            self._readings[key] = self._readings[key][-self.window_size:]
        return self._detect_anomalies(reading, key)

    def _detect_anomalies(self, reading: SCADAReading, key: str) -> Optional[AnomalyEvent]:
        history = self._readings[key]
        if len(history) < 3:
            return None
        # Check rate of change
        prev = history[-2]
        rate = abs(reading.value - prev.value)
        if rate > self.rate_threshold:
            return AnomalyEvent(
                anomaly_id=str(uuid.uuid4()),
                device_id=reading.device_id,
                tag=reading.tag,
                anomaly_type=AnomalyType.RATE_OF_CHANGE,
                description=f"Rate of change {rate:.2f} exceeds threshold {self.rate_threshold}",
                timestamp=reading.timestamp,
                value=reading.value,
            )
        # Check pattern deviation using standard deviation
        values = [r.value for r in history[:-1]]
        mean = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        if std > 0 and abs(reading.value - mean) > self.deviation_factor * std:
            return AnomalyEvent(
                anomaly_id=str(uuid.uuid4()),
                device_id=reading.device_id,
                tag=reading.tag,
                anomaly_type=AnomalyType.PATTERN_DEVIATION,
                description=f"Value {reading.value} deviates from mean {mean:.2f} (std={std:.2f})",
                timestamp=reading.timestamp,
                value=reading.value,
            )
        return None

    def detect_threshold_breach(self, device_id: str, tag: str, value: float, low: float, high: float) -> Optional[AnomalyEvent]:
        if value > high or value < low:
            return AnomalyEvent(
                anomaly_id=str(uuid.uuid4()),
                device_id=device_id,
                tag=tag,
                anomaly_type=AnomalyType.THRESHOLD_BREACH,
                description=f"Value {value} outside [{low}, {high}]",
                timestamp=time.time(),
                value=value,
            )
        return None

    def detect_communication_loss(self, device_id: str, last_seen: float, threshold: float) -> Optional[AnomalyEvent]:
        if time.time() - last_seen > threshold:
            return AnomalyEvent(
                anomaly_id=str(uuid.uuid4()),
                device_id=device_id,
                tag="communication",
                anomaly_type=AnomalyType.COMMUNICATION_LOSS,
                description=f"No communication for {time.time() - last_seen:.0f}s",
                timestamp=time.time(),
            )
        return None


# ── OTITGateway ────────────────────────────────────────────────────────

class OTITGateway:
    """Gateway for secure OT/IT data exchange with protocol translation."""

    def __init__(self):
        self.ot_segments: dict[str, OTNetworkSegment] = {}
        self.it_segments: dict[str, ITNetworkSegment] = {}
        self._data_diode_enabled: bool = False
        self._protocol_mappings: dict[ProtocolType, ProtocolType] = {}

    def add_ot_segment(self, segment: OTNetworkSegment) -> None:
        self.ot_segments[segment.segment_id] = segment

    def add_it_segment(self, segment: ITNetworkSegment) -> None:
        self.it_segments[segment.segment_id] = segment

    def enable_data_diode(self) -> None:
        self._data_diode_enabled = True

    def disable_data_diode(self) -> None:
        self._data_diode_enabled = False

    def transmit_ot_to_it(self, data: dict) -> dict:
        result = dict(data)
        result["direction"] = "ot_to_it"
        return result

    def transmit_it_to_ot(self, data: dict) -> dict:
        if self._data_diode_enabled:
            raise PermissionError("Data diode blocks IT->OT communication")
        result = dict(data)
        result["direction"] = "it_to_ot"
        return result

    def translate_protocol(self, source_protocol: ProtocolType) -> ProtocolType:
        return self._protocol_mappings.get(source_protocol, source_protocol)


# ── SCADASystem ────────────────────────────────────────────────────────

class SCADASystem:
    """Integrated SCADA system combining monitoring, anomaly detection, and OT/IT gateway."""

    def __init__(self):
        self.monitor = SCADAMonitor()
        self.detector = AnomalyDetector()
        self.gateway = OTITGateway()

    def register_device(self, device: SCADADevice) -> None:
        self.monitor.add_device(device)

    def process_reading(self, reading: SCADAReading) -> dict:
        alarms = self.monitor.collect_reading(reading)
        anomaly = self.detector.add_reading(reading)
        anomalies = [anomaly] if anomaly else []
        return {"alarms": alarms, "anomalies": anomalies}

    def get_system_health(self) -> dict:
        total = len(self.monitor.devices)
        online = sum(1 for d in self.monitor.devices.values() if d.status == DeviceStatus.ONLINE)
        active_alarms = sum(1 for a in self.monitor.alarms if not a.acknowledged)
        return {
            "total_devices": total,
            "online_devices": online,
            "active_alarms": active_alarms,
        }
