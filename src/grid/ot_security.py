"""OT security: anomaly detection, protocol analysis, and incident response for SCADA/ICS."""
import statistics
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Enums ──────────────────────────────────────────────────────────────

class ProtocolAnomalyType(str, Enum):
    STUCK_VALUE = "stuck_value"
    OUT_OF_RANGE = "out_of_range"
    BASELINE_DEVIATION = "baseline_deviation"
    INVALID_FUNCTION_CODE = "invalid_function_code"
    UNUSUAL_COMMAND = "unusual_command"
    COMMUNICATION_LOSS = "communication_loss"


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    OPEN = "open"
    ESCALATED = "escalated"
    RESOLVED = "resolved"


class ResponseAction(str, Enum):
    ISOLATE_DEVICE = "isolate_device"
    BLOCK_IP = "block_ip"
    NOTIFY_OPERATOR = "notify_operator"
    SHUTDOWN_DEVICE = "shutdown_device"
    LOG_INCIDENT = "log_incident"


# ── Data classes ───────────────────────────────────────────────────────

@dataclass
class ProtocolAnomaly:
    anomaly_id: str
    device_id: str
    anomaly_type: ProtocolAnomalyType
    description: str
    timestamp: float
    value: float = 0.0


@dataclass
class ModbusFrame:
    transaction_id: int
    protocol_id: int
    unit_id: int
    function_code: int
    data: bytes
    raw: bytes


@dataclass
class DNP3Frame:
    source: int
    destination: int
    control: int
    data: bytes
    raw: bytes


@dataclass
class Incident:
    incident_id: str
    severity: IncidentSeverity
    description: str
    source: str
    status: IncidentStatus = IncidentStatus.OPEN
    timestamp: float = 0.0
    actions_taken: list = field(default_factory=list)


# ── OT Anomaly Detector ────────────────────────────────────────────────

class OTAnomalyDetector:
    """Detects anomalies in OT device readings using statistical and rule-based methods."""

    def __init__(self, stuck_threshold: int = 4, deviation_factor: float = 3.0):
        self.stuck_threshold = stuck_threshold
        self.deviation_factor = deviation_factor
        self._baselines: dict[str, dict[str, dict]] = {}
        self._last_values: dict[str, list] = {}

    def learn_baseline(self, device_id: str, tag: str, values: list[float]) -> None:
        if len(values) < 2:
            raise ValueError("Need at least 2 values to learn baseline")
        self._baselines.setdefault(device_id, {})[tag] = {
            "mean": statistics.mean(values),
            "std": statistics.stdev(values),
            "min": min(values),
            "max": max(values),
        }

    def get_baseline_stats(self, device_id: str, tag: str) -> Optional[dict]:
        return self._baselines.get(device_id, {}).get(tag)

    def detect_stuck_value(self, device_id: str, tag: str, value: float) -> Optional[ProtocolAnomaly]:
        key = f"{device_id}:{tag}"
        history = self._last_values.setdefault(key, [])
        history.append(value)
        if len(history) > self.stuck_threshold:
            history = history[-self.stuck_threshold:]
            self._last_values[key] = history
        if len(history) == self.stuck_threshold and len(set(history)) == 1:
            return ProtocolAnomaly(
                anomaly_id=str(uuid.uuid4()),
                device_id=device_id,
                anomaly_type=ProtocolAnomalyType.STUCK_VALUE,
                description=f"Stuck value {value} for {self.stuck_threshold} consecutive readings",
                timestamp=time.time(),
                value=value,
            )
        return None

    def detect_out_of_range(self, device_id: str, tag: str, value: float, low: float, high: float) -> Optional[ProtocolAnomaly]:
        if value < low or value > high:
            return ProtocolAnomaly(
                anomaly_id=str(uuid.uuid4()),
                device_id=device_id,
                anomaly_type=ProtocolAnomalyType.OUT_OF_RANGE,
                description=f"Value {value} outside range [{low}, {high}]",
                timestamp=time.time(),
                value=value,
            )
        return None

    def detect_baseline_deviation(self, device_id: str, tag: str, value: float) -> Optional[ProtocolAnomaly]:
        stats = self.get_baseline_stats(device_id, tag)
        if stats is None:
            return None
        mean = stats["mean"]
        std = stats["std"]
        if std > 0 and abs(value - mean) > self.deviation_factor * std:
            return ProtocolAnomaly(
                anomaly_id=str(uuid.uuid4()),
                device_id=device_id,
                anomaly_type=ProtocolAnomalyType.BASELINE_DEVIATION,
                description=f"Value {value} deviates from baseline mean {mean:.2f} (std={std:.2f})",
                timestamp=time.time(),
                value=value,
            )
        return None


# ── Protocol Analyzer ──────────────────────────────────────────────────

class ProtocolAnalyzer:
    """Analyzes industrial protocol frames for anomalies."""

    VALID_MODBUS_FUNCTION_CODES = {1, 2, 3, 4, 5, 6, 15, 16}

    def parse_modbus_frame(self, data: bytes) -> ModbusFrame:
        if len(data) < 8:
            raise ValueError("Modbus frame too short")
        transaction_id = (data[0] << 8) | data[1]
        protocol_id = (data[2] << 8) | data[3]
        length = (data[4] << 8) | data[5]
        unit_id = data[6]
        function_code = data[7]
        frame_data = data[8:8 + length - 2] if length >= 2 else b""
        return ModbusFrame(
            transaction_id=transaction_id,
            protocol_id=protocol_id,
            unit_id=unit_id,
            function_code=function_code,
            data=frame_data,
            raw=data,
        )

    def validate_modbus_frame(self, frame: ModbusFrame) -> list[ProtocolAnomaly]:
        anomalies = []
        if frame.function_code not in self.VALID_MODBUS_FUNCTION_CODES:
            anomalies.append(ProtocolAnomaly(
                anomaly_id=str(uuid.uuid4()),
                device_id=str(frame.unit_id),
                anomaly_type=ProtocolAnomalyType.INVALID_FUNCTION_CODE,
                description=f"Invalid Modbus function code: {frame.function_code}",
                timestamp=time.time(),
                value=float(frame.function_code),
            ))
        return anomalies

    def parse_dnp3_frame(self, data: bytes) -> DNP3Frame:
        if len(data) < 10:
            raise ValueError("DNP3 frame too short")
        destination = data[4] | (data[5] << 8)
        source = data[6] | (data[7] << 8)
        control = data[3]
        return DNP3Frame(
            source=source,
            destination=destination,
            control=control,
            data=data[10:],
            raw=data,
        )

    def detect_unusual_commands(self, device_id: str, function_code: int, history: list[int]) -> Optional[ProtocolAnomaly]:
        if len(history) < 3:
            return None
        counter = Counter(history)
        most_common_code, most_common_count = counter.most_common(1)[0]
        if function_code != most_common_code and most_common_count >= len(history) * 0.6:
            return ProtocolAnomaly(
                anomaly_id=str(uuid.uuid4()),
                device_id=device_id,
                anomaly_type=ProtocolAnomalyType.UNUSUAL_COMMAND,
                description=f"Unusual command {function_code}, expected {most_common_code}",
                timestamp=time.time(),
                value=float(function_code),
            )
        return None


# ── Incident Response ──────────────────────────────────────────────────

class IncidentResponsePlaybook:
    """Defines response actions for different incident severities."""

    def __init__(self):
        self._actions: dict[IncidentSeverity, list[ResponseAction]] = {}

    def add_action(self, severity: IncidentSeverity, action: ResponseAction) -> None:
        self._actions.setdefault(severity, []).append(action)

    def get_actions(self, severity: IncidentSeverity) -> list[ResponseAction]:
        return self._actions.get(severity, [])


class IncidentResponseOrchestrator:
    """Orchestrates incident creation, response, escalation, and resolution."""

    def __init__(self, playbook: Optional[IncidentResponsePlaybook] = None):
        self.playbook = playbook or IncidentResponsePlaybook()
        self._incidents: dict[str, Incident] = {}

    def create_incident(self, severity: IncidentSeverity, description: str, source: str) -> Incident:
        incident = Incident(
            incident_id=str(uuid.uuid4()),
            severity=severity,
            description=description,
            source=source,
            timestamp=time.time(),
        )
        self._incidents[incident.incident_id] = incident
        return incident

    def respond_to_incident(self, incident_id: str) -> list[ResponseAction]:
        incident = self._incidents.get(incident_id)
        if incident is None:
            raise ValueError(f"Unknown incident: {incident_id}")
        actions = self.playbook.get_actions(incident.severity)
        incident.actions_taken.extend(actions)
        return actions

    def escalate_incident(self, incident_id: str) -> None:
        incident = self._incidents.get(incident_id)
        if incident is None:
            raise ValueError(f"Unknown incident: {incident_id}")
        incident.status = IncidentStatus.ESCALATED

    def resolve_incident(self, incident_id: str) -> None:
        incident = self._incidents.get(incident_id)
        if incident is None:
            raise ValueError(f"Unknown incident: {incident_id}")
        incident.status = IncidentStatus.RESOLVED

    def get_incident_status(self, incident_id: str) -> IncidentStatus:
        incident = self._incidents.get(incident_id)
        if incident is None:
            raise ValueError(f"Unknown incident: {incident_id}")
        return incident.status
