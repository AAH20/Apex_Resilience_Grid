"""Predictive maintenance, anomaly detection, and automatic remediation."""
import time
import statistics
from typing import Callable, List, Optional, Dict, Any


# ── Health Metric Tracker ──────────────────────────────────────────────

class HealthMetricTracker:
    """Tracks health metrics over time and predicts time-to-failure."""

    def __init__(self, component_id: str, max_history: int = 100):
        self.component_id = component_id
        self.max_history = max_history
        self._history: List[float] = []

    def record(self, value: float) -> None:
        """Record a new metric reading."""
        self._history.append(value)
        if len(self._history) > self.max_history:
            self._history = self._history[-self.max_history:]

    def get_history(self) -> List[float]:
        """Return the full history of readings."""
        return list(self._history)

    def get_trend(self) -> float:
        """Calculate the linear trend (slope) of recent readings."""
        n = len(self._history)
        if n < 2:
            return 0.0
        # Simple linear regression slope
        x_mean = (n - 1) / 2.0
        y_mean = sum(self._history) / n
        numerator = sum((i - x_mean) * (y - y_mean) for i, y in enumerate(self._history))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        if denominator == 0:
            return 0.0
        return numerator / denominator

    def predict_time_to_failure(self, failure_threshold: float) -> Optional[float]:
        """Predict readings-until-failure based on current trend.
        
        Returns None if trend is improving or flat.
        Returns 0.0 if already below threshold.
        """
        if not self._history:
            return None
        current = self._history[-1]
        if current <= failure_threshold:
            return 0.0
        trend = self.get_trend()
        if trend >= 0:
            return None  # Improving or stable
        # How many more readings until we hit the threshold
        readings_to_failure = (current - failure_threshold) / abs(trend)
        return readings_to_failure


# ── Anomaly Detector ───────────────────────────────────────────────────

class AnomalyDetector:
    """Detects anomalies using statistical methods (zscore or IQR)."""

    def __init__(self, method: str = "zscore", threshold: float = 3.0):
        self.method = method
        self.threshold = threshold
        self._readings: List[float] = []

    def add_reading(self, value: float) -> None:
        """Add a reading to the baseline dataset."""
        self._readings.append(value)

    def is_anomaly(self, value: float) -> bool:
        """Check if a value is anomalous compared to baseline."""
        if len(self._readings) < 2:
            return False
        if self.method == "zscore":
            return self._is_zscore_anomaly(value)
        elif self.method == "iqr":
            return self._is_iqr_anomaly(value)
        return False

    def _is_zscore_anomaly(self, value: float) -> bool:
        """Z-score based anomaly detection."""
        mean = statistics.mean(self._readings)
        stdev = statistics.pstdev(self._readings)
        if stdev == 0:
            # When all baseline values are identical, use a relative tolerance
            return abs(value - mean) > max(abs(mean) * 0.05, 1.0)
        zscore = abs(value - mean) / stdev
        return zscore >= self.threshold

    def _is_iqr_anomaly(self, value: float) -> bool:
        """Interquartile range based anomaly detection."""
        sorted_r = sorted(self._readings)
        n = len(sorted_r)
        q1 = sorted_r[n // 4]
        q3 = sorted_r[(3 * n) // 4]
        iqr = q3 - q1
        if iqr == 0:
            return value != sorted_r[0]
        lower = q1 - self.threshold * iqr
        upper = q3 + self.threshold * iqr
        return value < lower or value > upper

    def get_stats(self) -> Dict[str, float]:
        """Return statistics about the baseline readings."""
        if not self._readings:
            return {"count": 0, "mean": 0.0, "min": 0.0, "max": 0.0, "stdev": 0.0}
        return {
            "count": len(self._readings),
            "mean": statistics.mean(self._readings),
            "min": min(self._readings),
            "max": max(self._readings),
            "stdev": statistics.pstdev(self._readings) if len(self._readings) > 1 else 0.0,
        }


# ── Remediation Action ─────────────────────────────────────────────────

class RemediationAction:
    """A callable remediation action with cooldown."""

    def __init__(self, name: str, action: Callable, cooldown: float = 0.0):
        self.name = name
        self.action = action
        self.cooldown = cooldown
        self.execution_count = 0
        self._last_executed: Optional[float] = None

    def execute(self) -> None:
        """Execute the remediation action."""
        self.action()
        self.execution_count += 1
        self._last_executed = time.time()

    def can_execute(self) -> bool:
        """Check if enough time has passed since last execution."""
        if self._last_executed is None:
            return True
        return (time.time() - self._last_executed) >= self.cooldown


# ── Auto Remediator ───────────────────────────────────────────────────

class AutoRemediator:
    """Automatically executes remediation actions when anomalies are detected."""

    def __init__(self):
        self._actions: List[RemediationAction] = []
        self._history: List[Dict[str, Any]] = []

    def register_action(self, action: RemediationAction) -> None:
        """Register a remediation action."""
        self._actions.append(action)

    def on_anomaly(self, component_id: str, anomaly_score: float) -> None:
        """Handle an anomaly by executing all eligible actions."""
        for action in self._actions:
            if action.can_execute():
                action.execute()
                self._history.append({
                    "component_id": component_id,
                    "action_name": action.name,
                    "anomaly_score": anomaly_score,
                    "timestamp": time.time(),
                })

    def get_action_history(self) -> List[Dict[str, Any]]:
        """Return the history of executed remediation actions."""
        return list(self._history)


# ── Predictive Maintenance Engine ─────────────────────────────────────

class PredictiveMaintenanceEngine:
    """Orchestrates health tracking, anomaly detection, and auto-remediation."""

    def __init__(self, anomaly_threshold: float = 3.0, failure_threshold: float = 50.0):
        self.anomaly_threshold = anomaly_threshold
        self.failure_threshold = failure_threshold
        self._trackers: Dict[str, HealthMetricTracker] = {}
        self._detectors: Dict[str, AnomalyDetector] = {}
        self._remediator = AutoRemediator()
        self._anomaly_callbacks: Dict[str, Callable] = {}

    def register_component(
        self,
        component_id: str,
        on_anomaly: Optional[Callable] = None,
    ) -> None:
        """Register a component for predictive maintenance."""
        self._trackers[component_id] = HealthMetricTracker(component_id)
        self._detectors[component_id] = AnomalyDetector(
            method="zscore",
            threshold=self.anomaly_threshold,
        )
        if on_anomaly:
            self._anomaly_callbacks[component_id] = on_anomaly

    def record_metric(self, component_id: str, value: float) -> None:
        """Record a metric reading for a component."""
        if component_id not in self._trackers:
            raise KeyError(f"Unknown component: {component_id}")
        tracker = self._trackers[component_id]
        detector = self._detectors[component_id]
        tracker.record(value)
        detector.add_reading(value)
        # Check for anomaly
        if detector.is_anomaly(value):
            stats = detector.get_stats()
            anomaly_score = abs(value - stats["mean"]) / (stats["stdev"] if stats["stdev"] > 0 else 1.0)
            self._remediator.on_anomaly(component_id, anomaly_score)
            if component_id in self._anomaly_callbacks:
                self._anomaly_callbacks[component_id](component_id, anomaly_score)

    def check_anomalies(self, component_id: str) -> List[Dict[str, Any]]:
        """Check for anomalies in recent readings."""
        if component_id not in self._detectors:
            raise KeyError(f"Unknown component: {component_id}")
        detector = self._detectors[component_id]
        tracker = self._trackers[component_id]
        anomalies = []
        for value in tracker.get_history():
            if detector.is_anomaly(value):
                anomalies.append({"value": value, "component_id": component_id})
        return anomalies

    def get_maintenance_schedule(self) -> List[Dict[str, Any]]:
        """Generate a prioritized maintenance schedule."""
        schedule = []
        for cid, tracker in self._trackers.items():
            ttf = tracker.predict_time_to_failure(self.failure_threshold)
            if ttf is not None and ttf > 0:
                schedule.append({
                    "component_id": cid,
                    "time_to_failure": ttf,
                    "current_health": tracker.get_history()[-1] if tracker.get_history() else 0.0,
                    "trend": tracker.get_trend(),
                })
        # Sort by time-to-failure (most urgent first)
        schedule.sort(key=lambda x: x["time_to_failure"])
        return schedule

    def run_cycle(self) -> List[Dict[str, Any]]:
        """Run a full predictive maintenance cycle across all components."""
        issues = []
        for cid in self._trackers:
            anomalies = self.check_anomalies(cid)
            if anomalies:
                issues.append({
                    "component_id": cid,
                    "type": "anomaly",
                    "count": len(anomalies),
                })
            ttf = self._trackers[cid].predict_time_to_failure(self.failure_threshold)
            if ttf is not None and ttf > 0:
                issues.append({
                    "component_id": cid,
                    "type": "predicted_failure",
                    "time_to_failure": ttf,
                })
        return issues

    def register_remediation_action(self, action: RemediationAction) -> None:
        """Register a remediation action with the auto-remediator."""
        self._remediator.register_action(action)

    def get_remediation_history(self) -> List[Dict[str, Any]]:
        """Get the history of remediation actions taken."""
        return self._remediator.get_action_history()