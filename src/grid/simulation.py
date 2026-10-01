"""Real-time simulation, what-if analysis, and predictive modeling for the digital twin."""
from __future__ import annotations

import enum
import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

from .digital_twin import (
    DigitalTwin,
    InfrastructureNode,
    InfrastructureEdge,
    NodeState,
)


class TrendDirection(enum.Enum):
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"


@dataclass
class SimulationEvent:
    event_type: str
    node_id: str
    timestamp: float
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScenarioConfig:
    name: str
    load_changes: dict[str, float] = field(default_factory=dict)
    capacity_changes: dict[str, float] = field(default_factory=dict)
    node_failures: list[str] = field(default_factory=list)


class RealTimeSimulator:
    """Real-time simulation engine for the digital twin."""

    def __init__(
        self,
        twin: DigitalTwin,
        dt: float = 1.0,
        degradation_rate: float = 0.01,
        load_propagation_factor: float = 0.1,
    ) -> None:
        self.twin = twin
        self.dt = dt
        self.degradation_rate = degradation_rate
        self.load_propagation_factor = load_propagation_factor
        self.current_time: float = 0.0
        self.is_running: bool = False
        self._callbacks: list[Callable[[SimulationEvent], None]] = []
        self._initial_state: dict[str, Any] | None = None

    def start(self) -> None:
        self.is_running = True
        self._initial_state = self.twin.snapshot_state()

    def stop(self) -> None:
        self.is_running = False

    def step(self) -> None:
        if not self.is_running:
            raise RuntimeError("Simulator is not running. Call start() first.")
        self.current_time += self.dt
        self._apply_degradation()
        self._propagate_load()
        self._check_failures()

    def run(self, steps: int) -> None:
        if not self.is_running:
            self.start()
        for _ in range(steps):
            self.step()

    def reset(self) -> None:
        self.current_time = 0.0
        self.is_running = False
        if self._initial_state is not None:
            self.twin.restore_state(self._initial_state)

    def register_callback(self, callback: Callable[[SimulationEvent], None]) -> None:
        self._callbacks.append(callback)

    def snapshot_state(self) -> dict[str, Any]:
        return {
            "current_time": self.current_time,
            "twin_state": self.twin.snapshot_state(),
        }

    def restore_state(self, snapshot: dict[str, Any]) -> None:
        self.current_time = snapshot["current_time"]
        self.twin.restore_state(snapshot["twin_state"])

    def _apply_degradation(self) -> None:
        for node in self.twin.nodes.values():
            if node.load_ratio > 0.8:
                stress = (node.load_ratio - 0.8) / 0.2
                node.degrade_health(self.degradation_rate * stress * self.dt)

    def _propagate_load(self) -> None:
        for edge in self.twin.edges:
            if not edge.is_active:
                continue
            source = self.twin.nodes[edge.source]
            target = self.twin.nodes[edge.target]
            if source.load_ratio >= 0.5:
                excess = (source.load_ratio - 0.5) * self.load_propagation_factor * edge.weight
                target.current_load += excess * self.dt

    def _check_failures(self) -> None:
        for node in self.twin.nodes.values():
            if node.health <= 0.0 and node.state != NodeState.FAILED:
                node.set_state(NodeState.FAILED)
                self._emit("failure", node.id, {"health": node.health})
            elif node.load_ratio > 1.2 and node.state != NodeState.FAILED:
                node.set_state(NodeState.FAILED)
                self._emit("failure", node.id, {"load_ratio": node.load_ratio})

    def _emit(self, event_type: str, node_id: str, data: dict[str, Any]) -> None:
        event = SimulationEvent(
            event_type=event_type,
            node_id=node_id,
            timestamp=self.current_time,
            data=data,
        )
        for cb in self._callbacks:
            cb(event)


class WhatIfAnalyzer:
    """What-if analysis engine for scenario planning."""

    def __init__(self, twin: DigitalTwin) -> None:
        self.twin = twin

    def simulate_load_increase(self, node_id: str, increase: float) -> dict[str, Any]:
        if node_id not in self.twin.nodes:
            raise KeyError(f"Node '{node_id}' not found")
        node = self.twin.nodes[node_id]
        new_load = node.current_load + increase
        would_overload = new_load > node.capacity
        overload_amount = max(0.0, new_load - node.capacity)
        return {
            "node_id": node_id,
            "current_load": node.current_load,
            "new_load": new_load,
            "would_overload": would_overload,
            "overload_amount": overload_amount,
        }

    def simulate_node_failure(self, node_id: str) -> dict[str, Any]:
        if node_id not in self.twin.nodes:
            raise KeyError(f"Node '{node_id}' not found")
        result = self.twin.simulate_cascading_failure(node_id)
        return {
            "failed_nodes": result.failed_nodes,
            "total_failed": result.total_failed,
            "cascade_depth": result.cascade_depth,
        }

    def simulate_capacity_reduction(self, node_id: str, factor: float) -> dict[str, Any]:
        if node_id not in self.twin.nodes:
            raise KeyError(f"Node '{node_id}' not found")
        node = self.twin.nodes[node_id]
        new_capacity = node.capacity * factor
        would_overload = node.current_load > new_capacity
        return {
            "node_id": node_id,
            "current_capacity": node.capacity,
            "new_capacity": new_capacity,
            "current_load": node.current_load,
            "would_overload": would_overload,
        }

    def compare_scenarios(self, scenarios: list[ScenarioConfig]) -> list[dict[str, Any]]:
        results = []
        for scenario in scenarios:
            result = self._run_scenario(scenario)
            results.append(result)
        return results

    def sensitivity_analysis(
        self, node_id: str, parameter: str, values: list[float]
    ) -> list[dict[str, Any]]:
        if node_id not in self.twin.nodes:
            raise KeyError(f"Node '{node_id}' not found")
        results = []
        for value in values:
            if parameter == "load":
                result = self.simulate_load_increase(node_id, value)
            elif parameter == "capacity":
                result = self.simulate_capacity_reduction(node_id, value)
            else:
                raise ValueError(f"Unknown parameter: {parameter}")
            results.append(result)
        return results

    def _run_scenario(self, scenario: ScenarioConfig) -> dict[str, Any]:
        snapshot = self.twin.snapshot_state()
        try:
            for nid, change in scenario.load_changes.items():
                if nid in self.twin.nodes:
                    self.twin.nodes[nid].current_load += change
            for nid, factor in scenario.capacity_changes.items():
                if nid in self.twin.nodes:
                    self.twin.nodes[nid].capacity *= factor
            for nid in scenario.node_failures:
                if nid in self.twin.nodes:
                    self.twin.nodes[nid].set_state(NodeState.FAILED)
            return {
                "scenario_name": scenario.name,
                "system_health": self.twin.get_system_health(),
                "grid_load_ratio": self.twin.grid_load_ratio,
                "vulnerable_count": len(self.twin.get_vulnerable_components()),
            }
        finally:
            self.twin.restore_state(snapshot)


class PredictiveModel:
    """Predictive modeling engine for forecasting and anomaly detection."""

    def __init__(self, history_window: int = 10) -> None:
        self.history_window = history_window
        self.observations: dict[str, list[dict[str, float]]] = defaultdict(list)

    def record_observation(self, node_id: str, load: float, health: float) -> None:
        obs = self.observations[node_id]
        obs.append({"load": load, "health": health})
        if len(obs) > self.history_window:
            obs.pop(0)

    def analyze_trend(self, node_id: str, metric: str) -> dict[str, Any]:
        if node_id not in self.observations or len(self.observations[node_id]) < 2:
            raise KeyError(f"Insufficient data for node '{node_id}'")
        values = [obs[metric] for obs in self.observations[node_id]]
        n = len(values)
        x_mean = (n - 1) / 2.0
        y_mean = statistics.mean(values)
        numerator = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        slope = numerator / denominator if denominator != 0 else 0.0

        if slope > 0.1:
            direction = TrendDirection.INCREASING
        elif slope < -0.1:
            direction = TrendDirection.DECREASING
        else:
            direction = TrendDirection.STABLE

        return {
            "node_id": node_id,
            "metric": metric,
            "direction": direction,
            "slope": slope,
            "mean": y_mean,
        }

    def forecast(self, node_id: str, metric: str, steps: int) -> list[float]:
        if node_id not in self.observations or len(self.observations[node_id]) < 2:
            raise ValueError("Insufficient data for forecasting")
        values = [obs[metric] for obs in self.observations[node_id]]
        n = len(values)
        x_mean = (n - 1) / 2.0
        y_mean = statistics.mean(values)
        numerator = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        slope = numerator / denominator if denominator != 0 else 0.0
        intercept = y_mean - slope * x_mean
        return [intercept + slope * (n + i) for i in range(steps)]

    def predict_failure_probability(self, node_id: str) -> float:
        if node_id not in self.observations or len(self.observations[node_id]) < 2:
            raise ValueError("Insufficient data for prediction")
        latest = self.observations[node_id][-1]
        load_factor = min(1.0, latest["load"] / 100.0)
        health_factor = 1.0 - latest["health"]
        return min(1.0, load_factor * 0.6 + health_factor * 0.4)

    def detect_anomaly(self, node_id: str, load: float, threshold: float = 2.0) -> bool:
        if node_id not in self.observations or len(self.observations[node_id]) < 3:
            return False
        values = [obs["load"] for obs in self.observations[node_id]]
        mean = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        if std == 0.0:
            return abs(load - mean) > max(1.0, abs(mean) * 0.05)
        z_score = abs(load - mean) / std
        return z_score > threshold
