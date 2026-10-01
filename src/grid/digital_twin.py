"""Digital Twin — real-time infrastructure modeling, simulation, and predictive analysis."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class NodeState(enum.Enum):
    ONLINE = "online"
    DEGRADED = "degraded"
    FAILED = "failed"


@dataclass
class InfrastructureNode:
    id: str
    node_type: str
    capacity: float
    current_load: float = 0.0
    health: float = 1.0
    state: NodeState = NodeState.ONLINE

    @property
    def load_ratio(self) -> float:
        if self.capacity <= 0:
            return 0.0
        return self.current_load / self.capacity

    @property
    def is_overloaded(self) -> bool:
        return self.current_load > self.capacity

    @property
    def effective_capacity(self) -> float:
        return self.capacity * self.health

    def degrade_health(self, amount: float) -> None:
        self.health = max(0.0, self.health - amount)

    def repair(self, amount: float) -> None:
        self.health = min(1.0, self.health + amount)

    def set_state(self, state: NodeState) -> None:
        self.state = state


@dataclass
class InfrastructureEdge:
    source: str
    target: str
    weight: float = 1.0
    is_active: bool = True


@dataclass
class SimulationResult:
    failed_nodes: list[str] = field(default_factory=list)
    total_failed: int = 0
    cascade_depth: int = 0


@dataclass
class PredictionResult:
    probability: float = 0.0
    risk_level: str = "low"
    factors: dict[str, float] = field(default_factory=dict)


@dataclass
class LoadIncreaseResult:
    new_load: float = 0.0
    would_overload: bool = False
    overload_amount: float = 0.0


class DigitalTwin:
    def __init__(self) -> None:
        self.nodes: dict[str, InfrastructureNode] = {}
        self.edges: list[InfrastructureEdge] = []

    def add_node(self, node: InfrastructureNode) -> None:
        if node.id in self.nodes:
            raise ValueError(f"Node '{node.id}' already exists")
        self.nodes[node.id] = node

    def remove_node(self, node_id: str) -> None:
        if node_id not in self.nodes:
            raise KeyError(f"Node '{node_id}' not found")
        del self.nodes[node_id]
        self.edges = [e for e in self.edges if e.source != node_id and e.target != node_id]

    def add_edge(self, edge: InfrastructureEdge) -> None:
        if edge.source not in self.nodes:
            raise ValueError(f"Source node '{edge.source}' not found")
        if edge.target not in self.nodes:
            raise ValueError(f"Target node '{edge.target}' not found")
        self.edges.append(edge)

    def get_neighbors(self, node_id: str) -> list[str]:
        return [e.target for e in self.edges if e.source == node_id and e.is_active]

    @property
    def total_capacity(self) -> float:
        return sum(n.capacity for n in self.nodes.values())

    @property
    def total_load(self) -> float:
        return sum(n.current_load for n in self.nodes.values())

    @property
    def grid_load_ratio(self) -> float:
        cap = self.total_capacity
        if cap <= 0:
            return 0.0
        return self.total_load / cap

    def update_node_load(self, node_id: str, new_load: float) -> None:
        if node_id not in self.nodes:
            raise KeyError(f"Node '{node_id}' not found")
        self.nodes[node_id].current_load = new_load

    def get_critical_nodes(self, threshold: float = 0.9) -> list[str]:
        return [nid for nid, n in self.nodes.items() if n.load_ratio >= threshold]

    def simulate_cascading_failure(self, initial_node_id: str) -> SimulationResult:
        if initial_node_id not in self.nodes:
            raise KeyError(f"Node '{initial_node_id}' not found")

        failed: list[str] = []
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(initial_node_id, 0)]
        max_depth = 0

        while queue:
            node_id, depth = queue.pop(0)
            if node_id in visited:
                continue
            visited.add(node_id)
            failed.append(node_id)
            max_depth = max(max_depth, depth)

            for neighbor in self.get_neighbors(node_id):
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1))

        return SimulationResult(
            failed_nodes=failed,
            total_failed=len(failed),
            cascade_depth=max_depth,
        )

    def predict_failure_probability(self, node_id: str) -> PredictionResult:
        if node_id not in self.nodes:
            raise KeyError(f"Node '{node_id}' not found")

        node = self.nodes[node_id]
        load_factor = min(1.0, node.load_ratio)
        health_factor = 1.0 - node.health
        probability = min(1.0, (load_factor * 0.6 + health_factor * 0.4))

        risk_level = "low"
        if probability >= 0.7:
            risk_level = "critical"
        elif probability >= 0.4:
            risk_level = "medium"

        return PredictionResult(
            probability=probability,
            risk_level=risk_level,
            factors={"load_factor": load_factor, "health_factor": health_factor},
        )

    def predict_time_to_failure(self, node_id: str) -> float | None:
        if node_id not in self.nodes:
            raise KeyError(f"Node '{node_id}' not found")

        node = self.nodes[node_id]
        if node.health >= 0.95 and node.load_ratio < 0.5:
            return None

        degradation_rate = (1.0 - node.health) * 0.1 + node.load_ratio * 0.05
        if degradation_rate <= 0:
            return None
        return max(1.0, node.health / degradation_rate)

    def get_system_health(self) -> float:
        if not self.nodes:
            return 1.0
        return sum(n.health for n in self.nodes.values()) / len(self.nodes)

    def get_vulnerable_components(self) -> list[str]:
        vulnerable = []
        for nid, node in self.nodes.items():
            if node.load_ratio > 0.8 or node.health < 0.5:
                vulnerable.append(nid)
        return vulnerable

    def snapshot_state(self) -> dict[str, dict[str, Any]]:
        return {
            nid: {
                "current_load": n.current_load,
                "capacity": n.capacity,
                "health": n.health,
                "state": n.state.value,
            }
            for nid, n in self.nodes.items()
        }

    def restore_state(self, snapshot: dict[str, dict[str, Any]]) -> None:
        for nid, data in snapshot.items():
            if nid not in self.nodes:
                raise KeyError(f"Node '{nid}' not found in twin")
            node = self.nodes[nid]
            node.current_load = data["current_load"]
            node.capacity = data["capacity"]
            node.health = data["health"]

    def simulate_load_increase(self, node_id: str, increase: float) -> LoadIncreaseResult:
        if node_id not in self.nodes:
            raise KeyError(f"Node '{node_id}' not found")

        node = self.nodes[node_id]
        new_load = node.current_load + increase
        would_overload = new_load > node.capacity
        overload_amount = max(0.0, new_load - node.capacity)

        return LoadIncreaseResult(
            new_load=new_load,
            would_overload=would_overload,
            overload_amount=overload_amount,
        )

    def get_topology_summary(self) -> dict[str, Any]:
        node_types: dict[str, int] = {}
        for n in self.nodes.values():
            node_types[n.node_type] = node_types.get(n.node_type, 0) + 1

        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "node_types": node_types,
        }
