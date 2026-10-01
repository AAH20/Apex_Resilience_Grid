"""Cascading failure analysis engine for the Apex Resilience Grid.

Models critical-infrastructure nodes and their interdependencies, simulates
failure propagation across multiple hops, and assesses network-wide impact.
"""

from dataclasses import dataclass, field
from enum import Enum


class NodeStatus(str, Enum):
    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    FAILED = "failed"


@dataclass
class GridNode:
    node_id: str
    node_type: str
    capacity: float = 100.0
    status: NodeStatus = NodeStatus.OPERATIONAL


@dataclass
class Dependency:
    from_node: str
    to_node: str
    weight: float = 1.0


@dataclass
class FailureResult:
    failed_nodes: set
    blast_radius: int
    total_capacity_lost: float = 0.0
    propagation_path: list = field(default_factory=list)
    impact_percentage: float = 0.0


class CascadingFailureAnalyzer:
    """Analyzes cascading failures across a dependency graph."""

    def __init__(self):
        self.nodes = {}
        self.dependencies = {}

    def add_node(self, node: GridNode):
        self.nodes[node.node_id] = node
        self.dependencies.setdefault(node.node_id, [])

    def add_dependency(self, from_node: str, to_node: str, weight: float = 1.0):
        if from_node not in self.nodes or to_node not in self.nodes:
            raise ValueError("Both nodes must be registered before adding a dependency")
        self.dependencies.setdefault(from_node, []).append(
            Dependency(from_node=from_node, to_node=to_node, weight=weight)
        )

    def _build_dependents_index(self):
        """Reverse adjacency: who depends on a given node."""
        dependents = {}
        for from_node, deps in self.dependencies.items():
            for dep in deps:
                dependents.setdefault(dep.to_node, []).append((from_node, dep.weight))
        return dependents

    def simulate_failure(self, node_id: str, threshold: float = 0.5) -> FailureResult:
        if node_id not in self.nodes:
            raise ValueError(f"Unknown node: {node_id}")
        # Conjunctive propagation: a node fails only when ALL its strong
        # dependencies (weight >= threshold) have failed. This models
        # redundancy — a node with multiple power sources survives one loss.
        strong_deps = {}  # node_id -> list of strong dependency targets
        dependents = {}   # node_id -> list of (dependent, weight)
        for from_node, deps in self.dependencies.items():
            strong_deps[from_node] = [d.to_node for d in deps if d.weight >= threshold]
            for dep in deps:
                if dep.weight >= threshold:
                    dependents.setdefault(dep.to_node, []).append(from_node)

        failed = {node_id}
        propagation_path = [node_id]
        # Track how many strong deps have failed for each node
        failed_dep_count = {nid: 0 for nid in self.nodes}
        queue = [node_id]
        while queue:
            current = queue.pop(0)
            for dependent in dependents.get(current, []):
                if dependent not in failed:
                    failed_dep_count[dependent] += 1
                    if failed_dep_count[dependent] >= len(strong_deps[dependent]):
                        failed.add(dependent)
                        propagation_path.append(dependent)
                        queue.append(dependent)
        total_capacity_lost = sum(self.nodes[n].capacity for n in failed)
        total_network = sum(n.capacity for n in self.nodes.values())
        impact_pct = (total_capacity_lost / total_network * 100.0) if total_network > 0 else 0.0
        return FailureResult(
            failed_nodes=failed,
            blast_radius=len(failed),
            total_capacity_lost=total_capacity_lost,
            propagation_path=propagation_path,
            impact_percentage=impact_pct,
        )

    def impact_percentage(self, failed_nodes: set) -> float:
        """Percentage of total network capacity lost due to failed nodes."""
        total = sum(n.capacity for n in self.nodes.values())
        if total == 0:
            return 0.0
        lost = sum(self.nodes[n].capacity for n in failed_nodes if n in self.nodes)
        return lost / total * 100.0

    def critical_nodes(self) -> list:
        """Nodes ranked by blast radius (descending). Only nodes causing cascades."""
        if not self.nodes:
            return []
        ranked = []
        for node_id in self.nodes:
            result = self.simulate_failure(node_id)
            if result.blast_radius > 1:
                ranked.append((node_id, result.blast_radius))
        ranked.sort(key=lambda x: -x[1])
        return [n for n, _ in ranked]

    def single_points_of_failure(self) -> list:
        """Nodes whose failure cascades to at least one other node."""
        spofs = []
        for node_id in self.nodes:
            result = self.simulate_failure(node_id)
            if result.blast_radius > 1:
                spofs.append(node_id)
        return spofs

    def worst_case_failure(self):
        """Node whose failure produces the largest blast radius."""
        if not self.nodes:
            raise ValueError("Empty graph")
        worst_node = None
        worst_result = None
        for node_id in self.nodes:
            result = self.simulate_failure(node_id)
            if worst_result is None or result.blast_radius > worst_result.blast_radius:
                worst_node = node_id
                worst_result = result
        return worst_node, worst_result

    def resilience_score(self) -> float:
        """1.0 = fully resilient (no SPOFs), 0.0 = every node is a SPOF."""
        if not self.nodes:
            return 1.0
        spofs = self.single_points_of_failure()
        return 1.0 - len(spofs) / len(self.nodes)

    def effective_capacity(self, node_id: str) -> float:
        """Capacity adjusted for node status."""
        if node_id not in self.nodes:
            raise ValueError(f"Unknown node: {node_id}")
        node = self.nodes[node_id]
        if node.status == NodeStatus.OPERATIONAL:
            return node.capacity
        elif node.status == NodeStatus.DEGRADED:
            return node.capacity * 0.5
        else:
            return 0.0

    def network_effective_capacity(self) -> float:
        """Sum of effective capacities across all nodes."""
        return sum(self.effective_capacity(nid) for nid in self.nodes)

    def analyze(self, origin: str):
        """Analyze cascading failure from a single origin node (pipeline API)."""
        from .models import CascadingResult
        if origin not in self.nodes:
            # Node not in analyzer state — treat as isolated (blast radius 1)
            return CascadingResult(
                origin=origin,
                affected_nodes={origin},
                node_depths={origin: 0},
                blast_radius=1,
            )
        # Build reverse adjacency: who depends on a given node
        dependents = {}
        for from_node, deps in self.dependencies.items():
            for dep in deps:
                dependents.setdefault(dep.to_node, []).append(from_node)
        affected = set()
        depths = {}
        queue = [(origin, 0)]
        while queue:
            node_id, depth = queue.pop(0)
            if node_id in affected:
                if depth < depths.get(node_id, float("inf")):
                    depths[node_id] = depth
                continue
            affected.add(node_id)
            depths[node_id] = depth
            for dependent in dependents.get(node_id, []):
                if dependent not in affected:
                    queue.append((dependent, depth + 1))
        return CascadingResult(
            origin=origin,
            affected_nodes=affected,
            node_depths=depths,
            blast_radius=len(affected),
        )

    def analyze_multiple(self, origins: list):
        """Analyze cascading failure from multiple simultaneous origins."""
        from .models import CascadingResult
        all_affected = set()
        all_depths = {}
        for origin in origins:
            result = self.analyze(origin)
            all_affected.update(result.affected_nodes)
            for node, depth in result.node_depths.items():
                if node not in all_depths or depth < all_depths[node]:
                    all_depths[node] = depth
        return CascadingResult(
            origin=",".join(origins),
            affected_nodes=all_affected,
            node_depths=all_depths,
            blast_radius=len(all_affected),
        )
