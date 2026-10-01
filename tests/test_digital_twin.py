"""Tests for Digital Twin — real-time infrastructure modeling, simulation, predictive analysis."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from grid.digital_twin import (
    InfrastructureNode,
    InfrastructureEdge,
    DigitalTwin,
    NodeState,
    SimulationResult,
    PredictionResult,
)


# ── InfrastructureNode tests ──

class TestInfrastructureNode:
    def test_node_creation_with_defaults(self):
        node = InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0)
        assert node.id == "n1"
        assert node.node_type == "power_plant"
        assert node.capacity == 100.0
        assert node.current_load == 0.0
        assert node.health == 1.0
        assert node.state == NodeState.ONLINE

    def test_node_creation_with_custom_load(self):
        node = InfrastructureNode(id="n2", node_type="substation", capacity=50.0, current_load=25.0)
        assert node.current_load == 25.0
        assert node.load_ratio == 0.5

    def test_node_load_ratio_zero_capacity(self):
        node = InfrastructureNode(id="n3", node_type="load", capacity=0.0, current_load=0.0)
        assert node.load_ratio == 0.0

    def test_node_overload_detection(self):
        node = InfrastructureNode(id="n4", node_type="substation", capacity=100.0, current_load=120.0)
        assert node.is_overloaded is True

    def test_node_not_overloaded(self):
        node = InfrastructureNode(id="n5", node_type="substation", capacity=100.0, current_load=80.0)
        assert node.is_overloaded is False

    def test_node_health_degradation(self):
        node = InfrastructureNode(id="n6", node_type="power_plant", capacity=100.0)
        node.degrade_health(0.2)
        assert node.health == pytest.approx(0.8)

    def test_node_health_floor_at_zero(self):
        node = InfrastructureNode(id="n7", node_type="power_plant", capacity=100.0)
        node.degrade_health(1.5)
        assert node.health == 0.0

    def test_node_repair(self):
        node = InfrastructureNode(id="n8", node_type="substation", capacity=100.0, health=0.3)
        node.repair(0.5)
        assert node.health == pytest.approx(0.8)

    def test_node_repair_capped_at_one(self):
        node = InfrastructureNode(id="n9", node_type="substation", capacity=100.0, health=0.9)
        node.repair(0.5)
        assert node.health == 1.0

    def test_node_state_transition_to_failed(self):
        node = InfrastructureNode(id="n10", node_type="power_plant", capacity=100.0)
        node.set_state(NodeState.FAILED)
        assert node.state == NodeState.FAILED

    def test_node_effective_capacity(self):
        node = InfrastructureNode(id="n11", node_type="power_plant", capacity=100.0, health=0.5)
        assert node.effective_capacity == pytest.approx(50.0)

    def test_node_effective_capacity_zero_health(self):
        node = InfrastructureNode(id="n12", node_type="power_plant", capacity=100.0, health=0.0)
        assert node.effective_capacity == 0.0


# ── InfrastructureEdge tests ──

class TestInfrastructureEdge:
    def test_edge_creation(self):
        edge = InfrastructureEdge(source="n1", target="n2", weight=1.0)
        assert edge.source == "n1"
        assert edge.target == "n2"
        assert edge.weight == 1.0
        assert edge.is_active is True

    def test_edge_deactivation(self):
        edge = InfrastructureEdge(source="n1", target="n2", weight=1.0)
        edge.is_active = False
        assert edge.is_active is False


# ── DigitalTwin tests ──

class TestDigitalTwin:
    def test_twin_creation_empty(self):
        twin = DigitalTwin()
        assert len(twin.nodes) == 0
        assert len(twin.edges) == 0

    def test_add_node(self):
        twin = DigitalTwin()
        node = InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0)
        twin.add_node(node)
        assert "n1" in twin.nodes
        assert twin.nodes["n1"].id == "n1"

    def test_add_duplicate_node_raises(self):
        twin = DigitalTwin()
        node = InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0)
        twin.add_node(node)
        with pytest.raises(ValueError, match="already exists"):
            twin.add_node(node)

    def test_remove_node(self):
        twin = DigitalTwin()
        node = InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0)
        twin.add_node(node)
        twin.remove_node("n1")
        assert "n1" not in twin.nodes

    def test_remove_nonexistent_node_raises(self):
        twin = DigitalTwin()
        with pytest.raises(KeyError):
            twin.remove_node("nonexistent")

    def test_add_edge(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0))
        twin.add_node(InfrastructureNode(id="n2", node_type="substation", capacity=50.0))
        edge = InfrastructureEdge(source="n1", target="n2", weight=1.0)
        twin.add_edge(edge)
        assert len(twin.edges) == 1

    def test_add_edge_missing_source_raises(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n2", node_type="substation", capacity=50.0))
        edge = InfrastructureEdge(source="n1", target="n2", weight=1.0)
        with pytest.raises(ValueError, match="Source node.*not found"):
            twin.add_edge(edge)

    def test_add_edge_missing_target_raises(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0))
        edge = InfrastructureEdge(source="n1", target="n2", weight=1.0)
        with pytest.raises(ValueError, match="Target node.*not found"):
            twin.add_edge(edge)

    def test_get_neighbors(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0))
        twin.add_node(InfrastructureNode(id="n2", node_type="substation", capacity=50.0))
        twin.add_node(InfrastructureNode(id="n3", node_type="load", capacity=30.0))
        twin.add_edge(InfrastructureEdge(source="n1", target="n2", weight=1.0))
        twin.add_edge(InfrastructureEdge(source="n1", target="n3", weight=1.0))
        neighbors = twin.get_neighbors("n1")
        assert set(neighbors) == {"n2", "n3"}

    def test_get_neighbors_no_edges(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0))
        assert twin.get_neighbors("n1") == []

    def test_total_capacity(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0))
        twin.add_node(InfrastructureNode(id="n2", node_type="power_plant", capacity=200.0))
        assert twin.total_capacity == 300.0

    def test_total_load(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=50.0))
        twin.add_node(InfrastructureNode(id="n2", node_type="substation", capacity=200.0, current_load=80.0))
        assert twin.total_load == 130.0

    def test_grid_load_ratio(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=50.0))
        twin.add_node(InfrastructureNode(id="n2", node_type="substation", capacity=100.0, current_load=50.0))
        assert twin.grid_load_ratio == pytest.approx(0.5)

    def test_grid_load_ratio_zero_capacity(self):
        twin = DigitalTwin()
        assert twin.grid_load_ratio == 0.0

    def test_update_node_load(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0))
        twin.update_node_load("n1", 75.0)
        assert twin.nodes["n1"].current_load == 75.0

    def test_update_node_load_nonexistent_raises(self):
        twin = DigitalTwin()
        with pytest.raises(KeyError):
            twin.update_node_load("nonexistent", 50.0)

    def test_update_node_load_exceeds_capacity(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0))
        twin.update_node_load("n1", 150.0)
        assert twin.nodes["n1"].is_overloaded is True

    def test_get_critical_nodes(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=95.0))
        twin.add_node(InfrastructureNode(id="n2", node_type="substation", capacity=100.0, current_load=50.0))
        critical = twin.get_critical_nodes(threshold=0.9)
        assert "n1" in critical
        assert "n2" not in critical

    def test_get_critical_nodes_empty(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=50.0))
        assert twin.get_critical_nodes(threshold=0.9) == []

    def test_simulate_cascading_failure(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="gen1", node_type="power_plant", capacity=100.0, current_load=80.0))
        twin.add_node(InfrastructureNode(id="sub1", node_type="substation", capacity=100.0, current_load=60.0))
        twin.add_node(InfrastructureNode(id="load1", node_type="load", capacity=50.0, current_load=40.0))
        twin.add_edge(InfrastructureEdge(source="gen1", target="sub1", weight=1.0))
        twin.add_edge(InfrastructureEdge(source="sub1", target="load1", weight=1.0))

        # Fail the generator — should cascade
        result = twin.simulate_cascading_failure("gen1")
        assert isinstance(result, SimulationResult)
        assert "gen1" in result.failed_nodes
        assert result.total_failed >= 1

    def test_simulate_cascading_failure_nonexistent_node(self):
        twin = DigitalTwin()
        with pytest.raises(KeyError):
            twin.simulate_cascading_failure("nonexistent")

    def test_simulate_cascading_failure_no_cascade(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="gen1", node_type="power_plant", capacity=100.0, current_load=80.0))
        twin.add_node(InfrastructureNode(id="load1", node_type="load", capacity=50.0, current_load=40.0))
        # No edge between them — no cascade
        result = twin.simulate_cascading_failure("gen1")
        assert result.total_failed == 1
        assert "load1" not in result.failed_nodes

    def test_predict_failure_probability(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=95.0, health=0.3))
        result = twin.predict_failure_probability("n1")
        assert isinstance(result, PredictionResult)
        assert 0.0 <= result.probability <= 1.0
        assert result.probability > 0.5  # High load + low health = high risk

    def test_predict_failure_probability_healthy_node(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=30.0, health=1.0))
        result = twin.predict_failure_probability("n1")
        assert result.probability < 0.3

    def test_predict_failure_probability_nonexistent_node(self):
        twin = DigitalTwin()
        with pytest.raises(KeyError):
            twin.predict_failure_probability("nonexistent")

    def test_predict_time_to_failure(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=95.0, health=0.5))
        result = twin.predict_time_to_failure("n1")
        assert result is not None
        assert result > 0

    def test_predict_time_to_failure_healthy_node(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=20.0, health=1.0))
        result = twin.predict_time_to_failure("n1")
        assert result is None  # No failure predicted

    def test_get_system_health(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, health=0.8))
        twin.add_node(InfrastructureNode(id="n2", node_type="substation", capacity=100.0, health=0.6))
        health = twin.get_system_health()
        assert health == pytest.approx(0.7)

    def test_get_system_health_empty(self):
        twin = DigitalTwin()
        assert twin.get_system_health() == 1.0

    def test_get_vulnerable_components(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=95.0, health=0.4))
        twin.add_node(InfrastructureNode(id="n2", node_type="substation", capacity=100.0, current_load=50.0, health=0.9))
        vulnerable = twin.get_vulnerable_components()
        assert "n1" in vulnerable
        assert "n2" not in vulnerable

    def test_snapshot_state(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=50.0))
        snapshot = twin.snapshot_state()
        assert "n1" in snapshot
        assert snapshot["n1"]["current_load"] == 50.0
        assert snapshot["n1"]["capacity"] == 100.0

    def test_restore_state(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=50.0))
        snapshot = twin.snapshot_state()
        twin.update_node_load("n1", 80.0)
        twin.restore_state(snapshot)
        assert twin.nodes["n1"].current_load == 50.0

    def test_restore_state_missing_node_raises(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0))
        snapshot = {"nonexistent": {"current_load": 50.0, "capacity": 100.0, "health": 1.0}}
        with pytest.raises(KeyError):
            twin.restore_state(snapshot)

    def test_simulate_load_increase(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=50.0))
        result = twin.simulate_load_increase("n1", 30.0)
        assert result.new_load == 80.0
        assert result.would_overload is False

    def test_simulate_load_increase_overload(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=80.0))
        result = twin.simulate_load_increase("n1", 30.0)
        assert result.new_load == 110.0
        assert result.would_overload is True

    def test_simulate_load_increase_nonexistent_node(self):
        twin = DigitalTwin()
        with pytest.raises(KeyError):
            twin.simulate_load_increase("nonexistent", 10.0)

    def test_get_topology_summary(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0))
        twin.add_node(InfrastructureNode(id="n2", node_type="substation", capacity=50.0))
        twin.add_edge(InfrastructureEdge(source="n1", target="n2", weight=1.0))
        summary = twin.get_topology_summary()
        assert summary["node_count"] == 2
        assert summary["edge_count"] == 1
        assert summary["node_types"]["power_plant"] == 1
        assert summary["node_types"]["substation"] == 1

    def test_get_topology_summary_empty(self):
        twin = DigitalTwin()
        summary = twin.get_topology_summary()
        assert summary["node_count"] == 0
        assert summary["edge_count"] == 0
        assert summary["node_types"] == {}
