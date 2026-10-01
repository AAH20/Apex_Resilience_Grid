"""Unit tests for cascading failure analysis engine (TDD)."""

import pytest

from src.grid.cascading import (
    CascadingFailureAnalyzer,
    GridNode,
    NodeStatus,
)


def make_analyzer():
    return CascadingFailureAnalyzer()


class TestNodeRegistration:
    def test_add_node_stores_node(self):
        analyzer = make_analyzer()
        node = GridNode(node_id="GEN-1", node_type="power", capacity=500.0)
        analyzer.add_node(node)
        assert "GEN-1" in analyzer.nodes
        assert analyzer.nodes["GEN-1"].node_type == "power"
        assert analyzer.nodes["GEN-1"].capacity == 500.0

    def test_add_dependency_creates_edge(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=0.8)
        assert len(analyzer.dependencies["PUMP-1"]) == 1
        assert analyzer.dependencies["PUMP-1"][0].to_node == "GEN-1"
        assert analyzer.dependencies["PUMP-1"][0].weight == 0.8

    def test_add_dependency_unknown_node_raises(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="A", node_type="power"))
        with pytest.raises(ValueError):
            analyzer.add_dependency("A", "MISSING")

    def test_simulate_failure_of_isolated_node_fails_only_that_node(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="A", node_type="power"))
        analyzer.add_node(GridNode(node_id="B", node_type="water"))
        result = analyzer.simulate_failure("A")
        assert result.failed_nodes == {"A"}
        assert result.blast_radius == 1

    def test_failure_propagates_one_hop(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        result = analyzer.simulate_failure("GEN-1")
        assert result.failed_nodes == {"GEN-1", "PUMP-1"}
        assert result.blast_radius == 2

    def test_failure_propagates_multiple_hops(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_node(GridNode(node_id="HOSP-1", node_type="medical"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        analyzer.add_dependency("HOSP-1", "PUMP-1", weight=1.0)
        result = analyzer.simulate_failure("GEN-1")
        assert result.failed_nodes == {"GEN-1", "PUMP-1", "HOSP-1"}
        assert result.blast_radius == 3

    def test_failure_does_not_propagate_against_dependency_direction(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        result = analyzer.simulate_failure("PUMP-1")
        assert result.failed_nodes == {"PUMP-1"}
        assert result.blast_radius == 1

    def test_weak_dependency_below_threshold_does_not_propagate(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=0.3)
        result = analyzer.simulate_failure("GEN-1")
        assert result.failed_nodes == {"GEN-1"}
        assert result.blast_radius == 1

    def test_strong_dependency_above_threshold_propagates(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=0.6)
        result = analyzer.simulate_failure("GEN-1")
        assert result.failed_nodes == {"GEN-1", "PUMP-1"}
        assert result.blast_radius == 2

    def test_propagation_terminates_on_cycle(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="A", node_type="power"))
        analyzer.add_node(GridNode(node_id="B", node_type="water"))
        analyzer.add_node(GridNode(node_id="C", node_type="transport"))
        analyzer.add_dependency("A", "B", weight=1.0)
        analyzer.add_dependency("B", "C", weight=1.0)
        analyzer.add_dependency("C", "A", weight=1.0)
        result = analyzer.simulate_failure("A")
        assert result.failed_nodes == {"A", "B", "C"}
        assert result.blast_radius == 3

    def test_simulate_failure_unknown_node_raises(self):
        analyzer = make_analyzer()
        with pytest.raises(ValueError):
            analyzer.simulate_failure("NOPE")

    def test_capacity_lost_sums_failed_node_capacities(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power", capacity=500.0))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water", capacity=100.0))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        result = analyzer.simulate_failure("GEN-1")
        assert result.total_capacity_lost == 600.0

    def test_propagation_path_traces_cascade_order(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_node(GridNode(node_id="HOSP-1", node_type="medical"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        analyzer.add_dependency("HOSP-1", "PUMP-1", weight=1.0)
        result = analyzer.simulate_failure("GEN-1")
        assert result.propagation_path[0] == "GEN-1"
        assert set(result.propagation_path) == {"GEN-1", "PUMP-1", "HOSP-1"}
        assert result.propagation_path.index("PUMP-1") < result.propagation_path.index("HOSP-1")

    def test_impact_percentage_of_total_network_capacity(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power", capacity=500.0))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water", capacity=100.0))
        analyzer.add_node(GridNode(node_id="HOSP-1", node_type="medical", capacity=100.0))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        result = analyzer.simulate_failure("GEN-1")
        assert result.impact_percentage == pytest.approx(600.0 / 700.0 * 100.0)

    def test_impact_percentage_empty_network_is_zero(self):
        analyzer = make_analyzer()
        result = analyzer.simulate_failure.__self__  # noqa: F841 - placeholder
        # No nodes: impact of nothing is zero
        assert analyzer.impact_percentage(set()) == 0.0

    def test_critical_nodes_ranked_by_blast_radius(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_node(GridNode(node_id="HOSP-1", node_type="medical"))
        analyzer.add_node(GridNode(node_id="ISO-1", node_type="transport"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        analyzer.add_dependency("HOSP-1", "PUMP-1", weight=1.0)
        critical = analyzer.critical_nodes()
        assert critical[0] == "GEN-1"
        assert critical[1] == "PUMP-1"
        assert "HOSP-1" not in critical
        assert "ISO-1" not in critical

    def test_critical_nodes_empty_graph_returns_empty(self):
        analyzer = make_analyzer()
        assert analyzer.critical_nodes() == []

    def test_n_minus_one_contingency_finds_single_points_of_failure(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_node(GridNode(node_id="HOSP-1", node_type="medical"))
        analyzer.add_node(GridNode(node_id="GEN-2", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-2", node_type="water"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        analyzer.add_dependency("HOSP-1", "PUMP-1", weight=1.0)
        analyzer.add_dependency("PUMP-2", "GEN-2", weight=1.0)
        spof = analyzer.single_points_of_failure()
        assert "GEN-1" in spof
        assert "GEN-2" in spof
        assert "HOSP-1" not in spof

    def test_redundancy_eliminates_single_point_of_failure(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="GEN-2", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        analyzer.add_dependency("PUMP-1", "GEN-2", weight=1.0)
        assert analyzer.single_points_of_failure() == []

    def test_worst_case_failure_returns_largest_blast(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_node(GridNode(node_id="HOSP-1", node_type="medical"))
        analyzer.add_node(GridNode(node_id="ISO-1", node_type="transport"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        analyzer.add_dependency("HOSP-1", "PUMP-1", weight=1.0)
        node_id, result = analyzer.worst_case_failure()
        assert node_id == "GEN-1"
        assert result.blast_radius == 3

    def test_worst_case_failure_empty_graph_raises(self):
        analyzer = make_analyzer()
        with pytest.raises(ValueError):
            analyzer.worst_case_failure()

    def test_resilience_score_decreases_with_cascading_failures(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_node(GridNode(node_id="HOSP-1", node_type="medical"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        analyzer.add_dependency("HOSP-1", "PUMP-1", weight=1.0)
        score = analyzer.resilience_score()
        assert 0.0 <= score <= 1.0
        # Fully redundant network scores higher
        analyzer2 = make_analyzer()
        analyzer2.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer2.add_node(GridNode(node_id="GEN-2", node_type="power"))
        analyzer2.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer2.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        analyzer2.add_dependency("PUMP-1", "GEN-2", weight=1.0)
        assert analyzer2.resilience_score() > score

    def test_resilience_score_empty_graph_is_perfect(self):
        analyzer = make_analyzer()
        assert analyzer.resilience_score() == 1.0

    def test_degraded_node_reduces_effective_capacity(self):
        analyzer = make_analyzer()
        node = GridNode(node_id="GEN-1", node_type="power", capacity=500.0)
        node.status = NodeStatus.DEGRADED
        analyzer.add_node(node)
        assert analyzer.effective_capacity("GEN-1") == 250.0

    def test_failed_node_has_zero_effective_capacity(self):
        analyzer = make_analyzer()
        node = GridNode(node_id="GEN-1", node_type="power", capacity=500.0)
        node.status = NodeStatus.FAILED
        analyzer.add_node(node)
        assert analyzer.effective_capacity("GEN-1") == 0.0

    def test_operational_node_has_full_effective_capacity(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power", capacity=500.0))
        assert analyzer.effective_capacity("GEN-1") == 500.0

    def test_effective_capacity_unknown_node_raises(self):
        analyzer = make_analyzer()
        with pytest.raises(ValueError):
            analyzer.effective_capacity("NOPE")

    def test_network_effective_capacity_sums_operational_nodes(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power", capacity=500.0))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water", capacity=100.0))
        analyzer.add_node(GridNode(node_id="HOSP-1", node_type="medical", capacity=200.0))
        assert analyzer.network_effective_capacity() == 800.0

    def test_network_effective_capacity_accounts_for_degraded_nodes(self):
        analyzer = make_analyzer()
        n1 = GridNode(node_id="GEN-1", node_type="power", capacity=500.0)
        n1.status = NodeStatus.DEGRADED
        analyzer.add_node(n1)
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water", capacity=100.0))
        assert analyzer.network_effective_capacity() == 350.0

    def test_diamond_dependency_propagates_to_all_dependents(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_node(GridNode(node_id="HOSP-1", node_type="medical"))
        analyzer.add_node(GridNode(node_id="TRANS-1", node_type="transport"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        analyzer.add_dependency("HOSP-1", "GEN-1", weight=1.0)
        analyzer.add_dependency("TRANS-1", "GEN-1", weight=1.0)
        result = analyzer.simulate_failure("GEN-1")
        assert result.failed_nodes == {"GEN-1", "PUMP-1", "HOSP-1", "TRANS-1"}
        assert result.blast_radius == 4

    def test_partial_threshold_filters_weak_links_in_multi_hop(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_node(GridNode(node_id="HOSP-1", node_type="medical"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=0.9)
        analyzer.add_dependency("HOSP-1", "PUMP-1", weight=0.4)
        result = analyzer.simulate_failure("GEN-1")
        assert result.failed_nodes == {"GEN-1", "PUMP-1"}
        assert result.blast_radius == 2

    def test_custom_threshold_overrides_default(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=0.7)
        result = analyzer.simulate_failure("GEN-1", threshold=0.8)
        assert result.failed_nodes == {"GEN-1"}
        result2 = analyzer.simulate_failure("GEN-1", threshold=0.6)
        assert result2.failed_nodes == {"GEN-1", "PUMP-1"}

    def test_multiple_simulations_are_independent(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="GEN-1", node_type="power"))
        analyzer.add_node(GridNode(node_id="PUMP-1", node_type="water"))
        analyzer.add_dependency("PUMP-1", "GEN-1", weight=1.0)
        r1 = analyzer.simulate_failure("GEN-1")
        r2 = analyzer.simulate_failure("PUMP-1")
        assert r1.failed_nodes == {"GEN-1", "PUMP-1"}
        assert r2.failed_nodes == {"PUMP-1"}
