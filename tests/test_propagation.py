"""Unit tests for failure propagation modeling, critical node identification,
and resilience metrics (TDD)."""

import pytest

from src.grid.cascading import CascadingFailureAnalyzer, GridNode
from src.grid.propagation import (
    CriticalNodeIdentifier,
    CriticalityScore,
    FailurePropagationModel,
    PropagationConfig,
    PropagationTrace,
    ResilienceMetrics,
    ResilienceReport,
)


def make_analyzer():
    return CascadingFailureAnalyzer()


def build_linear_analyzer():
    """A -> B -> C -> D chain."""
    a = make_analyzer()
    a.add_node(GridNode(node_id="A", node_type="power", capacity=100.0))
    a.add_node(GridNode(node_id="B", node_type="water", capacity=100.0))
    a.add_node(GridNode(node_id="C", node_type="transport", capacity=100.0))
    a.add_node(GridNode(node_id="D", node_type="medical", capacity=100.0))
    a.add_dependency("B", "A", weight=1.0)
    a.add_dependency("C", "B", weight=1.0)
    a.add_dependency("D", "C", weight=1.0)
    return a


def build_redundant_analyzer():
    """A and B both feed C (redundant)."""
    a = make_analyzer()
    a.add_node(GridNode(node_id="A", node_type="power", capacity=100.0))
    a.add_node(GridNode(node_id="B", node_type="power", capacity=100.0))
    a.add_node(GridNode(node_id="C", node_type="water", capacity=100.0))
    a.add_dependency("C", "A", weight=1.0)
    a.add_dependency("C", "B", weight=1.0)
    return a


def build_star_analyzer():
    """Hub node H with 3 dependents."""
    a = make_analyzer()
    a.add_node(GridNode(node_id="H", node_type="power", capacity=100.0))
    a.add_node(GridNode(node_id="X", node_type="water", capacity=100.0))
    a.add_node(GridNode(node_id="Y", node_type="transport", capacity=100.0))
    a.add_node(GridNode(node_id="Z", node_type="medical", capacity=100.0))
    a.add_dependency("X", "H", weight=1.0)
    a.add_dependency("Y", "H", weight=1.0)
    a.add_dependency("Z", "H", weight=1.0)
    return a


class TestPropagationConfig:
    def test_default_config_values(self):
        config = PropagationConfig()
        assert config.threshold == 0.5
        assert config.propagation_probability == 1.0
        assert config.recovery_rate == 0.0
        assert config.max_steps == 100

    def test_custom_config_values(self):
        config = PropagationConfig(
            threshold=0.7,
            propagation_probability=0.8,
            recovery_rate=0.1,
            max_steps=50,
        )
        assert config.threshold == 0.7
        assert config.propagation_probability == 0.8
        assert config.recovery_rate == 0.1
        assert config.max_steps == 50


class TestFailurePropagationModel:
    def test_simulate_returns_trace(self):
        analyzer = build_linear_analyzer()
        model = FailurePropagationModel(analyzer)
        trace = model.simulate("A")
        assert isinstance(trace, PropagationTrace)
        assert trace.origin == "A"

    def test_simulate_records_steps(self):
        analyzer = build_linear_analyzer()
        model = FailurePropagationModel(analyzer)
        trace = model.simulate("A")
        assert len(trace.steps) > 0
        assert trace.total_steps == len(trace.steps)

    def test_simulate_final_failed_matches_cascade(self):
        analyzer = build_linear_analyzer()
        model = FailurePropagationModel(analyzer)
        trace = model.simulate("A")
        assert trace.final_failed == {"A", "B", "C", "D"}

    def test_simulate_isolated_node_single_step(self):
        analyzer = make_analyzer()
        analyzer.add_node(GridNode(node_id="ISO", node_type="power"))
        model = FailurePropagationModel(analyzer)
        trace = model.simulate("ISO")
        assert trace.final_failed == {"ISO"}
        assert trace.total_steps == 1

    def test_simulate_with_recovery(self):
        analyzer = build_linear_analyzer()
        config = PropagationConfig(recovery_rate=0.5)
        model = FailurePropagationModel(analyzer, config=config)
        trace = model.simulate("A")
        # With recovery, some nodes may recover
        assert isinstance(trace, PropagationTrace)
        assert trace.total_steps > 0

    def test_simulate_multiple_origins(self):
        analyzer = build_linear_analyzer()
        model = FailurePropagationModel(analyzer)
        trace = model.simulate_multiple(["A", "C"])
        assert "A" in trace.final_failed
        assert "C" in trace.final_failed

    def test_monte_carlo_returns_statistics(self):
        analyzer = build_linear_analyzer()
        model = FailurePropagationModel(analyzer)
        stats = model.monte_carlo("A", iterations=50)
        assert "mean_blast_radius" in stats
        assert "std_blast_radius" in stats
        assert "min_blast_radius" in stats
        assert "max_blast_radius" in stats
        assert "failure_probability" in stats

    def test_monte_carlo_deterministic_with_prob_1(self):
        analyzer = build_linear_analyzer()
        config = PropagationConfig(propagation_probability=1.0)
        model = FailurePropagationModel(analyzer, config=config)
        stats = model.monte_carlo("A", iterations=20)
        assert stats["std_blast_radius"] == 0.0
        assert stats["mean_blast_radius"] == 4.0

    def test_monte_carlo_with_probabilistic_propagation(self):
        analyzer = build_linear_analyzer()
        config = PropagationConfig(propagation_probability=0.5)
        model = FailurePropagationModel(analyzer, config=config)
        stats = model.monte_carlo("A", iterations=100)
        assert 1.0 <= stats["mean_blast_radius"] <= 4.0

    def test_propagation_trace_peak_concurrent(self):
        analyzer = build_star_analyzer()
        model = FailurePropagationModel(analyzer)
        trace = model.simulate("H")
        assert trace.peak_concurrent_failures >= 1


class TestCriticalNodeIdentifier:
    def test_identify_returns_ranked_nodes(self):
        analyzer = build_linear_analyzer()
        identifier = CriticalNodeIdentifier(analyzer)
        results = identifier.identify()
        assert len(results) > 0
        assert all(isinstance(r, CriticalityScore) for r in results)

    def test_identify_top_k_limits_results(self):
        analyzer = build_linear_analyzer()
        identifier = CriticalNodeIdentifier(analyzer)
        results = identifier.identify(top_k=2)
        assert len(results) <= 2

    def test_criticality_score_has_required_fields(self):
        analyzer = build_linear_analyzer()
        identifier = CriticalNodeIdentifier(analyzer)
        results = identifier.identify()
        score = results[0]
        assert score.node_id is not None
        assert score.blast_radius >= 1
        assert score.betweenness >= 0.0
        assert score.pagerank >= 0.0
        assert score.vulnerability_index >= 0.0
        assert score.rank >= 1

    def test_betweenness_centrality_identifies_bridge_nodes(self):
        analyzer = build_linear_analyzer()
        identifier = CriticalNodeIdentifier(analyzer)
        bc = identifier.betweenness_centrality()
        # B and C are bridges in A->B->C->D
        assert bc["B"] > bc["A"]
        assert bc["C"] > bc["D"]

    def test_pagerank_ranks_nodes(self):
        analyzer = build_star_analyzer()
        identifier = CriticalNodeIdentifier(analyzer)
        pr = identifier.pagerank()
        assert len(pr) == 4
        assert all(v >= 0.0 for v in pr.values())

    def test_identify_empty_graph_returns_empty(self):
        analyzer = make_analyzer()
        identifier = CriticalNodeIdentifier(analyzer)
        assert identifier.identify() == []

    def test_vulnerability_index_higher_for_critical_nodes(self):
        analyzer = build_star_analyzer()
        identifier = CriticalNodeIdentifier(analyzer)
        results = identifier.identify()
        hub_score = next(r for r in results if r.node_id == "H")
        leaf_score = next(r for r in results if r.node_id == "X")
        assert hub_score.vulnerability_index > leaf_score.vulnerability_index


class TestResilienceMetrics:
    def test_compute_returns_report(self):
        analyzer = build_linear_analyzer()
        metrics = ResilienceMetrics(analyzer)
        report = metrics.compute()
        assert isinstance(report, ResilienceReport)

    def test_robustness_index_range(self):
        analyzer = build_linear_analyzer()
        metrics = ResilienceMetrics(analyzer)
        ri = metrics.robustness_index()
        assert 0.0 <= ri <= 1.0

    def test_redundancy_ratio_range(self):
        analyzer = build_redundant_analyzer()
        metrics = ResilienceMetrics(analyzer)
        rr = metrics.redundancy_ratio()
        assert 0.0 <= rr <= 1.0

    def test_fragmentation_index_range(self):
        analyzer = build_linear_analyzer()
        metrics = ResilienceMetrics(analyzer)
        fi = metrics.fragmentation_index()
        assert 0.0 <= fi <= 1.0

    def test_resilience_report_overall_score(self):
        analyzer = build_linear_analyzer()
        metrics = ResilienceMetrics(analyzer)
        report = metrics.compute()
        assert 0.0 <= report.overall_score <= 1.0

    def test_redundant_network_scores_higher(self):
        linear = build_linear_analyzer()
        redundant = build_redundant_analyzer()
        linear_metrics = ResilienceMetrics(linear)
        redundant_metrics = ResilienceMetrics(redundant)
        assert redundant_metrics.compute().overall_score > linear_metrics.compute().overall_score

    def test_resilience_metrics_empty_graph(self):
        analyzer = make_analyzer()
        metrics = ResilienceMetrics(analyzer)
        report = metrics.compute()
        assert report.robustness_index == 1.0
        assert report.overall_score == 1.0

    def test_mean_time_to_failure_positive(self):
        analyzer = build_linear_analyzer()
        metrics = ResilienceMetrics(analyzer)
        report = metrics.compute()
        assert report.mean_time_to_failure > 0.0
