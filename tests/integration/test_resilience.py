"""
Integration tests for the Apex Resilience Grid full pipeline.

Tests cover:
  - Cross-domain orchestration (energy, water, transport, emergency)
  - Cascading failure analysis (multi-hop dependencies)
  - NIST/CISA compliance (audit trails, blast-radius isolation)
  - End-to-end resilience pipeline

TDD: These tests were written BEFORE the implementation.
"""

import pytest
import json
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers / Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def grid():
    """Build a small but realistic multi-domain grid for testing."""
    from src.grid.models import Grid, Domain, Node, Dependency

    g = Grid("test-grid")

    # Energy domain
    g.add_node(Node("power-plant-1", "energy", capacity=100))
    g.add_node(Node("substation-1", "energy", capacity=80))
    g.add_node(Node("substation-2", "energy", capacity=60))

    # Water domain
    g.add_node(Node("water-plant-1", "water", capacity=50))
    g.add_node(Node("pump-station-1", "water", capacity=30))

    # Transport domain
    g.add_node(Node("traffic-hub-1", "transport", capacity=40))
    g.add_node(Node("traffic-hub-2", "transport", capacity=35))

    # Emergency domain
    g.add_node(Node("hospital-1", "emergency", capacity=20))
    g.add_node(Node("fire-station-1", "emergency", capacity=15))

    # Dependencies (cross-domain)
    g.add_dependency(Dependency("substation-1", "power-plant-1"))
    g.add_dependency(Dependency("substation-2", "power-plant-1"))
    g.add_dependency(Dependency("water-plant-1", "substation-1"))
    g.add_dependency(Dependency("pump-station-1", "substation-1"))
    g.add_dependency(Dependency("traffic-hub-1", "substation-2"))
    g.add_dependency(Dependency("traffic-hub-2", "substation-2"))
    g.add_dependency(Dependency("hospital-1", "substation-1"))
    g.add_dependency(Dependency("hospital-1", "water-plant-1"))
    g.add_dependency(Dependency("fire-station-1", "substation-2"))
    g.add_dependency(Dependency("fire-station-1", "water-plant-1"))

    return g


@pytest.fixture
def pipeline(grid):
    """Create a resilience pipeline from a grid."""
    from src.grid.pipeline import ResiliencePipeline
    return ResiliencePipeline(grid)


# ---------------------------------------------------------------------------
# Test 1: Pipeline initialization
# ---------------------------------------------------------------------------

class TestPipelineInitialization:
    def test_pipeline_loads_grid(self, pipeline, grid):
        assert pipeline.grid is grid
        assert pipeline.grid.name == "test-grid"

    def test_pipeline_has_orchestrator(self, pipeline):
        assert pipeline.orchestrator is not None

    def test_pipeline_has_cascading_analyzer(self, pipeline):
        assert pipeline.cascading_analyzer is not None

    def test_pipeline_has_compliance_engine(self, pipeline):
        assert pipeline.compliance_engine is not None


# ---------------------------------------------------------------------------
# Test 2: Cross-domain orchestration
# ---------------------------------------------------------------------------

class TestCrossDomainOrchestration:
    def test_orchestrator_returns_all_domains(self, pipeline):
        domains = pipeline.orchestrator.get_domains()
        assert set(domains) == {"energy", "water", "transport", "emergency"}

    def test_orchestrator_returns_nodes_per_domain(self, pipeline):
        energy_nodes = pipeline.orchestrator.get_nodes_by_domain("energy")
        assert len(energy_nodes) == 3
        water_nodes = pipeline.orchestrator.get_nodes_by_domain("water")
        assert len(water_nodes) == 2

    def test_orchestrator_cross_domain_dependencies(self, pipeline):
        cross = pipeline.orchestrator.get_cross_domain_dependencies()
        assert len(cross) > 0
        # water-plant-1 depends on substation-1 (energy domain)
        assert any(
            d.source == "water-plant-1" and d.target == "substation-1"
            for d in cross
        )

    def test_orchestrator_domain_health(self, pipeline):
        health = pipeline.orchestrator.get_domain_health("energy")
        assert health["total_nodes"] == 3
        assert health["healthy_nodes"] == 3
        assert health["total_capacity"] == 240


# ---------------------------------------------------------------------------
# Test 3: Cascading failure analysis
# ---------------------------------------------------------------------------

class TestCascadingFailureAnalysis:
    def test_cascading_from_single_failure(self, pipeline):
        """Failing power-plant-1 should cascade to substations, then to water, transport, emergency."""
        result = pipeline.cascading_analyzer.analyze("power-plant-1")
        assert result is not None
        assert "power-plant-1" in result.affected_nodes
        assert "substation-1" in result.affected_nodes
        assert "substation-2" in result.affected_nodes
        # Multi-hop: water-plant-1 depends on substation-1
        assert "water-plant-1" in result.affected_nodes
        # Multi-hop: hospital-1 depends on substation-1 and water-plant-1
        assert "hospital-1" in result.affected_nodes

    def test_cascading_depth(self, pipeline):
        """Cascading should track hop depth."""
        result = pipeline.cascading_analyzer.analyze("power-plant-1")
        depths = result.node_depths
        assert depths["power-plant-1"] == 0
        assert depths["substation-1"] == 1
        assert depths["water-plant-1"] == 2
        assert depths["hospital-1"] == 2  # via substation-1

    def test_cascading_blast_radius(self, pipeline):
        """Blast radius = total affected nodes."""
        result = pipeline.cascading_analyzer.analyze("power-plant-1")
        assert result.blast_radius >= 5

    def test_cascading_from_leaf_node(self, pipeline):
        """Failing a leaf node should have minimal blast radius."""
        result = pipeline.cascading_analyzer.analyze("hospital-1")
        assert result.blast_radius == 1  # only itself

    def test_cascading_isolated_node(self, pipeline):
        """A node with no dependents has blast radius 1."""
        from src.grid.models import Node
        pipeline.grid.add_node(Node("isolated-1", "energy", capacity=10))
        result = pipeline.cascading_analyzer.analyze("isolated-1")
        assert result.blast_radius == 1
        assert result.affected_nodes == {"isolated-1"}


# ---------------------------------------------------------------------------
# Test 4: NIST/CISA compliance
# ---------------------------------------------------------------------------

class TestCompliance:
    def test_audit_trail_created(self, pipeline):
        """Every pipeline run should create an audit trail entry."""
        pipeline.run_full_analysis()
        audit_log = pipeline.compliance_engine.get_audit_log()
        assert len(audit_log) > 0

    def test_audit_trail_contains_timestamp(self, pipeline):
        pipeline.run_full_analysis()
        audit_log = pipeline.compliance_engine.get_audit_log()
        entry = audit_log[0]
        assert "timestamp" in entry
        assert "action" in entry

    def test_audit_trail_contains_actor(self, pipeline):
        pipeline.run_full_analysis()
        audit_log = pipeline.compliance_engine.get_audit_log()
        entry = audit_log[0]
        assert "actor" in entry

    def test_blast_radius_isolation(self, pipeline):
        """Compliance engine should identify isolation points."""
        result = pipeline.cascading_analyzer.analyze("power-plant-1")
        isolation_points = pipeline.compliance_engine.get_isolation_points(result)
        assert len(isolation_points) > 0
        # substation-1 is a key isolation point (many dependents)
        assert "substation-1" in isolation_points

    def test_compliance_report_generated(self, pipeline):
        """Pipeline should generate a compliance report."""
        report = pipeline.run_full_analysis()
        assert report is not None
        assert "audit_trail" in report
        assert "cascading_failures" in report
        assert "isolation_points" in report

    def test_compliance_report_is_json_serializable(self, pipeline):
        report = pipeline.run_full_analysis()
        json_str = json.dumps(report)
        assert len(json_str) > 0


# ---------------------------------------------------------------------------
# Test 5: Full pipeline end-to-end
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_full_pipeline_returns_report(self, pipeline):
        report = pipeline.run_full_analysis()
        assert isinstance(report, dict)
        assert "grid_name" in report
        assert report["grid_name"] == "test-grid"

    def test_full_pipeline_includes_all_domains(self, pipeline):
        report = pipeline.run_full_analysis()
        assert "domains" in report
        assert set(report["domains"]) == {"energy", "water", "transport", "emergency"}

    def test_full_pipeline_includes_cascading_for_all_nodes(self, pipeline):
        report = pipeline.run_full_analysis()
        cascading = report["cascading_failures"]
        # Should have cascading analysis for every node
        all_nodes = {n.id for n in pipeline.grid.get_all_nodes()}
        assert set(cascading.keys()) == all_nodes

    def test_full_pipeline_includes_isolation_points(self, pipeline):
        report = pipeline.run_full_analysis()
        assert "isolation_points" in report
        assert len(report["isolation_points"]) > 0

    def test_full_pipeline_includes_audit_trail(self, pipeline):
        report = pipeline.run_full_analysis()
        assert "audit_trail" in report
        assert len(report["audit_trail"]) > 0

    def test_full_pipeline_includes_compliance_status(self, pipeline):
        report = pipeline.run_full_analysis()
        assert "compliance_status" in report
        assert report["compliance_status"] in ("compliant", "non_compliant", "warning")

    def test_full_pipeline_summary_stats(self, pipeline):
        report = pipeline.run_full_analysis()
        assert "summary" in report
        summary = report["summary"]
        assert "total_nodes" in summary
        assert "total_dependencies" in summary
        assert "max_blast_radius" in summary
        assert summary["total_nodes"] == 9
        assert summary["total_dependencies"] == 10

    def test_pipeline_handles_empty_grid(self):
        from src.grid.models import Grid
        from src.grid.pipeline import ResiliencePipeline
        empty_grid = Grid("empty")
        p = ResiliencePipeline(empty_grid)
        report = p.run_full_analysis()
        assert report["summary"]["total_nodes"] == 0
        assert report["summary"]["total_dependencies"] == 0

    def test_pipeline_handles_single_node_grid(self):
        from src.grid.models import Grid, Node
        from src.grid.pipeline import ResiliencePipeline
        g = Grid("single")
        g.add_node(Node("only-node", "energy", capacity=100))
        p = ResiliencePipeline(g)
        report = p.run_full_analysis()
        assert report["summary"]["total_nodes"] == 1
        assert report["summary"]["max_blast_radius"] == 1

    def test_pipeline_identifies_critical_nodes(self, pipeline):
        """Critical nodes have the highest blast radius."""
        report = pipeline.run_full_analysis()
        critical = report.get("critical_nodes", [])
        assert len(critical) > 0
        # power-plant-1 should be critical (highest blast radius)
        assert "power-plant-1" in critical

    def test_pipeline_recovery_recommendations(self, pipeline):
        """Pipeline should generate recovery recommendations."""
        report = pipeline.run_full_analysis()
        recs = report.get("recovery_recommendations", [])
        assert len(recs) > 0
        # Should recommend redundancy for critical nodes
        assert any("redundancy" in r.lower() or "backup" in r.lower() for r in recs)

    def test_pipeline_resilience_score(self, pipeline):
        """Pipeline should compute an overall resilience score."""
        report = pipeline.run_full_analysis()
        score = report.get("resilience_score")
        assert score is not None
        assert 0 <= score <= 100


# ---------------------------------------------------------------------------
# Test 6: Audit trail persistence
# ---------------------------------------------------------------------------

class TestAuditTrailPersistence:
    def test_audit_trail_can_be_exported(self, pipeline, tmp_path):
        pipeline.run_full_analysis()
        export_path = tmp_path / "audit_log.json"
        pipeline.compliance_engine.export_audit_log(str(export_path))
        assert export_path.exists()
        data = json.loads(export_path.read_text())
        assert len(data) > 0

    def test_audit_trail_export_contains_required_fields(self, pipeline, tmp_path):
        pipeline.run_full_analysis()
        export_path = tmp_path / "audit_log.json"
        pipeline.compliance_engine.export_audit_log(str(export_path))
        data = json.loads(export_path.read_text())
        entry = data[0]
        assert "timestamp" in entry
        assert "action" in entry
        assert "actor" in entry
        assert "details" in entry


# ---------------------------------------------------------------------------
# Test 7: Multi-failure scenario
# ---------------------------------------------------------------------------

class TestMultiFailureScenario:
    def test_simultaneous_failures(self, pipeline):
        """Pipeline should handle multiple simultaneous failures."""
        result = pipeline.analyze_multiple_with_audit(["power-plant-1", "water-plant-1"])
        assert result is not None
        assert "power-plant-1" in result.affected_nodes
        assert "water-plant-1" in result.affected_nodes
        # Union of both blast radii
        assert result.blast_radius >= 5

    def test_multi_failure_audit_trail(self, pipeline):
        pipeline.analyze_multiple_with_audit(["power-plant-1", "water-plant-1"])
        audit_log = pipeline.compliance_engine.get_audit_log()
        # Should have entries for the multi-failure analysis
        assert len(audit_log) > 0


# ---------------------------------------------------------------------------
# Test 8: Domain isolation
# ---------------------------------------------------------------------------

class TestDomainIsolation:
    def test_isolate_domain(self, pipeline):
        """Isolating a domain should prevent cascading to other domains."""
        result = pipeline.isolate_domain_with_audit("energy")
        assert result is not None
        assert result["isolated_domain"] == "energy"
        assert "affected_nodes" in result

    def test_domain_isolation_creates_audit_entry(self, pipeline):
        pipeline.isolate_domain_with_audit("energy")
        audit_log = pipeline.compliance_engine.get_audit_log()
        isolation_entries = [e for e in audit_log if "isolate" in e.get("action", "").lower()]
        assert len(isolation_entries) > 0


# ---------------------------------------------------------------------------
# Test 9: Recovery orchestration
# ---------------------------------------------------------------------------

class TestRecoveryOrchestration:
    def test_recovery_plan_generated(self, pipeline):
        """Pipeline should generate a recovery plan after failures."""
        report = pipeline.run_full_analysis()
        recovery = report.get("recovery_plan")
        assert recovery is not None
        assert "steps" in recovery
        assert len(recovery["steps"]) > 0

    def test_recovery_plan_prioritizes_critical(self, pipeline):
        report = pipeline.run_full_analysis()
        recovery = report.get("recovery_plan")
        steps = recovery["steps"]
        # First step should address the most critical node
        assert "power-plant-1" in steps[0].get("target", "")


# ---------------------------------------------------------------------------
# Test 10: Stress / edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_circular_dependency_handled(self, pipeline):
        """Circular dependencies should not cause infinite loops."""
        from src.grid.models import Dependency
        # Create a cycle: A -> B -> C -> A
        pipeline.grid.add_dependency(Dependency("power-plant-1", "hospital-1"))
        result = pipeline.cascading_analyzer.analyze("power-plant-1")
        assert result is not None
        assert result.blast_radius > 0

    def test_self_dependency_ignored(self, pipeline):
        """Self-dependencies should be ignored."""
        from src.grid.models import Dependency
        pipeline.grid.add_dependency(Dependency("power-plant-1", "power-plant-1"))
        result = pipeline.cascading_analyzer.analyze("power-plant-1")
        assert result is not None

    def test_large_grid_performance(self):
        """Pipeline should handle a reasonably large grid."""
        from src.grid.models import Grid, Node, Dependency
        from src.grid.pipeline import ResiliencePipeline

        g = Grid("large")
        # Create 100 nodes across 4 domains
        domains = ["energy", "water", "transport", "emergency"]
        for i in range(100):
            domain = domains[i % 4]
            g.add_node(Node(f"node-{i}", domain, capacity=50))
        # Create ~200 dependencies
        for i in range(200):
            src = f"node-{i % 100}"
            tgt = f"node-{(i + 1) % 100}"
            if src != tgt:
                g.add_dependency(Dependency(src, tgt))

        p = ResiliencePipeline(g)
        report = p.run_full_analysis()
        assert report["summary"]["total_nodes"] == 100
        assert report["summary"]["total_dependencies"] > 0
