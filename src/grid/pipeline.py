"""Full resilience pipeline for the Apex Resilience Grid."""

from typing import Dict, List, Set, Optional
from .models import Grid, CascadingResult
from .orchestrator import CrossDomainOrchestrator
from .cascading import CascadingFailureAnalyzer
from .compliance import ComplianceEngine


class ResiliencePipeline:
    """End-to-end resilience analysis pipeline."""

    def __init__(self, grid: Grid):
        self.grid = grid
        self.orchestrator = CrossDomainOrchestrator(grid)
        self.cascading_analyzer = CascadingFailureAnalyzer()
        # Populate the cascading analyzer from the grid
        from .cascading import GridNode
        for node in grid.get_all_nodes():
            self.cascading_analyzer.add_node(
                GridNode(node_id=node.id, node_type=node.domain, capacity=node.capacity)
            )
        for dep in grid.get_all_dependencies():
            self.cascading_analyzer.add_dependency(dep.source, dep.target)
        self.compliance_engine = ComplianceEngine(grid)

    def _sync_cascading_analyzer(self):
        """Re-sync the cascading analyzer with the current grid state."""
        from .cascading import GridNode
        self.cascading_analyzer.nodes.clear()
        self.cascading_analyzer.dependencies.clear()
        for node in self.grid.get_all_nodes():
            self.cascading_analyzer.add_node(
                GridNode(node_id=node.id, node_type=node.domain, capacity=node.capacity)
            )
        for dep in self.grid.get_all_dependencies():
            self.cascading_analyzer.add_dependency(dep.source, dep.target)

    def run_full_analysis(self) -> Dict:
        """Run the complete resilience analysis pipeline."""
        # Sync cascading analyzer with current grid state
        self._sync_cascading_analyzer()
        # Log pipeline start
        self.compliance_engine.log_action(
            "pipeline_start",
            details={"grid_name": self.grid.name},
        )

        # Gather domain info
        domains = self.orchestrator.get_domains()

        # Run cascading analysis for all nodes
        cascading_results: Dict[str, Dict] = {}
        max_blast_radius = 0
        for node in self.grid.get_all_nodes():
            result = self.cascading_analyzer.analyze(node.id)
            cascading_results[node.id] = {
                "blast_radius": result.blast_radius,
                "affected_nodes": list(result.affected_nodes),
                "node_depths": result.node_depths,
            }
            if result.blast_radius > max_blast_radius:
                max_blast_radius = result.blast_radius

        # Identify critical nodes (highest blast radius)
        critical_nodes = [
            node_id for node_id, data in cascading_results.items()
            if data["blast_radius"] == max_blast_radius and max_blast_radius > 1
        ]

        # Get isolation points from the most critical node
        isolation_points: List[str] = []
        if critical_nodes:
            critical_result = self.cascading_analyzer.analyze(critical_nodes[0])
            isolation_points = self.compliance_engine.get_isolation_points(critical_result)

        # Generate recovery recommendations
        recovery_recommendations = self._generate_recovery_recommendations(
            critical_nodes, cascading_results
        )

        # Generate recovery plan
        recovery_plan = self._generate_recovery_plan(critical_nodes, cascading_results)

        # Compute resilience score
        resilience_score = self._compute_resilience_score(cascading_results)

        # Log pipeline completion
        self.compliance_engine.log_action(
            "pipeline_complete",
            details={
                "grid_name": self.grid.name,
                "nodes_analyzed": len(cascading_results),
                "max_blast_radius": max_blast_radius,
            },
        )

        # Build report
        report = {
            "grid_name": self.grid.name,
            "domains": list(domains),
            "cascading_failures": cascading_results,
            "isolation_points": isolation_points,
            "audit_trail": self.compliance_engine.get_audit_log(),
            "compliance_status": self.compliance_engine.check_compliance_status(),
            "critical_nodes": critical_nodes,
            "recovery_recommendations": recovery_recommendations,
            "recovery_plan": recovery_plan,
            "resilience_score": resilience_score,
            "summary": {
                "total_nodes": len(self.grid.get_all_nodes()),
                "total_dependencies": len(self.grid.get_all_dependencies()),
                "max_blast_radius": max_blast_radius,
            },
        }

        return report

    def analyze_multiple_with_audit(self, origins: List[str]):
        """Analyze multiple failures and log to audit trail."""
        self._sync_cascading_analyzer()
        result = self.cascading_analyzer.analyze_multiple(origins)
        self.compliance_engine.log_action(
            "multi_failure_analysis",
            details={"origins": origins, "blast_radius": result.blast_radius},
        )
        return result

    def isolate_domain_with_audit(self, domain: str) -> Dict:
        """Isolate a domain and log to audit trail."""
        result = self.orchestrator.isolate_domain(domain)
        self.compliance_engine.log_action(
            "isolate_domain",
            details={"domain": domain, "affected_nodes": result["affected_nodes"]},
        )
        return result

    def _generate_recovery_recommendations(
        self, critical_nodes: List[str], cascading_results: Dict
    ) -> List[str]:
        """Generate recovery recommendations based on analysis."""
        recommendations = []
        for node_id in critical_nodes:
            node = self.grid.get_node(node_id)
            if node:
                recommendations.append(
                    f"Add redundancy for critical node {node_id} in domain {node.domain}"
                )
                recommendations.append(
                    f"Implement backup power supply for {node_id}"
                )
        if not recommendations:
            recommendations.append("No critical nodes identified — maintain current resilience posture")
        return recommendations

    def _generate_recovery_plan(
        self, critical_nodes: List[str], cascading_results: Dict
    ) -> Dict:
        """Generate a prioritized recovery plan."""
        steps = []
        for node_id in critical_nodes:
            node = self.grid.get_node(node_id)
            if node:
                steps.append({
                    "target": node_id,
                    "domain": node.domain,
                    "priority": 1,
                    "action": "restore_service",
                })
        # Add remaining nodes sorted by blast radius
        remaining = [
            (node_id, data["blast_radius"])
            for node_id, data in cascading_results.items()
            if node_id not in critical_nodes
        ]
        remaining.sort(key=lambda x: -x[1])
        for node_id, _ in remaining:
            node = self.grid.get_node(node_id)
            if node:
                steps.append({
                    "target": node_id,
                    "domain": node.domain,
                    "priority": 2,
                    "action": "verify_integrity",
                })
        return {"steps": steps}

    def _compute_resilience_score(self, cascading_results: Dict) -> int:
        """Compute an overall resilience score (0-100)."""
        if not cascading_results:
            return 100
        total_nodes = len(cascading_results)
        # Score based on average blast radius — lower is better
        avg_blast = sum(d["blast_radius"] for d in cascading_results.values()) / total_nodes
        # Normalize: if avg blast radius is 1, score is 100; if it's total_nodes, score is 0
        if total_nodes <= 1:
            return 100
        score = int(100 * (1 - (avg_blast - 1) / (total_nodes - 1)))
        return max(0, min(100, score))
