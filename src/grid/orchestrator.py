"""Cross-domain orchestration for the Apex Resilience Grid."""

from typing import Dict, List, Set, Optional
from .models import Grid, Node, Dependency


class CrossDomainOrchestrator:
    """Orchestrates operations across multiple domains."""

    def __init__(self, grid: Grid):
        self.grid = grid

    def get_domains(self) -> Set[str]:
        return self.grid.get_domains()

    def get_nodes_by_domain(self, domain: str) -> List[Node]:
        return self.grid.get_nodes_by_domain(domain)

    def get_cross_domain_dependencies(self) -> List[Dependency]:
        """Get dependencies that cross domain boundaries."""
        result = []
        for dep in self.grid.get_all_dependencies():
            source_node = self.grid.get_node(dep.source)
            target_node = self.grid.get_node(dep.target)
            if source_node and target_node and source_node.domain != target_node.domain:
                result.append(dep)
        return result

    def get_domain_health(self, domain: str) -> Dict:
        """Get health metrics for a domain."""
        nodes = self.grid.get_nodes_by_domain(domain)
        total_capacity = sum(n.capacity for n in nodes)
        return {
            "total_nodes": len(nodes),
            "healthy_nodes": len(nodes),  # Simplified: all nodes healthy by default
            "total_capacity": total_capacity,
        }

    def isolate_domain(self, domain: str) -> Dict:
        """Isolate a domain from the rest of the grid."""
        nodes = self.grid.get_nodes_by_domain(domain)
        affected = {n.id for n in nodes}
        return {
            "isolated_domain": domain,
            "affected_nodes": list(affected),
            "node_count": len(nodes),
        }
