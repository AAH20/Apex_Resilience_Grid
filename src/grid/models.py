"""Core data models for the Apex Resilience Grid."""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional


@dataclass
class Node:
    """A node in the resilience grid."""
    id: str
    domain: str
    capacity: float = 0.0
    metadata: dict = field(default_factory=dict)


@dataclass
class Dependency:
    """A directed dependency: source depends on target."""
    source: str
    target: str


@dataclass
class Domain:
    """A domain in the grid (energy, water, transport, emergency)."""
    name: str
    description: str = ""


@dataclass
class CascadingResult:
    """Result of a cascading failure analysis."""
    origin: str
    affected_nodes: Set[str]
    node_depths: Dict[str, int]
    blast_radius: int


class Grid:
    """The resilience grid containing nodes and dependencies."""

    def __init__(self, name: str):
        self.name = name
        self._nodes: Dict[str, Node] = {}
        self._dependencies: List[Dependency] = []
        self._dependents: Dict[str, Set[str]] = {}  # target -> set of sources

    def add_node(self, node: Node) -> None:
        self._nodes[node.id] = node
        if node.id not in self._dependents:
            self._dependents[node.id] = set()

    def add_dependency(self, dep: Dependency) -> None:
        self._dependencies.append(dep)
        if dep.target not in self._dependents:
            self._dependents[dep.target] = set()
        self._dependents[dep.target].add(dep.source)

    def get_node(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id)

    def get_all_nodes(self) -> List[Node]:
        return list(self._nodes.values())

    def get_all_dependencies(self) -> List[Dependency]:
        return list(self._dependencies)

    def get_dependents(self, node_id: str) -> Set[str]:
        """Get all nodes that depend on the given node."""
        return self._dependents.get(node_id, set())

    def get_dependencies_of(self, node_id: str) -> List[Dependency]:
        """Get all dependencies where the given node is the source."""
        return [d for d in self._dependencies if d.source == node_id]

    def get_nodes_by_domain(self, domain: str) -> List[Node]:
        return [n for n in self._nodes.values() if n.domain == domain]

    def get_domains(self) -> Set[str]:
        return {n.domain for n in self._nodes.values()}

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes
