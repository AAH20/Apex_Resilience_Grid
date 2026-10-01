"""Cross-domain event bus for the Apex Resilience Grid.

Provides three collaborating pieces:

* :class:`EventBus` — publish/subscribe routing with domain filtering,
  priority-ordered handlers, wildcard subscriptions, dead-letter capture,
  and per-delivery error isolation.
* :class:`EntityResolver` — shared entity resolution across domains:
  bare IDs, qualified IDs (``domain:id``), and aliases, with ambiguity
  detection.
* :class:`DependencyTracker` — inter-domain dependency graph with
  multi-hop cascade analysis, cycle detection, and path queries.

All classes are dependency-light (stdlib only) and thread-unsafe by
design; callers serialize access if needed.
"""

from __future__ import annotations

import enum
import itertools
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple


class Domain(enum.Enum):
    """Infrastructure domains participating in the grid."""

    ENERGY = "energy"
    WATER = "water"
    TRANSPORT = "transport"
    EMERGENCY = "emergency"


class EventBusError(Exception):
    """Base class for event-bus errors."""


class EntityNotFoundError(EventBusError):
    """Raised when an entity reference cannot be resolved."""


class AmbiguousEntityError(EventBusError):
    """Raised when a bare ID matches entities in multiple domains."""


class AliasConflictError(EventBusError):
    """Raised when an alias is already bound to a different entity."""


@dataclass(frozen=True)
class DomainEntity:
    """An entity that lives in exactly one domain."""

    entity_id: str
    domain: Domain
    name: str = ""

    @property
    def qualified_id(self) -> str:
        return f"{self.domain.value}:{self.entity_id}"


@dataclass
class Event:
    """A routable event.

    ``target_domains`` empty means broadcast to all domains; otherwise
    delivery is restricted to the listed domains.
    """

    event_type: str
    source_domain: Domain
    entity_refs: List[str] = field(default_factory=list)
    target_domains: Optional[List[Domain]] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    event_id: str = ""

    def __post_init__(self) -> None:
        if not self.event_id:
            self.event_id = f"{self.source_domain.value}:{id(self):x}"


@dataclass
class Delivery:
    """Outcome of delivering one event to one subscriber."""

    subscriber_id: str
    event_type: str
    delivered: bool
    error: Optional[str] = None


@dataclass
class DeliveryReport:
    """Summary of a single :meth:`EventBus.publish` call."""

    event: Event
    deliveries: List[Delivery] = field(default_factory=list)
    resolved_entities: List[DomainEntity] = field(default_factory=list)
    unresolved_refs: List[str] = field(default_factory=list)
    dead_lettered: bool = False

    @property
    def delivered_count(self) -> int:
        return sum(1 for d in self.deliveries if d.delivered)

    @property
    def failed_count(self) -> int:
        return sum(1 for d in self.deliveries if not d.delivered)


@dataclass(frozen=True)
class DependencyEdge:
    """A directed dependency: ``dependent`` relies on ``dependency``."""

    dependent: str
    dependency: str
    relation: str = "depends_on"


@dataclass
class CascadeResult:
    """Result of a cascade analysis from one or more origin entities."""

    affected: Dict[str, int] = field(default_factory=dict)
    edges_traversed: List[DependencyEdge] = field(default_factory=list)
    origins: List[str] = field(default_factory=list)

    @property
    def domains_affected(self) -> Set[Domain]:
        """Domains touched by the cascade (requires resolver context)."""

        def _domain_of(ref: str) -> Optional[Domain]:
            if ":" in ref:
                try:
                    return Domain(ref.split(":", 1)[0])
                except ValueError:
                    return None
            return None

        return {d for d in (_domain_of(r) for r in self.affected) if d is not None}

    @property
    def max_hops(self) -> int:
        return max(self.affected.values(), default=0)


class EntityResolver:
    """Resolves entity references across domains.

    Lookup order for a reference:
      1. qualified id ``domain:id``
      2. alias
      3. bare id — unique across all domains, else :class:`AmbiguousEntityError`
    """

    def __init__(self) -> None:
        self._entities: Dict[str, DomainEntity] = {}
        self._by_domain: Dict[Domain, Dict[str, DomainEntity]] = defaultdict(dict)
        self._aliases: Dict[str, str] = {}

    # -- registration ---------------------------------------------------

    def register(self, entity: DomainEntity) -> None:
        """Register (or replace) an entity."""
        self._entities[entity.qualified_id] = entity
        self._by_domain[entity.domain][entity.entity_id] = entity

    def add_alias(self, entity_ref: str, alias: str) -> None:
        """Bind ``alias`` to the entity referenced by ``entity_ref``."""
        target = self.resolve(entity_ref)
        existing = self._aliases.get(alias)
        if existing is not None and existing != target.qualified_id:
            raise AliasConflictError(
                f"alias {alias!r} already bound to {existing}"
            )
        self._aliases[alias] = target.qualified_id

    # -- resolution -----------------------------------------------------

    def resolve(self, ref: str) -> DomainEntity:
        """Resolve a single reference to a :class:`DomainEntity`."""
        if ":" in ref:
            entity = self._entities.get(ref)
            if entity is not None:
                return entity
            # fall through: maybe it's an alias containing a colon
        if ref in self._aliases:
            return self._entities[self._aliases[ref]]
        # bare id: must be unique across domains
        matches = [
            e
            for domain_map in self._by_domain.values()
            for eid, e in domain_map.items()
            if eid == ref
        ]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise EntityNotFoundError(f"unknown entity reference: {ref!r}")
        domains = sorted(e.domain.value for e in matches)
        raise AmbiguousEntityError(
            f"bare id {ref!r} is ambiguous across domains: {domains}"
        )

    def resolve_all(self, refs: Iterable[str]) -> List[DomainEntity]:
        """Resolve many references, preserving order."""
        return [self.resolve(r) for r in refs]

    # -- introspection --------------------------------------------------

    def entities_in_domain(self, domain: Domain) -> List[DomainEntity]:
        """All entities registered in ``domain``."""
        return list(self._by_domain.get(domain, {}).values())


class EventBus:
    """Publish/subscribe event bus with domain-aware routing."""

    WILDCARD = "*"

    def __init__(self, resolver: Optional[EntityResolver] = None) -> None:
        self._resolver = resolver
        self._subscribers: Dict[str, List[Tuple[int, str, Callable[[Event], None], Optional[Set[Domain]]]]] = defaultdict(list)
        self._by_id: Dict[str, Tuple[int, str, Callable[[Event], None], Optional[Set[Domain]]]] = {}
        self._counter = itertools.count(1)
        self.dead_letters: List[Event] = []

    # -- subscription ---------------------------------------------------

    def subscribe(
        self,
        event_type: str,
        handler: Callable[[Event], None],
        *,
        priority: int = 50,
        domains: Optional[Set[Domain]] = None,
    ) -> str:
        """Register ``handler`` for ``event_type``.

        ``priority`` lower values run first. ``domains`` restricts delivery
        to events whose ``target_domains`` intersect the set; ``None``
        means all domains. Returns a subscription id for :meth:`unsubscribe`.
        """
        sid = f"sub-{next(self._counter)}"
        entry = (priority, sid, handler, domains)
        self._subscribers[event_type].append(entry)
        self._subscribers[event_type].sort(key=lambda e: (e[0], e[1]))
        self._by_id[sid] = entry
        return sid

    def unsubscribe(self, subscriber_id: str) -> bool:
        """Remove a subscription by id. Returns True if it existed."""
        entry = self._by_id.pop(subscriber_id, None)
        if entry is None:
            return False
        _, _, _, _ = entry
        for etype, entries in self._subscribers.items():
            for e in list(entries):
                if e[1] == subscriber_id:
                    entries.remove(e)
                    return True
        return False

    def get_subscribers(
        self,
        *,
        event_type: Optional[str] = None,
        domain: Optional[Domain] = None,
    ) -> List[str]:
        """List subscriber ids, optionally filtered by type and/or domain."""
        out: List[str] = []
        for etype, entries in self._subscribers.items():
            if event_type is not None and etype != event_type and etype != self.WILDCARD:
                continue
            for _, sid, _, doms in entries:
                if domain is not None:
                    if doms is not None and domain not in doms:
                        continue
                out.append(sid)
        return out

    # -- publishing -----------------------------------------------------

    def publish(self, event: Event) -> DeliveryReport:
        """Deliver ``event`` to all matching subscribers.

        Handler exceptions are captured per-delivery and never propagate.
        If no subscriber matches, the event is dead-lettered.
        """
        report = DeliveryReport(event=event)

        # resolve entity refs through the shared resolver
        if self._resolver is not None and event.entity_refs:
            for ref in event.entity_refs:
                try:
                    report.resolved_entities.append(self._resolver.resolve(ref))
                except EventBusError:
                    report.unresolved_refs.append(ref)

        targets = self._matching_subscribers(event)
        if not targets:
            report.dead_lettered = True
            self.dead_letters.append(event)
            return report

        for priority, sid, handler, _domains in targets:
            try:
                handler(event)
                report.deliveries.append(
                    Delivery(subscriber_id=sid, event_type=event.event_type, delivered=True)
                )
            except Exception as exc:  # noqa: BLE001 - isolate handler failures
                report.deliveries.append(
                    Delivery(
                        subscriber_id=sid,
                        event_type=event.event_type,
                        delivered=False,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
        return report

    # -- internals ------------------------------------------------------

    def _matching_subscribers(
        self, event: Event
    ) -> List[Tuple[int, str, Callable[[Event], None], Optional[Set[Domain]]]]:
        """Subscribers that should receive ``event``, priority-ordered."""
        candidates: List[Tuple[int, str, Callable[[Event], None], Optional[Set[Domain]]]] = []
        for etype in (event.event_type, self.WILDCARD):
            candidates.extend(self._subscribers.get(etype, []))
        # dedupe (a handler subscribed to both type and wildcard runs once)
        seen: Set[str] = set()
        unique = []
        for entry in candidates:
            if entry[1] not in seen:
                seen.add(entry[1])
                unique.append(entry)
        unique.sort(key=lambda e: (e[0], e[1]))

        matched = []
        for entry in unique:
            _prio, _sid, _handler, domains = entry
            if not self._domain_allowed(event, domains):
                continue
            matched.append(entry)
        return matched

    @staticmethod
    def _domain_allowed(event: Event, domains: Optional[Set[Domain]]) -> bool:
        """Whether a subscriber with ``domains`` may see ``event``."""
        if domains is None:
            return True
        if not event.target_domains:
            return True  # broadcast reaches everyone
        return bool(domains.intersection(event.target_domains))


class DependencyTracker:
    """Inter-domain dependency graph with cascade analysis."""

    def __init__(self, resolver: Optional[EntityResolver] = None) -> None:
        self._resolver = resolver
        self._graph: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)
        self._reverse: Dict[str, Set[str]] = defaultdict(set)

    # -- graph construction ---------------------------------------------

    def add_dependency(
        self, dependent: str, dependency: str, *, relation: str = "depends_on"
    ) -> DependencyEdge:
        """Record that ``dependent`` relies on ``dependency``."""
        self._assert_resolvable(dependent)
        self._assert_resolvable(dependency)
        edge = DependencyEdge(dependent=dependent, dependency=dependency, relation=relation)
        self._graph[dependent].add((dependency, relation))
        self._reverse[dependency].add(dependent)
        return edge

    def remove_dependency(self, dependent: str, dependency: str) -> bool:
        """Remove a dependency edge. Returns True if it existed."""
        removed = False
        for dep, rel in list(self._graph.get(dependent, ())):
            if dep == dependency:
                self._graph[dependent].discard((dep, rel))
                removed = True
        if removed:
            self._reverse[dependency].discard(dependent)
        return removed

    # -- queries --------------------------------------------------------

    def dependencies_of(self, entity_ref: str) -> List[str]:
        """Direct dependencies of ``entity_ref`` (things it needs)."""
        return sorted({dep for dep, _ in self._graph.get(entity_ref, ())})

    def dependents_of(self, entity_ref: str) -> List[str]:
        """Direct dependents of ``entity_ref`` (things that need it)."""
        return sorted(self._reverse.get(entity_ref, ()))

    def has_dependency(self, dependent: str, dependency: str) -> bool:
        """Whether ``dependent`` directly depends on ``dependency``."""
        return any(dep == dependency for dep, _ in self._graph.get(dependent, ()))

    def dependency_path(self, start: str, goal: str) -> Optional[List[str]]:
        """Shortest dependency chain from ``start`` to ``goal``, or None."""
        if start == goal:
            return [start]
        visited = {start}
        queue: deque[Tuple[str, List[str]]] = deque([(start, [start])])
        while queue:
            node, path = queue.popleft()
            for dep, _ in sorted(self._graph.get(node, ())):
                if dep in visited:
                    continue
                new_path = path + [dep]
                if dep == goal:
                    return new_path
                visited.add(dep)
                queue.append((dep, new_path))
        return None

    # -- cascade analysis -----------------------------------------------

    def cascade(
        self, origins: Iterable[str], *, max_hops: Optional[int] = None
    ) -> CascadeResult:
        """BFS outward from ``origins`` through the dependency graph.

        Returns a :class:`CascadeResult` mapping each affected entity to
        its hop distance from the nearest origin.
        """
        result = CascadeResult(origins=list(origins))
        queue: deque[Tuple[str, int]] = deque()
        for origin in result.origins:
            self._assert_resolvable(origin)
            if origin not in result.affected:
                result.affected[origin] = 0
                queue.append((origin, 0))

        while queue:
            node, dist = queue.popleft()
            if max_hops is not None and dist >= max_hops:
                continue
            for dependent in sorted(self._reverse.get(node, ())):
                if dependent not in result.affected:
                    result.affected[dependent] = dist + 1
                    result.edges_traversed.append(
                        DependencyEdge(dependent=dependent, dependency=node)
                    )
                    queue.append((dependent, dist + 1))
        return result

    # -- cycle detection ------------------------------------------------

    def has_cycle(self) -> bool:
        """Whether the dependency graph contains a cycle (DFS)."""
        WHITE, GRAY, BLACK = 0, 1, 2
        color: Dict[str, int] = defaultdict(int)

        def visit(node: str) -> bool:
            color[node] = GRAY
            for dep, _ in self._graph.get(node, ()):
                if color[dep] == GRAY:
                    return True
                if color[dep] == WHITE and visit(dep):
                    return True
            color[node] = BLACK
            return False

        for node in list(self._graph):
            if color[node] == WHITE:
                if visit(node):
                    return True
        return False

    # -- internals ------------------------------------------------------

    def _assert_resolvable(self, ref: str) -> None:
        if self._resolver is not None:
            self._resolver.resolve(ref)
