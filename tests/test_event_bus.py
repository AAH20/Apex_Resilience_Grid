"""Unit tests for the cross-domain event bus.

TDD: this file was written before ``src/grid/event_bus.py`` existed.
Run ``pytest tests/test_event_bus.py`` — every test should pass against
the implementation.
"""

import pytest

from src.grid.event_bus import (
    AmbiguousEntityError,
    AliasConflictError,
    CascadeResult,
    DeliveryReport,
    DependencyEdge,
    DependencyTracker,
    Domain,
    DomainEntity,
    EntityNotFoundError,
    EntityResolver,
    Event,
    EventBus,
)


@pytest.fixture
def resolver():
    r = EntityResolver()
    r.register(DomainEntity("feeder-1", Domain.ENERGY, "North Feeder"))
    r.register(DomainEntity("pump-1", Domain.WATER, "Pump Station 1"))
    r.register(DomainEntity("hub-1", Domain.TRANSPORT, "Central Hub"))
    r.register(DomainEntity("shelter-1", Domain.EMERGENCY, "Shelter A"))
    return r


class TestEntityResolver:
    def test_register_and_resolve_by_bare_id(self, resolver):
        e = resolver.resolve("feeder-1")
        assert e.domain is Domain.ENERGY
        assert e.name == "North Feeder"

    def test_resolve_by_qualified_id(self, resolver):
        e = resolver.resolve("water:pump-1")
        assert e.entity_id == "pump-1"
        assert e.domain is Domain.WATER

    def test_resolve_by_alias(self, resolver):
        resolver.add_alias("feeder-1", "grid-feeder")
        assert resolver.resolve("grid-feeder").entity_id == "feeder-1"

    def test_resolve_unknown_raises(self, resolver):
        with pytest.raises(EntityNotFoundError):
            resolver.resolve("nope")

    def test_resolve_ambiguous_bare_id_raises(self, resolver):
        resolver.register(DomainEntity("pump-1", Domain.ENERGY, "Energy pump"))
        with pytest.raises(AmbiguousEntityError):
            resolver.resolve("pump-1")

    def test_register_same_entity_twice_is_idempotent(self, resolver):
        resolver.register(DomainEntity("feeder-1", Domain.ENERGY, "Renamed"))
        assert resolver.resolve("feeder-1").name == "Renamed"
        assert len(resolver.entities_in_domain(Domain.ENERGY)) == 1

    def test_resolve_all_mixed_refs(self, resolver):
        resolver.add_alias("hub-1", "central")
        out = resolver.resolve_all(["energy:feeder-1", "central", "water:pump-1"])
        assert [e.qualified_id for e in out] == [
            "energy:feeder-1",
            "transport:hub-1",
            "water:pump-1",
        ]

    def test_alias_conflict_raises(self, resolver):
        resolver.add_alias("feeder-1", "shared-name")
        with pytest.raises(AliasConflictError):
            resolver.add_alias("pump-1", "shared-name")

    def test_entities_in_domain(self, resolver):
        got = resolver.entities_in_domain(Domain.EMERGENCY)
        assert [e.entity_id for e in got] == ["shelter-1"]


class TestEventBus:
    def test_publish_delivers_to_subscriber(self):
        bus = EventBus()
        seen = []
        bus.subscribe("asset.failure", lambda ev: seen.append(ev))
        event = Event("asset.failure", Domain.ENERGY)
        report = bus.publish(event)
        assert seen == [event]
        assert report.delivered_count == 1

    def test_subscribe_filters_by_event_type(self):
        bus = EventBus()
        failures, others = [], []
        bus.subscribe("asset.failure", lambda ev: failures.append(ev))
        bus.subscribe("asset.recovered", lambda ev: others.append(ev))
        bus.publish(Event("asset.failure", Domain.ENERGY))
        assert len(failures) == 1
        assert others == []

    def test_targeted_event_reaches_only_target_domains(self):
        bus = EventBus()
        water, energy = [], []
        bus.subscribe("alert", lambda ev: water.append(ev), domains={Domain.WATER})
        bus.subscribe("alert", lambda ev: energy.append(ev), domains={Domain.ENERGY})
        bus.publish(Event("alert", Domain.ENERGY, target_domains=[Domain.WATER]))
        assert len(water) == 1
        assert energy == []

    def test_broadcast_reaches_all_domains(self):
        bus = EventBus()
        got = {d: [] for d in Domain}
        for d in Domain:
            bus.subscribe("alert", lambda ev, d=d: got[d].append(ev), domains={d})
        bus.publish(Event("alert", Domain.ENERGY))  # broadcast
        assert all(len(v) == 1 for v in got.values())

    def test_priority_orders_handlers(self):
        bus = EventBus()
        order = []
        bus.subscribe("t", lambda ev: order.append("low"), priority=30)
        bus.subscribe("t", lambda ev: order.append("high"), priority=10)
        bus.subscribe("t", lambda ev: order.append("mid"), priority=20)
        bus.publish(Event("t", Domain.ENERGY))
        assert order == ["high", "mid", "low"]

    def test_unsubscribe_stops_delivery(self):
        bus = EventBus()
        seen = []
        sid = bus.subscribe("t", lambda ev: seen.append(ev))
        assert bus.unsubscribe(sid) is True
        bus.publish(Event("t", Domain.ENERGY))
        assert seen == []
        assert bus.unsubscribe(sid) is False

    def test_no_subscribers_dead_letters(self):
        bus = EventBus()
        event = Event("mystery", Domain.ENERGY)
        report = bus.publish(event)
        assert report.dead_lettered is True
        assert len(bus.dead_letters) == 1
        assert bus.dead_letters[0] is event

    def test_delivery_report_counts(self):
        bus = EventBus()

        def boom(ev):
            raise RuntimeError("handler exploded")

        bus.subscribe("t", boom)
        bus.subscribe("t", lambda ev: None)
        report = bus.publish(Event("t", Domain.ENERGY))
        assert report.delivered_count == 1
        assert report.failed_count == 1
        assert report.deliveries[0].error is not None

    def test_handler_exception_does_not_break_other_handlers(self):
        bus = EventBus()
        seen = []

        def boom(ev):
            raise ValueError("x")

        bus.subscribe("t", boom)
        bus.subscribe("t", lambda ev: seen.append(ev))
        bus.publish(Event("t", Domain.ENERGY))
        assert len(seen) == 1

    def test_wildcard_subscription_receives_all_types(self):
        bus = EventBus()
        seen = []
        bus.subscribe("*", lambda ev: seen.append(ev.event_type))
        bus.publish(Event("a", Domain.ENERGY))
        bus.publish(Event("b", Domain.WATER))
        assert seen == ["a", "b"]

    def test_get_subscribers_by_type_and_domain(self):
        bus = EventBus()
        bus.subscribe("t", lambda ev: None, domains={Domain.WATER})
        bus.subscribe("t", lambda ev: None, domains={Domain.ENERGY})
        bus.subscribe("other", lambda ev: None, domains={Domain.WATER})
        assert len(bus.get_subscribers(event_type="t")) == 2
        assert len(bus.get_subscribers(domain=Domain.WATER)) == 2
        assert len(bus.get_subscribers(event_type="t", domain=Domain.WATER)) == 1
        assert len(bus.get_subscribers()) == 3

    def test_publish_returns_report_with_event(self):
        bus = EventBus()
        event = Event("t", Domain.ENERGY, payload={"k": "v"})
        report = bus.publish(event)
        assert isinstance(report, DeliveryReport)
        assert report.event is event

    def test_subscriber_with_no_domain_receives_targeted_events(self):
        bus = EventBus()
        seen = []
        bus.subscribe("t", lambda ev: seen.append(ev))  # domains=None -> all
        bus.publish(Event("t", Domain.ENERGY, target_domains=[Domain.WATER]))
        assert len(seen) == 1

    def test_unresolved_refs_recorded_in_report(self, resolver):
        bus = EventBus(resolver=resolver)
        report = bus.publish(
            Event("t", Domain.ENERGY, entity_refs=["energy:feeder-1", "ghost"])
        )
        assert len(report.resolved_entities) == 1
        assert report.resolved_entities[0].entity_id == "feeder-1"
        assert report.unresolved_refs == ["ghost"]


class TestDependencyTracker:
    @pytest.fixture
    def tracker(self, resolver):
        return DependencyTracker(resolver)

    def test_add_and_query_dependencies_of(self, tracker):
        tracker.add_dependency("water:pump-1", "energy:feeder-1")
        assert tracker.dependencies_of("water:pump-1") == ["energy:feeder-1"]

    def test_dependents_of(self, tracker):
        tracker.add_dependency("water:pump-1", "energy:feeder-1")
        assert tracker.dependents_of("energy:feeder-1") == ["water:pump-1"]

    def test_cross_domain_edge(self, tracker):
        edge = tracker.add_dependency(
            "water:pump-1", "energy:feeder-1", relation="powered_by"
        )
        assert isinstance(edge, DependencyEdge)
        assert edge.dependent == "water:pump-1"
        assert edge.dependency == "energy:feeder-1"
        assert edge.relation == "powered_by"

    def test_cascade_single_hop(self, tracker):
        tracker.add_dependency("water:pump-1", "energy:feeder-1")
        result = tracker.cascade(["energy:feeder-1"])
        assert result.affected == {"energy:feeder-1": 0, "water:pump-1": 1}

    def test_cascade_multi_hop_distances(self, tracker):
        tracker.add_dependency("water:pump-1", "energy:feeder-1")
        tracker.add_dependency("transport:hub-1", "water:pump-1")
        tracker.add_dependency("emergency:shelter-1", "transport:hub-1")
        result = tracker.cascade(["energy:feeder-1"])
        assert result.affected == {
            "energy:feeder-1": 0,
            "water:pump-1": 1,
            "transport:hub-1": 2,
            "emergency:shelter-1": 3,
        }

    def test_cascade_across_domains(self, tracker):
        tracker.add_dependency("water:pump-1", "energy:feeder-1")
        tracker.add_dependency("emergency:shelter-1", "water:pump-1")
        result = tracker.cascade(["energy:feeder-1"])
        assert result.domains_affected == {Domain.ENERGY, Domain.WATER, Domain.EMERGENCY}

    def test_cascade_cycle_safe(self, resolver, tracker):
        resolver.register(DomainEntity("a1", Domain.ENERGY))
        resolver.register(DomainEntity("b2", Domain.WATER))
        resolver.register(DomainEntity("c3", Domain.TRANSPORT))
        tracker.add_dependency("energy:a1", "water:b2")
        tracker.add_dependency("water:b2", "transport:c3")
        tracker.add_dependency("transport:c3", "energy:a1")
        result = tracker.cascade(["energy:a1"])
        assert set(result.affected) == {"energy:a1", "water:b2", "transport:c3"}
        assert tracker.has_cycle() is True

    def test_cascade_unknown_entity_raises(self, tracker):
        with pytest.raises(EntityNotFoundError):
            tracker.cascade(["energy:ghost"])

    def test_cascade_no_dependents_empty(self, tracker):
        result = tracker.cascade(["energy:feeder-1"])
        assert result.affected == {"energy:feeder-1": 0}
        assert result.edges_traversed == []

    def test_cascade_max_hops(self, tracker):
        tracker.add_dependency("water:pump-1", "energy:feeder-1")
        tracker.add_dependency("transport:hub-1", "water:pump-1")
        result = tracker.cascade(["energy:feeder-1"], max_hops=1)
        assert result.affected == {"energy:feeder-1": 0, "water:pump-1": 1}

    def test_dependency_path_found(self, tracker):
        tracker.add_dependency("water:pump-1", "energy:feeder-1")
        tracker.add_dependency("transport:hub-1", "water:pump-1")
        path = tracker.dependency_path("transport:hub-1", "energy:feeder-1")
        assert path == ["transport:hub-1", "water:pump-1", "energy:feeder-1"]

    def test_dependency_path_none_when_unreachable(self, tracker):
        tracker.add_dependency("water:pump-1", "energy:feeder-1")
        assert tracker.dependency_path("energy:feeder-1", "water:pump-1") is None

    def test_remove_dependency(self, tracker):
        tracker.add_dependency("water:pump-1", "energy:feeder-1")
        assert tracker.remove_dependency("water:pump-1", "energy:feeder-1") is True
        assert tracker.dependencies_of("water:pump-1") == []
        assert tracker.remove_dependency("water:pump-1", "energy:feeder-1") is False

    def test_has_cycle_false_for_dag(self, tracker):
        tracker.add_dependency("water:pump-1", "energy:feeder-1")
        tracker.add_dependency("transport:hub-1", "water:pump-1")
        assert tracker.has_cycle() is False

    def test_has_dependency(self, tracker):
        tracker.add_dependency("water:pump-1", "energy:feeder-1")
        assert tracker.has_dependency("water:pump-1", "energy:feeder-1") is True
        assert tracker.has_dependency("energy:feeder-1", "water:pump-1") is False


class TestCrossDomainIntegration:
    def test_failure_event_triggers_cross_domain_cascade(self, resolver):
        tracker = DependencyTracker(resolver)
        tracker.add_dependency("water:pump-1", "energy:feeder-1")
        tracker.add_dependency("transport:hub-1", "water:pump-1")
        tracker.add_dependency("emergency:shelter-1", "transport:hub-1")

        bus = EventBus(resolver=resolver)
        cascades = []

        def on_failure(event):
            assert isinstance(event, Event)
            cascades.append(tracker.cascade(event.entity_refs))

        bus.subscribe(
            "asset.failure",
            on_failure,
            domains={Domain.WATER, Domain.TRANSPORT, Domain.EMERGENCY},
        )
        event = Event("asset.failure", Domain.ENERGY, entity_refs=["energy:feeder-1"])
        report = bus.publish(event)

        assert report.delivered_count == 1
        assert report.resolved_entities[0].entity_id == "feeder-1"
        assert cascades[0].domains_affected == {
            Domain.ENERGY,
            Domain.WATER,
            Domain.TRANSPORT,
            Domain.EMERGENCY,
        }

    def test_cascade_result_type(self, resolver):
        tracker = DependencyTracker(resolver)
        tracker.add_dependency("water:pump-1", "energy:feeder-1")
        result = tracker.cascade(["energy:feeder-1"])
        assert isinstance(result, CascadeResult)
        assert result.max_hops == 1
