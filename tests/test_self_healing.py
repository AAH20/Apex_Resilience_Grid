"""TDD tests for self-healing framework: circuit breakers, auto-failover, health monitoring, recovery."""
import pytest
import time
from src.grid.self_healing import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    HealthMonitor,
    FailoverManager,
    FailoverExhaustedError,
    SelfHealingEngine,
    ComponentStatus,
)


# ── Circuit Breaker tests ──────────────────────────────────────────────

class TestCircuitBreaker:
    def test_circuit_breaker_starts_closed(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        assert cb.state == "CLOSED"

    def test_circuit_breaker_allows_calls_when_closed(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        result = cb.call(lambda: "success")
        assert result == "success"

    def test_circuit_breaker_counts_failures(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        assert cb.failure_count == 2
        assert cb.state == "CLOSED"

    def test_circuit_breaker_opens_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        for _ in range(3):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        assert cb.state == "OPEN"

    def test_circuit_breaker_blocks_calls_when_open(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=10.0)
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        with pytest.raises(CircuitBreakerOpenError):
            cb.call(lambda: "should not reach")

    def test_circuit_breaker_transitions_to_half_open_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        assert cb.state == "OPEN"
        time.sleep(0.02)
        # Next call should transition to HALF_OPEN
        result = cb.call(lambda: "recovered")
        assert result == "recovered"
        assert cb.state == "CLOSED"

    def test_circuit_breaker_reopens_on_half_open_failure(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        time.sleep(0.02)
        with pytest.raises(ValueError):
            cb.call(lambda: (_ for _ in ()).throw(ValueError("still failing")))
        assert cb.state == "OPEN"

    def test_circuit_breaker_resets_failure_count_on_success(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        with pytest.raises(ValueError):
            cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        assert cb.failure_count == 1
        cb.call(lambda: "ok")
        assert cb.failure_count == 0


# ── Health Monitor tests ───────────────────────────────────────────────

class TestHealthMonitor:
    def test_health_monitor_tracks_healthy_component(self):
        hm = HealthMonitor()
        hm.register("GEN-1", check=lambda: True)
        assert hm.check_health("GEN-1") == ComponentStatus.HEALTHY

    def test_health_monitor_detects_unhealthy_component(self):
        hm = HealthMonitor()
        hm.register("GEN-1", check=lambda: False)
        assert hm.check_health("GEN-1") == ComponentStatus.UNHEALTHY

    def test_health_monitor_recovers_component(self):
        hm = HealthMonitor()
        healthy = False
        hm.register("GEN-1", check=lambda: healthy)
        assert hm.check_health("GEN-1") == ComponentStatus.UNHEALTHY
        healthy = True
        assert hm.check_health("GEN-1") == ComponentStatus.HEALTHY

    def test_health_monitor_unregister_component(self):
        hm = HealthMonitor()
        hm.register("GEN-1", check=lambda: True)
        hm.unregister("GEN-1")
        with pytest.raises(KeyError):
            hm.check_health("GEN-1")

    def test_health_monitor_unknown_component_raises(self):
        hm = HealthMonitor()
        with pytest.raises(KeyError):
            hm.check_health("UNKNOWN")


# ── Auto-Failover tests ────────────────────────────────────────────────

class TestFailoverManager:
    def test_failover_switches_to_backup(self):
        fm = FailoverManager()
        fm.register("primary", ["backup1", "backup2"])
        fm.failover("primary")
        assert fm.get_active("primary") == "backup1"

    def test_failover_cycles_through_backups(self):
        fm = FailoverManager()
        fm.register("primary", ["backup1", "backup2"])
        fm.failover("primary")
        fm.failover("primary")
        assert fm.get_active("primary") == "backup2"

    def test_failover_exhausted_raises_error(self):
        fm = FailoverManager()
        fm.register("primary", ["backup1"])
        fm.failover("primary")
        with pytest.raises(FailoverExhaustedError):
            fm.failover("primary")

    def test_failover_restores_primary(self):
        fm = FailoverManager()
        fm.register("primary", ["backup1"])
        fm.failover("primary")
        assert fm.get_active("primary") == "backup1"
        fm.restore("primary")
        assert fm.get_active("primary") == "primary"

    def test_failover_unknown_component_raises(self):
        fm = FailoverManager()
        with pytest.raises(KeyError):
            fm.failover("UNKNOWN")


# ── Self-Healing Engine tests ──────────────────────────────────────────

class TestSelfHealingEngine:
    def test_engine_detects_failure_and_triggers_failover(self):
        engine = SelfHealingEngine()
        engine.register_component("GEN-1", ["GEN-2"], check=lambda: False)
        engine.monitor("GEN-1")
        assert engine.failover_manager.get_active("GEN-1") == "GEN-2"

    def test_engine_restores_after_recovery(self):
        engine = SelfHealingEngine()
        healthy = False
        engine.register_component("GEN-1", ["GEN-2"], check=lambda: healthy)
        engine.monitor("GEN-1")
        assert engine.failover_manager.get_active("GEN-1") == "GEN-2"
        healthy = True
        engine.monitor("GEN-1")
        assert engine.failover_manager.get_active("GEN-1") == "GEN-1"

    def test_engine_circuit_breaker_integrates_with_failover(self):
        engine = SelfHealingEngine()
        engine.register_component("GEN-1", ["GEN-2"], check=lambda: False)
        engine.monitor("GEN-1")
        assert engine.circuit_breakers["GEN-1"].state == "OPEN"

    def test_engine_health_monitoring_detects_recovery(self):
        engine = SelfHealingEngine()
        healthy = False
        engine.register_component("GEN-1", ["GEN-2"], check=lambda: healthy)
        engine.monitor("GEN-1")
        assert engine.health_monitor.get_status("GEN-1") == ComponentStatus.UNHEALTHY
        healthy = True
        engine.monitor("GEN-1")
        assert engine.health_monitor.get_status("GEN-1") == ComponentStatus.HEALTHY

    def test_engine_multiple_failover_cycles(self):
        engine = SelfHealingEngine()
        engine.register_component("GEN-1", ["GEN-2", "GEN-3"], check=lambda: False)
        engine.monitor("GEN-1")
        assert engine.failover_manager.get_active("GEN-1") == "GEN-2"
        engine.monitor("GEN-1")
        assert engine.failover_manager.get_active("GEN-1") == "GEN-3"

    def test_engine_circuit_breaker_prevents_cascading_failures(self):
        engine = SelfHealingEngine()
        engine.register_component("GEN-1", ["GEN-2"], check=lambda: False)
        engine.monitor("GEN-1")
        # Circuit breaker should be open, preventing further calls
        with pytest.raises(CircuitBreakerOpenError):
            engine.circuit_breakers["GEN-1"].call(lambda: "should not reach")

    def test_engine_does_not_failover_healthy_component(self):
        engine = SelfHealingEngine()
        engine.register_component("GEN-1", ["GEN-2"], check=lambda: True)
        engine.monitor("GEN-1")
        assert engine.failover_manager.get_active("GEN-1") == "GEN-1"

    def test_engine_circuit_breaker_closes_after_recovery(self):
        engine = SelfHealingEngine()
        healthy = False
        engine.register_component("GEN-1", ["GEN-2"], check=lambda: healthy)
        engine.monitor("GEN-1")
        assert engine.circuit_breakers["GEN-1"].state == "OPEN"
        healthy = True
        engine.monitor("GEN-1")
        # After recovery, circuit breaker should be closed
        assert engine.circuit_breakers["GEN-1"].state == "CLOSED"
