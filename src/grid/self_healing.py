"""Self-healing framework: circuit breakers, auto-failover, health monitoring, automatic recovery."""
import time
from enum import Enum
from typing import Callable, List, Optional


# ── Exceptions ─────────────────────────────────────────────────────────

class CircuitBreakerOpenError(Exception):
    """Raised when a call is attempted on an open circuit breaker."""


class FailoverExhaustedError(Exception):
    """Raised when all failover targets have been exhausted."""


# ── Enums ──────────────────────────────────────────────────────────────

class ComponentStatus(Enum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


# ── Circuit Breaker ────────────────────────────────────────────────────

class CircuitBreaker:
    """Prevents cascading failures by blocking calls after repeated failures."""

    def __init__(self, failure_threshold: int = 3, recovery_timeout: float = 1.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.state = "CLOSED"
        self._last_failure_time: Optional[float] = None

    def call(self, func: Callable, *args, **kwargs):
        if self.state == "OPEN":
            if self._last_failure_time and (time.time() - self._last_failure_time) >= self.recovery_timeout:
                self.state = "HALF_OPEN"
            else:
                raise CircuitBreakerOpenError("Circuit breaker is OPEN")

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e

    def _on_success(self):
        self.failure_count = 0
        self.state = "CLOSED"

    def _on_failure(self):
        self.failure_count += 1
        self._last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"


# ── Health Monitor ─────────────────────────────────────────────────────

class HealthMonitor:
    """Tracks component health status."""

    def __init__(self):
        self._checks: dict[str, Callable[[], bool]] = {}
        self._statuses: dict[str, ComponentStatus] = {}

    def register(self, component_id: str, check: Callable[[], bool]) -> None:
        self._checks[component_id] = check

    def unregister(self, component_id: str) -> None:
        self._checks.pop(component_id, None)
        self._statuses.pop(component_id, None)

    def check_health(self, component_id: str) -> ComponentStatus:
        if component_id not in self._checks:
            raise KeyError(f"Unknown component: {component_id}")
        healthy = self._checks[component_id]()
        status = ComponentStatus.HEALTHY if healthy else ComponentStatus.UNHEALTHY
        self._statuses[component_id] = status
        return status

    def get_status(self, component_id: str) -> ComponentStatus:
        if component_id not in self._statuses:
            raise KeyError(f"Unknown component: {component_id}")
        return self._statuses[component_id]


# ── Failover Manager ───────────────────────────────────────────────────

class FailoverManager:
    """Manages automatic failover to backup components."""

    def __init__(self):
        self._backups: dict[str, List[str]] = {}
        self._active: dict[str, str] = {}
        self._failover_index: dict[str, int] = {}

    def register(self, component_id: str, backups: List[str]) -> None:
        self._backups[component_id] = backups
        self._active[component_id] = component_id
        self._failover_index[component_id] = 0

    def failover(self, component_id: str) -> str:
        if component_id not in self._backups:
            raise KeyError(f"Unknown component: {component_id}")
        idx = self._failover_index[component_id]
        backups = self._backups[component_id]
        if idx >= len(backups):
            raise FailoverExhaustedError(f"No more backups for {component_id}")
        self._active[component_id] = backups[idx]
        self._failover_index[component_id] = idx + 1
        return self._active[component_id]

    def restore(self, component_id: str) -> str:
        if component_id not in self._backups:
            raise KeyError(f"Unknown component: {component_id}")
        self._active[component_id] = component_id
        self._failover_index[component_id] = 0
        return component_id

    def get_active(self, component_id: str) -> str:
        if component_id not in self._active:
            raise KeyError(f"Unknown component: {component_id}")
        return self._active[component_id]


# ── Self-Healing Engine ────────────────────────────────────────────────

class SelfHealingEngine:
    """Orchestrates circuit breakers, health monitoring, and auto-failover."""

    def __init__(self):
        self.circuit_breakers: dict[str, CircuitBreaker] = {}
        self.health_monitor = HealthMonitor()
        self.failover_manager = FailoverManager()
        self._checks: dict[str, Callable[[], bool]] = {}

    def register_component(
        self,
        component_id: str,
        backups: List[str],
        check: Callable[[], bool],
    ) -> None:
        self.circuit_breakers[component_id] = CircuitBreaker()
        self.health_monitor.register(component_id, check)
        self.failover_manager.register(component_id, backups)
        self._checks[component_id] = check

    def monitor(self, component_id: str) -> None:
        status = self.health_monitor.check_health(component_id)
        if status == ComponentStatus.UNHEALTHY:
            cb = self.circuit_breakers[component_id]
            cb.failure_count = cb.failure_threshold
            cb._last_failure_time = time.time()
            cb.state = "OPEN"
            try:
                self.failover_manager.failover(component_id)
            except FailoverExhaustedError:
                pass
        else:
            self.circuit_breakers[component_id]._on_success()
            self.failover_manager.restore(component_id)
