"""Advanced zero-trust: micro-segmentation, identity analytics, least-privilege enforcement."""
import time
import secrets
from typing import Optional, Set, Dict, List, Tuple


# ── Exceptions ─────────────────────────────────────────────────────────

class PrivilegeEscalationError(Exception):
    """Raised when privilege escalation is attempted without approval."""

class SegmentIsolationError(Exception):
    """Raised when cross-segment access is blocked."""

class IdentityRiskError(Exception):
    """Raised when an identity is too high-risk to access resources."""

class AnalyticsError(Exception):
    """Raised when identity analytics encounters an error."""


# ── Micro-segmentation ─────────────────────────────────────────────────

class MicroSegment:
    """A fine-grained network segment with VLAN isolation and peer rules."""

    def __init__(self, name: str, zone: str, vlan: int):
        self.name = name
        self.zone = zone
        self.vlan = vlan
        self.isolated = True
        self._peers: Set[str] = set()

    def allow_peer(self, peer_name: str) -> None:
        self._peers.add(peer_name)

    def deny_peer(self, peer_name: str) -> None:
        self._peers.discard(peer_name)

    def can_communicate_with(self, other_name: str) -> bool:
        return other_name in self._peers


class SegmentPolicy:
    """Defines allowed traffic between segments with port/protocol filtering."""

    def __init__(
        self,
        src_segment: str,
        dst_segment: str,
        port: int,
        protocol: str,
        port_range: Optional[Tuple[int, int]] = None,
    ):
        self.src_segment = src_segment
        self.dst_segment = dst_segment
        self.port = port
        self.protocol = protocol
        self.port_range = port_range

    def allows_traffic(self, port: int, protocol: str) -> bool:
        if protocol != self.protocol:
            return False
        if self.port_range is not None:
            return self.port_range[0] <= port <= self.port_range[1]
        return port == self.port


# ── Identity analytics ────────────────────────────────────────────────

class IdentityProfile:
    """Tracks identity behavior, risk score, and authentication history."""

    def __init__(
        self,
        id: str,
        identity_type: str,
        role: str,
        segment: str,
        certificate: str,
    ):
        self.id = id
        self.identity_type = identity_type
        self.role = role
        self.segment = segment
        self.certificate = certificate
        self.risk_score = 0.0
        self.failed_attempts = 0
        self._last_success: Optional[float] = None

    def record_success(self) -> None:
        self.failed_attempts = 0
        self.risk_score = 0.0
        self._last_success = time.time()

    def record_failure(self) -> None:
        self.failed_attempts += 1
        self.risk_score = min(1.0, self.failed_attempts * 0.1)

    def decay_risk(self) -> None:
        self.risk_score = max(0.0, self.risk_score * 0.5)

    def is_high_risk(self) -> bool:
        return self.risk_score >= 0.8


class IdentityAnalytics:
    """Aggregates identity events, detects anomalies, and enforces risk-based access."""

    def __init__(self):
        self._events: Dict[str, List[dict]] = {}
        self._profiles: Dict[str, IdentityProfile] = {}

    def register_profile(self, profile: IdentityProfile) -> None:
        self._profiles[profile.id] = profile

    def track_access(self, identity_id: str, segment: str, action: str, success: bool) -> None:
        if identity_id not in self._events:
            self._events[identity_id] = []
        self._events[identity_id].append({
            "segment": segment,
            "action": action,
            "success": success,
            "timestamp": time.time(),
        })

    def get_events(self, identity_id: str) -> List[dict]:
        return self._events.get(identity_id, [])

    def detect_anomaly(self, identity_id: str) -> bool:
        events = self._events.get(identity_id, [])
        if len(events) < 5:
            return False
        recent = events[-5:]
        failures = sum(1 for e in recent if not e["success"])
        return failures >= 3

    def get_risk_score(self, identity_id: str) -> float:
        events = self._events.get(identity_id, [])
        if not events:
            return 0.0
        failures = sum(1 for e in events if not e["success"])
        return min(1.0, failures / max(len(events), 1))

    def check_access_allowed(self, identity_id: str, segment: str, action: str) -> None:
        profile = self._profiles.get(identity_id)
        if profile and profile.is_high_risk():
            raise IdentityRiskError(
                f"Identity {identity_id} is high-risk (score={profile.risk_score:.2f})"
            )


# ── Least-privilege enforcement ────────────────────────────────────────

class LeastPrivilegeEngine:
    """Enforces least-privilege access with JIT, escalation, and audit logging."""

    def __init__(self):
        self.policies: Dict[str, Set[str]] = {}
        self._segments: Dict[str, int] = {}
        self._escalations: Dict[str, Tuple[Set[str], Optional[float]]] = {}
        self._audit_log: List[dict] = []

    def add_segment(self, name: str, vlan: int) -> None:
        self._segments[name] = vlan

    def grant(self, role: str, segment: str, permissions: Set[str]) -> None:
        key = f"{role}:{segment}"
        self.policies[key] = permissions

    def revoke(self, role: str, segment: str) -> None:
        key = f"{role}:{segment}"
        self.policies.pop(key, None)

    def check(self, role: str, segment: str, permission: str) -> bool:
        key = f"{role}:{segment}"
        self._audit_log.append({
            "role": role,
            "segment": segment,
            "permission": permission,
            "granted": key in self.policies and permission in self.policies[key],
            "timestamp": time.time(),
        })
        if key in self.policies and permission in self.policies[key]:
            return True
        esc_key = f"{role}:{segment}"
        if esc_key in self._escalations:
            perms, expires = self._escalations[esc_key]
            if expires is None or time.time() < expires:
                if permission in perms:
                    return True
        return False

    def request_escalation(self, role: str, segment: str, permission: str) -> None:
        key = f"{role}:{segment}"
        if key not in self.policies:
            raise PrivilegeEscalationError(
                f"Role {role} has no base policy on {segment}"
            )
        raise PrivilegeEscalationError(
            f"Escalation to {permission} requires approval"
        )

    def approve_escalation(
        self,
        role: str,
        segment: str,
        permission: str,
        approver: str,
        ttl: Optional[float] = None,
    ) -> None:
        key = f"{role}:{segment}"
        perms = self._escalations.get(key, (set(), None))[0]
        perms.add(permission)
        expires = time.time() + ttl if ttl is not None else None
        self._escalations[key] = (perms, expires)

    def cross_segment_access(
        self,
        role: str,
        src_segment: str,
        dst_segment: str,
        permission: str,
    ) -> None:
        if src_segment not in self._segments or dst_segment not in self._segments:
            raise SegmentIsolationError("Unknown segment")
        if self._segments[src_segment] != self._segments[dst_segment]:
            raise SegmentIsolationError(
                f"VLAN isolation: {src_segment} and {dst_segment} on different VLANs"
            )
        if not self.check(role, dst_segment, permission):
            raise SegmentIsolationError(
                f"Role {role} denied {permission} on {dst_segment}"
            )

    def request_jit_access(
        self,
        role: str,
        segment: str,
        permission: str,
        ttl: float,
    ) -> None:
        key = f"{role}:{segment}"
        perms = self._escalations.get(key, (set(), None))[0]
        perms.add(permission)
        self._escalations[key] = (perms, time.time() + ttl)

    def get_audit_log(self) -> List[dict]:
        return list(self._audit_log)
