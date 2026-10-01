"""Zero-trust architecture: micro-segmentation, identity verification, least-privilege access."""

import hashlib
import secrets
import time
from typing import Optional, Set


# ── Exceptions ─────────────────────────────────────────────────────────

class AuthenticationError(Exception):
    """Raised when identity verification fails."""


class AuthorizationError(Exception):
    """Raised when access is denied by policy."""


class SegmentIsolationError(Exception):
    """Raised when inter-segment communication is blocked."""


# ── Micro-segmentation ─────────────────────────────────────────────────

class Segment:
    """A network segment with explicit ingress/egress rules (default-deny)."""

    def __init__(self, name: str, zone: str):
        self.name = name
        self.zone = zone
        self.allowed_ingress: Set[str] = set()
        self.allowed_egress: Set[str] = set()

    def allow_ingress_from(self, segment_name: str) -> None:
        self.allowed_ingress.add(segment_name)

    def allow_egress_to(self, segment_name: str) -> None:
        self.allowed_egress.add(segment_name)

    def can_ingress_from(self, segment_name: str) -> bool:
        return segment_name in self.allowed_ingress

    def can_egress_to(self, segment_name: str) -> bool:
        return segment_name in self.allowed_egress


# ── Identity verification ──────────────────────────────────────────────

class Identity:
    """A verified identity (device, user, or service)."""

    def __init__(
        self,
        id: str,
        identity_type: str,
        certificate: str,
        mfa_required: bool = False,
        role: Optional[str] = None,
    ):
        self.id = id
        self.identity_type = identity_type
        self.certificate = certificate
        self.mfa_required = mfa_required
        self.role = role
        self._authenticated = False
        self._token: Optional[str] = None
        self._expires_at: Optional[float] = None

    @property
    def authenticated(self) -> bool:
        if not self._authenticated:
            return False
        if self._expires_at is not None and time.time() > self._expires_at:
            self._authenticated = False
            self._token = None
            return False
        return True

    def authenticate(
        self,
        certificate: str,
        mfa_token: Optional[str] = None,
        session_ttl: Optional[float] = None,
    ) -> None:
        if certificate != self.certificate:
            raise AuthenticationError(f"Invalid certificate for {self.id}")
        if self.mfa_required and mfa_token is None:
            raise AuthenticationError(f"MFA required for {self.id}")
        self._authenticated = True
        self._token = None
        if session_ttl is not None:
            self._expires_at = time.time() + session_ttl
        else:
            self._expires_at = None

    def generate_token(self) -> str:
        if not self.authenticated:
            raise AuthenticationError(f"Identity {self.id} is not authenticated")
        self._token = secrets.token_hex(32)
        return self._token

    def validate_token(self, token: str) -> bool:
        if not self.authenticated or self._token is None:
            return False
        return secrets.compare_digest(self._token, token)


# ── Least-privilege access ─────────────────────────────────────────────

class Role:
    """A role with a set of permissions."""

    def __init__(self, name: str, permissions: Set[str]):
        self.name = name
        self.permissions = permissions

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions


class AccessPolicy:
    """Maps a role to a segment with specific permissions."""

    def __init__(self, role: str, segment: str, permissions: Set[str]):
        self.role = role
        self.segment = segment
        self.permissions = permissions

    def allows(self, permission: str) -> bool:
        return permission in self.permissions


# ── Zero-trust engine ──────────────────────────────────────────────────

class ZeroTrustEngine:
    """Orchestrates micro-segmentation, identity, and least-privilege policies."""

    def __init__(self):
        self.segments: dict[str, Segment] = {}
        self.roles: dict[str, Role] = {}
        self.policies: dict[str, AccessPolicy] = {}
        self._policy_expiry: dict[str, float] = {}

    def add_segment(self, segment: Segment) -> None:
        self.segments[segment.name] = segment

    def add_role(self, role: Role) -> None:
        self.roles[role.name] = role

    def grant_access(
        self,
        role: str,
        segment: str,
        permissions: Set[str],
        ttl: Optional[float] = None,
    ) -> None:
        key = f"{role}:{segment}"
        self.policies[key] = AccessPolicy(role, segment, permissions)
        if ttl is not None:
            self._policy_expiry[key] = time.time() + ttl
        else:
            self._policy_expiry.pop(key, None)

    def revoke_access(self, role: str, segment: str) -> None:
        key = f"{role}:{segment}"
        self.policies.pop(key, None)
        self._policy_expiry.pop(key, None)

    def check_access(self, role: str, segment: str, permission: str) -> bool:
        key = f"{role}:{segment}"
        if key not in self.policies:
            return False
        if key in self._policy_expiry and time.time() > self._policy_expiry[key]:
            self.policies.pop(key, None)
            self._policy_expiry.pop(key, None)
            return False
        return self.policies[key].allows(permission)

    def communicate(self, src: str, dst: str, data: str) -> None:
        if src not in self.segments or dst not in self.segments:
            raise SegmentIsolationError(f"Unknown segment: {src} or {dst}")
        src_seg = self.segments[src]
        dst_seg = self.segments[dst]
        if not src_seg.can_egress_to(dst):
            raise SegmentIsolationError(f"{src} cannot egress to {dst}")
        if not dst_seg.can_ingress_from(src):
            raise SegmentIsolationError(f"{dst} cannot ingress from {src}")

    def authorize(self, identity: Identity, segment: str, permission: str) -> None:
        if not identity.authenticated:
            raise AuthenticationError(f"Identity {identity.id} is not authenticated")
        if segment not in self.segments:
            raise AuthorizationError(f"Unknown segment: {segment}")
        role_name = identity.role
        if role_name is None:
            raise AuthorizationError(f"Identity {identity.id} has no assigned role")
        if not self.check_access(role_name, segment, permission):
            raise AuthorizationError(
                f"Identity {identity.id} denied {permission} on {segment}"
            )
