"""TDD tests for zero-trust architecture: micro-segmentation, identity verification, least-privilege."""

import pytest
import time
from src.grid.zero_trust import (
    Segment,
    Identity,
    Role,
    AccessPolicy,
    ZeroTrustEngine,
    AuthenticationError,
    AuthorizationError,
    SegmentIsolationError,
)


# ── Micro-segmentation tests ──────────────────────────────────────────

class TestMicroSegmentation:
    def test_segment_creation(self):
        seg = Segment(name="energy-core", zone="critical")
        assert seg.name == "energy-core"
        assert seg.zone == "critical"
        assert seg.allowed_ingress == set()
        assert seg.allowed_egress == set()

    def test_default_deny_ingress(self):
        seg = Segment(name="isolated", zone="restricted")
        assert not seg.can_ingress_from("any-other-segment")

    def test_default_deny_egress(self):
        seg = Segment(name="isolated", zone="restricted")
        assert not seg.can_egress_to("any-other-segment")

    def test_allow_ingress(self):
        seg = Segment(name="energy", zone="critical")
        seg.allow_ingress_from("water")
        assert seg.can_ingress_from("water")
        assert not seg.can_ingress_from("transport")

    def test_allow_egress(self):
        seg = Segment(name="energy", zone="critical")
        seg.allow_egress_to("emergency")
        assert seg.can_egress_to("emergency")
        assert not seg.can_egress_to("water")

    def test_segment_isolation_blocks_unauthorized(self):
        engine = ZeroTrustEngine()
        engine.add_segment(Segment(name="energy", zone="critical"))
        engine.add_segment(Segment(name="water", zone="critical"))
        with pytest.raises(SegmentIsolationError):
            engine.communicate("energy", "water", "data")

    def test_segment_communication_allowed(self):
        engine = ZeroTrustEngine()
        engine.add_segment(Segment(name="energy", zone="critical"))
        engine.add_segment(Segment(name="water", zone="critical"))
        engine.segments["energy"].allow_egress_to("water")
        engine.segments["water"].allow_ingress_from("energy")
        # Should not raise
        engine.communicate("energy", "water", "data")


# ── Identity verification tests ────────────────────────────────────────

class TestIdentityVerification:
    def test_identity_creation(self):
        ident = Identity(id="dev-001", identity_type="device", certificate="cert-abc")
        assert ident.id == "dev-001"
        assert ident.identity_type == "device"
        assert ident.certificate == "cert-abc"
        assert not ident.authenticated

    def test_authenticate_with_valid_certificate(self):
        ident = Identity(id="dev-001", identity_type="device", certificate="cert-abc")
        ident.authenticate(certificate="cert-abc")
        assert ident.authenticated

    def test_authenticate_with_invalid_certificate(self):
        ident = Identity(id="dev-001", identity_type="device", certificate="cert-abc")
        with pytest.raises(AuthenticationError):
            ident.authenticate(certificate="wrong-cert")
        assert not ident.authenticated

    def test_mfa_required_blocks_authentication(self):
        ident = Identity(id="user-001", identity_type="user", certificate="cert-xyz", mfa_required=True)
        with pytest.raises(AuthenticationError):
            ident.authenticate(certificate="cert-xyz")
        assert not ident.authenticated

    def test_mfa_success(self):
        ident = Identity(id="user-001", identity_type="user", certificate="cert-xyz", mfa_required=True)
        ident.authenticate(certificate="cert-xyz", mfa_token="123456")
        assert ident.authenticated

    def test_session_expiry(self):
        ident = Identity(id="dev-002", identity_type="device", certificate="cert-def")
        ident.authenticate(certificate="cert-def", session_ttl=0.01)
        assert ident.authenticated
        time.sleep(0.02)
        assert not ident.authenticated

    def test_token_generation(self):
        ident = Identity(id="dev-003", identity_type="device", certificate="cert-ghi")
        ident.authenticate(certificate="cert-ghi")
        token = ident.generate_token()
        assert token is not None
        assert len(token) > 0

    def test_token_validation(self):
        ident = Identity(id="dev-004", identity_type="device", certificate="cert-jkl")
        ident.authenticate(certificate="cert-jkl")
        token = ident.generate_token()
        assert ident.validate_token(token)
        assert not ident.validate_token("invalid-token")


# ── Least-privilege access tests ───────────────────────────────────────

class TestLeastPrivilege:
    def test_role_creation(self):
        role = Role(name="operator", permissions={"read"})
        assert role.name == "operator"
        assert "read" in role.permissions
        assert "write" not in role.permissions

    def test_role_deny_by_default(self):
        role = Role(name="viewer", permissions={"read"})
        assert not role.has_permission("write")
        assert not role.has_permission("delete")

    def test_access_policy_allows(self):
        policy = AccessPolicy(role="operator", segment="energy", permissions={"read", "write"})
        assert policy.allows("read")
        assert policy.allows("write")
        assert not policy.allows("delete")

    def test_access_policy_deny_unlisted(self):
        policy = AccessPolicy(role="viewer", segment="energy", permissions={"read"})
        assert not policy.allows("admin")

    def test_least_privilege_grant_minimal(self):
        engine = ZeroTrustEngine()
        engine.add_role(Role(name="operator", permissions={"read"}))
        engine.add_segment(Segment(name="energy", zone="critical"))
        engine.grant_access("operator", "energy", {"read"})
        assert engine.check_access("operator", "energy", "read")
        assert not engine.check_access("operator", "energy", "write")

    def test_jit_access_temporary(self):
        engine = ZeroTrustEngine()
        engine.add_role(Role(name="contractor", permissions={"read"}))
        engine.add_segment(Segment(name="energy", zone="critical"))
        engine.grant_access("contractor", "energy", {"read"}, ttl=0.01)
        assert engine.check_access("contractor", "energy", "read")
        time.sleep(0.02)
        assert not engine.check_access("contractor", "energy", "read")

    def test_permission_boundary_enforced(self):
        engine = ZeroTrustEngine()
        engine.add_role(Role(name="operator", permissions={"read", "write"}))
        engine.add_segment(Segment(name="energy", zone="critical"))
        engine.grant_access("operator", "energy", {"read"})
        # Even though role has write, policy only grants read
        assert not engine.check_access("operator", "energy", "write")

    def test_revoke_access(self):
        engine = ZeroTrustEngine()
        engine.add_role(Role(name="operator", permissions={"read"}))
        engine.add_segment(Segment(name="energy", zone="critical"))
        engine.grant_access("operator", "energy", {"read"})
        assert engine.check_access("operator", "energy", "read")
        engine.revoke_access("operator", "energy")
        assert not engine.check_access("operator", "energy", "read")


# ── Engine integration tests ───────────────────────────────────────────

class TestZeroTrustEngine:
    def test_engine_enforces_all_policies(self):
        engine = ZeroTrustEngine()
        engine.add_segment(Segment(name="energy", zone="critical"))
        engine.add_segment(Segment(name="water", zone="critical"))
        engine.add_role(Role(name="operator", permissions={"read"}))
        engine.grant_access("operator", "energy", {"read"})
        # Identity not authenticated
        ident = Identity(id="dev-001", identity_type="device", certificate="cert-abc")
        with pytest.raises(AuthenticationError):
            engine.authorize(ident, "energy", "read")

    def test_engine_authorizes_authenticated_identity(self):
        engine = ZeroTrustEngine()
        engine.add_segment(Segment(name="energy", zone="critical"))
        engine.add_role(Role(name="operator", permissions={"read"}))
        engine.grant_access("operator", "energy", {"read"})
        ident = Identity(id="dev-001", identity_type="device", certificate="cert-abc", role="operator")
        ident.authenticate(certificate="cert-abc")
        # Should not raise
        engine.authorize(ident, "energy", "read")

    def test_engine_blocks_unauthorized_segment_access(self):
        engine = ZeroTrustEngine()
        engine.add_segment(Segment(name="energy", zone="critical"))
        engine.add_role(Role(name="operator", permissions={"read"}))
        engine.grant_access("operator", "energy", {"read"})
        ident = Identity(id="dev-001", identity_type="device", certificate="cert-abc")
        ident.authenticate(certificate="cert-abc")
        with pytest.raises(AuthorizationError):
            engine.authorize(ident, "water", "read")
