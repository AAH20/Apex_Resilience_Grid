"""TDD tests for advanced zero-trust: micro-segmentation, identity analytics, least-privilege."""
import pytest
import time
from src.grid.segmentation import (
    MicroSegment,
    SegmentPolicy,
    IdentityProfile,
    IdentityAnalytics,
    LeastPrivilegeEngine,
    PrivilegeEscalationError,
    SegmentIsolationError,
    IdentityRiskError,
    AnalyticsError,
)


# ── Micro-segmentation tests ──────────────────────────────────────────

class TestMicroSegmentation:
    def test_micro_segment_creation(self):
        seg = MicroSegment(name="sub-station-a", zone="energy", vlan=100)
        assert seg.name == "sub-station-a"
        assert seg.zone == "energy"
        assert seg.vlan == 100
        assert seg.isolated is True

    def test_micro_segment_default_deny(self):
        seg = MicroSegment(name="isolated", zone="energy", vlan=200)
        assert not seg.can_communicate_with("other-seg")

    def test_micro_segment_allow_peer(self):
        seg = MicroSegment(name="seg-a", zone="energy", vlan=100)
        seg.allow_peer("seg-b")
        assert seg.can_communicate_with("seg-b")
        assert not seg.can_communicate_with("seg-c")

    def test_micro_segment_deny_peer(self):
        seg = MicroSegment(name="seg-a", zone="energy", vlan=100)
        seg.allow_peer("seg-b")
        seg.deny_peer("seg-b")
        assert not seg.can_communicate_with("seg-b")

    def test_micro_segment_vlan_isolation(self):
        seg_a = MicroSegment(name="seg-a", zone="energy", vlan=100)
        seg_b = MicroSegment(name="seg-b", zone="energy", vlan=200)
        # Different VLANs cannot communicate even in same zone
        assert not seg_a.can_communicate_with("seg-b")

    def test_micro_segment_same_vlan_communication(self):
        seg_a = MicroSegment(name="seg-a", zone="energy", vlan=100)
        seg_b = MicroSegment(name="seg-b", zone="energy", vlan=100)
        seg_a.allow_peer("seg-b")
        seg_b.allow_peer("seg-a")
        assert seg_a.can_communicate_with("seg-b")

    def test_segment_policy_creation(self):
        policy = SegmentPolicy(src_segment="seg-a", dst_segment="seg-b", port=443, protocol="tcp")
        assert policy.src_segment == "seg-a"
        assert policy.dst_segment == "seg-b"
        assert policy.port == 443
        assert policy.protocol == "tcp"

    def test_segment_policy_blocks_wrong_port(self):
        policy = SegmentPolicy(src_segment="seg-a", dst_segment="seg-b", port=443, protocol="tcp")
        assert policy.allows_traffic(port=443, protocol="tcp")
        assert not policy.allows_traffic(port=80, protocol="tcp")

    def test_segment_policy_blocks_wrong_protocol(self):
        policy = SegmentPolicy(src_segment="seg-a", dst_segment="seg-b", port=443, protocol="tcp")
        assert not policy.allows_traffic(port=443, protocol="udp")

    def test_segment_policy_port_range(self):
        policy = SegmentPolicy(src_segment="seg-a", dst_segment="seg-b", port=1000, protocol="tcp", port_range=(1000, 2000))
        assert policy.allows_traffic(port=1500, protocol="tcp")
        assert not policy.allows_traffic(port=500, protocol="tcp")


# ── Identity analytics tests ──────────────────────────────────────────

class TestIdentityAnalytics:
    def test_identity_profile_creation(self):
        profile = IdentityProfile(
            id="user-001",
            identity_type="user",
            role="operator",
            segment="energy",
            certificate="cert-abc",
        )
        assert profile.id == "user-001"
        assert profile.identity_type == "user"
        assert profile.role == "operator"
        assert profile.segment == "energy"
        assert profile.risk_score == 0.0
        assert profile.failed_attempts == 0

    def test_identity_profile_record_success(self):
        profile = IdentityProfile(id="user-001", identity_type="user", role="operator", segment="energy", certificate="cert-abc")
        profile.record_success()
        assert profile.failed_attempts == 0
        assert profile.risk_score == 0.0

    def test_identity_profile_record_failure(self):
        profile = IdentityProfile(id="user-001", identity_type="user", role="operator", segment="energy", certificate="cert-abc")
        profile.record_failure()
        assert profile.failed_attempts == 1
        assert profile.risk_score > 0.0

    def test_identity_profile_risk_escalation(self):
        profile = IdentityProfile(id="user-001", identity_type="user", role="operator", segment="energy", certificate="cert-abc")
        for _ in range(5):
            profile.record_failure()
        assert profile.risk_score >= 0.5

    def test_identity_profile_risk_decay(self):
        profile = IdentityProfile(id="user-001", identity_type="user", role="operator", segment="energy", certificate="cert-abc")
        for _ in range(5):
            profile.record_failure()
        initial_risk = profile.risk_score
        profile.decay_risk()
        assert profile.risk_score < initial_risk

    def test_identity_profile_is_high_risk(self):
        profile = IdentityProfile(id="user-001", identity_type="user", role="operator", segment="energy", certificate="cert-abc")
        assert not profile.is_high_risk()
        for _ in range(10):
            profile.record_failure()
        assert profile.is_high_risk()

    def test_identity_analytics_track_access(self):
        analytics = IdentityAnalytics()
        analytics.track_access("user-001", "energy", "read", success=True)
        events = analytics.get_events("user-001")
        assert len(events) == 1
        assert events[0]["action"] == "read"
        assert events[0]["success"] is True

    def test_identity_analytics_detect_anomaly(self):
        analytics = IdentityAnalytics()
        # Normal pattern
        for _ in range(10):
            analytics.track_access("user-001", "energy", "read", success=True)
        # Anomaly: sudden write attempts
        for _ in range(5):
            analytics.track_access("user-001", "energy", "write", success=False)
        assert analytics.detect_anomaly("user-001")

    def test_identity_analytics_no_anomaly_for_normal(self):
        analytics = IdentityAnalytics()
        for _ in range(10):
            analytics.track_access("user-001", "energy", "read", success=True)
        assert not analytics.detect_anomaly("user-001")

    def test_identity_analytics_risk_score_aggregation(self):
        analytics = IdentityAnalytics()
        analytics.track_access("user-001", "energy", "read", success=True)
        analytics.track_access("user-001", "energy", "write", success=False)
        analytics.track_access("user-001", "energy", "write", success=False)
        score = analytics.get_risk_score("user-001")
        assert score > 0.0

    def test_identity_analytics_block_high_risk(self):
        analytics = IdentityAnalytics()
        profile = IdentityProfile(id="user-001", identity_type="user", role="operator", segment="energy", certificate="cert-abc")
        for _ in range(10):
            profile.record_failure()
        analytics.register_profile(profile)
        with pytest.raises(IdentityRiskError):
            analytics.check_access_allowed("user-001", "energy", "read")


# ── Least-privilege enforcement tests ─────────────────────────────────

class TestLeastPrivilege:
    def test_least_privilege_engine_creation(self):
        engine = LeastPrivilegeEngine()
        assert engine.policies == {}

    def test_least_privilege_grant(self):
        engine = LeastPrivilegeEngine()
        engine.grant("operator", "energy", {"read"})
        assert engine.check("operator", "energy", "read")
        assert not engine.check("operator", "energy", "write")

    def test_least_privilege_revoke(self):
        engine = LeastPrivilegeEngine()
        engine.grant("operator", "energy", {"read"})
        assert engine.check("operator", "energy", "read")
        engine.revoke("operator", "energy")
        assert not engine.check("operator", "energy", "read")

    def test_least_privilege_escalation_blocked(self):
        engine = LeastPrivilegeEngine()
        engine.grant("operator", "energy", {"read"})
        with pytest.raises(PrivilegeEscalationError):
            engine.request_escalation("operator", "energy", "admin")

    def test_least_privilege_escalation_allowed_with_approval(self):
        engine = LeastPrivilegeEngine()
        engine.grant("operator", "energy", {"read"})
        engine.approve_escalation("operator", "energy", "admin", approver="super-admin")
        assert engine.check("operator", "energy", "admin")

    def test_least_privilege_escalation_expires(self):
        engine = LeastPrivilegeEngine()
        engine.grant("operator", "energy", {"read"})
        engine.approve_escalation("operator", "energy", "admin", approver="super-admin", ttl=0.01)
        assert engine.check("operator", "energy", "admin")
        time.sleep(0.02)
        assert not engine.check("operator", "energy", "admin")

    def test_least_privilege_segment_isolation(self):
        engine = LeastPrivilegeEngine()
        engine.add_segment("energy", vlan=100)
        engine.add_segment("water", vlan=200)
        engine.grant("operator", "energy", {"read"})
        with pytest.raises(SegmentIsolationError):
            engine.cross_segment_access("operator", "energy", "water", "read")

    def test_least_privilege_cross_segment_with_policy(self):
        engine = LeastPrivilegeEngine()
        engine.add_segment("energy", vlan=100)
        engine.add_segment("water", vlan=100)
        engine.grant("operator", "energy", {"read"})
        engine.grant("operator", "water", {"read"})
        # Should not raise
        engine.cross_segment_access("operator", "energy", "water", "read")

    def test_least_privilege_minimal_permissions(self):
        engine = LeastPrivilegeEngine()
        engine.grant("viewer", "energy", {"read"})
        assert engine.check("viewer", "energy", "read")
        assert not engine.check("viewer", "energy", "write")
        assert not engine.check("viewer", "energy", "delete")
        assert not engine.check("viewer", "energy", "admin")

    def test_least_privilege_role_hierarchy(self):
        engine = LeastPrivilegeEngine()
        engine.grant("admin", "energy", {"read", "write", "delete"})
        engine.grant("operator", "energy", {"read", "write"})
        engine.grant("viewer", "energy", {"read"})
        assert engine.check("admin", "energy", "delete")
        assert not engine.check("operator", "energy", "delete")
        assert not engine.check("viewer", "energy", "write")

    def test_least_privilege_audit_log(self):
        engine = LeastPrivilegeEngine()
        engine.grant("operator", "energy", {"read"})
        engine.check("operator", "energy", "read")
        engine.check("operator", "energy", "write")
        log = engine.get_audit_log()
        assert len(log) >= 2

    def test_least_privilege_just_in_time_access(self):
        engine = LeastPrivilegeEngine()
        engine.grant("contractor", "energy", {"read"})
        engine.request_jit_access("contractor", "energy", "write", ttl=0.01)
        assert engine.check("contractor", "energy", "write")
        time.sleep(0.02)
        assert not engine.check("contractor", "energy", "write")
