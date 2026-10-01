"""Tests for AI Governance Framework, Risk Assessment, and Compliance Automation.

Covers NIST AI RMF 1.0 aligned governance policies, risk assessment,
and automated compliance checking.
"""

import pytest

from src.grid.ai_governance import (
    AIAuditRecord,
    AIApprovalRequest,
    AIGovernanceFramework,
    AIGovernancePolicy,
    ComplianceAutomationEngine,
    ComplianceCheck,
    ComplianceRule,
    ComplianceSeverity,
    ComplianceViolation,
    GovernanceLevel,
    PolicyStatus,
    ApprovalStatus,
    RiskAssessment,
    RiskCategory,
    RiskFactor,
    RiskMatrix,
)


# ── AIGovernancePolicy Tests ─────────────────────────────────────────────────


class TestAIGovernancePolicy:
    """Tests for AIGovernancePolicy."""

    def test_policy_creation_with_required_fields(self):
        policy = AIGovernancePolicy(
            policy_id="POL-001",
            name="Model Validation Policy",
            description="All models must pass validation before deployment",
            level=GovernanceLevel.MANDATORY,
        )
        assert policy.policy_id == "POL-001"
        assert policy.name == "Model Validation Policy"
        assert policy.level == GovernanceLevel.MANDATORY
        assert policy.status == PolicyStatus.DRAFT
        assert policy.rules == []

    def test_policy_activate_changes_status(self):
        policy = AIGovernancePolicy(
            policy_id="POL-002",
            name="Test Policy",
            description="Test",
            level=GovernanceLevel.ADVISORY,
        )
        assert policy.status == PolicyStatus.DRAFT
        policy.activate()
        assert policy.status == PolicyStatus.ACTIVE

    def test_policy_deprecate_changes_status(self):
        policy = AIGovernancePolicy(
            policy_id="POL-003",
            name="Test Policy",
            description="Test",
            level=GovernanceLevel.ADVISORY,
        )
        policy.activate()
        policy.deprecate()
        assert policy.status == PolicyStatus.DEPRECATED

    def test_add_rule_appends_unique_rules(self):
        policy = AIGovernancePolicy(
            policy_id="POL-004",
            name="Test Policy",
            description="Test",
            level=GovernanceLevel.MANDATORY,
        )
        policy.add_rule("model_version:exists")
        policy.add_rule("validation_report:exists")
        policy.add_rule("model_version:exists")  # duplicate
        assert len(policy.rules) == 2
        assert "model_version:exists" in policy.rules

    def test_to_dict_contains_all_fields(self):
        policy = AIGovernancePolicy(
            policy_id="POL-005",
            name="Test Policy",
            description="Test description",
            level=GovernanceLevel.CRITICAL,
        )
        policy.add_rule("test_rule:exists")
        d = policy.to_dict()
        assert d["policy_id"] == "POL-005"
        assert d["name"] == "Test Policy"
        assert d["level"] == "critical"
        assert d["status"] == "draft"
        assert d["rules"] == ["test_rule:exists"]
        assert "created_at" in d


# ── AIApprovalRequest Tests ──────────────────────────────────────────────────


class TestAIApprovalRequest:
    """Tests for AIApprovalRequest."""

    def test_approval_request_creation(self):
        req = AIApprovalRequest(
            request_id="REQ-001",
            system_name="GridOptimizer",
            system_version="1.0.0",
            requester="ml-team",
        )
        assert req.request_id == "REQ-001"
        assert req.system_name == "GridOptimizer"
        assert req.status == ApprovalStatus.PENDING
        assert req.conditions == []

    def test_approve_sets_status_and_conditions(self):
        req = AIApprovalRequest(
            request_id="REQ-002",
            system_name="GridOptimizer",
            system_version="1.0.0",
            requester="ml-team",
        )
        req.approve(conditions=["Must run in sandbox"])
        assert req.status == ApprovalStatus.APPROVED
        assert "Must run in sandbox" in req.conditions

    def test_reject_sets_status(self):
        req = AIApprovalRequest(
            request_id="REQ-003",
            system_name="GridOptimizer",
            system_version="1.0.0",
            requester="ml-team",
        )
        req.reject()
        assert req.status == ApprovalStatus.REJECTED

    def test_add_condition_no_duplicates(self):
        req = AIApprovalRequest(
            request_id="REQ-004",
            system_name="GridOptimizer",
            system_version="1.0.0",
            requester="ml-team",
        )
        req.add_condition("Condition A")
        req.add_condition("Condition A")
        req.add_condition("Condition B")
        assert len(req.conditions) == 2

    def test_to_dict_contains_all_fields(self):
        req = AIApprovalRequest(
            request_id="REQ-005",
            system_name="GridOptimizer",
            system_version="2.0.0",
            requester="ml-team",
        )
        req.approve()
        d = req.to_dict()
        assert d["request_id"] == "REQ-005"
        assert d["system_name"] == "GridOptimizer"
        assert d["status"] == "approved"
        assert "created_at" in d


# ── AIAuditRecord Tests ──────────────────────────────────────────────────────


class TestAIAuditRecord:
    """Tests for AIAuditRecord."""

    def test_audit_record_creation(self):
        record = AIAuditRecord(
            action="policy_added",
            actor="admin",
            target="POL-001",
            details={"name": "Test Policy"},
        )
        assert record.action == "policy_added"
        assert record.actor == "admin"
        assert record.target == "POL-001"
        assert record.details == {"name": "Test Policy"}
        assert record.record_id is not None

    def test_audit_record_to_dict(self):
        record = AIAuditRecord(action="test", actor="system", target="test-target")
        d = record.to_dict()
        assert d["action"] == "test"
        assert d["actor"] == "system"
        assert d["target"] == "test-target"
        assert "record_id" in d
        assert "timestamp" in d


# ── AIGovernanceFramework Tests ──────────────────────────────────────────────


class TestAIGovernanceFramework:
    """Tests for AIGovernanceFramework."""

    def test_framework_creation(self):
        framework = AIGovernanceFramework("ApexGrid Governance")
        assert framework.name == "ApexGrid Governance"
        assert framework.get_audit_log() == []

    def test_add_policy_and_retrieve(self):
        framework = AIGovernanceFramework("Test")
        policy = AIGovernancePolicy(
            policy_id="POL-001",
            name="Test Policy",
            description="Test",
            level=GovernanceLevel.MANDATORY,
        )
        framework.add_policy(policy)
        retrieved = framework.get_policy("POL-001")
        assert retrieved is not None
        assert retrieved.name == "Test Policy"

    def test_get_active_policies_only_returns_active(self):
        framework = AIGovernanceFramework("Test")
        p1 = AIGovernancePolicy(
            policy_id="POL-001",
            name="Active Policy",
            description="Test",
            level=GovernanceLevel.MANDATORY,
        )
        p1.activate()
        p2 = AIGovernancePolicy(
            policy_id="POL-002",
            name="Draft Policy",
            description="Test",
            level=GovernanceLevel.ADVISORY,
        )
        framework.add_policy(p1)
        framework.add_policy(p2)
        active = framework.get_active_policies()
        assert len(active) == 1
        assert active[0].policy_id == "POL-001"

    def test_submit_approval_request(self):
        framework = AIGovernanceFramework("Test")
        req = AIApprovalRequest(
            request_id="REQ-001",
            system_name="GridOptimizer",
            system_version="1.0.0",
            requester="ml-team",
        )
        framework.submit_approval_request(req)
        retrieved = framework.get_approval("REQ-001")
        assert retrieved is not None
        assert retrieved.system_name == "GridOptimizer"

    def test_evaluate_policies_returns_violations(self):
        framework = AIGovernanceFramework("Test")
        policy = AIGovernancePolicy(
            policy_id="POL-001",
            name="Model Validation",
            description="Test",
            level=GovernanceLevel.MANDATORY,
        )
        policy.add_rule("model_version:exists")
        policy.activate()
        framework.add_policy(policy)
        # Missing model_version attribute
        violations = framework.evaluate_policies({"other_attr": "value"})
        assert len(violations) == 1
        assert "Model Validation" in violations[0]

    def test_evaluate_policies_no_violations_when_compliant(self):
        framework = AIGovernanceFramework("Test")
        policy = AIGovernancePolicy(
            policy_id="POL-001",
            name="Model Validation",
            description="Test",
            level=GovernanceLevel.MANDATORY,
        )
        policy.add_rule("model_version:exists")
        policy.activate()
        framework.add_policy(policy)
        violations = framework.evaluate_policies({"model_version": "1.0"})
        assert len(violations) == 0

    def test_audit_log_tracks_actions(self):
        framework = AIGovernanceFramework("Test")
        policy = AIGovernancePolicy(
            policy_id="POL-001",
            name="Test Policy",
            description="Test",
            level=GovernanceLevel.MANDATORY,
        )
        framework.add_policy(policy)
        log = framework.get_audit_log()
        assert len(log) == 1
        assert log[0].action == "policy_added"


# ── RiskFactor Tests ─────────────────────────────────────────────────────────


class TestRiskFactor:
    """Tests for RiskFactor."""

    def test_risk_factor_creation(self):
        factor = RiskFactor(
            factor_id="RF-001",
            name="Model Drift",
            category=RiskCategory.VALIDITY,
            likelihood=0.6,
            impact=0.8,
            description="Model performance degrades over time",
        )
        assert factor.factor_id == "RF-001"
        assert factor.name == "Model Drift"
        assert factor.category == RiskCategory.VALIDITY
        assert factor.likelihood == 0.6
        assert factor.impact == 0.8

    def test_risk_score_is_likelihood_times_impact(self):
        factor = RiskFactor(
            factor_id="RF-002",
            name="Test",
            category=RiskCategory.SAFETY,
            likelihood=0.5,
            impact=0.5,
        )
        assert factor.risk_score == pytest.approx(0.25)

    def test_add_mitigation_no_duplicates(self):
        factor = RiskFactor(
            factor_id="RF-003",
            name="Test",
            category=RiskCategory.SECURITY,
            likelihood=0.3,
            impact=0.4,
        )
        factor.add_mitigation("Encryption")
        factor.add_mitigation("Encryption")
        factor.add_mitigation("Access control")
        assert len(factor.mitigations) == 2

    def test_to_dict_contains_all_fields(self):
        factor = RiskFactor(
            factor_id="RF-004",
            name="Test Factor",
            category=RiskCategory.PRIVACY,
            likelihood=0.7,
            impact=0.9,
            description="Test description",
        )
        factor.add_mitigation("Anonymization")
        d = factor.to_dict()
        assert d["factor_id"] == "RF-004"
        assert d["category"] == "privacy"
        assert d["risk_score"] == pytest.approx(0.63)
        assert d["mitigations"] == ["Anonymization"]


# ── RiskMatrix Tests ─────────────────────────────────────────────────────────


class TestRiskMatrix:
    """Tests for RiskMatrix."""

    def test_high_likelihood_high_impact_is_critical(self):
        level = RiskMatrix.get_risk_level(0.9, 0.9)
        assert level == "critical"

    def test_medium_risk_scoring(self):
        level = RiskMatrix.get_risk_level(0.5, 0.5)
        assert level == "medium"

    def test_low_risk_scoring(self):
        level = RiskMatrix.get_risk_level(0.1, 0.1)
        assert level == "low"

    def test_get_risk_level_from_score(self):
        assert RiskMatrix.get_risk_level_from_score(0.8) == "critical"
        assert RiskMatrix.get_risk_level_from_score(0.5) == "high"
        assert RiskMatrix.get_risk_level_from_score(0.3) == "medium"
        assert RiskMatrix.get_risk_level_from_score(0.1) == "low"


# ── RiskAssessment Tests ─────────────────────────────────────────────────────


class TestRiskAssessment:
    """Tests for RiskAssessment."""

    def test_assessment_creation(self):
        assessment = RiskAssessment(
            assessment_id="RA-001",
            system_name="GridOptimizer",
            system_version="1.0.0",
        )
        assert assessment.assessment_id == "RA-001"
        assert assessment.system_name == "GridOptimizer"
        assert assessment.factors == []

    def test_add_factor_and_overall_score(self):
        assessment = RiskAssessment(
            assessment_id="RA-002",
            system_name="GridOptimizer",
            system_version="1.0.0",
        )
        assessment.add_factor(RiskFactor(
            factor_id="RF-001",
            name="Risk 1",
            category=RiskCategory.VALIDITY,
            likelihood=0.5,
            impact=0.5,
        ))
        assessment.add_factor(RiskFactor(
            factor_id="RF-002",
            name="Risk 2",
            category=RiskCategory.SAFETY,
            likelihood=0.2,
            impact=0.3,
        ))
        # (0.25 + 0.06) / 2 = 0.155
        assert assessment.get_overall_risk_score() == pytest.approx(0.155)

    def test_get_risk_level(self):
        assessment = RiskAssessment(
            assessment_id="RA-003",
            system_name="GridOptimizer",
            system_version="1.0.0",
        )
        assessment.add_factor(RiskFactor(
            factor_id="RF-001",
            name="Critical Risk",
            category=RiskCategory.SAFETY,
            likelihood=0.9,
            impact=0.9,
        ))
        assert assessment.get_risk_level() == "critical"

    def test_get_factors_by_category(self):
        assessment = RiskAssessment(
            assessment_id="RA-004",
            system_name="GridOptimizer",
            system_version="1.0.0",
        )
        assessment.add_factor(RiskFactor(
            factor_id="RF-001",
            name="Validity Risk",
            category=RiskCategory.VALIDITY,
            likelihood=0.5,
            impact=0.5,
        ))
        assessment.add_factor(RiskFactor(
            factor_id="RF-002",
            name="Safety Risk",
            category=RiskCategory.SAFETY,
            likelihood=0.3,
            impact=0.4,
        ))
        validity_factors = assessment.get_factors_by_category(RiskCategory.VALIDITY)
        assert len(validity_factors) == 1
        assert validity_factors[0].name == "Validity Risk"

    def test_get_critical_factors(self):
        assessment = RiskAssessment(
            assessment_id="RA-005",
            system_name="GridOptimizer",
            system_version="1.0.0",
        )
        assessment.add_factor(RiskFactor(
            factor_id="RF-001",
            name="Critical",
            category=RiskCategory.SAFETY,
            likelihood=0.9,
            impact=0.9,
        ))
        assessment.add_factor(RiskFactor(
            factor_id="RF-002",
            name="Low",
            category=RiskCategory.VALIDITY,
            likelihood=0.1,
            impact=0.1,
        ))
        critical = assessment.get_critical_factors()
        assert len(critical) == 1
        assert critical[0].name == "Critical"

    def test_to_dict_contains_all_fields(self):
        assessment = RiskAssessment(
            assessment_id="RA-006",
            system_name="GridOptimizer",
            system_version="1.0.0",
        )
        assessment.add_factor(RiskFactor(
            factor_id="RF-001",
            name="Risk 1",
            category=RiskCategory.VALIDITY,
            likelihood=0.5,
            impact=0.5,
        ))
        d = assessment.to_dict()
        assert d["assessment_id"] == "RA-006"
        assert d["system_name"] == "GridOptimizer"
        assert "overall_risk_score" in d
        assert "risk_level" in d
        assert len(d["factors"]) == 1


# ── ComplianceRule Tests ─────────────────────────────────────────────────────


class TestComplianceRule:
    """Tests for ComplianceRule."""

    def test_rule_creation(self):
        rule = ComplianceRule(
            rule_id="CR-001",
            name="Model Version Check",
            description="Model must have a version",
            severity=ComplianceSeverity.HIGH,
            rule_expression="model_version:exists",
        )
        assert rule.rule_id == "CR-001"
        assert rule.name == "Model Version Check"
        assert rule.severity == ComplianceSeverity.HIGH

    def test_evaluate_expression_exists_passes(self):
        rule = ComplianceRule(
            rule_id="CR-002",
            name="Test",
            description="Test",
            severity=ComplianceSeverity.MEDIUM,
            rule_expression="model_version:exists",
        )
        result = rule.evaluate({"model_version": "1.0"})
        assert result is True

    def test_evaluate_expression_exists_fails(self):
        rule = ComplianceRule(
            rule_id="CR-003",
            name="Test",
            description="Test",
            severity=ComplianceSeverity.MEDIUM,
            rule_expression="model_version:exists",
        )
        result = rule.evaluate({"other": "value"})
        assert result is False

    def test_evaluate_with_custom_function(self):
        def check_func(ctx):
            return ctx.get("score", 0) > 0.5

        rule = ComplianceRule(
            rule_id="CR-004",
            name="Score Check",
            description="Score must be above 0.5",
            severity=ComplianceSeverity.HIGH,
            check_function=check_func,
        )
        assert rule.evaluate({"score": 0.8}) is True
        assert rule.evaluate({"score": 0.3}) is False

    def test_to_dict_contains_all_fields(self):
        rule = ComplianceRule(
            rule_id="CR-005",
            name="Test Rule",
            description="Test description",
            severity=ComplianceSeverity.CRITICAL,
            rule_expression="test:exists",
        )
        d = rule.to_dict()
        assert d["rule_id"] == "CR-005"
        assert d["severity"] == "critical"
        assert d["rule_expression"] == "test:exists"


# ── ComplianceCheck Tests ────────────────────────────────────────────────────


class TestComplianceCheck:
    """Tests for ComplianceCheck."""

    def test_check_creation(self):
        check = ComplianceCheck(
            rule_id="CR-001",
            rule_name="Test Rule",
            compliant=True,
            severity=ComplianceSeverity.LOW,
            message="All good",
        )
        assert check.rule_id == "CR-001"
        assert check.compliant is True
        assert check.severity == ComplianceSeverity.LOW

    def test_check_to_dict(self):
        check = ComplianceCheck(
            rule_id="CR-001",
            rule_name="Test Rule",
            compliant=False,
            severity=ComplianceSeverity.HIGH,
            message="Violation found",
        )
        d = check.to_dict()
        assert d["rule_id"] == "CR-001"
        assert d["compliant"] is False
        assert d["severity"] == "high"
        assert "check_id" in d
        assert "timestamp" in d


# ── ComplianceViolation Tests ────────────────────────────────────────────────


class TestComplianceViolation:
    """Tests for ComplianceViolation."""

    def test_violation_creation(self):
        violation = ComplianceViolation(
            rule_id="CR-001",
            rule_name="Test Rule",
            severity=ComplianceSeverity.HIGH,
            description="Test violation",
            system_name="GridOptimizer",
        )
        assert violation.rule_id == "CR-001"
        assert violation.resolved is False
        assert violation.resolved_at is None

    def test_resolve_violation(self):
        violation = ComplianceViolation(
            rule_id="CR-001",
            rule_name="Test Rule",
            severity=ComplianceSeverity.HIGH,
            description="Test violation",
            system_name="GridOptimizer",
        )
        violation.resolve()
        assert violation.resolved is True
        assert violation.resolved_at is not None

    def test_violation_to_dict(self):
        violation = ComplianceViolation(
            rule_id="CR-001",
            rule_name="Test Rule",
            severity=ComplianceSeverity.MEDIUM,
            description="Test violation",
            system_name="GridOptimizer",
        )
        d = violation.to_dict()
        assert d["rule_id"] == "CR-001"
        assert d["resolved"] is False
        assert "violation_id" in d
        assert "detected_at" in d


# ── ComplianceAutomationEngine Tests ─────────────────────────────────────────


class TestComplianceAutomationEngine:
    """Tests for ComplianceAutomationEngine."""

    def test_engine_creation(self):
        engine = ComplianceAutomationEngine("ApexGrid Compliance")
        assert engine.name == "ApexGrid Compliance"
        assert engine.get_checks() == []

    def test_add_and_retrieve_rule(self):
        engine = ComplianceAutomationEngine("Test")
        rule = ComplianceRule(
            rule_id="CR-001",
            name="Test Rule",
            description="Test",
            severity=ComplianceSeverity.HIGH,
            rule_expression="model_version:exists",
        )
        engine.add_rule(rule)
        retrieved = engine.get_rule("CR-001")
        assert retrieved is not None
        assert retrieved.name == "Test Rule"

    def test_run_check_compliant(self):
        engine = ComplianceAutomationEngine("Test")
        rule = ComplianceRule(
            rule_id="CR-001",
            name="Version Check",
            description="Must have version",
            severity=ComplianceSeverity.HIGH,
            rule_expression="model_version:exists",
        )
        engine.add_rule(rule)
        check = engine.run_check("CR-001", {"model_version": "1.0"})
        assert check.compliant is True
        assert check.rule_name == "Version Check"

    def test_run_check_non_compliant_creates_violation(self):
        engine = ComplianceAutomationEngine("Test")
        rule = ComplianceRule(
            rule_id="CR-001",
            name="Version Check",
            description="Must have version",
            severity=ComplianceSeverity.HIGH,
            rule_expression="model_version:exists",
        )
        engine.add_rule(rule)
        check = engine.run_check("CR-001", {"other": "value"})
        assert check.compliant is False
        violations = engine.get_violations()
        assert len(violations) == 1
        assert violations[0].rule_id == "CR-001"

    def test_run_all_checks(self):
        engine = ComplianceAutomationEngine("Test")
        engine.add_rule(ComplianceRule(
            rule_id="CR-001",
            name="Rule 1",
            description="Test 1",
            severity=ComplianceSeverity.HIGH,
            rule_expression="attr1:exists",
        ))
        engine.add_rule(ComplianceRule(
            rule_id="CR-002",
            name="Rule 2",
            description="Test 2",
            severity=ComplianceSeverity.MEDIUM,
            rule_expression="attr2:exists",
        ))
        checks = engine.run_all_checks({"attr1": "value"})
        assert len(checks) == 2
        assert checks[0].compliant is True
        assert checks[1].compliant is False

    def test_get_compliance_score(self):
        engine = ComplianceAutomationEngine("Test")
        engine.add_rule(ComplianceRule(
            rule_id="CR-001",
            name="Rule 1",
            description="Test 1",
            severity=ComplianceSeverity.HIGH,
            rule_expression="attr1:exists",
        ))
        engine.add_rule(ComplianceRule(
            rule_id="CR-002",
            name="Rule 2",
            description="Test 2",
            severity=ComplianceSeverity.MEDIUM,
            rule_expression="attr2:exists",
        ))
        engine.run_all_checks({"attr1": "value", "attr2": "value"})
        assert engine.get_compliance_score() == 1.0
        # Fresh engine: 1 compliant out of 2 checks
        engine2 = ComplianceAutomationEngine("Test2")
        engine2.add_rule(ComplianceRule(
            rule_id="CR-001",
            name="Rule 1",
            description="Test 1",
            severity=ComplianceSeverity.HIGH,
            rule_expression="attr1:exists",
        ))
        engine2.add_rule(ComplianceRule(
            rule_id="CR-002",
            name="Rule 2",
            description="Test 2",
            severity=ComplianceSeverity.MEDIUM,
            rule_expression="attr2:exists",
        ))
        engine2.run_all_checks({"attr1": "value"})
        assert engine2.get_compliance_score() == pytest.approx(0.5)

    def test_resolve_violation(self):
        engine = ComplianceAutomationEngine("Test")
        engine.add_rule(ComplianceRule(
            rule_id="CR-001",
            name="Rule 1",
            description="Test 1",
            severity=ComplianceSeverity.HIGH,
            rule_expression="attr1:exists",
        ))
        engine.run_check("CR-001", {})
        violations = engine.get_violations()
        assert len(violations) == 1
        vid = violations[0].violation_id
        assert engine.resolve_violation(vid) is True
        assert len(engine.get_violations()) == 0
        # Include resolved
        assert len(engine.get_violations(include_resolved=True)) == 1

    def test_get_violations_by_severity(self):
        engine = ComplianceAutomationEngine("Test")
        engine.add_rule(ComplianceRule(
            rule_id="CR-001",
            name="Critical Rule",
            description="Test",
            severity=ComplianceSeverity.CRITICAL,
            rule_expression="attr1:exists",
        ))
        engine.add_rule(ComplianceRule(
            rule_id="CR-002",
            name="Low Rule",
            description="Test",
            severity=ComplianceSeverity.LOW,
            rule_expression="attr2:exists",
        ))
        engine.run_all_checks({})
        critical = engine.get_violations_by_severity(ComplianceSeverity.CRITICAL)
        assert len(critical) == 1
        assert critical[0].rule_id == "CR-001"

    def test_get_summary(self):
        engine = ComplianceAutomationEngine("Test")
        engine.add_rule(ComplianceRule(
            rule_id="CR-001",
            name="Rule 1",
            description="Test",
            severity=ComplianceSeverity.HIGH,
            rule_expression="attr1:exists",
        ))
        engine.run_check("CR-001", {"attr1": "value"})
        summary = engine.get_summary()
        assert summary["engine_name"] == "Test"
        assert summary["total_checks"] == 1
        assert summary["compliant_checks"] == 1
        assert summary["violations"] == 0
        assert summary["compliance_score"] == 1.0
        assert summary["rules_count"] == 1

    def test_run_check_unknown_rule(self):
        engine = ComplianceAutomationEngine("Test")
        check = engine.run_check("NONEXISTENT", {})
        assert check.compliant is False
        assert "not found" in check.message
