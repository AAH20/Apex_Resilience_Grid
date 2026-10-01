"""Tests for NIST AI 100-2 compliance module.

Covers AI risk management, governance controls, and compliance reporting
per NIST AI 100-2 (Adversarial Machine Learning: A Taxonomy and Terminology
of Attacks, Mitigations, and Failures).
"""

import json
import os
import tempfile

import pytest

from src.grid.nist_compliance import (
    AIRisk,
    AttackCategory,
    ComplianceReport,
    GovernanceControl,
    MitigationStatus,
    RiskLevel,
)


# ── AIRisk Tests ─────────────────────────────────────────────────────────────


class TestAIRisk:
    """Tests for the AIRisk dataclass."""

    def test_risk_creation_with_required_fields(self):
        """AIRisk can be created with all required fields."""
        risk = AIRisk(
            risk_id="RISK-001",
            name="Data Poisoning",
            description="Adversarial poisoning of training data",
            attack_category=AttackCategory.POISONING,
            risk_level=RiskLevel.HIGH,
            likelihood=0.7,
            impact=0.9,
        )
        assert risk.risk_id == "RISK-001"
        assert risk.name == "Data Poisoning"
        assert risk.attack_category == AttackCategory.POISONING
        assert risk.risk_level == RiskLevel.HIGH
        assert risk.likelihood == 0.7
        assert risk.impact == 0.9

    def test_risk_score_is_likelihood_times_impact(self):
        """Risk score equals likelihood multiplied by impact."""
        risk = AIRisk(
            risk_id="RISK-002",
            name="Evasion Attack",
            description="Model evasion via adversarial examples",
            attack_category=AttackCategory.EVASION,
            risk_level=RiskLevel.MEDIUM,
            likelihood=0.5,
            impact=0.8,
        )
        assert risk.risk_score == pytest.approx(0.4)

    def test_risk_score_with_zero_likelihood(self):
        """Risk score is zero when likelihood is zero."""
        risk = AIRisk(
            risk_id="RISK-003",
            name="Privacy Leakage",
            description="Model inversion attack",
            attack_category=AttackCategory.PRIVACY,
            risk_level=RiskLevel.LOW,
            likelihood=0.0,
            impact=0.9,
        )
        assert risk.risk_score == 0.0

    def test_add_mitigation_appends_to_list(self):
        """Adding a mitigation appends it to the mitigations list."""
        risk = AIRisk(
            risk_id="RISK-004",
            name="Model Theft",
            description="Model extraction attack",
            attack_category=AttackCategory.ABUSE,
            risk_level=RiskLevel.MEDIUM,
            likelihood=0.3,
            impact=0.6,
        )
        risk.add_mitigation("Rate limiting")
        risk.add_mitigation("Differential privacy")
        assert len(risk.mitigations) == 2
        assert "Rate limiting" in risk.mitigations
        assert "Differential privacy" in risk.mitigations

    def test_to_dict_contains_all_fields(self):
        """to_dict returns a dictionary with all risk fields."""
        risk = AIRisk(
            risk_id="RISK-005",
            name="Backdoor Attack",
            description="Trojan trigger in model",
            attack_category=AttackCategory.POISONING,
            risk_level=RiskLevel.CRITICAL,
            likelihood=0.8,
            impact=0.95,
        )
        risk.add_mitigation("Input sanitization")
        d = risk.to_dict()
        assert d["risk_id"] == "RISK-005"
        assert d["name"] == "Backdoor Attack"
        assert d["attack_category"] == "poisoning"
        assert d["risk_level"] == "critical"
        assert d["likelihood"] == 0.8
        assert d["impact"] == 0.95
        assert d["risk_score"] == pytest.approx(0.76)
        assert d["mitigations"] == ["Input sanitization"]
        assert d["status"] == "identified"
        assert "created_at" in d

    def test_default_status_is_identified(self):
        """Default status for a new risk is 'identified'."""
        risk = AIRisk(
            risk_id="RISK-006",
            name="Membership Inference",
            description="Membership inference attack",
            attack_category=AttackCategory.PRIVACY,
            risk_level=RiskLevel.LOW,
            likelihood=0.2,
            impact=0.3,
        )
        assert risk.status == "identified"


# ── GovernanceControl Tests ──────────────────────────────────────────────────


class TestGovernanceControl:
    """Tests for the GovernanceControl dataclass."""

    def test_control_creation_with_required_fields(self):
        """GovernanceControl can be created with all required fields."""
        control = GovernanceControl(
            control_id="CTRL-001",
            name="Data Validation Pipeline",
            description="Validates all training data inputs",
            control_type="preventive",
            owner="ML Team",
            status=MitigationStatus.IMPLEMENTED,
        )
        assert control.control_id == "CTRL-001"
        assert control.name == "Data Validation Pipeline"
        assert control.control_type == "preventive"
        assert control.owner == "ML Team"
        assert control.status == MitigationStatus.IMPLEMENTED

    def test_add_evidence_appends_to_list(self):
        """Adding evidence appends it to the evidence list."""
        control = GovernanceControl(
            control_id="CTRL-002",
            name="Access Control",
            description="Role-based access to ML pipeline",
            control_type="preventive",
            owner="Security Team",
            status=MitigationStatus.VERIFIED,
        )
        control.add_evidence("Audit log 2024-01-15")
        control.add_evidence("Penetration test report")
        assert len(control.evidence) == 2
        assert "Audit log 2024-01-15" in control.evidence

    def test_link_risk_adds_risk_id(self):
        """Linking a risk adds the risk_id to related_risks."""
        control = GovernanceControl(
            control_id="CTRL-003",
            name="Model Monitoring",
            description="Continuous model output monitoring",
            control_type="detective",
            owner="Ops Team",
            status=MitigationStatus.IMPLEMENTED,
        )
        control.link_risk("RISK-001")
        control.link_risk("RISK-002")
        assert "RISK-001" in control.related_risks
        assert "RISK-002" in control.related_risks

    def test_link_risk_does_not_duplicate(self):
        """Linking the same risk twice does not create duplicates."""
        control = GovernanceControl(
            control_id="CTRL-004",
            name="Encryption at Rest",
            description="Encrypt model artifacts at rest",
            control_type="preventive",
            owner="Infra Team",
            status=MitigationStatus.VERIFIED,
        )
        control.link_risk("RISK-001")
        control.link_risk("RISK-001")
        assert control.related_risks.count("RISK-001") == 1

    def test_to_dict_contains_all_fields(self):
        """to_dict returns a dictionary with all control fields."""
        control = GovernanceControl(
            control_id="CTRL-005",
            name="Incident Response Plan",
            description="Documented IR plan for ML incidents",
            control_type="corrective",
            owner="Security Team",
            status=MitigationStatus.PLANNED,
        )
        control.link_risk("RISK-001")
        control.add_evidence("IR plan v1.2")
        d = control.to_dict()
        assert d["control_id"] == "CTRL-005"
        assert d["name"] == "Incident Response Plan"
        assert d["control_type"] == "corrective"
        assert d["owner"] == "Security Team"
        assert d["status"] == "planned"
        assert d["related_risks"] == ["RISK-001"]
        assert d["evidence"] == ["IR plan v1.2"]
        assert "created_at" in d


# ── ComplianceReport Tests ───────────────────────────────────────────────────


class TestComplianceReport:
    """Tests for the ComplianceReport class."""

    def test_report_creation_with_system_info(self):
        """ComplianceReport can be created with system name and version."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        assert report.system_name == "ApexGrid"
        assert report.system_version == "2.1.0"
        assert report.risks == []
        assert report.controls == []

    def test_add_risk_appends_to_list(self):
        """Adding a risk appends it to the risks list."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        risk = AIRisk(
            risk_id="RISK-001",
            name="Data Poisoning",
            description="Training data poisoning",
            attack_category=AttackCategory.POISONING,
            risk_level=RiskLevel.HIGH,
            likelihood=0.7,
            impact=0.9,
        )
        report.add_risk(risk)
        assert len(report.risks) == 1
        assert report.risks[0].risk_id == "RISK-001"

    def test_add_control_appends_to_list(self):
        """Adding a control appends it to the controls list."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        control = GovernanceControl(
            control_id="CTRL-001",
            name="Data Validation",
            description="Input validation",
            control_type="preventive",
            owner="ML Team",
            status=MitigationStatus.IMPLEMENTED,
        )
        report.add_control(control)
        assert len(report.controls) == 1
        assert report.controls[0].control_id == "CTRL-001"

    def test_risks_by_category_filters_correctly(self):
        """risks_by_category returns only risks matching the category."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        report.add_risk(
            AIRisk(
                risk_id="R1",
                name="Poisoning",
                description="d",
                attack_category=AttackCategory.POISONING,
                risk_level=RiskLevel.HIGH,
                likelihood=0.5,
                impact=0.5,
            )
        )
        report.add_risk(
            AIRisk(
                risk_id="R2",
                name="Evasion",
                description="d",
                attack_category=AttackCategory.EVASION,
                risk_level=RiskLevel.MEDIUM,
                likelihood=0.3,
                impact=0.4,
            )
        )
        report.add_risk(
            AIRisk(
                risk_id="R3",
                name="Poisoning 2",
                description="d",
                attack_category=AttackCategory.POISONING,
                risk_level=RiskLevel.LOW,
                likelihood=0.1,
                impact=0.2,
            )
        )
        poisoning_risks = report.risks_by_category(AttackCategory.POISONING)
        assert len(poisoning_risks) == 2
        assert all(r.attack_category == AttackCategory.POISONING for r in poisoning_risks)

    def test_risks_by_level_filters_correctly(self):
        """risks_by_level returns only risks matching the level."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        report.add_risk(
            AIRisk(
                risk_id="R1",
                name="Critical Risk",
                description="d",
                attack_category=AttackCategory.POISONING,
                risk_level=RiskLevel.CRITICAL,
                likelihood=0.9,
                impact=0.9,
            )
        )
        report.add_risk(
            AIRisk(
                risk_id="R2",
                name="Low Risk",
                description="d",
                attack_category=AttackCategory.EVASION,
                risk_level=RiskLevel.LOW,
                likelihood=0.1,
                impact=0.1,
            )
        )
        critical_risks = report.risks_by_level(RiskLevel.CRITICAL)
        assert len(critical_risks) == 1
        assert critical_risks[0].risk_id == "R1"

    def test_controls_by_status_filters_correctly(self):
        """controls_by_status returns only controls matching the status."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        report.add_control(
            GovernanceControl(
                control_id="C1",
                name="Verified Control",
                description="d",
                control_type="preventive",
                owner="Team A",
                status=MitigationStatus.VERIFIED,
            )
        )
        report.add_control(
            GovernanceControl(
                control_id="C2",
                name="Planned Control",
                description="d",
                control_type="detective",
                owner="Team B",
                status=MitigationStatus.PLANNED,
            )
        )
        verified = report.controls_by_status(MitigationStatus.VERIFIED)
        assert len(verified) == 1
        assert verified[0].control_id == "C1"

    def test_overall_risk_score_is_average(self):
        """overall_risk_score returns the average risk score across all risks."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        report.add_risk(
            AIRisk(
                risk_id="R1",
                name="Risk 1",
                description="d",
                attack_category=AttackCategory.POISONING,
                risk_level=RiskLevel.HIGH,
                likelihood=0.5,
                impact=0.5,
            )
        )
        report.add_risk(
            AIRisk(
                risk_id="R2",
                name="Risk 2",
                description="d",
                attack_category=AttackCategory.EVASION,
                risk_level=RiskLevel.LOW,
                likelihood=0.2,
                impact=0.3,
            )
        )
        # (0.25 + 0.06) / 2 = 0.155
        assert report.overall_risk_score() == pytest.approx(0.155)

    def test_overall_risk_score_empty_report(self):
        """overall_risk_score returns 0.0 when there are no risks."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        assert report.overall_risk_score() == 0.0

    def test_compliance_score_is_verified_ratio(self):
        """compliance_score returns ratio of verified controls to total."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        report.add_control(
            GovernanceControl(
                control_id="C1",
                name="Verified",
                description="d",
                control_type="preventive",
                owner="Team A",
                status=MitigationStatus.VERIFIED,
            )
        )
        report.add_control(
            GovernanceControl(
                control_id="C2",
                name="Implemented",
                description="d",
                control_type="detective",
                owner="Team B",
                status=MitigationStatus.IMPLEMENTED,
            )
        )
        report.add_control(
            GovernanceControl(
                control_id="C3",
                name="Planned",
                description="d",
                control_type="corrective",
                owner="Team C",
                status=MitigationStatus.PLANNED,
            )
        )
        # 1 verified out of 3 total
        assert report.compliance_score() == pytest.approx(1.0 / 3.0)

    def test_compliance_score_empty_report(self):
        """compliance_score returns 0.0 when there are no controls."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        assert report.compliance_score() == 0.0

    def test_generate_summary_structure(self):
        """generate_summary returns a dictionary with expected keys."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        report.add_risk(
            AIRisk(
                risk_id="R1",
                name="Risk 1",
                description="d",
                attack_category=AttackCategory.POISONING,
                risk_level=RiskLevel.HIGH,
                likelihood=0.5,
                impact=0.5,
            )
        )
        report.add_control(
            GovernanceControl(
                control_id="C1",
                name="Control 1",
                description="d",
                control_type="preventive",
                owner="Team A",
                status=MitigationStatus.VERIFIED,
            )
        )
        summary = report.generate_summary()
        assert summary["system_name"] == "ApexGrid"
        assert summary["system_version"] == "2.1.0"
        assert summary["total_risks"] == 1
        assert summary["total_controls"] == 1
        assert "overall_risk_score" in summary
        assert "compliance_score" in summary
        assert "risks_by_category" in summary
        assert "risks_by_level" in summary
        assert "controls_by_status" in summary
        assert "report_id" in summary
        assert "generated_at" in summary

    def test_generate_full_report_includes_risks_and_controls(self):
        """generate_full_report includes full risk and control details."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        report.add_risk(
            AIRisk(
                risk_id="R1",
                name="Risk 1",
                description="d",
                attack_category=AttackCategory.POISONING,
                risk_level=RiskLevel.HIGH,
                likelihood=0.5,
                impact=0.5,
            )
        )
        report.add_control(
            GovernanceControl(
                control_id="C1",
                name="Control 1",
                description="d",
                control_type="preventive",
                owner="Team A",
                status=MitigationStatus.VERIFIED,
            )
        )
        full = report.generate_full_report()
        assert len(full["risks"]) == 1
        assert full["risks"][0]["risk_id"] == "R1"
        assert len(full["controls"]) == 1
        assert full["controls"][0]["control_id"] == "C1"

    def test_export_json_writes_valid_file(self):
        """export_json writes a valid JSON file to disk."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        report.add_risk(
            AIRisk(
                risk_id="R1",
                name="Risk 1",
                description="d",
                attack_category=AttackCategory.POISONING,
                risk_level=RiskLevel.HIGH,
                likelihood=0.5,
                impact=0.5,
            )
        )
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name
        try:
            report.export_json(filepath)
            assert os.path.exists(filepath)
            with open(filepath) as f:
                data = json.load(f)
            assert data["system_name"] == "ApexGrid"
            assert len(data["risks"]) == 1
        finally:
            os.unlink(filepath)

    def test_compute_hash_returns_sha256_hex(self):
        """compute_hash returns a 64-character hex string (SHA-256)."""
        report = ComplianceReport("ApexGrid", "2.1.0")
        hash_value = report.compute_hash()
        assert len(hash_value) == 64
        assert all(c in "0123456789abcdef" for c in hash_value)

    def test_compute_hash_is_deterministic(self):
        """compute_hash returns the same value for identical reports."""
        report1 = ComplianceReport("ApexGrid", "2.1.0")
        report1.add_risk(
            AIRisk(
                risk_id="R1",
                name="Risk 1",
                description="d",
                attack_category=AttackCategory.POISONING,
                risk_level=RiskLevel.HIGH,
                likelihood=0.5,
                impact=0.5,
            )
        )
        report2 = ComplianceReport("ApexGrid", "2.1.0")
        report2.add_risk(
            AIRisk(
                risk_id="R1",
                name="Risk 1",
                description="d",
                attack_category=AttackCategory.POISONING,
                risk_level=RiskLevel.HIGH,
                likelihood=0.5,
                impact=0.5,
            )
        )
        assert report1.compute_hash() == report2.compute_hash()

    def test_compute_hash_changes_with_different_content(self):
        """compute_hash returns different values for different reports."""
        report1 = ComplianceReport("ApexGrid", "2.1.0")
        report1.add_risk(
            AIRisk(
                risk_id="R1",
                name="Risk 1",
                description="d",
                attack_category=AttackCategory.POISONING,
                risk_level=RiskLevel.HIGH,
                likelihood=0.5,
                impact=0.5,
            )
        )
        report2 = ComplianceReport("ApexGrid", "2.1.0")
        report2.add_risk(
            AIRisk(
                risk_id="R2",
                name="Risk 2",
                description="d",
                attack_category=AttackCategory.EVASION,
                risk_level=RiskLevel.LOW,
                likelihood=0.1,
                impact=0.1,
            )
        )
        assert report1.compute_hash() != report2.compute_hash()


# ── Enum Tests ───────────────────────────────────────────────────────────────


class TestEnums:
    """Tests for enum values."""

    def test_risk_level_values(self):
        """RiskLevel enum has LOW, MEDIUM, HIGH, CRITICAL."""
        assert RiskLevel.LOW is not None
        assert RiskLevel.MEDIUM is not None
        assert RiskLevel.HIGH is not None
        assert RiskLevel.CRITICAL is not None

    def test_attack_category_values(self):
        """AttackCategory enum has POISONING, EVASION, PRIVACY, ABUSE."""
        assert AttackCategory.POISONING.value == "poisoning"
        assert AttackCategory.EVASION.value == "evasion"
        assert AttackCategory.PRIVACY.value == "privacy"
        assert AttackCategory.ABUSE.value == "abuse"

    def test_mitigation_status_values(self):
        """MitigationStatus enum has PLANNED, IMPLEMENTED, VERIFIED."""
        assert MitigationStatus.PLANNED.value == "planned"
        assert MitigationStatus.IMPLEMENTED.value == "implemented"
        assert MitigationStatus.VERIFIED.value == "verified"
