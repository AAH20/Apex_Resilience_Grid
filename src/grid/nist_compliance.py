"""NIST AI 100-2 Compliance Module.

Implements AI risk management, governance controls, and compliance reporting
per NIST AI 100-2 (Adversarial Machine Learning: A Taxonomy and Terminology
of Attacks, Mitigations, and Failures).

Provides:
- AIRisk: Risk identification and tracking
- GovernanceControl: Control implementation and evidence
- ComplianceReport: Aggregated compliance reporting and export
"""

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class RiskLevel(Enum):
    """Risk severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackCategory(Enum):
    """NIST AI 100-2 attack categories."""

    POISONING = "poisoning"
    EVASION = "evasion"
    PRIVACY = "privacy"
    ABUSE = "abuse"


class MitigationStatus(Enum):
    """Control implementation status."""

    PLANNED = "planned"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"


@dataclass
class AIRisk:
    """Represents an AI system risk per NIST AI 100-2."""

    risk_id: str
    name: str
    description: str
    attack_category: AttackCategory
    risk_level: RiskLevel
    likelihood: float
    impact: float
    mitigations: List[str] = field(default_factory=list)
    status: str = "identified"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def risk_score(self) -> float:
        """Computed risk score: likelihood × impact."""
        return self.likelihood * self.impact

    def add_mitigation(self, mitigation: str) -> None:
        """Add a mitigation strategy to this risk."""
        self.mitigations.append(mitigation)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize risk to dictionary."""
        return {
            "risk_id": self.risk_id,
            "name": self.name,
            "description": self.description,
            "attack_category": self.attack_category.value,
            "risk_level": self.risk_level.value,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk_score": self.risk_score,
            "mitigations": list(self.mitigations),
            "status": self.status,
            "created_at": self.created_at,
        }


@dataclass
class GovernanceControl:
    """Represents a governance control for AI risk mitigation."""

    control_id: str
    name: str
    description: str
    control_type: str
    owner: str
    status: MitigationStatus
    related_risks: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def add_evidence(self, evidence: str) -> None:
        """Add evidence supporting this control."""
        self.evidence.append(evidence)

    def link_risk(self, risk_id: str) -> None:
        """Link a risk to this control (no duplicates)."""
        if risk_id not in self.related_risks:
            self.related_risks.append(risk_id)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize control to dictionary."""
        return {
            "control_id": self.control_id,
            "name": self.name,
            "description": self.description,
            "control_type": self.control_type,
            "owner": self.owner,
            "status": self.status.value,
            "related_risks": list(self.related_risks),
            "evidence": list(self.evidence),
            "created_at": self.created_at,
        }


class ComplianceReport:
    """Aggregated NIST AI 100-2 compliance report."""

    def __init__(self, system_name: str, system_version: str):
        self.system_name = system_name
        self.system_version = system_version
        self.risks: List[AIRisk] = []
        self.controls: List[GovernanceControl] = []
        self.report_id = str(uuid.uuid4())
        self.generated_at = datetime.now(timezone.utc).isoformat()

    def add_risk(self, risk: AIRisk) -> None:
        """Add a risk to the report."""
        self.risks.append(risk)

    def add_control(self, control: GovernanceControl) -> None:
        """Add a control to the report."""
        self.controls.append(control)

    def risks_by_category(self, category: AttackCategory) -> List[AIRisk]:
        """Filter risks by attack category."""
        return [r for r in self.risks if r.attack_category == category]

    def risks_by_level(self, level: RiskLevel) -> List[AIRisk]:
        """Filter risks by risk level."""
        return [r for r in self.risks if r.risk_level == level]

    def controls_by_status(self, status: MitigationStatus) -> List[GovernanceControl]:
        """Filter controls by mitigation status."""
        return [c for c in self.controls if c.status == status]

    def overall_risk_score(self) -> float:
        """Average risk score across all risks."""
        if not self.risks:
            return 0.0
        return sum(r.risk_score for r in self.risks) / len(self.risks)

    def compliance_score(self) -> float:
        """Ratio of verified controls to total controls."""
        if not self.controls:
            return 0.0
        verified = len(self.controls_by_status(MitigationStatus.VERIFIED))
        return verified / len(self.controls)

    def generate_summary(self) -> Dict[str, Any]:
        """Generate a summary of the compliance report."""
        risks_by_cat: Dict[str, int] = {}
        for cat in AttackCategory:
            risks_by_cat[cat.value] = len(self.risks_by_category(cat))

        risks_by_lvl: Dict[str, int] = {}
        for lvl in RiskLevel:
            risks_by_lvl[lvl.value] = len(self.risks_by_level(lvl))

        controls_by_stat: Dict[str, int] = {}
        for stat in MitigationStatus:
            controls_by_stat[stat.value] = len(self.controls_by_status(stat))

        return {
            "system_name": self.system_name,
            "system_version": self.system_version,
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "total_risks": len(self.risks),
            "total_controls": len(self.controls),
            "overall_risk_score": self.overall_risk_score(),
            "compliance_score": self.compliance_score(),
            "risks_by_category": risks_by_cat,
            "risks_by_level": risks_by_lvl,
            "controls_by_status": controls_by_stat,
        }

    def generate_full_report(self) -> Dict[str, Any]:
        """Generate the full compliance report with all details."""
        summary = self.generate_summary()
        summary["risks"] = [r.to_dict() for r in self.risks]
        summary["controls"] = [c.to_dict() for c in self.controls]
        return summary

    def export_json(self, filepath: str) -> None:
        """Export the full report to a JSON file."""
        report = self.generate_full_report()
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of the report content (excluding volatile fields)."""
        report = self.generate_full_report()
        # Exclude volatile fields that change between instances
        volatile_keys = {"report_id", "generated_at", "created_at"}
        for key in list(report.keys()):
            if key in volatile_keys:
                report.pop(key)
        for risk in report.get("risks", []):
            for key in list(risk.keys()):
                if key in volatile_keys:
                    risk.pop(key)
        for control in report.get("controls", []):
            for key in list(control.keys()):
                if key in volatile_keys:
                    control.pop(key)
        content = json.dumps(report, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
