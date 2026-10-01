"""CISA Cybersecurity Framework (CSF) alignment module.

Maps Apex Resilience Grid controls to the CISA CSF v2.0 framework,
provides control assessment, gap analysis, and compliance reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CSFFunction(Enum):
    """CISA CSF v2.0 six core functions."""

    GOVERN = "GOVERN"
    IDENTIFY = "IDENTIFY"
    PROTECT = "PROTECT"
    DETECT = "DETECT"
    RESPOND = "RESPOND"
    RECOVER = "RECOVER"


class ControlStatus(Enum):
    """Implementation maturity levels for a control."""

    NOT_IMPLEMENTED = 0
    PARTIALLY_IMPLEMENTED = 1
    IMPLEMENTED = 2


@dataclass
class Control:
    """A single CISA CSF control."""

    id: str
    name: str
    function: CSFFunction
    description: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "function": self.function.value,
            "description": self.description,
            "status": "NOT_IMPLEMENTED",
            "evidence": list(self.evidence),
        }


@dataclass
class Gap:
    """A gap between current and target control implementation."""

    control_id: str
    control_name: str
    function: CSFFunction
    severity: str
    recommendation: str
    current_status: ControlStatus = ControlStatus.NOT_IMPLEMENTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "function": self.function.value,
            "severity": self.severity,
            "recommendation": self.recommendation,
            "current_status": self.current_status.name,
        }


# ── Severity mapping per CSF function ──────────────────────────────────────

_SEVERITY_MAP: dict[CSFFunction, str] = {
    CSFFunction.GOVERN: "critical",
    CSFFunction.IDENTIFY: "high",
    CSFFunction.PROTECT: "medium",
    CSFFunction.DETECT: "high",
    CSFFunction.RESPOND: "high",
    CSFFunction.RECOVER: "low",
}


# ── CISA CSF v2.0 control catalog ─────────────────────────────────────────

_CATALOG_DATA: list[tuple[str, str, CSFFunction, str]] = [
    # GOVERN
    ("GV-OC-01", "Organizational Context", CSFFunction.GOVERN,
     "Identify and communicate organizational mission, objectives, and stakeholders."),
    ("GV-OC-02", "Risk Management Strategy", CSFFunction.GOVERN,
     "Establish and communicate a risk management strategy aligned with organizational objectives."),
    ("GV-PO-01", "Cybersecurity Policy", CSFFunction.GOVERN,
     "Develop and communicate cybersecurity policies approved by senior leadership."),
    ("GV-PO-02", "Cybersecurity Roles and Responsibilities", CSFFunction.GOVERN,
     "Define and assign cybersecurity roles and responsibilities across the organization."),
    ("GV-OV-01", "Cybersecurity Oversight", CSFFunction.GOVERN,
     "Establish oversight mechanisms to monitor cybersecurity program effectiveness."),
    ("GV-OV-02", "Cybersecurity Risk Management Oversight", CSFFunction.GOVERN,
     "Oversee cybersecurity risk management activities and outcomes."),
    ("GV-SR-01", "Supply Chain Risk Management", CSFFunction.GOVERN,
     "Identify, assess, and manage supply chain cybersecurity risks."),
    ("GV-SR-02", "Third-Party Risk Management", CSFFunction.GOVERN,
     "Manage cybersecurity risks from third-party relationships and services."),
    ("GV-RM-01", "Risk Management Process", CSFFunction.GOVERN,
     "Establish and maintain a cybersecurity risk management process."),
    ("GV-RM-02", "Risk Assessment", CSFFunction.GOVERN,
     "Conduct regular cybersecurity risk assessments."),
    ("GV-RA-01", "Risk Analysis", CSFFunction.GOVERN,
     "Analyze cybersecurity risks to inform decision-making."),
    ("GV-RA-02", "Risk Response", CSFFunction.GOVERN,
     "Determine and implement appropriate risk response strategies."),
    # IDENTIFY
    ("ID.AM-1", "Asset Management", CSFFunction.IDENTIFY,
     "Identify and maintain an inventory of physical and logical assets."),
    ("ID.AM-2", "Software and Services Inventory", CSFFunction.IDENTIFY,
     "Maintain an inventory of software and services used in the organization."),
    ("ID.AM-3", "Data Inventory", CSFFunction.IDENTIFY,
     "Identify and classify data assets and their associated risks."),
    ("ID.RA-1", "Risk Assessment", CSFFunction.IDENTIFY,
     "Identify and assess cybersecurity risks to assets and operations."),
    ("ID.RA-2", "Threat Intelligence", CSFFunction.IDENTIFY,
     "Collect and analyze threat intelligence to inform risk decisions."),
    ("ID.RA-3", "Vulnerability Management", CSFFunction.IDENTIFY,
     "Identify and track vulnerabilities across the asset inventory."),
    ("ID.SC-1", "Supply Chain Risk Assessment", CSFFunction.IDENTIFY,
     "Assess cybersecurity risks in the supply chain."),
    ("ID.SC-2", "Supplier Contracts", CSFFunction.IDENTIFY,
     "Include cybersecurity requirements in supplier contracts."),
    # PROTECT
    ("PR.AA-1", "Identity and Access Management", CSFFunction.PROTECT,
     "Implement identity and access management controls for all users and systems."),
    ("PR.AA-2", "Authentication", CSFFunction.PROTECT,
     "Enforce strong authentication mechanisms for all access points."),
    ("PR.AA-3", "Authorization", CSFFunction.PROTECT,
     "Enforce least-privilege authorization policies."),
    ("PR.AA-4", "Identity Proofing", CSFFunction.PROTECT,
     "Verify identities before granting access to systems and data."),
    ("PR.AA-5", "Credential Management", CSFFunction.PROTECT,
     "Manage credentials securely throughout their lifecycle."),
    ("PR.DS-1", "Data Security", CSFFunction.PROTECT,
     "Protect data at rest, in transit, and in use."),
    ("PR.DS-2", "Data Encryption", CSFFunction.PROTECT,
     "Encrypt sensitive data at rest and in transit."),
    ("PR.DS-3", "Data Masking", CSFFunction.PROTECT,
     "Mask sensitive data in non-production environments."),
    ("PR.PS-1", "Platform Security", CSFFunction.PROTECT,
     "Secure platform configurations and hardening baselines."),
    ("PR.PS-2", "Secure Configuration", CSFFunction.PROTECT,
     "Maintain secure configurations for hardware and software."),
    ("PR.PS-3", "Patch Management", CSFFunction.PROTECT,
     "Apply security patches in a timely manner."),
    ("PR.IR-1", "Infrastructure Resilience", CSFFunction.PROTECT,
     "Design and maintain resilient infrastructure architectures."),
    ("PR.IR-2", "Redundancy", CSFFunction.PROTECT,
     "Implement redundancy for critical systems and services."),
    ("PR.IR-3", "Backup and Recovery", CSFFunction.PROTECT,
     "Maintain reliable backup and recovery capabilities."),
    # DETECT
    ("DE.CM-1", "Continuous Monitoring", CSFFunction.DETECT,
     "Implement continuous monitoring of networks and systems."),
    ("DE.CM-2", "Anomaly Detection", CSFFunction.DETECT,
     "Detect anomalous behavior through automated analysis."),
    ("DE.CM-3", "Security Event Detection", CSFFunction.DETECT,
     "Detect security events and potential incidents."),
    ("DE.CM-4", "Threat Detection", CSFFunction.DETECT,
     "Detect known and emerging threats using multiple data sources."),
    ("DE.AE-1", "Adverse Event Analysis", CSFFunction.DETECT,
     "Analyze adverse events to determine scope and impact."),
    ("DE.AE-2", "Threat Hunting", CSFFunction.DETECT,
     "Proactively hunt for threats within the environment."),
    ("DE.AE-3", "Security Analytics", CSFFunction.DETECT,
     "Apply security analytics to improve detection capabilities."),
    # RESPOND
    ("RS.MA-1", "Incident Management", CSFFunction.RESPOND,
     "Establish and maintain an incident management process."),
    ("RS.MA-2", "Incident Response Planning", CSFFunction.RESPOND,
     "Develop and maintain incident response plans."),
    ("RS.MA-3", "Incident Response Training", CSFFunction.RESPOND,
     "Train personnel on incident response procedures."),
    ("RS.AN-1", "Incident Analysis", CSFFunction.RESPOND,
     "Analyze incidents to determine root cause and impact."),
    ("RS.AN-2", "Incident Reporting", CSFFunction.RESPOND,
     "Report incidents to relevant stakeholders and authorities."),
    ("RS.CO-1", "Communications", CSFFunction.RESPOND,
     "Coordinate incident communications with internal and external stakeholders."),
    ("RS.CO-2", "External Communications", CSFFunction.RESPOND,
     "Manage external communications during and after incidents."),
    ("RS.MI-1", "Incident Mitigation", CSFFunction.RESPOND,
     "Contain and mitigate the impact of incidents."),
    ("RS.MI-2", "Eradication", CSFFunction.RESPOND,
     "Eradicate the root cause of incidents."),
    # RECOVER
    ("RC.RP-1", "Recovery Planning", CSFFunction.RECOVER,
     "Develop and maintain recovery plans for critical services."),
    ("RC.RP-2", "Recovery Execution", CSFFunction.RECOVER,
     "Execute recovery plans to restore services."),
    ("RC.RP-3", "Recovery Testing", CSFFunction.RECOVER,
     "Test recovery plans regularly to ensure effectiveness."),
    ("RC.IM-1", "Improvements", CSFFunction.RECOVER,
     "Incorporate lessons learned into recovery plans."),
    ("RC.IM-2", "Post-Incident Review", CSFFunction.RECOVER,
     "Conduct post-incident reviews to improve future response."),
    ("RC.CO-1", "Communications", CSFFunction.RECOVER,
     "Communicate recovery status to stakeholders."),
    ("RC.CO-2", "Service Restoration", CSFFunction.RECOVER,
     "Restore services in priority order after an incident."),
]


class CSFControlCatalog:
    """Catalog of CISA CSF controls with lookup methods."""

    def __init__(self) -> None:
        self._controls: dict[str, Control] = {}
        for cid, name, func, desc in _CATALOG_DATA:
            self._controls[cid] = Control(id=cid, name=name, function=func, description=desc)

    def all_controls(self) -> list[Control]:
        """Return all controls in the catalog."""
        return list(self._controls.values())

    def get_control(self, control_id: str) -> Control:
        """Look up a control by its ID."""
        return self._controls[control_id]

    def get_controls_by_function(self, function: CSFFunction) -> list[Control]:
        """Return all controls belonging to a specific CSF function."""
        return [c for c in self._controls.values() if c.function == function]


class ControlAssessment:
    """Assess the implementation status of CSF controls."""

    def __init__(self, catalog: CSFControlCatalog) -> None:
        self._catalog = catalog
        self._assessments: dict[str, ControlStatus] = {}
        self._evidence: dict[str, list[str]] = {}

    def assess_control(
        self,
        control_id: str,
        status: ControlStatus,
        evidence: list[str] | None = None,
    ) -> None:
        """Record the implementation status of a control."""
        # Validate control exists
        control = self._catalog.get_control(control_id)
        self._assessments[control_id] = status
        if evidence is not None:
            self._evidence[control_id] = list(evidence)
            control.evidence = list(evidence)

    def get_assessment(self, control_id: str) -> ControlStatus:
        """Get the current assessment status for a control."""
        return self._assessments.get(control_id, ControlStatus.NOT_IMPLEMENTED)

    def get_function_score(self, function: CSFFunction) -> float:
        """Calculate the implementation score (0-100) for a CSF function."""
        controls = self._catalog.get_controls_by_function(function)
        if not controls:
            return 0.0
        max_score = len(controls) * ControlStatus.IMPLEMENTED.value
        actual_score = sum(
            self._assessments.get(c.id, ControlStatus.NOT_IMPLEMENTED).value
            for c in controls
        )
        return (actual_score / max_score) * 100.0

    def get_overall_score(self) -> float:
        """Calculate the overall implementation score (0-100) across all controls."""
        controls = self._catalog.all_controls()
        if not controls:
            return 0.0
        max_score = len(controls) * ControlStatus.IMPLEMENTED.value
        actual_score = sum(
            self._assessments.get(c.id, ControlStatus.NOT_IMPLEMENTED).value
            for c in controls
        )
        return (actual_score / max_score) * 100.0


class GapAnalysis:
    """Identify gaps between current and target control implementation."""

    def __init__(self, assessment: ControlAssessment) -> None:
        self._assessment = assessment

    def identify_gaps(self) -> list[Gap]:
        """Return all controls that are not fully implemented."""
        gaps: list[Gap] = []
        for control in self._assessment._catalog.all_controls():
            status = self._assessment.get_assessment(control.id)
            if status != ControlStatus.IMPLEMENTED:
                severity = _SEVERITY_MAP.get(control.function, "medium")
                recommendation = self._generate_recommendation(control, status)
                gaps.append(Gap(
                    control_id=control.id,
                    control_name=control.name,
                    function=control.function,
                    severity=severity,
                    recommendation=recommendation,
                    current_status=status,
                ))
        return gaps

    def get_critical_gaps(self) -> list[Gap]:
        """Return only critical-severity gaps."""
        return [g for g in self.identify_gaps() if g.severity == "critical"]

    def get_gaps_by_function(self, function: CSFFunction) -> list[Gap]:
        """Return gaps filtered by CSF function."""
        return [g for g in self.identify_gaps() if g.function == function]

    def get_gap_count(self) -> int:
        """Return the total number of identified gaps."""
        return len(self.identify_gaps())

    @staticmethod
    def _generate_recommendation(control: Control, status: ControlStatus) -> str:
        if status == ControlStatus.NOT_IMPLEMENTED:
            return f"Implement {control.id} ({control.name}) to meet {control.function.value} objectives."
        return f"Complete remaining work for {control.id} ({control.name}) to achieve full implementation."


class CISAComplianceReport:
    """Generate a compliance report from assessment and gap analysis."""

    def __init__(self, assessment: ControlAssessment, gap_analysis: GapAnalysis) -> None:
        self._assessment = assessment
        self._gap_analysis = gap_analysis

    def generate_summary(self) -> dict[str, Any]:
        """Generate a high-level compliance summary."""
        all_controls = self._assessment._catalog.all_controls()
        implemented = sum(
            1 for c in all_controls
            if self._assessment.get_assessment(c.id) == ControlStatus.IMPLEMENTED
        )
        return {
            "overall_score": round(self._assessment.get_overall_score(), 2),
            "total_controls": len(all_controls),
            "implemented_controls": implemented,
            "gap_count": self._gap_analysis.get_gap_count(),
            "function_scores": {
                f.value: round(self._assessment.get_function_score(f), 2)
                for f in CSFFunction
            },
        }

    def generate_function_breakdown(self) -> dict[str, dict[str, Any]]:
        """Generate per-function breakdown of scores and gaps."""
        breakdown: dict[str, dict[str, Any]] = {}
        for func in CSFFunction:
            controls = self._assessment._catalog.get_controls_by_function(func)
            implemented = sum(
                1 for c in controls
                if self._assessment.get_assessment(c.id) == ControlStatus.IMPLEMENTED
            )
            gaps = self._gap_analysis.get_gaps_by_function(func)
            breakdown[func.value] = {
                "total_controls": len(controls),
                "implemented": implemented,
                "score": round(self._assessment.get_function_score(func), 2),
                "gap_count": len(gaps),
            }
        return breakdown

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full report to a dictionary."""
        return {
            "summary": self.generate_summary(),
            "function_breakdown": self.generate_function_breakdown(),
            "gaps": [g.to_dict() for g in self._gap_analysis.identify_gaps()],
        }
