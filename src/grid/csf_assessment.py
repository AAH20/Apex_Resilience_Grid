"""CISA CSF assessment, control mapping, and gap remediation module.

Extends the base CISA compliance module with control mapping,
gap remediation planning, and remediation tracking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.grid.cisa_compliance import (
    CSFFunction,
    ControlStatus,
    Control,
    CSFControlCatalog,
    ControlAssessment,
    GapAnalysis,
    CISAComplianceReport,
    Gap,
)


# ── ControlMapping ─────────────────────────────────────────────────────────


class ControlMapping:
    """Maps internal grid controls to CISA CSF controls."""

    def __init__(self) -> None:
        self._mappings: dict[str, list[str]] = {}
        self._reverse: dict[str, list[str]] = {}

    def add_mapping(self, internal_control: str, csf_control_ids: list[str]) -> None:
        """Map an internal control to one or more CSF control IDs."""
        self._mappings[internal_control] = list(csf_control_ids)
        for csf_id in csf_control_ids:
            if csf_id not in self._reverse:
                self._reverse[csf_id] = []
            if internal_control not in self._reverse[csf_id]:
                self._reverse[csf_id].append(internal_control)

    def get_csf_controls(self, internal_control: str) -> list[str]:
        """Get CSF control IDs for an internal control."""
        return list(self._mappings.get(internal_control, []))

    def get_internal_controls(self, csf_control_id: str) -> list[str]:
        """Get internal controls mapped to a CSF control ID."""
        return list(self._reverse.get(csf_control_id, []))

    def get_all_mappings(self) -> dict[str, list[str]]:
        """Return all mappings."""
        return {k: list(v) for k, v in self._mappings.items()}


# ── GapRemediation ─────────────────────────────────────────────────────────


@dataclass
class RemediationPlan:
    """A remediation plan for a specific gap."""

    control_id: str
    control_name: str
    priority: int
    effort: str
    timeline_days: int
    actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "priority": self.priority,
            "effort": self.effort,
            "timeline_days": self.timeline_days,
            "actions": list(self.actions),
        }


class GapRemediation:
    """Generate remediation plans for identified gaps."""

    _SEVERITY_PRIORITY = {
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 4,
    }

    _SEVERITY_EFFORT = {
        "critical": "high",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }

    _SEVERITY_TIMELINE = {
        "critical": 30,
        "high": 60,
        "medium": 90,
        "low": 180,
    }

    def __init__(self, gap_analysis: GapAnalysis) -> None:
        self._gap_analysis = gap_analysis

    def generate_remediation_plan(self, gap: Gap) -> RemediationPlan:
        """Generate a remediation plan for a specific gap."""
        priority = self._SEVERITY_PRIORITY.get(gap.severity, 3)
        effort = self._SEVERITY_EFFORT.get(gap.severity, "medium")
        timeline = self._SEVERITY_TIMELINE.get(gap.severity, 90)
        actions = self._generate_actions(gap)
        return RemediationPlan(
            control_id=gap.control_id,
            control_name=gap.control_name,
            priority=priority,
            effort=effort,
            timeline_days=timeline,
            actions=actions,
        )

    def generate_all_plans(self) -> list[RemediationPlan]:
        """Generate remediation plans for all gaps."""
        return [self.generate_remediation_plan(g) for g in self._gap_analysis.identify_gaps()]

    @staticmethod
    def _generate_actions(gap: Gap) -> list[str]:
        """Generate actionable steps for a gap."""
        if gap.current_status == ControlStatus.NOT_IMPLEMENTED:
            return [
                f"Define implementation approach for {gap.control_id}",
                f"Assign owner and team for {gap.control_name}",
                f"Develop implementation timeline for {gap.control_id}",
                f"Establish success criteria for {gap.control_name}",
            ]
        return [
            f"Assess remaining work for {gap.control_id}",
            f"Identify blockers for {gap.control_name}",
            f"Complete implementation of {gap.control_id}",
            f"Validate and document {gap.control_name}",
        ]
