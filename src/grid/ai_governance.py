"""AI Governance Framework, Risk Assessment, and Compliance Automation.

NIST AI RMF 1.0 aligned governance for the Apex Resilience Grid.
Provides policy management, risk assessment, and automated compliance checking.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


# ── Enums ────────────────────────────────────────────────────────────────────


class GovernanceLevel(Enum):
    """Governance policy levels."""
    ADVISORY = "advisory"
    MANDATORY = "mandatory"
    CRITICAL = "critical"


class PolicyStatus(Enum):
    """Policy lifecycle status."""
    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"


class ApprovalStatus(Enum):
    """Approval request status."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class RiskCategory(Enum):
    """NIST AI RMF risk categories."""
    VALIDITY = "validity"
    RELIABILITY = "reliability"
    SAFETY = "safety"
    SECURITY = "security"
    PRIVACY = "privacy"
    FAIRNESS = "fairness"
    TRANSPARENCY = "transparency"
    ACCOUNTABILITY = "accountability"


class ComplianceSeverity(Enum):
    """Compliance violation severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ── Governance Policies ──────────────────────────────────────────────────────


@dataclass
class AIGovernancePolicy:
    """Represents an AI governance policy."""

    policy_id: str
    name: str
    description: str
    level: GovernanceLevel
    status: PolicyStatus = PolicyStatus.DRAFT
    rules: List[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def activate(self) -> None:
        """Activate the policy."""
        self.status = PolicyStatus.ACTIVE

    def deprecate(self) -> None:
        """Deprecate the policy."""
        self.status = PolicyStatus.DEPRECATED

    def add_rule(self, rule: str) -> None:
        """Add a rule to the policy (no duplicates)."""
        if rule not in self.rules:
            self.rules.append(rule)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize policy to dictionary."""
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "level": self.level.value,
            "status": self.status.value,
            "rules": list(self.rules),
            "created_at": self.created_at,
        }


@dataclass
class AIApprovalRequest:
    """Represents an AI system approval request."""

    request_id: str
    system_name: str
    system_version: str
    requester: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    conditions: List[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def approve(self, conditions: Optional[List[str]] = None) -> None:
        """Approve the request with optional conditions."""
        self.status = ApprovalStatus.APPROVED
        if conditions:
            for c in conditions:
                self.add_condition(c)

    def reject(self) -> None:
        """Reject the request."""
        self.status = ApprovalStatus.REJECTED

    def add_condition(self, condition: str) -> None:
        """Add a condition (no duplicates)."""
        if condition not in self.conditions:
            self.conditions.append(condition)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize request to dictionary."""
        return {
            "request_id": self.request_id,
            "system_name": self.system_name,
            "system_version": self.system_version,
            "requester": self.requester,
            "status": self.status.value,
            "conditions": list(self.conditions),
            "created_at": self.created_at,
        }


@dataclass
class AIAuditRecord:
    """Represents an audit log entry."""

    action: str
    actor: str
    target: str
    details: Dict[str, Any] = field(default_factory=dict)
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize record to dictionary."""
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "actor": self.actor,
            "target": self.target,
            "details": dict(self.details),
        }


class AIGovernanceFramework:
    """Manages AI governance policies, approvals, and audit trails."""

    def __init__(self, name: str):
        self.name = name
        self._policies: Dict[str, AIGovernancePolicy] = {}
        self._approvals: Dict[str, AIApprovalRequest] = {}
        self._audit_log: List[AIAuditRecord] = []

    def add_policy(self, policy: AIGovernancePolicy) -> None:
        """Add a policy to the framework."""
        self._policies[policy.policy_id] = policy
        self._audit_log.append(AIAuditRecord(
            action="policy_added",
            actor="system",
            target=policy.policy_id,
            details={"name": policy.name},
        ))

    def get_policy(self, policy_id: str) -> Optional[AIGovernancePolicy]:
        """Retrieve a policy by ID."""
        return self._policies.get(policy_id)

    def get_active_policies(self) -> List[AIGovernancePolicy]:
        """Get all active policies."""
        return [p for p in self._policies.values() if p.status == PolicyStatus.ACTIVE]

    def submit_approval_request(self, request: AIApprovalRequest) -> None:
        """Submit an approval request."""
        self._approvals[request.request_id] = request
        self._audit_log.append(AIAuditRecord(
            action="approval_submitted",
            actor=request.requester,
            target=request.request_id,
            details={"system": request.system_name},
        ))

    def get_approval(self, request_id: str) -> Optional[AIApprovalRequest]:
        """Retrieve an approval request by ID."""
        return self._approvals.get(request_id)

    def evaluate_policies(self, context: Dict[str, Any]) -> List[str]:
        """Evaluate all active policies against a context.

        Returns list of violation descriptions.
        """
        violations = []
        for policy in self.get_active_policies():
            for rule in policy.rules:
                if not self._evaluate_rule(rule, context):
                    violations.append(
                        f"Policy '{policy.name}' ({policy.policy_id}) violated: rule '{rule}'"
                    )
        return violations

    @staticmethod
    def _evaluate_rule(rule: str, context: Dict[str, Any]) -> bool:
        """Evaluate a single rule expression against context.

        Rule format: "attribute:exists" — checks if attribute is in context.
        """
        if ":" not in rule:
            return True
        attr, check = rule.split(":", 1)
        if check == "exists":
            return attr in context
        return True

    def get_audit_log(self) -> List[AIAuditRecord]:
        """Get the full audit log."""
        return list(self._audit_log)


# ── Risk Assessment ──────────────────────────────────────────────────────────


@dataclass
class RiskFactor:
    """Represents a risk factor in an AI system."""

    factor_id: str
    name: str
    category: RiskCategory
    likelihood: float
    impact: float
    description: str = ""
    mitigations: List[str] = field(default_factory=list)

    @property
    def risk_score(self) -> float:
        """Computed risk score: likelihood × impact."""
        return self.likelihood * self.impact

    def add_mitigation(self, mitigation: str) -> None:
        """Add a mitigation strategy (no duplicates)."""
        if mitigation not in self.mitigations:
            self.mitigations.append(mitigation)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize risk factor to dictionary."""
        return {
            "factor_id": self.factor_id,
            "name": self.name,
            "category": self.category.value,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk_score": self.risk_score,
            "description": self.description,
            "mitigations": list(self.mitigations),
        }


class RiskMatrix:
    """NIST AI RMF risk scoring matrix."""

    @staticmethod
    def get_risk_level(likelihood: float, impact: float) -> str:
        """Determine risk level from likelihood and impact."""
        score = likelihood * impact
        return RiskMatrix.get_risk_level_from_score(score)

    @staticmethod
    def get_risk_level_from_score(score: float) -> str:
        """Map a risk score to a risk level."""
        if score >= 0.7:
            return "critical"
        elif score >= 0.4:
            return "high"
        elif score >= 0.2:
            return "medium"
        else:
            return "low"


@dataclass
class RiskAssessment:
    """Represents a comprehensive risk assessment for an AI system."""

    assessment_id: str
    system_name: str
    system_version: str
    factors: List[RiskFactor] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def add_factor(self, factor: RiskFactor) -> None:
        """Add a risk factor to the assessment."""
        self.factors.append(factor)

    def get_overall_risk_score(self) -> float:
        """Average risk score across all factors."""
        if not self.factors:
            return 0.0
        return sum(f.risk_score for f in self.factors) / len(self.factors)

    def get_risk_level(self) -> str:
        """Overall risk level based on average score."""
        return RiskMatrix.get_risk_level_from_score(self.get_overall_risk_score())

    def get_factors_by_category(self, category: RiskCategory) -> List[RiskFactor]:
        """Filter factors by category."""
        return [f for f in self.factors if f.category == category]

    def get_critical_factors(self) -> List[RiskFactor]:
        """Get factors with critical risk level."""
        return [
            f for f in self.factors
            if RiskMatrix.get_risk_level_from_score(f.risk_score) == "critical"
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize assessment to dictionary."""
        return {
            "assessment_id": self.assessment_id,
            "system_name": self.system_name,
            "system_version": self.system_version,
            "overall_risk_score": self.get_overall_risk_score(),
            "risk_level": self.get_risk_level(),
            "factors": [f.to_dict() for f in self.factors],
            "created_at": self.created_at,
        }


# ── Compliance Automation ────────────────────────────────────────────────────


@dataclass
class ComplianceRule:
    """Represents an automated compliance rule."""

    rule_id: str
    name: str
    description: str
    severity: ComplianceSeverity
    rule_expression: str = ""
    check_function: Optional[Callable[[Dict[str, Any]], bool]] = None

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate the rule against a context."""
        if self.check_function is not None:
            return self.check_function(context)
        if not self.rule_expression:
            return True
        return self._evaluate_expression(self.rule_expression, context)

    @staticmethod
    def _evaluate_expression(expression: str, context: Dict[str, Any]) -> bool:
        """Evaluate a rule expression.

        Format: "attribute:exists" — checks if attribute is in context.
        """
        if ":" not in expression:
            return True
        attr, check = expression.split(":", 1)
        if check == "exists":
            return attr in context
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Serialize rule to dictionary."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "rule_expression": self.rule_expression,
        }


@dataclass
class ComplianceCheck:
    """Result of a compliance check."""

    rule_id: str
    rule_name: str
    compliant: bool
    severity: ComplianceSeverity
    message: str
    check_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize check result to dictionary."""
        return {
            "check_id": self.check_id,
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "compliant": self.compliant,
            "severity": self.severity.value,
            "message": self.message,
        }


@dataclass
class ComplianceViolation:
    """Represents a detected compliance violation."""

    rule_id: str
    rule_name: str
    severity: ComplianceSeverity
    description: str
    system_name: str = ""
    resolved: bool = False
    resolved_at: Optional[str] = None
    violation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def resolve(self) -> None:
        """Mark the violation as resolved."""
        self.resolved = True
        self.resolved_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize violation to dictionary."""
        return {
            "violation_id": self.violation_id,
            "detected_at": self.detected_at,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "description": self.description,
            "system_name": self.system_name,
            "resolved": self.resolved,
            "resolved_at": self.resolved_at,
        }


class ComplianceAutomationEngine:
    """Automated compliance checking engine."""

    def __init__(self, name: str):
        self.name = name
        self._rules: Dict[str, ComplianceRule] = {}
        self._checks: List[ComplianceCheck] = []
        self._violations: List[ComplianceViolation] = []

    def add_rule(self, rule: ComplianceRule) -> None:
        """Add a compliance rule."""
        self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> Optional[ComplianceRule]:
        """Retrieve a rule by ID."""
        return self._rules.get(rule_id)

    def run_check(self, rule_id: str, context: Dict[str, Any]) -> ComplianceCheck:
        """Run a single compliance check."""
        rule = self._rules.get(rule_id)
        if rule is None:
            check = ComplianceCheck(
                rule_id=rule_id,
                rule_name="Unknown",
                compliant=False,
                severity=ComplianceSeverity.HIGH,
                message=f"Rule '{rule_id}' not found",
            )
            self._checks.append(check)
            return check

        passed = rule.evaluate(context)
        check = ComplianceCheck(
            rule_id=rule_id,
            rule_name=rule.name,
            compliant=passed,
            severity=rule.severity,
            message="Compliant" if passed else f"Violation: {rule.description}",
        )
        self._checks.append(check)

        if not passed:
            self._violations.append(ComplianceViolation(
                rule_id=rule_id,
                rule_name=rule.name,
                severity=rule.severity,
                description=rule.description,
            ))

        return check

    def run_all_checks(self, context: Dict[str, Any]) -> List[ComplianceCheck]:
        """Run all registered compliance checks."""
        return [self.run_check(rid, context) for rid in self._rules]

    def get_checks(self) -> List[ComplianceCheck]:
        """Get all check results."""
        return list(self._checks)

    def get_violations(self, include_resolved: bool = False) -> List[ComplianceViolation]:
        """Get violations, optionally including resolved ones."""
        if include_resolved:
            return list(self._violations)
        return [v for v in self._violations if not v.resolved]

    def get_violations_by_severity(self, severity: ComplianceSeverity) -> List[ComplianceViolation]:
        """Get unresolved violations filtered by severity."""
        return [v for v in self.get_violations() if v.severity == severity]

    def resolve_violation(self, violation_id: str) -> bool:
        """Resolve a violation by ID. Returns True if found and resolved."""
        for v in self._violations:
            if v.violation_id == violation_id and not v.resolved:
                v.resolve()
                return True
        return False

    def get_compliance_score(self) -> float:
        """Ratio of compliant checks to total checks."""
        if not self._checks:
            return 0.0
        compliant = sum(1 for c in self._checks if c.compliant)
        return compliant / len(self._checks)

    def get_summary(self) -> Dict[str, Any]:
        """Get a compliance summary."""
        checks = self._checks
        violations = self.get_violations()
        return {
            "engine_name": self.name,
            "total_checks": len(checks),
            "compliant_checks": sum(1 for c in checks if c.compliant),
            "violations": len(violations),
            "compliance_score": self.get_compliance_score(),
            "rules_count": len(self._rules),
        }
