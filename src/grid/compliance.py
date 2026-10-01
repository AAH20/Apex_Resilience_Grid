"""NIST/CISA compliance engine for the Apex Resilience Grid."""

import json
from typing import Dict, List, Set, Optional
from datetime import datetime, timezone
from .models import Grid, CascadingResult


class ComplianceEngine:
    """Handles audit trails, blast-radius isolation, and compliance reporting."""

    def __init__(self, grid: Grid):
        self.grid = grid
        self._audit_log: List[Dict] = []

    def log_action(self, action: str, actor: str = "system", details: Optional[Dict] = None) -> None:
        """Log an action to the audit trail."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "actor": actor,
            "details": details or {},
        }
        self._audit_log.append(entry)

    def get_audit_log(self) -> List[Dict]:
        return list(self._audit_log)

    def get_isolation_points(self, result: CascadingResult) -> List[str]:
        """Identify key isolation points from a cascading result."""
        # Isolation points are nodes with the most dependents among affected nodes
        candidates = []
        for node_id in result.affected_nodes:
            dependents = self.grid.get_dependents(node_id)
            # Count how many dependents are also affected
            affected_dependents = dependents & result.affected_nodes
            if len(affected_dependents) >= 2:
                candidates.append(node_id)
        return candidates

    def export_audit_log(self, filepath: str) -> None:
        """Export the audit log to a JSON file."""
        with open(filepath, "w") as f:
            json.dump(self._audit_log, f, indent=2)

    def check_compliance_status(self) -> str:
        """Check overall compliance status."""
        if not self._audit_log:
            return "warning"
        # Simplified: if we have audit entries, we're compliant
        return "compliant"
