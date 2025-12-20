"""
Allowlist Control
-----------------
Deterministic suppression of known-safe identifiers.

This runs BEFORE scoring and BEFORE aggregation.
No ML. No probabilities. Fully auditable.
"""

from typing import Dict, List, Optional


class AllowList:
    """
    Central allowlist registry.

    Keys:
    - regulation (optional)
    - field_path
    - exact values OR regex patterns (kept explicit)
    """

    def __init__(self):
        # Structure:
        # {
        #   "HIPAA": {
        #       "Patient.identifier.value": ["TEST123", "DUMMY999"]
        #   },
        #   "*": {  # Global allowlist
        #       "Observation.note.text": ["SAMPLE DATA"]
        #   }
        # }
        self._allowlist: Dict[str, Dict[str, List[str]]] = {}

    def register(
        self,
        field_path: str,
        values: List[str],
        regulation: Optional[str] = "*",
    ) -> None:
        """
        Register allowlisted values for a field.

        Args:
            field_path: Canonical FHIR path (e.g., "Patient.identifier.value")
            values: Exact string values considered safe
            regulation: Regulation scope or "*" for global
        """
        if regulation not in self._allowlist:
            self._allowlist[regulation] = {}

        if field_path not in self._allowlist[regulation]:
            self._allowlist[regulation][field_path] = []

        self._allowlist[regulation][field_path].extend(values)

    def is_allowed(
        self,
        field_path: str,
        value: str,
        regulation: Optional[str] = "*",
    ) -> bool:
        """
        Check if a value is allowlisted.

        Resolution order:
        1. Regulation-specific
        2. Global ("*")
        """
        for scope in (regulation, "*"):
            fields = self._allowlist.get(scope, {})
            allowed_values = fields.get(field_path, [])
            if value in allowed_values:
                return True

        return False


# Singleton (intentional)
ALLOWLIST = AllowList()
