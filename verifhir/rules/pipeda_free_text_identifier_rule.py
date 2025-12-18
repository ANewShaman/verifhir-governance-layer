from typing import List
from verifhir.rules.base_rule import ComplianceRule
from verifhir.models.violation import Violation, ViolationSeverity
from verifhir.rules.utils.identifier_patterns import IDENTIFIER_REGEX

class PIPEDAFreeTextIdentifierRule(ComplianceRule):
    """
    Enforces PIPEDA Principle 4.3 (Consent).
    """
    
    def evaluate(self, resource: dict) -> List[Violation]:
        violations = []
        
        if "PIPEDA" not in self.context.applicable_regulations:
            return []

        # 1. Check for IDs using Centralized Regex
        notes = resource.get("note", [])
        has_identifier = False
        for note in notes:
            text = note.get("text", "")
            if IDENTIFIER_REGEX.search(text):
                has_identifier = True

        # 2. Check for Consent Meta
        has_consent = resource.get("meta", {}).get("consent_status") == "obtained"

        if has_identifier and not has_consent:
            violations.append(Violation(
                violation_type="UNCONSENTED_IDENTIFIER",
                severity=ViolationSeverity.MAJOR,
                regulation="PIPEDA",
                citation="PIPEDA Schedule 1, Principle 4.3",
                field_path="note[].text", # Updated generic path
                description="Personal identifier detected without explicit consent metadata.",
                detection_method="rule-based"
            ))
                
        return violations