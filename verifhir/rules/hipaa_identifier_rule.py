from typing import List
from verifhir.rules.base_rule import ComplianceRule
from verifhir.models.violation import Violation, ViolationSeverity

class HIPAAIdentifierRule(ComplianceRule):
    """
    Enforces HIPAA Privacy Rule by looking for common US identifiers (like MRN).
    """
    def evaluate(self, resource: dict) -> List[Violation]:
        if "HIPAA" not in self.context.applicable_regulations:
            return []
        
        violations = []
        notes = resource.get("note", [])
        
        # Simple check for "MRN" label in text
        for note in notes:
            if "MRN" in note.get("text", ""):
                 violations.append(Violation(
                    violation_type="HIPAA_IDENTIFIER",
                    severity=ViolationSeverity.MAJOR,
                    regulation="HIPAA",
                    citation="HIPAA Privacy Rule",
                    field_path="Observation.note",
                    description="Medical Record Number (MRN) found in unstructured text.",
                    detection_method="rule-based"
                ))
        return violations