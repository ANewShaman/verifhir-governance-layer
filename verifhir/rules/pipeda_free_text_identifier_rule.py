from typing import List
import re
from verifhir.rules.base_rule import ComplianceRule
from verifhir.models.violation import Violation, ViolationSeverity

class PIPEDAFreeTextRule(ComplianceRule):
    def evaluate(self, resource: dict) -> List[Violation]:
        # 1. CONSENT CHECK (The critical logic)
        # If consent is obtained, strictly return NO violations.
        meta = resource.get("meta", {})
        if meta.get("consent_status") == "obtained":
            return [] 

        violations = []
        text = str(resource)
        
        # 2. PII Check
        if re.search(r"Patient ID\s+\d+", text):
             violations.append(Violation(
                violation_type="UNCONSENTED_IDENTIFIER",
                severity=ViolationSeverity.MAJOR,
                regulation="PIPEDA",
                citation="PIPEDA Schedule 1, Principle 4.3",
                field_path="note.text",
                description="Personal Information detected under PIPEDA without consent",
                detection_method="DeterministicRule",
                confidence=1.0
             ))
        return violations