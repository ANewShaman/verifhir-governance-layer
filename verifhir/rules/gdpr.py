from typing import List, Dict, Any
from verifhir.rules.base import DeterministicRule
from verifhir.models.violation import Violation, ViolationSeverity


class GDPRFreeTextIdentifierRule(DeterministicRule):

    def regulation(self) -> str:
        return "GDPR"

    def evaluate(self, fhir_resource: Dict[str, Any]) -> List[Violation]:
        violations: List[Violation] = []

        # Example: Observation.note.text
        notes = (
            fhir_resource
            .get("note", [{}])[0]
            .get("text", "")
        )

        if notes and any(char.isdigit() for char in notes):
            violations.append(
                Violation(
                    violation_type="FREE_TEXT_IDENTIFIER",
                    severity=ViolationSeverity.MAJOR,
                    regulation="GDPR",
                    citation="GDPR Article 5(1)(c)",
                    field_path="Observation.note.text",
                    description="Free-text field may contain identifying information.",
                    detection_method="rule-based"
                )
            )

        return violations
