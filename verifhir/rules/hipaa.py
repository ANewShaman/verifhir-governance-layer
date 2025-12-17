from typing import List, Dict, Any
from verifhir.rules.base import DeterministicRule
from verifhir.models.violation import Violation, ViolationSeverity


class HIPAAMRNRule(DeterministicRule):

    def regulation(self) -> str:
        return "HIPAA"

    def evaluate(self, fhir_resource: Dict[str, Any]) -> List[Violation]:
        violations: List[Violation] = []

        text = str(fhir_resource)

        if "MRN" in text:
            violations.append(
                Violation(
                    violation_type="MRN_EXPOSED",
                    severity=ViolationSeverity.CRITICAL,
                    regulation="HIPAA",
                    citation="45 CFR §164.514",
                    field_path="*",
                    description="Medical Record Number detected in dataset.",
                    detection_method="rule-based"
                )
            )

        return violations
