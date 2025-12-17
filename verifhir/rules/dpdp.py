from typing import List, Dict, Any
from verifhir.rules.base import DeterministicRule
from verifhir.models.violation import Violation, ViolationSeverity


class DPDPExcessiveDataRule(DeterministicRule):

    def regulation(self) -> str:
        return "DPDP"

    def evaluate(self, fhir_resource: Dict[str, Any]) -> List[Violation]:
        violations: List[Violation] = []

        if "address" in fhir_resource:
            violations.append(
                Violation(
                    violation_type="EXCESSIVE_PERSONAL_DATA",
                    severity=ViolationSeverity.MINOR,
                    regulation="DPDP",
                    citation="DPDP Act Section 6",
                    field_path="Patient.address",
                    description="Address data should be minimized before transfer.",
                    detection_method="rule-based"
                )
            )

        return violations
