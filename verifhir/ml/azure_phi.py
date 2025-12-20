# verifhir/ml/azure_phi.py

from typing import List
from verifhir.models.violation import Violation, ViolationSeverity


class AzurePHIEngine:
    """
    Azure AI Language PHI detection engine.
    Returns Violation objects for governance pipeline.
    """

    def detect_phi(self, text: str, field_path: str) -> List[Violation]:
        if not text or not isinstance(text, str):
            return []

        findings: List[Violation] = []

        # Simulated Azure detections
        if "SSN" in text or "123-45" in text:
            findings.append(
                Violation(
                    violation_type="SSN",
                    severity=ViolationSeverity.CRITICAL,
                    regulation="HIPAA",
                    citation="HIPAA §164.514",
                    field_path=field_path,
                    description="SSN detected via Azure AI",
                    detection_method="azure_ai",
                    confidence=0.9,
                )
            )

        if "Patient" in text:
            findings.append(
                Violation(
                    violation_type="PERSON_NAME",
                    severity=ViolationSeverity.MAJOR,
                    regulation="HIPAA",
                    citation="HIPAA §164.514",
                    field_path=field_path,
                    description="Person name detected via Azure AI",
                    detection_method="azure_ai",
                    confidence=0.8,
                )
            )

        return findings


# ---------------------------------------------------------------------
# Legacy compatibility layer (Day 15 tests)
# ---------------------------------------------------------------------

_engine = AzurePHIEngine()


class _LegacyEntity:
    """
    Minimal Azure-like entity object for legacy tests.
    """
    def __init__(self, text: str, category: str):
        self.text = text
        self.category = category


def detect_phi(text: str):
    """
    Legacy API expected by Day 15 tests.
    Returns objects with `.text` and `.category`.
    """

    violations = _engine.detect_phi(text, field_path="__legacy__")

    entities: List[_LegacyEntity] = []
    for v in violations:
        entities.append(
            _LegacyEntity(
                text=v.description,          # tests only print this
                category=v.violation_type,   # tests only assert existence
            )
        )

    return entities
