from typing import List
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from verifhir.models.violation import Violation, ViolationSeverity

# -----------------------------
# Allowed Clinical Free-Text
# -----------------------------

_ALLOWED_FREE_TEXT_FIELDS = {
    "Observation.note",
    "ClinicalImpression.summary",
    "DiagnosticReport.conclusion",
    "Condition.note"
}

# -----------------------------
# Presidio Analyzer (Singleton)
# -----------------------------

analyzer = AnalyzerEngine()

# -----------------------------
# Custom Healthcare Recognizers
# -----------------------------

CUSTOM_RECOGNIZERS = [
    PatternRecognizer(
        supported_entity="MEDICAL_RECORD_NUMBER",
        patterns=[
            Pattern(
                "MRN Pattern",
                r"\bMRN\b(?:\s+is)?[:\s]*\d{6,10}\b",
                0.5,
            )
        ],
        supported_language="en",
    ),
    PatternRecognizer(
        supported_entity="DEVICE_ID",
        patterns=[
            Pattern(
                "Device ID Pattern",
                r"\b(Device ID|Implant ID)\b(?:\s+is)?[:\s]*[A-Z0-9\-]{4,}\b",
                0.5,
            )
        ],
        supported_language="en",
    ),
]


# Register recognizers once
for recognizer in CUSTOM_RECOGNIZERS:
    analyzer.registry.add_recognizer(recognizer)

# -----------------------------
# Severity Mapping (Bounded)
# -----------------------------

_ENTITY_CONFIG = {
    "MEDICAL_RECORD_NUMBER": ("Medical Record Number", ViolationSeverity.MAJOR),
    "US_NPI": ("National Provider Identifier", ViolationSeverity.MAJOR),
    "DEVICE_ID": ("Medical Device Identifier", ViolationSeverity.MAJOR),
    "INSURANCE_ID": ("Insurance Member Identifier", ViolationSeverity.MAJOR),
}


def detect_phi_presidio(
    text: str,
    field_path: str,
    azure_flagged: bool
) -> List[Violation]:
    """
    Presidio is a NON-authoritative augmentation layer.
    Runs only when Azure flags the field OR field is approved clinical free-text.
    """

    if not text or not isinstance(text, str):
        return []

    if not (azure_flagged or field_path in _ALLOWED_FREE_TEXT_FIELDS):
        return []

    results = analyzer.analyze(
        text=text,
        language="en",
        entities=list(_ENTITY_CONFIG.keys())
    )

    violations: List[Violation] = []

    for result in results:
        label, severity = _ENTITY_CONFIG.get(result.entity_type, (None, None))
        if not label:
            continue

        violations.append(
             Violation(
                 violation_type=result.entity_type,
                 severity=severity,
                 regulation="HIPAA",
                 citation="HIPAA §164.514",
                 field_path=field_path,
                 description=f"{label} detected via Presidio augmentation",
                 detection_method="ml-augmented",
                 confidence=1.0,

            )
        )

    return violations
