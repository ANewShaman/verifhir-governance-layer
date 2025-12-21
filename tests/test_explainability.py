import pytest
from verifhir.models.violation import Violation, ViolationSeverity
from verifhir.explainability.mapper import to_explainable_violation

def test_explainability_projection():
    # 1. Create a raw violation
    v = Violation(
        regulation="HIPAA",
        citation="45 CFR",
        violation_type="identifier",
        field_path="Patient.id",
        description="Patient ID detected",
        severity=ViolationSeverity.MAJOR,
        detection_method="Rule",
        confidence=1.0
    )

    # 2. Map to Explainable View
    ev = to_explainable_violation(v)

    # 3. Assertions
    assert ev.field_path == "Patient.id"
    assert ev.suppressed is False

def test_explainability_suppression():
    # 1. Create a violation that hits the ALLOWLIST (e.g. "Protocol ID")
    v = Violation(
        regulation="HIPAA",
        citation="45 CFR",
        violation_type="identifier",
        field_path="Patient.note",
        description="Protocol ID found",  # <--- 'Protocol ID' is in allow_list.py
        severity=ViolationSeverity.MAJOR,
        detection_method="Rule",
        confidence=1.0
    )

    # 2. Map
    ev = to_explainable_violation(v)

    # 3. Assertions
    assert ev.suppressed is True
    assert ev.suppression_reason == "Allowlisted field or value"