import pytest
from verifhir.models.violation import Violation, ViolationSeverity
# NEW: Import the function (No more FALSE_POSITIVES class)
from verifhir.controls.false_positives import is_false_positive

def test_false_positive_page_logic():
    """Verify 'Page 12' is flagged as a false positive."""
    
    # 1. Mock Violation
    v = Violation(
        violation_type="GDPR_IDENTIFIER",
        severity=ViolationSeverity.MAJOR,
        regulation="GDPR",
        citation="test",
        field_path="note",
        description="Patient ID detected",
        detection_method="manual",
        confidence=1.0
    )

    # 2. Context: "Page 12 of 50" (Safe)
    resource_safe = {"text": "Refer to Page 12 of the manual."}
    
    # 3. Context: "Patient 12" (Unsafe)
    resource_unsafe = {"text": "Patient 12 reported symptoms."}

    # 4. Assert
    assert is_false_positive(v, resource_safe) is True
    assert is_false_positive(v, resource_unsafe) is False