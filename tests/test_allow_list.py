import pytest
from verifhir.models.violation import Violation, ViolationSeverity
# NEW: Import the function and the set (No more ALLOWLIST class)
from verifhir.controls.allow_list import is_allowlisted, ALLOWLIST_TERMS

def test_allowlist_structure():
    """Verify strict set of allowed terms."""
    assert "support@verifhir.com" in ALLOWLIST_TERMS
    assert "protocol id" in ALLOWLIST_TERMS

def test_is_allowlisted_logic():
    # 1. Create a violation that SHOULD be allowed (Protocol ID)
    v_good = Violation(
        violation_type="test",
        severity=ViolationSeverity.MAJOR,
        regulation="GDPR",
        citation="test",
        field_path="note",
        description="Protocol ID found in text", 
        detection_method="manual",
        confidence=1.0
    )
    
    # 2. Create a violation that should NOT be allowed (Patient ID)
    v_bad = Violation(
        violation_type="test",
        severity=ViolationSeverity.MAJOR,
        regulation="GDPR",
        citation="test",
        field_path="note",
        description="Patient ID found in text",
        detection_method="manual",
        confidence=1.0
    )

    # 3. Assert using the functional check
    assert is_allowlisted(v_good) is True
    assert is_allowlisted(v_bad) is False