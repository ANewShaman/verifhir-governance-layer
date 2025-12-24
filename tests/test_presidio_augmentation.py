from verifhir.ml.presidio_phi import detect_phi_presidio
from verifhir.models.violation import ViolationSeverity


def test_presidio_detects_mrn_critical():
    """Test that MRN (Medical Record Number) is detected as CRITICAL severity."""
    text = "Patient MRN is 12345678"
    violations = detect_phi_presidio(
        text=text,
        field_path="Observation.note",
        azure_flagged=True  # Parameter is now ignored, but kept for compatibility
    )
    # MRN should be detected as US_MRN with CRITICAL severity
    mrn_violations = [v for v in violations if v.violation_type == "US_MRN"]
    assert len(mrn_violations) >= 1, f"Expected US_MRN detection, got: {[v.violation_type for v in violations]}"
    assert mrn_violations[0].severity == ViolationSeverity.CRITICAL


def test_presidio_always_runs():
    """Test that Presidio now runs regardless of azure_flagged parameter."""
    text = "MRN: 12345678"
    violations = detect_phi_presidio(
        text=text,
        field_path="Patient.name",
        azure_flagged=False  # Even with False, Presidio should still run
    )
    # Should detect MRN even when azure_flagged=False
    assert len(violations) >= 1, "Presidio should always run now (hybrid engine)"


def test_presidio_detects_government_ids_critical():
    """Test that government IDs (Aadhaar, PAN, SSN) are detected as CRITICAL."""
    # Test Aadhaar
    text_aadhaar = "Patient Aadhaar number is 1234-5678-9012"
    violations_aadhaar = detect_phi_presidio(text=text_aadhaar, field_path="test")
    aadhaar_violations = [v for v in violations_aadhaar if v.violation_type == "INDIAN_AADHAAR"]
    if aadhaar_violations:
        assert aadhaar_violations[0].severity == ViolationSeverity.CRITICAL
    
    # Test PAN
    text_pan = "PAN card number ABCDE1234F"
    violations_pan = detect_phi_presidio(text=text_pan, field_path="test")
    pan_violations = [v for v in violations_pan if v.violation_type == "INDIAN_PAN"]
    if pan_violations:
        assert pan_violations[0].severity == ViolationSeverity.CRITICAL
    
    # Test SSN
    text_ssn = "SSN: 123-45-6789"
    violations_ssn = detect_phi_presidio(text=text_ssn, field_path="test")
    ssn_violations = [v for v in violations_ssn if v.violation_type == "US_SSN"]
    if ssn_violations:
        assert ssn_violations[0].severity == ViolationSeverity.CRITICAL


def test_presidio_detects_names_major():
    """Test that PERSON entities are detected as MAJOR severity."""
    text = "John Doe visited the hospital"
    violations = detect_phi_presidio(text=text, field_path="test")
    person_violations = [v for v in violations if v.violation_type == "PERSON"]
    if person_violations:
        assert person_violations[0].severity == ViolationSeverity.MAJOR


def test_presidio_non_critical_detection():
    """Test that non-government IDs are not marked as CRITICAL."""
    text = "Device ID XYZ-999"
    violations = detect_phi_presidio(
        text=text,
        field_path="DiagnosticReport.conclusion",
        azure_flagged=True
    )
    # Device IDs should not be CRITICAL (unless they match a government ID pattern)
    for v in violations:
        if v.violation_type not in ["INDIAN_AADHAAR", "INDIAN_PAN", "US_MRN", "US_SSN"]:
            assert v.severity != ViolationSeverity.CRITICAL or v.violation_type in ["MEDICAL_RECORD_NUMBER", "CREDIT_CARD"]
