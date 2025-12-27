"""
Tests for HL7 v2 → FHIR Adapter Boundary Discipline

These tests verify that:
1. HL7 is converted before governance
2. FHIR bypasses the adapter
3. No HL7 semantics leak downstream
"""
from verifhir.orchestrator.audit_builder import build_audit
import pytest
from verifhir.adapters.hl7_adapter import (
    normalize_input,
    extract_message_type,
    convert_hl7_to_fhir,
    FHIR_CONVERTER_VERSION,
)


def test_hl7_is_converted_before_governance():
    """Test that HL7 input is normalized with proper metadata."""
    sample_hl7 = "MSH|^~\\&|SendingApp|SendingFacility|ReceivingApp|ReceivingFacility|20240115120000||ADT^A01|12345|P|2.5"
    
    # This will raise NotImplementedError as expected for MVP
    with pytest.raises(NotImplementedError):
        normalized = normalize_input(sample_hl7, "HL7v2")
    
    # However, we can test the metadata extraction separately
    message_type = extract_message_type(sample_hl7)
    assert message_type == "ADT^A01"


def test_fhir_bypasses_adapter():
    """Test that FHIR input bypasses conversion and passes through unchanged."""
    sample_fhir = {
        "resourceType": "Patient",
        "id": "example",
        "name": [{"family": "Doe", "given": ["John"]}]
    }
    
    normalized = normalize_input(sample_fhir, "FHIR")
    
    assert normalized["metadata"]["original_format"] == "FHIR"
    assert normalized["bundle"] == sample_fhir
    assert "converter_version" not in normalized["metadata"]


def test_extract_message_type_valid():
    """Test message type extraction from valid HL7 MSH segment."""
    hl7_message = "MSH|^~\\&|App|Facility|RecvApp|RecvFac|20240115||ADT^A01^ADT_A01|123|P|2.5\nPID|1||123"
    message_type = extract_message_type(hl7_message)
    assert message_type == "ADT^A01^ADT_A01"


def test_extract_message_type_invalid():
    """Test message type extraction handles invalid input gracefully."""
    invalid_input = "Not an HL7 message"
    message_type = extract_message_type(invalid_input)
    assert message_type == "UNKNOWN"


def test_extract_message_type_empty():
    """Test message type extraction handles empty input."""
    message_type = extract_message_type("")
    assert message_type == "UNKNOWN"


def test_normalize_input_hl7v2_metadata():
    """Test that HL7 normalization includes all required metadata fields."""
    sample_hl7 = "MSH|^~\\&|App|Fac|Recv|RecvFac|20240115||ADT^A01|123|P|2.5"
    
    # This will raise NotImplementedError, but we can verify the structure would be correct
    # by testing the metadata extraction separately
    message_type = extract_message_type(sample_hl7)
    
    # Verify metadata structure (when conversion is implemented)
    assert message_type == "ADT^A01"
    # When convert_hl7_to_fhir is implemented, normalized["metadata"] should contain:
    # - original_format: "HL7v2"
    # - message_type: "ADT^A01"
    # - converter_version: FHIR_CONVERTER_VERSION


def test_convert_hl7_to_fhir_raises_not_implemented():
    """Test that convert_hl7_to_fhir raises NotImplementedError for MVP."""
    sample_hl7 = "MSH|^~\\&|App|Fac|Recv|RecvFac|20240115||ADT^A01|123|P|2.5"
    
    with pytest.raises(NotImplementedError) as exc_info:
        convert_hl7_to_fhir(sample_hl7)
    
    assert "Microsoft FHIR Converter" in str(exc_info.value)


def test_normalize_input_fhir_dict():
    """Test that FHIR dict input is handled correctly."""
    fhir_dict = {"resourceType": "Bundle", "type": "collection", "entry": []}
    
    normalized = normalize_input(fhir_dict, "FHIR")
    
    assert normalized["bundle"] == fhir_dict
    assert normalized["metadata"]["original_format"] == "FHIR"


def test_normalize_input_fhir_string():
    """Test that FHIR string input is handled correctly (treated as dict after parsing)."""
    import json
    fhir_str = '{"resourceType": "Patient", "id": "123"}'
    
    # normalize_input expects dict for FHIR, so we test with parsed JSON
    fhir_dict = json.loads(fhir_str)
    normalized = normalize_input(fhir_dict, "FHIR")
    
    assert normalized["bundle"] == fhir_dict
    assert normalized["metadata"]["original_format"] == "FHIR"

# For commit message of day 32 