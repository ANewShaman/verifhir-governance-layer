from typing import Dict, Any, Optional

FHIR_CONVERTER_VERSION = "fhir-converter-v2.1.0"


def convert_hl7_to_fhir(hl7_message: str) -> dict:
    """
    Delegates HL7 v2 → FHIR conversion to Microsoft FHIR Converter.

    For MVP:
    - Use Dockerized converter OR
    - Mock with pre-converted sample
    """
    raise NotImplementedError(
        "HL7 → FHIR conversion delegated to Microsoft FHIR Converter"
    )


def extract_message_type(hl7_message: str) -> str:
    """
    Extracts HL7 message type (e.g., ADT^A01).
    """
    try:
        msh = hl7_message.split("\n")[0]
        fields = msh.split("|")
        return fields[8]  # MSH-9
    except Exception:
        return "UNKNOWN"


def normalize_input(
    payload: str | dict,
    input_format: str,
    conversion_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Normalizes input into FHIR for governance evaluation.

    HL7 v2 is converted externally and never processed directly.

    Added safeguard: if payload is not a dict and input_format is not HL7v2
    (e.g., raw text, IMAGE data, unstructured content), wrap it into a
    FHIR-like DocumentReference structure to prevent downstream TypeErrors.
    """
    # Grit Filter: Handle non-dictionary payloads (IMAGE, unstructured text, etc.)
    if not isinstance(payload, dict) and input_format != "HL7v2":
        payload = {
            "resourceType": "DocumentReference",
            "text": {"div": str(payload)}
        }

    if input_format == "HL7v2":
        fhir_bundle = convert_hl7_to_fhir(payload)

        return {
            "bundle": fhir_bundle,
            "metadata": {
                "original_format": "HL7v2",
                "message_type": extract_message_type(payload),
                "converter_version": FHIR_CONVERTER_VERSION,
            },
        }

    # Default: already FHIR or wrapped unstructured content
    return {
        "bundle": payload,
        "metadata": {
            "original_format": "FHIR",
        },
    }