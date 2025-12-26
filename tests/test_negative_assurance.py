from verifhir.assurance.generator import generate_negative_assertions
from verifhir.explainability.view import ExplainableViolation

def test_negative_assurance_not_created_when_detected():
    detections = [
        ExplainableViolation(
            regulation="HIPAA",
            citation="164.514",
            field_path="patient.biometric.fingerprint",
            description="Fingerprint scan",
            severity="CRITICAL",
            detection_method="ml-primary",
            confidence=0.99,
            suppressed=False,
            suppression_reason=None,
        )
    ]

    sensors_used = ["AzureAI-Pii"]

    negative_assertions = generate_negative_assertions(
        detections=detections,
        sensors_used=sensors_used
    )

    categories = [na.category for na in negative_assertions]

    assert "Biometric Identifiers" not in categories
