from verifhir.assurance.generator import generate_negative_assertions
from verifhir.explainability.view import ExplainableViolation

def test_negative_assurance_when_category_not_detected():
    detections = [
        ExplainableViolation(
            regulation="HIPAA",
            citation="164.502",
            field_path="patient.name",
            description="Patient full name",
            severity="MINOR",
            detection_method="rule-based",
            confidence=0.95,
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

    assert "Biometric Identifiers" in categories
    assert "Genetic Data" in categories
