from verifhir.scoring.ml_weighting import calculate_contribution
from verifhir.models.violation import Violation, ViolationSeverity


def test_confidence_scaling():
    high_conf = Violation(
        violation_type="EMAIL",
        severity=ViolationSeverity.MAJOR,
        regulation="GDPR",
        citation="GDPR Art 4",
        field_path="Patient.email",
        description="Email detected",
        detection_method="ml-primary",
        confidence=0.9,
    )

    low_conf = Violation(
        violation_type="EMAIL",
        severity=ViolationSeverity.MAJOR,
        regulation="GDPR",
        citation="GDPR Art 4",
        field_path="Patient.email",
        description="Email detected",
        detection_method="ml-primary",
        confidence=0.4,
    )

    assert calculate_contribution(high_conf) > calculate_contribution(low_conf)
