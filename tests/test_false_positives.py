from verifhir.controls.false_positives import FALSE_POSITIVES
from verifhir.models.violation import Violation


def test_false_positive_is_suppressed():
    v = Violation(
        regulation="HIPAA",
        violation_type="IDENTIFIER",
        citation="45 CFR §164.502",
        field_path="Patient.identifier.value",
        description="TEST patient identifier",
        severity="MINOR",
        detection_method="presidio_augmented",
        confidence=0.9,
    )

    assert FALSE_POSITIVES.should_suppress(v) is True


def test_real_violation_is_not_suppressed():
    v = Violation(
        regulation="HIPAA",
        violation_type="IDENTIFIER",
        citation="45 CFR §164.502",
        field_path="Patient.identifier.value",
        description="Real patient identifier",
        severity="MAJOR",
        detection_method="rule",
        confidence=1.0,
    )

    assert FALSE_POSITIVES.should_suppress(v) is False
