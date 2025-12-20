from verifhir.fusion.fuse_violations import fuse_violations
from verifhir.models.violation import Violation, ViolationSeverity


def test_rule_dominates_ml():
    rule_violation = Violation(
        violation_type="PATIENT_ID",
        severity=ViolationSeverity.MAJOR,
        regulation="HIPAA",
        citation="HIPAA §164.514",
        field_path="Patient.identifier",
        description="Rule-based identifier",
        detection_method="rule-based",
        confidence=None,
    )

    ml_violation = Violation(
        violation_type="PATIENT_ID",
        severity=ViolationSeverity.MAJOR,
        regulation="HIPAA",
        citation="HIPAA §164.514",
        field_path="Patient.identifier",
        description="ML-based identifier",
        detection_method="ml-primary",
        confidence=0.9,
    )

    fused = fuse_violations([rule_violation], [ml_violation])

    assert len(fused) == 1
    assert fused[0].detection_method == "rule-based"
