from verifhir.models.violation import Violation, ViolationSeverity
from verifhir.risk.components import build_risk_component


def test_critical_violation_weight():
    violation = Violation(
        violation_type="TEST",
        severity=ViolationSeverity.CRITICAL,
        regulation="GDPR",
        citation="GDPR Article 5",
        field_path="Patient.name",
        description="Test violation",
        detection_method="rule-based"
    )

    risk = build_risk_component(violation)

    assert risk.weight == 5.0
    assert risk.weighted_score == 5.0
    assert "GDPR Article 5" in risk.explanation
