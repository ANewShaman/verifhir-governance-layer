import pytest
from verifhir.models.violation import Violation, ViolationSeverity
from verifhir.decision.judge import DecisionEngine

def test_hard_rule_rejection():
    """Deterministic Rule (Confidence 1.0) should REJECT."""
    engine = DecisionEngine()
    
    v = Violation(
        violation_type="SSN_DETECTED",
        severity=ViolationSeverity.MAJOR, # Weight 0.7
        regulation="HIPAA",
        citation="N/A",
        field_path="text",
        description="SSN found",
        detection_method="Rule",
        confidence=1.0 
    )
    # Risk = 0.7 * 1.0 = 0.7 (Matches > 0.65 Block Threshold)
    
    decision = engine.decide([v])
    assert decision.status == "REJECTED"
    assert decision.max_risk_score == 0.7

def test_ml_low_confidence_review():
    """ML Detection (Confidence 0.5) should trigger REVIEW, not Block."""
    engine = DecisionEngine()
    
    v = Violation(
        violation_type="POSSIBLE_NAME",
        severity=ViolationSeverity.MAJOR, # Weight 0.7
        regulation="GDPR",
        citation="N/A",
        field_path="text",
        description="Possible Name",
        detection_method="ML_Presidio",
        confidence=0.5
    )
    # Risk = 0.7 * 0.5 = 0.35 (Above 0.30 Review, Below 0.65 Block)
    
    decision = engine.decide([v])
    assert decision.status == "NEEDS_REVIEW"
    assert decision.max_risk_score == 0.35

def test_minor_noise_approval():
    """Minor Severity (Confidence 1.0) should Pass with Warnings."""
    engine = DecisionEngine()
    
    v = Violation(
        violation_type="FORMAT_WARNING",
        severity=ViolationSeverity.MINOR, # Weight 0.2
        regulation="GDPR",
        citation="N/A",
        field_path="text",
        description="Weird spacing",
        detection_method="Rule",
        confidence=1.0
    )
    # Risk = 0.2 * 1.0 = 0.2 (Below 0.30)
    
    decision = engine.decide([v])
    assert decision.status == "APPROVED_WITH_WARNINGS"