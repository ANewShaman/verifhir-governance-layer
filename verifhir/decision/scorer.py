from verifhir.models.violation import Violation, ViolationSeverity

# Risk Weights
SEVERITY_WEIGHTS = {
    ViolationSeverity.CRITICAL: 1.0, # Immediate blocker
    ViolationSeverity.MAJOR: 0.7,    # Serious, likely blocker
    ViolationSeverity.MINOR: 0.2     # Noise, warnings
}

def calculate_risk_score(violation: Violation) -> float:
    """
    Calculates a single violation's risk score (0.0 to 1.0).
    Formula: Severity Weight * Confidence
    """
    # 1. Get Base Severity Score
    base_weight = SEVERITY_WEIGHTS.get(violation.severity, 0.0)
    
    # 2. Factor in Confidence (ML models might report 0.5, Rules report 1.0)
    # This prevents low-confidence ML noise from blocking pipelines.
    risk = base_weight * violation.confidence
    
    return round(risk, 2)