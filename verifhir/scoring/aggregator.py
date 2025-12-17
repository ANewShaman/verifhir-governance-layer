from typing import List, Dict, Any
from verifhir.models.risk_component import RiskComponent

def aggregate_risk_components(
    components: List[RiskComponent]
) -> Dict[str, Any]:
    """
    Deterministically aggregate risk components into an explainable score.
    Returns a structured summary, not a decision.
    """

    total_score = 0.0
    breakdown = []

    for component in components:
        # Micro-Improvement 2: Defensive Assertion
        # Prevents negative scoring bugs from corrupting the audit trail
        assert component.weighted_score >= 0, "Risk score cannot be negative"

        total_score += component.weighted_score
        
        breakdown.append({
            "regulation": component.violation.regulation,
            "violation_type": component.violation.violation_type,
            "severity": component.violation.severity.value,
            "weight": component.weight,
            "weighted_score": component.weighted_score,
            "citation": component.violation.citation,
            "field_path": component.violation.field_path,
            "explanation": component.explanation
        })

    # Micro-Improvement 1: Deterministic Ordering
    # Ensures the JSON output is identical every time for the same input (Audit Stability)
    breakdown.sort(key=lambda x: (x["regulation"], x["violation_type"]))

    return {
        "total_risk_score": round(total_score, 2),
        "component_count": len(components),
        "components": breakdown
    }