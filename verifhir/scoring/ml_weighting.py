# verifhir/scoring/ml_weighting.py

from verifhir.scoring.severity import SEVERITY_WEIGHTS


def calculate_contribution(violation) -> float:
    """
    Calculates numeric risk contribution for a violation.

    Rules:
        contribution = base severity weight

    ML (Azure / Presidio):
        contribution = base severity weight × confidence
    """

    base_weight = SEVERITY_WEIGHTS[violation.severity]

    # Deterministic rules ignore confidence
    if violation.detection_method == "rule-based":
        return base_weight

    # ML-based violations (confidence-scaled)
    confidence = violation.confidence if violation.confidence is not None else 1.0
    return round(base_weight * confidence, 2)