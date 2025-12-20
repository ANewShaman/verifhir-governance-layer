# verifhir/scoring/build_scored_items.py

from typing import List, Dict
from verifhir.scoring.ml_weighting import calculate_contribution
from verifhir.scoring.severity import SEVERITY_WEIGHTS


def build_scored_items(violations) -> List[Dict]:
    """
    Converts fused violations into score-ready items
    without performing aggregation.
    """

    scored_items = []

    for v in violations:
        base_weight = SEVERITY_WEIGHTS[v.severity]
        final_weight = calculate_contribution(v)

        scored_items.append({
            "violation": v,
            "base_weight": base_weight,
            "confidence": v.confidence if v.confidence is not None else 1.0,
            "final_weight": final_weight,
        })

    return scored_items
