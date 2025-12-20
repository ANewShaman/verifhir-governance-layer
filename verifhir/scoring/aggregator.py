# verifhir/scoring/aggregator.py

from typing import List, Dict, Any


def aggregate_scored_items(scored_items: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_score = 0.0
    breakdown = []

    for item in scored_items:
        v = item["violation"]
        total_score += item["final_weight"]

        breakdown.append({
            "regulation": v.regulation,
            "violation_type": v.violation_type,
            "severity": v.severity.value,
            "base_weight": item["base_weight"],
            "confidence": item["confidence"],
            "final_weight": item["final_weight"],
            "citation": v.citation,
            "field_path": v.field_path,
            "detection_method": v.detection_method,
            "description": v.description,
        })

    return {
        "total_risk_score": round(total_score, 2),
        "violation_count": len(scored_items),
        "component_count": len(scored_items),
        "breakdown": breakdown,
        "components": breakdown,  # legacy alias
    }


def aggregate_risk_components(components):
    scored_items = []

    for rc in components:
        scored_items.append({
            "violation": rc.violation,
            "base_weight": rc.weight,
            "confidence": rc.violation.confidence or 1.0,
            "final_weight": rc.weighted_score,
        })

    return aggregate_scored_items(scored_items)
