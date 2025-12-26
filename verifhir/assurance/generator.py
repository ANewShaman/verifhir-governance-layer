from typing import List
from verifhir.models.negative_assurance import NegativeAssertion
from verifhir.assurance.categories import ASSURABLE_CATEGORIES
from verifhir.explainability.view import ExplainableViolation


def generate_negative_assertions(
    explainable_violations: List[ExplainableViolation],
    detection_methods_used: List[str],
) -> List[NegativeAssertion]:
    """
    Generate negative assertions for categories that were not detected.
    
    This is a bounded claim: "Given the detectors we ran, within their coverage,
    we did not detect certain categories."
    """
    detected_categories = set()

    # Check if any violation maps to a category
    for v in explainable_violations:
        # Check description and field_path for category keywords
        text = f"{v.description} {v.field_path}".lower()

        for category, keywords in ASSURABLE_CATEGORIES.items():
            for kw in keywords:
                if kw in text:
                    detected_categories.add(category)

    assertions = []

    # For each assurable category, if not detected, emit a negative assertion
    for category in ASSURABLE_CATEGORIES.keys():
        if category not in detected_categories:
            assertions.append(
                NegativeAssertion(
                    category=category,
                    status="NOT_DETECTED",
                    supported_by=", ".join(sorted(detection_methods_used)),
                    scope_note="Not detected within detector coverage"
                )
            )

    return assertions
