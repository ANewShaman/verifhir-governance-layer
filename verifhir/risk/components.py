from verifhir.models.violation import Violation
from verifhir.models.risk_component import RiskComponent
from verifhir.risk.severity import severity_to_weight


def build_risk_component(violation: Violation) -> RiskComponent:
    """
    Convert a Violation into a deterministic RiskComponent.
    """
    weight = severity_to_weight(violation.severity)
    weighted_score = weight  # no aggregation yet

    explanation = (
        f"{violation.regulation} violation "
        f"({violation.citation}) at {violation.field_path}"
    )

    return RiskComponent(
        violation=violation,
        weight=weight,
        weighted_score=weighted_score,
        explanation=explanation
    )
