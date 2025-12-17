from typing import List
from verifhir.models.violation import Violation
from verifhir.models.risk_component import RiskComponent
from verifhir.risk.components import build_risk_component

def violations_to_risk_components(
    violations: List[Violation]
) -> List[RiskComponent]:
    """
    Helper to batch convert Violations to RiskComponents using the Day 9 logic.
    """
    return [build_risk_component(v) for v in violations]