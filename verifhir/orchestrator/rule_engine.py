from typing import Dict, List, Any
from verifhir.jurisdiction.schemas import JurisdictionResolution
from verifhir.rules.base import DeterministicRule

# Import the specific rules created on Day 8
from verifhir.rules.gdpr import GDPRFreeTextIdentifierRule
from verifhir.rules.hipaa import HIPAAMRNRule
from verifhir.rules.dpdp import DPDPExcessiveDataRule
from verifhir.models.violation import Violation

# NOTE: We intentionally enforce only the governing regulation to avoid
# conflicting obligations across legal frameworks.
RULE_REGISTRY: Dict[str, List[DeterministicRule]] = {
    "GDPR": [
        GDPRFreeTextIdentifierRule(),
    ],
    "HIPAA": [
        HIPAAMRNRule(),
    ],
    "DPDP": [
        DPDPExcessiveDataRule(),
    ],
}

def run_deterministic_rules(
    jurisdiction: JurisdictionResolution,
    fhir_resource: Dict[str, Any]
) -> List[Violation]:
    """
    Execute deterministic rules based on the governing regulation.
    
    Architectural Decision:
    We enforce the 'Governing Regulation' (the most restrictive one) 
    rather than running all applicable rules. This prevents conflict 
    cycles where laws might have opposing requirements.
    """

    # 1. Safety Check: If no regulation governs, no rules run.
    if jurisdiction.governing_regulation is None:
        return []

    regulation = jurisdiction.governing_regulation

    # 2. Registry Lookup
    if regulation not in RULE_REGISTRY:
        raise ValueError(f"No rules registered for governing regulation: {regulation}")

    violations: List[Violation] = []

    # 3. Execution Loop
    for rule in RULE_REGISTRY[regulation]:
        # Each rule evaluates the resource independently
        rule_violations = rule.evaluate(fhir_resource)
        violations.extend(rule_violations)

    # 4. Deterministic Ordering (Micro-Improvement)
    # Ensure violations are always returned in the same order for stable audits.
    violations.sort(key=lambda v: (v.regulation, v.violation_type))

    return violations