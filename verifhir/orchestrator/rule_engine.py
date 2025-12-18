from typing import List
from verifhir.jurisdiction.schemas import JurisdictionResolution
from verifhir.models.violation import Violation

# Import standard rules
from verifhir.rules.gdpr_free_text_identifier_rule import GDPRFreeTextIdentifierRule
from verifhir.rules.hipaa_identifier_rule import HIPAAIdentifierRule
from verifhir.rules.dpdp_data_principal_rule import DPDPDataPrincipalRule

# Import Tier 1 regulation rules (Intermediary Hardening)
from verifhir.rules.uk_gdpr_free_text_identifier_rule import UKGDPRFreeTextIdentifierRule
from verifhir.rules.pipeda_free_text_identifier_rule import PIPEDAFreeTextIdentifierRule

def run_deterministic_rules(jurisdiction: JurisdictionResolution, resource: dict) -> List[Violation]:
    """
    Orchestrates the execution of deterministic compliance rules.
    
    1. Selects rules based on the jurisdiction context.
    2. Runs each rule against the provided FHIR resource.
    3. Aggregates all detected violations.
    
    Args:
        jurisdiction: The resolved jurisdiction context (Week 1 output).
        resource: The FHIR resource to scan (e.g., Observation, Patient).
        
    Returns:
        List[Violation]: A flat list of all deterministic violations found.
    """
    
    all_violations: List[Violation] = []

    # Registry of all available deterministic rules.
    # Rules internally check 'jurisdiction.applicable_regulations' 
    # and skip execution if they don't apply.
    active_rules = [
        # Original Core Set
        GDPRFreeTextIdentifierRule(jurisdiction),
        HIPAAIdentifierRule(jurisdiction),
        DPDPDataPrincipalRule(jurisdiction),
        
        # Tier 1 Extensions (Week 2 Hardening)
        UKGDPRFreeTextIdentifierRule(jurisdiction),
        PIPEDAFreeTextIdentifierRule(jurisdiction)
    ]

    # Execute each rule
    for rule in active_rules:
        # Rules returns an empty list [] if not applicable
        found_violations = rule.evaluate(resource)
        all_violations.extend(found_violations)

    return all_violations