from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.jurisdiction.schemas import JurisdictionContext, JurisdictionResolution
from verifhir.scoring.utils import violations_to_risk_components
from verifhir.scoring.aggregator import aggregate_risk_components
from verifhir.scoring.decision import build_rule_only_decision
from verifhir.models.compliance_decision import ComplianceOutcome
from tests.fixtures.violating_fhir import DPDP_VIOLATION_FHIR


def test_dpdp_minor_violation_does_not_block():
    jurisdiction = JurisdictionResolution(
        context=JurisdictionContext(
            source_country="IN",
            destination_country="IN",
            data_subject_country="IN"
        ),
        applicable_regulations=["DPDP"],
        reasoning={"DPDP": "India processing"},
        regulation_snapshot_version="adequacy_v1_2025-01-01",
        governing_regulation="DPDP"
    )

    violations = run_deterministic_rules(jurisdiction, DPDP_VIOLATION_FHIR)
    assert len(violations) == 1

    risk_components = violations_to_risk_components(violations)
    score = aggregate_risk_components(risk_components)

    decision = build_rule_only_decision(
        total_risk_score=score["total_risk_score"],
        risk_components=risk_components
    )

    assert decision.outcome != ComplianceOutcome.REJECTED
