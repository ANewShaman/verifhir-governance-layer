from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.jurisdiction.schemas import JurisdictionContext, JurisdictionResolution
from verifhir.scoring.utils import violations_to_risk_components
from verifhir.scoring.aggregator import aggregate_risk_components
from verifhir.scoring.decision import build_rule_only_decision
from verifhir.models.compliance_decision import ComplianceOutcome
from tests.fixtures.violating_fhir import GDPR_VIOLATION_FHIR


def test_gdpr_violation_requires_remediation():
    jurisdiction = JurisdictionResolution(
        context=JurisdictionContext(
            source_country="US",
            destination_country="US",
            data_subject_country="DE"
        ),
        applicable_regulations=["GDPR", "HIPAA"],
        reasoning={"GDPR": "EU residency"},
        regulation_snapshot_version="adequacy_v1_2025-01-01",
        governing_regulation="GDPR"
    )

    violations = run_deterministic_rules(jurisdiction, GDPR_VIOLATION_FHIR)
    assert len(violations) == 1

    risk_components = violations_to_risk_components(violations)
    score = aggregate_risk_components(risk_components)

    decision = build_rule_only_decision(
        total_risk_score=score["total_risk_score"],
        risk_components=risk_components
    )

    assert decision.outcome == ComplianceOutcome.APPROVED_WITH_REDACTIONS
