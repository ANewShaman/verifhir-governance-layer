from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.jurisdiction.schemas import JurisdictionContext, JurisdictionResolution
from verifhir.scoring.utils import violations_to_risk_components
from verifhir.scoring.aggregator import aggregate_risk_components
from verifhir.scoring.decision import build_rule_only_decision
from verifhir.models.compliance_decision import ComplianceOutcome


def test_rule_only_decision_pipeline():
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

    fake_fhir = {
        "note": [{"text": "Patient ID 99999"}]
    }

    violations = run_deterministic_rules(jurisdiction, fake_fhir)
    risk_components = violations_to_risk_components(violations)
    score_summary = aggregate_risk_components(risk_components)

    decision = build_rule_only_decision(
        total_risk_score=score_summary["total_risk_score"],
        risk_components=risk_components
    )

    assert decision.outcome in {
        ComplianceOutcome.APPROVED,
        ComplianceOutcome.APPROVED_WITH_REDACTIONS,
        ComplianceOutcome.REJECTED
    }
    assert decision.total_risk_score > 0
    assert len(decision.risk_components) == len(risk_components)
