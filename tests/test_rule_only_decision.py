from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.jurisdiction.schemas import JurisdictionContext, JurisdictionResolution
from verifhir.scoring.utils import violations_to_risk_components
from verifhir.scoring.aggregator import aggregate_risk_components
from verifhir.scoring.decision import build_rule_only_decision
from verifhir.models.compliance_decision import ComplianceOutcome

def test_rule_only_decision_pipeline():
    # 1. Setup Context (GDPR applies)
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

    # 2. Setup Data (Trigger a Violation)
    # This triggers 'GDPRFreeTextIdentifierRule' -> Severity.MAJOR (2.0)
    fake_fhir = {
        "note": [{"text": "Patient ID 99999"}]
    }

    # 3. Run Pipeline
    violations = run_deterministic_rules(jurisdiction, fake_fhir)
    risk_components = violations_to_risk_components(violations)
    score_summary = aggregate_risk_components(risk_components)

    decision = build_rule_only_decision(
        total_risk_score=score_summary["total_risk_score"],
        risk_components=risk_components
    )

    # 4. Strict Assertions (Proves Determinism)
    # The weight for MAJOR is 2.0. The threshold for LOW_RISK is 3.0.
    # Therefore, the system MUST return APPROVED (Score 2.0).
    assert decision.total_risk_score == 2.0
    assert decision.outcome == ComplianceOutcome.APPROVED
    
    # Verify we didn't lose data
    assert len(decision.risk_components) == 1