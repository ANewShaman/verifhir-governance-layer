from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.jurisdiction.schemas import JurisdictionContext, JurisdictionResolution
from verifhir.scoring.utils import violations_to_risk_components
from verifhir.scoring.aggregator import aggregate_risk_components

def test_rule_only_scoring_pipeline():
    # 1. Setup Jurisdiction (Simulate Day 6 output)
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

    # 2. Setup Data (Simulate GDPR Violation)
    fake_fhir = {
        "note": [{"text": "Patient ID 99999"}]
    }

    # 3. Run Pipeline
    # A. Orchestrator finds violations
    violations = run_deterministic_rules(jurisdiction, fake_fhir)
    
    # B. Utils convert to risk
    risk_components = violations_to_risk_components(violations)
    
    # C. Aggregator sums it up
    summary = aggregate_risk_components(risk_components)

    # 4. Assertions
    assert summary["total_risk_score"] > 0
    assert summary["component_count"] == 1
    # Verify we can trace it back to the regulation
    assert summary["components"][0]["regulation"] == "GDPR"
    assert "GDPR Article 5(1)(c)" in summary["components"][0]["citation"]