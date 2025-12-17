from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.jurisdiction.schemas import JurisdictionContext, JurisdictionResolution

def test_orchestrator_runs_gdpr_rules_only_when_governing():
    """
    Verify that if Jurisdiction says 'GDPR Governs', 
    ONLY the GDPR rules are executed.
    """
    # 1. Mock a Jurisdiction Resolution (Day 6 Artifact)
    jurisdiction = JurisdictionResolution(
        context=JurisdictionContext(
            source_country="US",
            destination_country="US",
            data_subject_country="DE" # Triggers GDPR
        ),
        applicable_regulations=["GDPR", "HIPAA"],
        reasoning={"GDPR": "EU residency"},
        regulation_snapshot_version="adequacy_v1_2025-01-01",
        governing_regulation="GDPR" # <--- The Orchestrator cares about THIS
    )

    # 2. Mock Data with a GDPR violation (Patient ID in text)
    fake_fhir = {
        "resourceType": "Observation",
        "note": [{"text": "Patient ID 99999 reported symptoms"}]
    }

    # 3. Run Orchestrator
    violations = run_deterministic_rules(jurisdiction, fake_fhir)

    # 4. Assertions
    assert len(violations) == 1
    assert violations[0].regulation == "GDPR"
    assert violations[0].violation_type == "FREE_TEXT_IDENTIFIER"

def test_orchestrator_ignores_hipaa_violation_if_dpdp_governs():
    """
    Verify strict separation: If DPDP governs, don't run HIPAA rules.
    (Even if HIPAA was applicable, we enforced governing logic).
    """
    jurisdiction = JurisdictionResolution(
        context=JurisdictionContext("US", "IN", "IN"),
        applicable_regulations=["DPDP", "HIPAA"],
        reasoning={},
        regulation_snapshot_version="v1",
        governing_regulation="DPDP"
    )

    # Data has "MRN" (HIPAA Trigger) but Orchestrator shouldn't check HIPAA rules
    fake_fhir = {"text": "MRN: 12345"}

    violations = run_deterministic_rules(jurisdiction, fake_fhir)

    # Should be 0 because we only ran DPDP rules, and DPDP rules 
    # (from Day 8) check for 'address', not 'MRN'.
    assert len(violations) == 0