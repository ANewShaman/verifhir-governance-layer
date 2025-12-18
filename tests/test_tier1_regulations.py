from verifhir.jurisdiction.resolver import resolve_jurisdiction
from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.models.violation import ViolationSeverity # Import Enum

def test_uk_gdpr_governance_flow():
    # 1. Setup
    jurisdiction = resolve_jurisdiction("US", "US", "GB")
    resource = {
        "resourceType": "Observation",
        "note": [{"text": "Patient ID 12345 in London clinic."}]
    }

    # 2. Run
    violations = run_deterministic_rules(jurisdiction, resource)
    
    # 3. Assert (Strict Enum Check)
    assert len(violations) == 1
    v = violations[0]
    assert v.regulation == "UK_GDPR"
    assert "Article 5" in v.citation
    # FIX: Compare Enum to Enum
    assert v.severity == ViolationSeverity.MAJOR 

def test_pipeda_consent_logic():
    jurisdiction = resolve_jurisdiction("US", "US", "CA")
    
    # Bad Case
    resource_bad = {
        "resourceType": "Observation",
        "note": [{"text": "Patient ID 555"}] 
    }
    violations = run_deterministic_rules(jurisdiction, resource_bad)
    assert len(violations) == 1
    assert violations[0].violation_type == "UNCONSENTED_IDENTIFIER"
    assert violations[0].severity == ViolationSeverity.MAJOR # Enum check

    # Good Case
    resource_good = {
        "resourceType": "Observation",
        "note": [{"text": "Patient ID 555"}],
        "meta": {"consent_status": "obtained"}
    }
    violations_clean = run_deterministic_rules(jurisdiction, resource_good)
    assert len(violations_clean) == 0