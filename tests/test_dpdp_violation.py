import pytest
from verifhir.orchestrator.rule_engine import run_deterministic_rules

# Mock Classes (Same as above)
class MockContext:
    def __init__(self, subject="IN", regs=None):
        self.data_subject_country = subject
        self.applicable_regulations = regs or ["DPDP"]

class MockJurisdiction:
    def __init__(self, reg="DPDP", subject="IN"):
        self.governing_regulation = reg
        self.regulation_citation = "India DPDP Act 2023"
        self.context = MockContext(subject)

def test_dpdp_consent_missing():
    # 1. Patient without Consent
    resource = {"resourceType": "Patient", "id": "123"}
    
    # 2. Run Engine
    jurisdiction = MockJurisdiction("DPDP", "IN")
    violations = run_deterministic_rules(jurisdiction, resource)
    
    # 3. Assert Violation Found
    assert len(violations) > 0
    assert "DPDP_CONSENT_MISSING" in violations[0].violation_type