import pytest
from verifhir.orchestrator.rule_engine import run_deterministic_rules

# Mock Classes
class MockContext:
    def __init__(self, subject="DE", regs=None):
        self.data_subject_country = subject
        self.applicable_regulations = regs or ["GDPR"]

class MockJurisdiction:
    def __init__(self, reg="GDPR", subject="DE"):
        self.governing_regulation = reg
        self.regulation_citation = "GDPR Art 5"
        self.context = MockContext(subject)

def test_gdpr_identifier_found():
    # 1. Resource with ID in text
    resource = {"note": [{"text": "Patient ID 12345"}]}
    
    # 2. Run Engine
    jurisdiction = MockJurisdiction("GDPR", "DE")
    violations = run_deterministic_rules(jurisdiction, resource)
    
    # 3. Assert Violation Found
    assert len(violations) > 0
    assert "GDPR_IDENTIFIER" in violations[0].violation_type