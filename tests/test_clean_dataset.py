import pytest
from verifhir.orchestrator.rule_engine import run_deterministic_rules

class MockContext:
    def __init__(self, subject="US", regs=None):
        self.data_subject_country = subject
        self.applicable_regulations = regs or ["HIPAA"]
        self.source_country = "US"
        self.destination_country = "US"

class MockJurisdiction:
    def __init__(self, reg="HIPAA", subject="US"):
        self.governing_regulation = reg
        self.regulation_citation = "Unknown"
        self.context = MockContext(subject)

def test_clean_dataset_returns_zero_violations():
    # 1. Setup clean data
    resource = {
        "resourceType": "Patient",
        "id": "123",
        "active": True
    }
    
    # 2. Run Engine
    jurisdiction = MockJurisdiction("HIPAA", "US")
    violations = run_deterministic_rules(jurisdiction, resource)
    
    # 3. Assert NO violations found
    assert len(violations) == 0