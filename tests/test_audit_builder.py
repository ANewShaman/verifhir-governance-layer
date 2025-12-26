from datetime import datetime
import pytest

from verifhir.jurisdiction.models import JurisdictionContext
from verifhir.models.compliance_decision import ComplianceDecision
from verifhir.models.audit_record import HumanDecision
from verifhir.orchestrator.audit_builder import build_audit_record

def mock_jurisdiction_context():
    return JurisdictionContext(
        source_country="EU",
        destination_country="US",
        data_subject_country="FR",
    )

def mock_decision():
    return ComplianceDecision(
        outcome="APPROVED",
        total_risk_score=0.1,
        rationale="Low risk",
        risk_components=[]
    )

def test_audit_creation_succeeds_with_human_decision():
    human = HumanDecision(
        reviewer_id="reviewer-001",
        decision="APPROVED",
        rationale="All checks reviewed",
        timestamp=datetime.utcnow(),
    )

    audit = build_audit_record(
        ctx=mock_jurisdiction_context(),
        decision=mock_decision(),
        detections=[],
        human_decision=human,
        dataset_fingerprint="abc123",
        record_hash="hash123",
        previous_record_hash=None,
    )

    assert audit.human_decision.reviewer_id == "reviewer-001"
    assert audit.source_jurisdiction == "EU"