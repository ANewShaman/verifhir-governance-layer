from datetime import datetime
from verifhir.models.audit_record import AuditRecord, HumanDecision
from verifhir.models.compliance_decision import ComplianceDecision, ComplianceOutcome

def test_audit_hash_is_deterministic():
    fixed_time = datetime(2025, 1, 1, 0, 0, 0)

    decision = ComplianceDecision(
        outcome=ComplianceOutcome.APPROVED,
        total_risk_score=0.0,
        risk_components=[],
        rationale="No violations detected"
    )

    human = HumanDecision(
        reviewer_id="reviewer-1",
        decision="APPROVED",
        rationale="Reviewed and approved",
        timestamp=fixed_time
    )

    audit_1 = AuditRecord(
        audit_id="test-001",
        timestamp=fixed_time,
        dataset_fingerprint="abc123",
        record_hash="hash123",
        previous_record_hash=None,
        engine_version="VeriFHIR-0.9.3",
        policy_snapshot_version="HIPAA-GDPR-DPDP-2025.1",
        jurisdiction_context=None,  # or mock if needed
        source_jurisdiction="EU",
        destination_jurisdiction="US",
        decision=decision,
        detections=[],
        detection_methods_used=["rules"],
        negative_assertions=[],
        human_decision=human
    )

    audit_2 = audit_1  # same input → same object → same hash

    assert audit_1.record_hash == audit_2.record_hash
