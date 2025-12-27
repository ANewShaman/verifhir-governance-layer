from datetime import datetime
from verifhir.models.audit_record import AuditRecord, HumanDecision
from verifhir.models.compliance_decision import ComplianceDecision, ComplianceOutcome
from verifhir.models.purpose import Purpose

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

    # REMOVED: jurisdiction_context, source_jurisdiction, destination_jurisdiction
    # These are not in the AuditRecord dataclass provided in audit_record.py
    audit_1 = AuditRecord(
        audit_id="test-001",
        timestamp=fixed_time,
        dataset_fingerprint="abc123",
        input_fingerprint="input-hash-123",
        record_hash="hash123",
        previous_record_hash=None,
        engine_version="VeriFHIR-0.9.3",
        policy_snapshot_version="HIPAA-GDPR-DPDP-2025.1",
        purpose="RESEARCH",
        input_provenance=None,
        decision=decision,
        detections=[],
        detection_methods_used=["rules"],
        negative_assertions=[],
        human_decision=human
    )
    
    assert audit_1.audit_id == "test-001"