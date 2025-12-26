import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

from verifhir.models.audit_record import AuditRecord, HumanDecision
from verifhir.models.compliance_decision import ComplianceDecision, ComplianceOutcome
from verifhir.models.purpose import Purpose


@patch('verifhir.storage.AZURE_AVAILABLE', True)
@patch('verifhir.storage.BlobClient')
def test_audit_hash_chain_break_is_rejected(mock_blob_client_class):
    # Mock the blob client and its methods
    mock_blob_client = MagicMock()
    mock_blob_client_class.from_connection_string.return_value = mock_blob_client
    
    # Import after patching
    from verifhir.storage import AuditStorage
    
    storage = AuditStorage(
        connection_string="UseDevelopmentStorage=true",  # mocked / local
        container_name="audit-records"
    )

    fixed_time = datetime(2025, 1, 1)

    decision = ComplianceDecision(
        outcome=ComplianceOutcome.APPROVED,
        total_risk_score=0.0,
        risk_components=[],
        rationale="OK"
    )

    human = HumanDecision(
        reviewer_id="reviewer-1",
        decision="APPROVED",
        rationale="Reviewed",
        timestamp=fixed_time
    )

    # Simulate a previous valid audit
    last_audit = AuditRecord(
        audit_id="prev",
        timestamp=fixed_time,
        dataset_fingerprint="ds-1",
        record_hash="CORRECT_HASH",
        previous_record_hash=None,
        engine_version="VeriFHIR-0.9.3",
        policy_snapshot_version="HIPAA-GDPR-DPDP-2025.1",
        jurisdiction_context=None,
        source_jurisdiction="EU",
        destination_jurisdiction="US",
        purpose=Purpose.RESEARCH,
        decision=decision,
        detections=[],
        detection_methods_used=["rules"],
        negative_assertions=[],
        human_decision=human
    )

    # Monkeypatch: storage thinks this was the last audit
    storage.get_last_audit = lambda _: last_audit

    # Tampered audit: wrong previous hash
    tampered_audit = AuditRecord(
        audit_id="bad",
        timestamp=fixed_time,
        dataset_fingerprint="ds-1",
        record_hash="SOME_HASH",
        previous_record_hash="WRONG_HASH",  # <-- tampering
        engine_version="VeriFHIR-0.9.3",
        policy_snapshot_version="HIPAA-GDPR-DPDP-2025.1",
        jurisdiction_context=None,
        source_jurisdiction="EU",
        destination_jurisdiction="US",
        purpose=Purpose.RESEARCH,
        decision=decision,
        detections=[],
        detection_methods_used=["rules"],
        negative_assertions=[],
        human_decision=human
    )

    with pytest.raises(ValueError, match="Audit hash chain broken"):
        storage.commit_record(tampered_audit)
    
    # Verify blob client was never called (error raised before write)
    mock_blob_client.upload_blob.assert_not_called()
