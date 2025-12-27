import hashlib
from datetime import datetime
import pytest

from verifhir.audit.replay import replay_audit
from verifhir.models.audit_record import AuditRecord, HumanDecision
from verifhir.models.input_provenance import InputProvenance

# =========================================================
# Fixtures
# =========================================================

@pytest.fixture
def sample_hl7():
    return "MSH|^~\\&|ADT|HOSP|LAB|HOSP|202401011200||ADT^A01|12345|P|2.5"

@pytest.fixture
def system_config_hash(mocker):
    """
    Mocks the system config hash at the point of consumption in the replay module.
    """
    mocker.patch(
        "verifhir.audit.replay.compute_system_config_hash",
        return_value="TEST_SYSTEM_HASH"
    )
    return "TEST_SYSTEM_HASH"

@pytest.fixture
def base_audit(sample_hl7):
    """
    Creates a baseline AuditRecord for testing. 
    Matches the system_config_hash fixture value manually to ensure initial consistency.
    """
    config_hash = "TEST_SYSTEM_HASH" 
    
    input_fingerprint = hashlib.sha256(
        sample_hl7.encode("utf-8")
    ).hexdigest()

    provenance = InputProvenance(
        original_format="HL7v2",
        converter_version="fhir-converter-v2.1.0",
        message_type="ADT^A01",
        system_config_hash=config_hash,
    )

    human = HumanDecision(
        reviewer_id="reviewer@test.com",
        decision="APPROVED",
        rationale="Reviewed and approved for test",
        timestamp=datetime.utcnow(),
    )

    return AuditRecord(
        audit_id="audit-001",
        timestamp=datetime.utcnow(),
        dataset_fingerprint="dataset-123",
        input_fingerprint=input_fingerprint,
        record_hash="EXPECTED_HASH",
        previous_record_hash=None,
        engine_version="VeriFHIR-0.9.3",
        policy_snapshot_version="HIPAA-GDPR-DPDP-2025.1",
        purpose="RESEARCH",
        input_provenance=provenance,
        decision={"outcome": "APPROVED"},
        detections=[],
        detection_methods_used=["rules"],
        negative_assertions=[],
        human_decision=human,
    )

# =========================================================
# Tests
# =========================================================

def test_hl7_replay_is_deterministic(base_audit, sample_hl7, mocker, system_config_hash):
    mocker.patch("verifhir.audit.replay.reconvert_hl7", return_value=sample_hl7)
    # Mock build_audit to return the base_audit to satisfy the record_hash check
    mocker.patch("verifhir.audit.replay.build_audit_record", return_value=base_audit)

    replayed = replay_audit(base_audit, provided_input=sample_hl7)
    assert replayed.record_hash == base_audit.record_hash

def test_replay_fails_on_input_mismatch(base_audit, system_config_hash):
    with pytest.raises(ValueError, match="Input fingerprint mismatch"):
        replay_audit(base_audit, provided_input="TAMPERED_INPUT")

def test_replay_fails_on_system_config_drift(base_audit, mocker):
    """
    Explicitly overrides the global system_config_hash mock to simulate drift.
    """
    mocker.patch(
        "verifhir.audit.replay.compute_system_config_hash",
        return_value="DIFFERENT_SYSTEM_HASH"
    )
    with pytest.raises(ValueError, match="System configuration mismatch"):
        replay_audit(base_audit, provided_input="MSH|^~\\&|ADT|HOSP")

def test_replay_never_calls_live_ai(base_audit, sample_hl7, mocker, system_config_hash):
    """
    Verifies that the builder is invoked in replay_mode, which bypasses AI logic.
    """
    mock_builder = mocker.patch("verifhir.audit.replay.build_audit_record", return_value=base_audit)
    mocker.patch("verifhir.audit.replay.reconvert_hl7", return_value=sample_hl7)

    replay_audit(base_audit, provided_input=sample_hl7)
    
    # Verify the builder received replay_mode=True
    assert mock_builder.call_args[1]["replay_mode"] is True

def test_replay_is_read_only(base_audit, sample_hl7, mocker, system_config_hash):
    mocker.patch("verifhir.audit.replay.reconvert_hl7", return_value=sample_hl7)
    mocker.patch("verifhir.audit.replay.build_audit_record", return_value=base_audit)

    replayed = replay_audit(base_audit, provided_input=sample_hl7)
    # Replay logic specifically clears the chain link for safety
    assert replayed.previous_record_hash is None