"""
Day 33 Tests: Human Accountability Enforcement

Tests that audit_builder enforces mandatory human accountability:
- Rejects missing reviewer_id
- Rejects missing decision
- Rejects rationale < 20 chars
- Accepts valid HumanDecision
- Verifies audit hash changes when human decision changes
"""

import pytest
from datetime import datetime
from verifhir.models.audit_record import HumanDecision
from verifhir.models.input_provenance import InputProvenance
from verifhir.orchestrator.audit_builder import build_audit_record
from verifhir.audit.hash_utils import compute_audit_hash


# ============================================================
# FIXTURES
# ============================================================

@pytest.fixture
def valid_human_decision():
    """Valid HumanDecision for testing"""
    return HumanDecision(
        reviewer_id="test.reviewer@example.com",
        decision="APPROVED",
        rationale="This redaction properly protects PHI while maintaining clinical utility for research purposes.",
        timestamp=datetime.utcnow()
    )


@pytest.fixture
def valid_input_provenance():
    """Valid InputProvenance for testing"""
    return InputProvenance(
        original_format="FHIR",
        system_config_hash="test_config_hash_123",
        converter_version="1.0.0",
        message_type=None,
        ocr_engine_version=None,
        ocr_confidence=None
    )


@pytest.fixture
def base_audit_params(valid_input_provenance):
    """Base parameters for building an audit record"""
    return {
        "audit_id": "test-audit-001",
        "dataset_fingerprint": "abc123",
        "engine_version": "1.0.0",
        "policy_snapshot_version": "1.0",
        "jurisdiction_context": {"regulation": "HIPAA"},
        "source_jurisdiction": "US",
        "destination_jurisdiction": "US",
        "decision": {"action": "REDACT"},
        "detections": ["NAME", "SSN"],
        "detection_methods_used": ["AI", "REGEX"],
        "negative_assertions": [],
        "purpose": "clinical_research",
        "input_provenance": valid_input_provenance,
    }


# ============================================================
# TEST: MISSING REVIEWER_ID
# ============================================================

def test_builder_rejects_missing_reviewer_id(base_audit_params):
    """Builder must reject HumanDecision with empty reviewer_id"""
    
    invalid_decision = HumanDecision(
        reviewer_id="",  # INVALID: empty string
        decision="APPROVED",
        rationale="Valid rationale with enough characters to pass validation",
        timestamp=datetime.utcnow()
    )
    
    with pytest.raises(ValueError, match="Reviewer identity is required"):
        build_audit_record(
            **base_audit_params,
            human_decision=invalid_decision
        )


def test_builder_rejects_whitespace_only_reviewer_id(base_audit_params):
    """Builder must reject HumanDecision with whitespace-only reviewer_id"""
    
    invalid_decision = HumanDecision(
        reviewer_id="   ",  # INVALID: whitespace only
        decision="APPROVED",
        rationale="Valid rationale with enough characters to pass validation",
        timestamp=datetime.utcnow()
    )
    
    with pytest.raises(ValueError, match="Reviewer identity is required"):
        build_audit_record(
            **base_audit_params,
            human_decision=invalid_decision
        )


# ============================================================
# TEST: MISSING DECISION
# ============================================================

def test_builder_rejects_none_human_decision(base_audit_params):
    """Builder must reject None as human_decision"""
    
    with pytest.raises(ValueError, match="Audit cannot be created without a human decision"):
        build_audit_record(
            **base_audit_params,
            human_decision=None
        )


# ============================================================
# TEST: RATIONALE TOO SHORT
# ============================================================

def test_builder_rejects_short_rationale(base_audit_params):
    """Builder must reject rationale with fewer than 20 characters"""
    
    invalid_decision = HumanDecision(
        reviewer_id="test.reviewer@example.com",
        decision="APPROVED",
        rationale="Too short",  # INVALID: only 9 chars
        timestamp=datetime.utcnow()
    )
    
    with pytest.raises(ValueError, match="rationale must be at least 20 characters"):
        build_audit_record(
            **base_audit_params,
            human_decision=invalid_decision
        )


def test_builder_rejects_whitespace_rationale(base_audit_params):
    """Builder must reject rationale that is whitespace only"""
    
    invalid_decision = HumanDecision(
        reviewer_id="test.reviewer@example.com",
        decision="APPROVED",
        rationale="                         ",  # INVALID: whitespace only
        timestamp=datetime.utcnow()
    )
    
    with pytest.raises(ValueError, match="rationale must be at least 20 characters"):
        build_audit_record(
            **base_audit_params,
            human_decision=invalid_decision
        )


def test_builder_accepts_exactly_20_char_rationale(base_audit_params):
    """Builder must accept rationale with exactly 20 characters"""
    
    valid_decision = HumanDecision(
        reviewer_id="test.reviewer@example.com",
        decision="APPROVED",
        rationale="12345678901234567890",  # VALID: exactly 20 chars
        timestamp=datetime.utcnow()
    )
    
    # Should not raise
    record = build_audit_record(
        **base_audit_params,
        human_decision=valid_decision
    )
    
    assert record is not None
    assert record.human_decision.rationale == "12345678901234567890"


# ============================================================
# TEST: VALID HUMAN DECISION ACCEPTANCE
# ============================================================

def test_builder_accepts_valid_human_decision(base_audit_params, valid_human_decision):
    """Builder must accept a fully valid HumanDecision"""
    
    record = build_audit_record(
        **base_audit_params,
        human_decision=valid_human_decision
    )
    
    assert record is not None
    assert record.human_decision == valid_human_decision
    assert record.human_decision.reviewer_id == "test.reviewer@example.com"
    assert record.human_decision.decision == "APPROVED"
    assert len(record.human_decision.rationale) >= 20


def test_builder_accepts_all_decision_types(base_audit_params):
    """Builder must accept all valid decision types"""
    
    for decision_type in ["APPROVED", "NEEDS_REVIEW", "REJECTED"]:
        valid_decision = HumanDecision(
            reviewer_id="test.reviewer@example.com",
            decision=decision_type,
            rationale="This is a valid rationale with more than 20 characters",
            timestamp=datetime.utcnow()
        )
        
        record = build_audit_record(
            **base_audit_params,
            human_decision=valid_decision
        )
        
        assert record.human_decision.decision == decision_type


# ============================================================
# TEST: TIMESTAMP VALIDATION
# ============================================================

def test_builder_rejects_none_timestamp(base_audit_params):
    """Builder must reject HumanDecision with None timestamp"""
    
    invalid_decision = HumanDecision(
        reviewer_id="test.reviewer@example.com",
        decision="APPROVED",
        rationale="Valid rationale with enough characters",
        timestamp=None  # INVALID
    )
    
    with pytest.raises(ValueError, match="Human decision timestamp is required"):
        build_audit_record(
            **base_audit_params,
            human_decision=invalid_decision
        )


def test_builder_rejects_non_datetime_timestamp(base_audit_params):
    """Builder must reject HumanDecision with non-datetime timestamp"""
    
    invalid_decision = HumanDecision(
        reviewer_id="test.reviewer@example.com",
        decision="APPROVED",
        rationale="Valid rationale with enough characters",
        timestamp="2024-01-01"  # INVALID: string instead of datetime
    )
    
    with pytest.raises(ValueError, match="Human decision timestamp is required"):
        build_audit_record(
            **base_audit_params,
            human_decision=invalid_decision
        )


# ============================================================
# TEST: AUDIT HASH CHANGES WITH HUMAN DECISION
# ============================================================

def test_audit_hash_changes_when_reviewer_id_changes(base_audit_params):
    """Audit hash must change when reviewer_id changes"""
    
    decision_1 = HumanDecision(
        reviewer_id="reviewer.one@example.com",
        decision="APPROVED",
        rationale="Valid rationale with enough characters for testing",
        timestamp=datetime.utcnow()
    )
    
    decision_2 = HumanDecision(
        reviewer_id="reviewer.two@example.com",  # DIFFERENT
        decision="APPROVED",
        rationale="Valid rationale with enough characters for testing",
        timestamp=decision_1.timestamp  # Same timestamp
    )
    
    record_1 = build_audit_record(**base_audit_params, human_decision=decision_1)
    record_2 = build_audit_record(**base_audit_params, human_decision=decision_2)
    
    # Hashes MUST be different
    assert record_1.record_hash != record_2.record_hash, \
        "Audit hash must change when reviewer_id changes"


def test_audit_hash_changes_when_rationale_changes(base_audit_params):
    """Audit hash must change when rationale changes"""
    
    decision_1 = HumanDecision(
        reviewer_id="test.reviewer@example.com",
        decision="APPROVED",
        rationale="First rationale that meets minimum length requirements",
        timestamp=datetime.utcnow()
    )
    
    decision_2 = HumanDecision(
        reviewer_id="test.reviewer@example.com",
        decision="APPROVED",
        rationale="Second rationale that is different but also meets requirements",
        timestamp=decision_1.timestamp
    )
    
    record_1 = build_audit_record(**base_audit_params, human_decision=decision_1)
    record_2 = build_audit_record(**base_audit_params, human_decision=decision_2)
    
    # Hashes MUST be different
    assert record_1.record_hash != record_2.record_hash, \
        "Audit hash must change when rationale changes"


def test_audit_hash_changes_when_decision_changes(base_audit_params):
    """Audit hash must change when decision type changes"""
    
    decision_1 = HumanDecision(
        reviewer_id="test.reviewer@example.com",
        decision="APPROVED",
        rationale="Valid rationale with enough characters for testing",
        timestamp=datetime.utcnow()
    )
    
    decision_2 = HumanDecision(
        reviewer_id="test.reviewer@example.com",
        decision="REJECTED",  # DIFFERENT
        rationale="Valid rationale with enough characters for testing",
        timestamp=decision_1.timestamp
    )
    
    record_1 = build_audit_record(**base_audit_params, human_decision=decision_1)
    record_2 = build_audit_record(**base_audit_params, human_decision=decision_2)
    
    # Hashes MUST be different
    assert record_1.record_hash != record_2.record_hash, \
        "Audit hash must change when decision changes"


def test_audit_hash_changes_when_timestamp_changes(base_audit_params):
    """Audit hash must change when timestamp changes"""
    
    import time
    
    timestamp_1 = datetime.utcnow()
    time.sleep(0.1)  # Ensure different timestamp
    timestamp_2 = datetime.utcnow()
    
    decision_1 = HumanDecision(
        reviewer_id="test.reviewer@example.com",
        decision="APPROVED",
        rationale="Valid rationale with enough characters for testing",
        timestamp=timestamp_1
    )
    
    decision_2 = HumanDecision(
        reviewer_id="test.reviewer@example.com",
        decision="APPROVED",
        rationale="Valid rationale with enough characters for testing",
        timestamp=timestamp_2  # DIFFERENT
    )
    
    record_1 = build_audit_record(**base_audit_params, human_decision=decision_1)
    record_2 = build_audit_record(**base_audit_params, human_decision=decision_2)
    
    # Hashes MUST be different
    assert record_1.record_hash != record_2.record_hash, \
        "Audit hash must change when timestamp changes"


# ============================================================
# TEST: HASH INTEGRITY
# ============================================================

def test_record_hash_matches_computed_hash(base_audit_params, valid_human_decision, valid_input_provenance):
    """Record hash must match independently computed hash"""
    
    record = build_audit_record(
        **base_audit_params,
        human_decision=valid_human_decision
    )
    
    # Manually construct the payload that was used for hashing
    # This mirrors what build_audit_record does internally
    payload_for_hash = {
        "audit_id": base_audit_params["audit_id"],
        "timestamp": record.timestamp.isoformat(),
        "dataset_fingerprint": base_audit_params["dataset_fingerprint"],
        "input_fingerprint": base_audit_params["dataset_fingerprint"],
        "previous_record_hash": None,
        "engine_version": base_audit_params["engine_version"],
        "policy_snapshot_version": base_audit_params["policy_snapshot_version"],
        "jurisdiction_context": base_audit_params["jurisdiction_context"],
        "source_jurisdiction": base_audit_params["source_jurisdiction"],
        "destination_jurisdiction": base_audit_params["destination_jurisdiction"],
        "decision": base_audit_params["decision"],
        "detections": base_audit_params["detections"],
        "detection_methods_used": base_audit_params["detection_methods_used"],
        "negative_assertions": base_audit_params["negative_assertions"],
        "purpose": base_audit_params["purpose"],
        "human_decision": {
            "reviewer_id": valid_human_decision.reviewer_id,
            "decision": valid_human_decision.decision,
            "rationale": valid_human_decision.rationale,
            "timestamp": valid_human_decision.timestamp.isoformat(),
        },
        "input_provenance": {
            "original_format": valid_input_provenance.original_format,
            "system_config_hash": valid_input_provenance.system_config_hash,
            "converter_version": valid_input_provenance.converter_version,
            "message_type": valid_input_provenance.message_type,
            "ocr_engine_version": valid_input_provenance.ocr_engine_version,
            "ocr_confidence": valid_input_provenance.ocr_confidence,
        },
    }
    
    # Recompute hash
    recomputed_hash = compute_audit_hash(payload_for_hash)
    
    # Must match
    assert record.record_hash == recomputed_hash, \
        "Record hash must match independently computed hash"


# ============================================================
# TEST: IMMUTABILITY
# ============================================================

def test_human_decision_is_immutable(valid_human_decision):
    """HumanDecision must be frozen (immutable)"""
    
    with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
        valid_human_decision.reviewer_id = "hacker@evil.com"


def test_audit_record_is_immutable(base_audit_params, valid_human_decision):
    """AuditRecord must be frozen (immutable)"""
    
    record = build_audit_record(
        **base_audit_params,
        human_decision=valid_human_decision
    )
    
    with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
        record.human_decision = HumanDecision(
            reviewer_id="hacker@evil.com",
            decision="APPROVED",
            rationale="Trying to tamper with immutable record",
            timestamp=datetime.utcnow()
        )