from datetime import datetime
from typing import Any

from verifhir.models.audit_record import AuditRecord, HumanDecision
from verifhir.models.input_provenance import InputProvenance
from verifhir.audit.hash_utils import compute_audit_hash


def build_audit_record(
    *,
    audit_id: str,
    dataset_fingerprint: str,
    engine_version: str,
    policy_snapshot_version: str,
    jurisdiction_context: Any,
    source_jurisdiction: str,
    destination_jurisdiction: str,
    decision: Any,
    detections: list,
    detection_methods_used: list,
    negative_assertions: list,
    purpose: str,
    human_decision: HumanDecision,
    input_provenance: InputProvenance,
    previous_record_hash: str | None = None,
) -> AuditRecord:
    """
    Builds a single immutable AuditRecord.
    Day 33: Enforces mandatory human accountability.
    """

    # -------------------------------
    # 🔒 Human accountability checks
    # -------------------------------
    if human_decision is None:
        raise ValueError("Audit cannot be created without a human decision")

    if not human_decision.reviewer_id.strip():
        raise ValueError("Reviewer identity is required")

    if len(human_decision.rationale.strip()) < 20:
        raise ValueError("Human decision rationale must be at least 20 characters")

    if not isinstance(human_decision.timestamp, datetime):
        raise ValueError("Human decision timestamp is required")

    timestamp = datetime.utcnow()

    # -------------------------------
    # Serialize complex objects to dicts for hashing
    # This is critical: the hash must be computed on JSON-serializable data
    # -------------------------------
    
    # Serialize HumanDecision
    human_decision_dict = {
        "reviewer_id": human_decision.reviewer_id,
        "decision": human_decision.decision,
        "rationale": human_decision.rationale,
        "timestamp": human_decision.timestamp.isoformat(),
    }
    
    # Serialize InputProvenance
    input_provenance_dict = {
        "original_format": input_provenance.original_format,
        "system_config_hash": input_provenance.system_config_hash,
        "converter_version": input_provenance.converter_version,
        "message_type": input_provenance.message_type,
        "ocr_engine_version": input_provenance.ocr_engine_version,
        "ocr_confidence": input_provenance.ocr_confidence,
    }

    # -------------------------------
    # Canonical payload (NO hash yet)
    # All complex objects converted to dicts/strings for JSON serializability
    # -------------------------------
    payload = dict(
        audit_id=audit_id,
        timestamp=timestamp.isoformat(),
        dataset_fingerprint=dataset_fingerprint,
        input_fingerprint=dataset_fingerprint,
        previous_record_hash=previous_record_hash,
        engine_version=engine_version,
        policy_snapshot_version=policy_snapshot_version,
        jurisdiction_context=jurisdiction_context,
        source_jurisdiction=source_jurisdiction,
        destination_jurisdiction=destination_jurisdiction,
        decision=decision,
        detections=detections,
        detection_methods_used=detection_methods_used,
        negative_assertions=negative_assertions,
        purpose=purpose,
        human_decision=human_decision_dict,
        input_provenance=input_provenance_dict,
    )

    # Compute hash on the serializable payload
    record_hash = compute_audit_hash(payload)

    # Build the AuditRecord with the original objects (not serialized)
    return AuditRecord(
        audit_id=audit_id,
        timestamp=timestamp,
        dataset_fingerprint=dataset_fingerprint,
        input_fingerprint=dataset_fingerprint,
        record_hash=record_hash,
        previous_record_hash=previous_record_hash,
        engine_version=engine_version,
        policy_snapshot_version=policy_snapshot_version,
        purpose=purpose,
        input_provenance=input_provenance,  # Original InputProvenance object
        decision=decision,
        detections=detections,
        detection_methods_used=detection_methods_used,
        negative_assertions=negative_assertions,
        human_decision=human_decision,  # Original HumanDecision object
    )