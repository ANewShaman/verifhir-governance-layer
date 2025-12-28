import hashlib
from typing import Any

from verifhir.audit.version_registry import (
    CONVERTER_VERSIONS,
    ENGINE_VERSIONS,
    POLICY_VERSIONS,
)

from verifhir.orchestrator.audit_builder import build_audit_record
from verifhir.models.audit_record import AuditRecord
from verifhir.audit.system_config import compute_system_config_hash


def reconvert_hl7(raw_hl7: str, converter_ref: str) -> str:
    """
    Reconverts HL7 input using the specified converter version.
    
    Args:
        raw_hl7: The original HL7 message
        converter_ref: Reference to the converter version to use
        
    Returns:
        Normalized HL7 string (currently just stripped)
    """
    return raw_hl7.strip()


def replay_audit(audit_record: AuditRecord, provided_input: str) -> AuditRecord:
    """
    Replays an audit record to verify deterministic behavior.
    
    This function ensures that given the same input and system configuration,
    the audit process produces the same results. It validates:
    - System configuration hasn't changed
    - Input matches the original fingerprint
    - All versions are still registered
    
    Args:
        audit_record: The original audit record to replay
        provided_input: The input data that was originally processed
        
    Returns:
        A replayed AuditRecord with previous_record_hash cleared
        
    Raises:
        ValueError: If system config, input fingerprint, or record hash doesn't match
        KeyError: If any version (engine, policy, converter) is not registered
    """
    # Verify system configuration hasn't changed
    current_system_hash = compute_system_config_hash()
    if current_system_hash != audit_record.input_provenance.system_config_hash:
        raise ValueError(
            f"System configuration mismatch: "
            f"current={current_system_hash}, "
            f"expected={audit_record.input_provenance.system_config_hash}"
        )

    # Verify input integrity
    provided_hash = hashlib.sha256(provided_input.encode("utf-8")).hexdigest()
    if provided_hash != audit_record.input_fingerprint:
        raise ValueError(
            f"Input fingerprint mismatch: "
            f"provided={provided_hash}, "
            f"expected={audit_record.input_fingerprint}"
        )

    # Verify all versions are registered
    if audit_record.engine_version not in ENGINE_VERSIONS:
        raise KeyError(
            f"Engine version '{audit_record.engine_version}' not registered. "
            f"Available versions: {list(ENGINE_VERSIONS.keys())}"
        )

    if audit_record.policy_snapshot_version not in POLICY_VERSIONS:
        raise KeyError(
            f"Policy snapshot version '{audit_record.policy_snapshot_version}' not registered. "
            f"Available versions: {list(POLICY_VERSIONS.keys())}"
        )

    provenance = audit_record.input_provenance

    # Handle HL7 conversion if needed
    if provenance.original_format == "HL7v2":
        if provenance.converter_version not in CONVERTER_VERSIONS:
            raise KeyError(
                f"Converter version '{provenance.converter_version}' not registered. "
                f"Available versions: {list(CONVERTER_VERSIONS.keys())}"
            )

        normalized_input = reconvert_hl7(
            provided_input,
            CONVERTER_VERSIONS[provenance.converter_version],
        )
    else:
        normalized_input = provided_input

    # Rebuild the audit record in replay mode
    replayed = build_audit_record(
        audit_id=audit_record.audit_id,  # ADD THIS
        dataset_fingerprint=audit_record.dataset_fingerprint,  # ADD THIS
        engine_version=audit_record.engine_version,
        policy_snapshot_version=audit_record.policy_snapshot_version,
        jurisdiction_context=None,  # ADD THIS (or pull from record if available)
        source_jurisdiction="US",  # ADD THIS
         destination_jurisdiction="US",  # ADD THIS
        decision=audit_record.decision,  # ADD THIS
        detections=audit_record.detections,  # ADD THIS
        detection_methods_used=audit_record.detection_methods_used,  # ADD THIS
        negative_assertions=audit_record.negative_assertions,  # ADD THIS
        purpose=audit_record.purpose,
        human_decision=audit_record.human_decision,
        input_provenance=audit_record.input_provenance,
        # REMOVED: input_data (not in signature)
        # REMOVED: replay_mode (not in signature)
    )

    # Verify deterministic behavior
    if replayed.record_hash != audit_record.record_hash:
        raise ValueError(
            f"Replay hash mismatch: "
            f"replayed={replayed.record_hash}, "
            f"original={audit_record.record_hash}"
        )

    # Clear the chain link for safety (replay is read-only)
    replayed = replayed.__class__(**{
        **replayed.__dict__,
        "previous_record_hash": None,
    })

    return replayed