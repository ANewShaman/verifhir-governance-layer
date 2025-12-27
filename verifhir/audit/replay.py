import hashlib
from typing import Any

from verifhir.audit.version_registry import (
    CONVERTER_VERSIONS,
    ENGINE_VERSIONS,
    POLICY_VERSIONS,
)

from verifhir.orchestrator.audit_builder import build_audit
from verifhir.models.audit_record import AuditRecord
# FIXED: Updated from verifhir.utils to verifhir.audit
from verifhir.audit.system_config import compute_system_config_hash

def reconvert_hl7(raw_hl7: str, converter_ref: str) -> str:
    return raw_hl7.strip()

def replay_audit(audit_record: AuditRecord, provided_input: str) -> AuditRecord:
    if compute_system_config_hash() != audit_record.input_provenance.system_config_hash:
        raise ValueError("System configuration mismatch")

    provided_hash = hashlib.sha256(provided_input.encode("utf-8")).hexdigest()

    if provided_hash != audit_record.input_fingerprint:
        raise ValueError("Input fingerprint mismatch")

    if audit_record.engine_version not in ENGINE_VERSIONS:
        raise KeyError("Engine version not registered")

    if audit_record.policy_snapshot_version not in POLICY_VERSIONS:
        raise KeyError("Policy snapshot version not registered")

    provenance = audit_record.input_provenance

    if provenance.original_format == "HL7v2":
        if provenance.converter_version not in CONVERTER_VERSIONS:
            raise KeyError("Converter version not registered")

        normalized_input = reconvert_hl7(
            provided_input,
            CONVERTER_VERSIONS[provenance.converter_version],
        )
    else:
        normalized_input = provided_input

    replayed = build_audit(
        input_data=normalized_input,
        engine_version=audit_record.engine_version,
        policy_snapshot_version=audit_record.policy_snapshot_version,
        purpose=audit_record.purpose,
        human_decision=audit_record.human_decision,
        input_provenance=audit_record.input_provenance,
        replay_mode=True,
    )

    if replayed.record_hash != audit_record.record_hash:
        raise ValueError("Replay hash mismatch")

    replayed = replayed.__class__(**{
        **replayed.__dict__,
        "previous_record_hash": None,
    })

    return replayed