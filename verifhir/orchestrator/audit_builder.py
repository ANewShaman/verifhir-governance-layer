import uuid
import hashlib
from datetime import datetime

from verifhir.models.audit_record import AuditRecord


def build_audit(
    input_data: str,
    engine_version: str,
    policy_snapshot_version: str,
    purpose: str,
    human_decision,
    input_provenance,
    replay_mode: bool = False,
):
    """
    Builds an AuditRecord.

    DAY 32 CHANGES:
    - input_fingerprint is computed here
    - replay_mode disables any live AI calls upstream
    """

    # ================================
    # DAY 32 FIX — input fingerprint
    # ================================
    input_fingerprint = hashlib.sha256(
        input_data.encode("utf-8")
    ).hexdigest()

    # NOTE: record_hash is computed elsewhere after full assembly
    record_hash = "PLACEHOLDER_HASH"

    return AuditRecord(
        audit_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),

        dataset_fingerprint="dataset-placeholder",
        input_fingerprint=input_fingerprint,     # ✅ NEW (Day 32)

        record_hash=record_hash,
        previous_record_hash=None,

        engine_version=engine_version,
        policy_snapshot_version=policy_snapshot_version,

        purpose=purpose,
        input_provenance=input_provenance,

        decision=None,
        detections=[],
        detection_methods_used=[],
        negative_assertions=[],

        human_decision=human_decision,
    )
