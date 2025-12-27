from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Literal

from verifhir.models.input_provenance import InputProvenance


# =========================================================
# DAY 25 / DAY 32 — Human accountability (RESTORED)
# =========================================================
@dataclass(frozen=True)
class HumanDecision:
    """
    Explicit human attestation.
    Stored inside the audit record (non-negotiable).
    """
    reviewer_id: str
    decision: Literal["APPROVED", "NEEDS_REVIEW", "REJECTED"]
    rationale: str
    timestamp: datetime


# =========================================================
# DAY 32 — Canonical Audit Record
# =========================================================
@dataclass(frozen=True)
class AuditRecord:
    audit_id: str
    timestamp: datetime

    # Dataset + input integrity
    dataset_fingerprint: str
    input_fingerprint: str

    # Hash integrity
    record_hash: str
    previous_record_hash: Optional[str]

    # Version locking
    engine_version: str
    policy_snapshot_version: str

    # Purpose & provenance
    purpose: str
    input_provenance: InputProvenance

    # Decision evidence
    decision: object
    detections: List
    detection_methods_used: List[str]
    negative_assertions: List

    # Human accountability (mandatory at creation time)
    human_decision: HumanDecision
