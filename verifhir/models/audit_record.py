from dataclasses import dataclass
from typing import List, Optional, Literal
from datetime import datetime

from verifhir.jurisdiction.models import JurisdictionContext
from verifhir.explainability.view import ExplainableViolation
from .compliance_decision import ComplianceDecision


@dataclass(frozen=True)
class HumanDecision:
    reviewer_id: str
    decision: Literal["APPROVED", "NEEDS_REVIEW", "REJECTED"]
    rationale: str
    timestamp: datetime


@dataclass(frozen=True)
class AuditRecord:
    audit_id: str
    timestamp: datetime

    # Identity & integrity
    dataset_fingerprint: str
    record_hash: str
    previous_record_hash: Optional[str]

    # Versioning
    engine_version: str
    policy_snapshot_version: str

    # Context
    jurisdiction_context: JurisdictionContext
    source_jurisdiction: str
    destination_jurisdiction: str

    # Risk & detection
    decision: ComplianceDecision
    detections: List[ExplainableViolation]

    # Human accountability (mandatory by contract, enforced upstream)
    human_decision: HumanDecision
