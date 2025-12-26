from dataclasses import dataclass
from typing import List, Optional, Literal, Dict, Any
from datetime import datetime

from verifhir.jurisdiction.models import JurisdictionContext
from verifhir.explainability.view import ExplainableViolation
from verifhir.models.negative_assurance import NegativeAssertion
from verifhir.models.purpose import Purpose
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

    # Integrity
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
    purpose: Purpose

    # Evidence
    decision: ComplianceDecision
    detections: List[ExplainableViolation]
    detection_methods_used: List[str]
    negative_assertions: List[NegativeAssertion]

    # Human accountability
    human_decision: HumanDecision

    # Input provenance (HL7 → FHIR normalization metadata)
    input_provenance: Optional[Dict[str, Any]] = None
