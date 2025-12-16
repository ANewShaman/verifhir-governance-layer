from dataclasses import dataclass
from typing import Dict, List
from datetime import datetime
from .compliance_decision import ComplianceDecision


@dataclass(frozen=True)
class AuditRecord:
    audit_id: str
    timestamp: datetime
    dataset_fingerprint: str

    jurisdiction_context: Dict[str, str]
    applied_regulations: List[str]
    regulation_snapshot_version: str

    compliance_decision: ComplianceDecision

    reviewer_id: str
    reviewer_notes: str

    previous_record_hash: str
    record_hash: str
