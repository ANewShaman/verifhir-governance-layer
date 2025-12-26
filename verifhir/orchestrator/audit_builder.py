from datetime import datetime
import uuid
from typing import List

from verifhir.jurisdiction.models import JurisdictionContext
from verifhir.models.compliance_decision import ComplianceDecision
from verifhir.models.audit_record import AuditRecord, HumanDecision
from verifhir.models.purpose import Purpose
from verifhir.explainability.view import ExplainableViolation
from verifhir.assurance.generator import generate_negative_assertions


def build_audit_record(
    ctx: JurisdictionContext,
    decision: ComplianceDecision,
    detections: List[ExplainableViolation],
    human_decision: HumanDecision,
    dataset_fingerprint: str,
    record_hash: str,
    purpose: Purpose,
    previous_record_hash: str = None,
) -> AuditRecord:
    """
    Constructs a complete AuditRecord by mapping context and decision data.
    """

    # DAY 26 — detection method traceability (deterministic)
    detection_methods_used = sorted({
        v.detection_method
        for v in detections
        if v.detection_method
    })

    # DAY 26 — negative assurance
    negative_assertions = generate_negative_assertions(
        detections=detections,
        sensors_used=["AzureAI-Pii", "Presidio"]
    )

    return AuditRecord(
        audit_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),

        # Identity & integrity
        dataset_fingerprint=dataset_fingerprint,
        record_hash=record_hash,
        previous_record_hash=previous_record_hash,

        # Versioning
        engine_version="VeriFHIR-0.9.3",
        policy_snapshot_version="HIPAA-GDPR-DPDP-2025.1",

        # Context
        jurisdiction_context=ctx,
        source_jurisdiction=ctx.source_country,
        destination_jurisdiction=ctx.destination_country,
        purpose=purpose,

        # Risk & detection
        decision=decision,
        detections=detections,
        detection_methods_used=detection_methods_used,
        negative_assertions=negative_assertions,

        # Human accountability
        human_decision=human_decision
    )
