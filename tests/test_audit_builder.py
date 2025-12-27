from datetime import datetime
import pytest
import uuid

# FIXED: Corrected import name to match audit_builder.py
from verifhir.orchestrator.audit_builder import build_audit
from verifhir.models.audit_record import HumanDecision

def test_audit_creation_succeeds_with_human_decision():
    human = HumanDecision(
        reviewer_id="reviewer-001",
        decision="APPROVED",
        rationale="All checks reviewed",
        timestamp=datetime.utcnow(),
    )

    # FIXED: Updated arguments to match the signature in verifhir/orchestrator/audit_builder.py
    # Removed mock_jurisdiction_context and Purpose as they are not in the target function's signature
    audit = build_audit(
        input_data="sample_hl7_data",
        engine_version="VeriFHIR-0.9.3",
        policy_snapshot_version="HIPAA-GDPR-2025.1",
        purpose="RESEARCH",
        human_decision=human,
        input_provenance=None, # Placeholder as expected by the builder
        replay_mode=False
    )

    assert audit.human_decision.reviewer_id == "reviewer-001"
    assert audit.input_fingerprint is not None
    assert isinstance(uuid.UUID(audit.audit_id), uuid.UUID)