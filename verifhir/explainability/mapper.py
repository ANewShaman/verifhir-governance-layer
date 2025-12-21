from typing import List, Dict, Optional
from verifhir.models.violation import Violation
# These imports now work because we fixed the files above
from verifhir.controls.allow_list import is_allowlisted
from verifhir.controls.false_positives import is_false_positive
from verifhir.explainability.view import ExplainableViolation

def to_explainable_violation(v: Violation, resource: Optional[Dict] = None) -> ExplainableViolation:
    """
    Converts internal Violation -> explainable read model.
    """
    suppressed = False
    reason = None

    # Check Allowlist (Simple function call)
    if is_allowlisted(v):
        suppressed = True
        reason = "Allowlisted field or value"

    # Check False Positives (Pass resource for context)
    elif is_false_positive(v, resource):
        suppressed = True
        reason = "False positive pattern"

    return ExplainableViolation(
        regulation=v.regulation,
        citation=v.citation,
        field_path=v.field_path,
        description=v.description,
        severity=str(v.severity),
        detection_method=v.detection_method,
        confidence=v.confidence,
        suppressed=suppressed,
        suppression_reason=reason,
    )

def explain_violations(violations: List[Violation], resource: Optional[Dict] = None) -> List[ExplainableViolation]:
    """Batch helper"""
    return [to_explainable_violation(v, resource) for v in violations]