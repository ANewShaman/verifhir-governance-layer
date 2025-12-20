# verifhir/fusion/fuse_violations.py

from typing import List
from verifhir.models.violation import Violation


def fuse_violations(
    rule_violations: List[Violation],
    ml_violations: List[Violation],
) -> List[Violation]:
    """
    Deduplicates violations while enforcing rule dominance.

    Deduplication key:
        (regulation, field_path, violation_type)

    Rules always dominate ML findings.
    """

    fused_store = {}

    # Load deterministic rule violations first (authoritative)
    for rv in rule_violations:
        key = (rv.regulation, rv.field_path, rv.violation_type)
        fused_store[key] = rv

    # Load ML violations second (supplementary)
    for mv in ml_violations:
        key = (mv.regulation, mv.field_path, mv.violation_type)
        if key not in fused_store:
            fused_store[key] = mv

    return list(fused_store.values())
