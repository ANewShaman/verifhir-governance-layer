from verifhir.models.violation import ViolationSeverity


SEVERITY_WEIGHTS = {
    ViolationSeverity.CRITICAL: 5.0,
    ViolationSeverity.MAJOR: 2.0,
    ViolationSeverity.MINOR: 0.5,
}


def severity_to_weight(severity: ViolationSeverity) -> float:
    """
    Convert a violation severity to a deterministic numeric weight.
    """
    if severity not in SEVERITY_WEIGHTS:
        raise ValueError(f"Unknown severity: {severity}")

    return SEVERITY_WEIGHTS[severity]
