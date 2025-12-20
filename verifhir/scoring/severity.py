# verifhir/scoring/severity.py

from verifhir.models.violation import ViolationSeverity

"""
Centralized severity → base weight mapping.

This file must NOT import from any other scoring modules.
Other modules import SEVERITY_WEIGHTS from here.
"""

SEVERITY_WEIGHTS = {
    ViolationSeverity.CRITICAL: 5.0,
    ViolationSeverity.MAJOR: 2.0,
    ViolationSeverity.MINOR: 0.5,
}
