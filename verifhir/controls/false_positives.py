"""
False Positive Control
----------------------
Suppresses known systematic false positives.

Runs AFTER detection but BEFORE aggregation.
"""

from typing import Callable, List
from verifhir.models.violation import Violation


class FalsePositiveRule:
    """
    A callable rule that returns True if a violation should be suppressed.
    """

    def __init__(self, reason: str, predicate: Callable[[Violation], bool]):
        self.reason = reason
        self.predicate = predicate

    def matches(self, violation: Violation) -> bool:
        return self.predicate(violation)


class FalsePositiveRegistry:
    """
    Registry of known false-positive suppression rules.
    """

    def __init__(self):
        self._rules: List[FalsePositiveRule] = []

    def register(self, rule: FalsePositiveRule) -> None:
        self._rules.append(rule)

    def should_suppress(self, violation: Violation) -> bool:
        """
        Returns True if violation matches a known false positive pattern.
        """
        for rule in self._rules:
            if rule.matches(violation):
                return True
        return False


# Singleton (intentional)
FALSE_POSITIVES = FalsePositiveRegistry()


# --- DEFAULT BUILT-IN CONTROLS ---

# Example 1: Suppress ML-detected IDs inside test datasets
FALSE_POSITIVES.register(
    FalsePositiveRule(
        reason="Synthetic test identifier",
        predicate=lambda v: (
            v.detection_method != "DeterministicRule"
            and "TEST" in v.description.upper()
        ),
    )
)

# Example 2: Suppress Presidio device IDs with very low severity
FALSE_POSITIVES.register(
    FalsePositiveRule(
        reason="Low-impact device identifier",
        predicate=lambda v: (
            v.detection_method == "presidio_augmented"
            and v.severity.name == "MINOR"
        ),
    )
)
