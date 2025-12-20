# verifhir/ml/fusion.py

from typing import List
from verifhir.models.violation import Violation
from verifhir.ml.presidio_phi import detect_phi_presidio


def fuse_azure_and_presidio(
    text: str,
    field_path: str,
    azure_violations: List[Violation]
) -> List[Violation]:
    """
    Azure remains authoritative.
    Presidio augments ONLY when allowed.
    """

    azure_flagged = len(azure_violations) > 0

    presidio_violations = detect_phi_presidio(
        text=text,
        field_path=field_path,
        azure_flagged=azure_flagged
    )

    return azure_violations + presidio_violations
