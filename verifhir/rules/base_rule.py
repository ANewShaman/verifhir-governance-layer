from abc import ABC, abstractmethod
from typing import List
from verifhir.jurisdiction.schemas import JurisdictionResolution
from verifhir.models.violation import Violation

class ComplianceRule(ABC):
    """
    The abstract parent for ALL governance rules.
    Ensures every rule has access to context and implements 'evaluate'.
    """

    def __init__(self, context: JurisdictionResolution):
        self.context = context

    @abstractmethod
    def evaluate(self, resource: dict) -> List[Violation]:
        """
        Check the resource for non-compliance.
        Returns a list of Violations (empty list if compliant).
        """
        pass