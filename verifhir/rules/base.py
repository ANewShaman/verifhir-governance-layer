from abc import ABC, abstractmethod
from typing import List, Dict, Any
from verifhir.models.violation import Violation


class DeterministicRule(ABC):
    """
    Base class for all deterministic compliance rules.
    """

    @abstractmethod
    def regulation(self) -> str:
        """Return the regulation name (e.g., GDPR, HIPAA)."""
        pass

    @abstractmethod
    def evaluate(self, fhir_resource: Dict[str, Any]) -> List[Violation]:
        """
        Evaluate a FHIR resource and return zero or more Violations.
        """
        pass
