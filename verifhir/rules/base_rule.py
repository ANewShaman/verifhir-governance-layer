# verifhir/rules/base_rule.py

from abc import ABC, abstractmethod
from typing import List, Optional

# IMPORTS MUST MATCH YOUR FILES:
# 1. Import JurisdictionResolution from 'verifhir.jurisdiction.models'
from verifhir.jurisdiction.models import JurisdictionResolution 

# 2. Import Violation from 'verifhir.models.violation'
from verifhir.models.violation import Violation

class ComplianceRule(ABC):
    def __init__(self, context: Optional[JurisdictionResolution] = None):
        self.context = context

    @abstractmethod
    def evaluate(self, resource: dict) -> List[Violation]:
        pass