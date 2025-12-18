from typing import List
from verifhir.rules.base_rule import ComplianceRule
from verifhir.models.violation import Violation, ViolationSeverity
from verifhir.rules.utils.identifier_patterns import IDENTIFIER_REGEX

class BaseFreeTextIdentifierRule(ComplianceRule):
    """
    Abstract base class for regulations that forbid unconsented 
    identifiers in free text (GDPR, UK_GDPR, LGPD, etc.).
    """
    REGULATION = None
    CITATION = None
    DESCRIPTION = None

    def evaluate(self, resource: dict) -> List[Violation]:
        # 1. Safety Check: Is the child class configured?
        if not all([self.REGULATION, self.CITATION, self.DESCRIPTION]):
            raise NotImplementedError("Subclasses must define REGULATION, CITATION, and DESCRIPTION")

        # 2. Scope Check
        if self.REGULATION not in self.context.applicable_regulations:
            return []

        violations = []
        
        # 3. Generic Field Path Logic (Works for Observation, Patient, Task, etc.)
        # We look for any 'note' list with 'text' fields.
        notes = resource.get("note", [])
        for note in notes:
            text = note.get("text", "")
            if IDENTIFIER_REGEX.search(text):
                violations.append(Violation(
                    violation_type="FREE_TEXT_IDENTIFIER",
                    severity=ViolationSeverity.MAJOR,
                    regulation=self.REGULATION,
                    citation=self.CITATION,
                    field_path="note[].text", # Generic path
                    description=self.DESCRIPTION,
                    detection_method="rule-based"
                ))
                
        return violations