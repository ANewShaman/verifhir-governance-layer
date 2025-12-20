# verifhir/rules/base_free_text_identifier_rule.py

from typing import List
from verifhir.rules.base_rule import ComplianceRule
from verifhir.models.violation import Violation, ViolationSeverity
from verifhir.rules.utils.identifier_patterns import IDENTIFIER_REGEX


class BaseFreeTextIdentifierRule(ComplianceRule):
    """
    Base class for regulations that forbid identifiers in free text.
    """

    REGULATION = None
    CITATION = None
    DESCRIPTION = None

    def evaluate(self, resource: dict) -> List[Violation]:
        if not all([self.REGULATION, self.CITATION, self.DESCRIPTION]):
            raise NotImplementedError(
                "Subclasses must define REGULATION, CITATION, and DESCRIPTION"
            )

        # Context guard (unit tests may not provide one)
        if self.context is not None:
            if self.REGULATION not in self.context.applicable_regulations:
                return []

        violations: List[Violation] = []

        notes = resource.get("note", [])
        for note in notes:
            text = note.get("text", "")
            if IDENTIFIER_REGEX.search(text):
                violations.append(
                    Violation(
                        violation_type="FREE_TEXT_IDENTIFIER",
                        severity=ViolationSeverity.MAJOR,
                        regulation=self.REGULATION,
                        citation=self.CITATION,
                        field_path="note[].text",
                        description=self.DESCRIPTION,
                        detection_method="rule-based",
                        confidence=None,
                    )
                )

        return violations
