from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class ExplainableViolation:
    """
    Read-only explainability projection.
    No logic. No mutation. No inference.
    """

    regulation: str
    citation: str
    field_path: str
    description: str

    severity: str
    detection_method: str
    confidence: float

    suppressed: bool
    suppression_reason: Optional[str]

    def to_dict(self) -> dict:
        return {
            "regulation": self.regulation,
            "citation": self.citation,
            "field_path": self.field_path,
            "description": self.description,
            "severity": self.severity,
            "detection_method": self.detection_method,
            "confidence": self.confidence,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
        }