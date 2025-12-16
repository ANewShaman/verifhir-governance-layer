from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ViolationSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    MAJOR = "MAJOR"
    MINOR = "MINOR"


@dataclass(frozen=True)
class Violation:
    violation_type: str
    severity: ViolationSeverity
    regulation: str
    citation: str
    field_path: str
    description: str
    detection_method: str  # rule-based | ml-primary | ml-augmented
    confidence: Optional[float] = None
