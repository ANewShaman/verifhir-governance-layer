from dataclasses import dataclass
from typing import Optional
from .violation import Violation


@dataclass(frozen=True)
class RiskComponent:
    violation: Violation
    weight: float
    weighted_score: float
    explanation: str
