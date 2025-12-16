from dataclasses import dataclass
from enum import Enum
from typing import List
from .risk_component import RiskComponent

class ComplianceOutcome(str, Enum):
    APPROVED = "APPROVED"
    APPROVED_WITH_REDACTIONS = "APPROVED_WITH_REDACTIONS"
    REJECTED = "REJECTED"

@dataclass(frozen=True)
class ComplianceDecision:
    """
    Represents the system's calculated opinion on a dataset's compliance.
    This is a decision support object, not an execution command.
    """
    outcome: ComplianceOutcome
    total_risk_score: float
    risk_components: List[RiskComponent]
    rationale: str