from typing import List, Dict
from dataclasses import dataclass, field
from verifhir.models.violation import Violation
from verifhir.decision.scorer import calculate_risk_score

@dataclass
class ComplianceDecision:
    status: str  # "APPROVED", "REJECTED", "NEEDS_REVIEW"
    max_risk_score: float
    reason: str
    violations: List[Violation] = field(default_factory=list)

class DecisionEngine:
    """
    Determines the final compliance verdict based on risk thresholds.
    """
    # Thresholds
    BLOCK_THRESHOLD = 0.65  # Anything above 0.65 is automatic rejection
    REVIEW_THRESHOLD = 0.30 # Anything between 0.30 and 0.65 is manual review
    
    def decide(self, violations: List[Violation]) -> ComplianceDecision:
        if not violations:
            return ComplianceDecision(
                status="APPROVED", 
                max_risk_score=0.0, 
                reason="No violations found."
            )

        # 1. Score every violation
        scored_violations = []
        max_score = 0.0
        
        for v in violations:
            score = calculate_risk_score(v)
            max_score = max(max_score, score)
            scored_violations.append((score, v))

        # 2. Determine Verdict
        if max_score >= self.BLOCK_THRESHOLD:
            return ComplianceDecision(
                status="REJECTED",
                max_risk_score=max_score,
                reason=f"Critical violation detected (Risk: {max_score})",
                violations=violations
            )
        
        elif max_score >= self.REVIEW_THRESHOLD:
            return ComplianceDecision(
                status="NEEDS_REVIEW",
                max_risk_score=max_score,
                reason=f"Ambiguous violations detected (Risk: {max_score})",
                violations=violations
            )
            
        else:
            # Low severity noise (e.g., minor formatting issues) might be allowed
            return ComplianceDecision(
                status="APPROVED_WITH_WARNINGS",
                max_risk_score=max_score,
                reason="Only minor violations detected.",
                violations=violations
            )