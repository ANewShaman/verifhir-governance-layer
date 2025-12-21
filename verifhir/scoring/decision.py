from verifhir.models.compliance_decision import (
    ComplianceDecision,
    ComplianceOutcome
)
from verifhir.models.risk_component import RiskComponent
from verifhir.scoring.thresholds import LOW_RISK_MAX, MEDIUM_RISK_MAX


def build_rule_only_decision(
    total_risk_score: float,
    risk_components: list[RiskComponent]
) -> ComplianceDecision:
    """
    Build a deterministic, rule-only compliance decision.
    No ML, no redactions, no automation.
    """

    if total_risk_score <= LOW_RISK_MAX:
        outcome = ComplianceOutcome.APPROVED
        rationale = "Low deterministic risk based on rule evaluation."

    elif total_risk_score <= MEDIUM_RISK_MAX:
        outcome = ComplianceOutcome.APPROVED_WITH_REDACTIONS
        rationale = "Moderate deterministic risk; remediation recommended."

    else:
        outcome = ComplianceOutcome.REJECTED
        rationale = "High deterministic risk; remediation required before sharing."

    return ComplianceDecision(
        outcome=outcome,
        total_risk_score=round(total_risk_score, 2),
        risk_components=risk_components,
        rationale=rationale
    )