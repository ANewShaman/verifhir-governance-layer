from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# --- IMPORT THE BRAIN ---
from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.decision.judge import DecisionEngine
from verifhir.explainability.mapper import explain_violations

app = FastAPI(
    title="Verifhir Governance Layer",
    description="Automated compliance API for FHIR datasets (HIPAA/GDPR/DPDP).",
    version="1.0.0"
)

# --- DATA MODELS ---
class ContextModel(BaseModel):
    data_subject_country: str = "US"
    applicable_regulations: List[str] = ["HIPAA"]

class PolicyRequest(BaseModel):
    governing_regulation: str = "HIPAA"
    regulation_citation: str = "Unknown"
    context: ContextModel

class VerifyRequest(BaseModel):
    resource: Dict[str, Any]
    policy: PolicyRequest

class ComplianceResponse(BaseModel):
    status: str
    max_risk_score: float
    reason: str
    violations: List[Dict[str, Any]]

# --- ADAPTER (THE FIX) ---
class PolicyAdapter:
    """
    Wraps the Pydantic PolicyRequest to ensure legacy rules 
    can find attributes where they expect them.
    """
    def __init__(self, pydantic_policy: PolicyRequest):
        self.governing_regulation = pydantic_policy.governing_regulation
        self.regulation_citation = pydantic_policy.regulation_citation
        self.context = pydantic_policy.context
        
        # BRIDGE: Some legacy rules look for this at the top level
        self.applicable_regulations = pydantic_policy.context.applicable_regulations

# --- THE ENDPOINT ---
@app.post("/verify", response_model=ComplianceResponse)
def verify_resource(request: VerifyRequest):
    try:
        # 1. Adapt the Policy (Fixes the crash)
        adapted_policy = PolicyAdapter(request.policy)

        # 2. Run the Rules & ML
        # We pass the ADAPTER, not the raw Pydantic model
        raw_violations = run_deterministic_rules(adapted_policy, request.resource)
        
        # 3. Judge the Risk
        judge = DecisionEngine()
        decision = judge.decide(raw_violations)
        
        # 4. Explain the Results
        explanation = explain_violations(decision.violations)
        
        # 5. Return the Verdict
        return {
            "status": decision.status,
            "max_risk_score": decision.max_risk_score,
            "reason": decision.reason,
            "violations": [v.to_dict() for v in explanation]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Governance Engine Error: {str(e)}")

@app.get("/health")
def health():
    return {"status": "online", "modules": ["Rules", "ML", "Judge"]}