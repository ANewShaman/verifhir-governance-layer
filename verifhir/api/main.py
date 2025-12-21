import logging
import time
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

# --- IMPORT THE BRAIN ---
from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.decision.judge import DecisionEngine
from verifhir.explainability.mapper import explain_violations

# --- 1. SETUP AUDIT LOGGING (Option 2) ---
logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
audit_logger = logging.getLogger("audit")

# --- 2. VISUAL POLISH (Option 1) ---
tags_metadata = [
    {
        "name": "Verification",
        "description": "Core compliance logic. Submits data to the **Hybrid Engine** (Rules + ML) for risk scoring.",
    },
    {
        "name": "System",
        "description": "Health checks and operational metadata.",
    },
]

app = FastAPI(
    title="Verifhir Governance Engine",
    description="""
    **Enterprise Compliance Layer** for FHIR Datasets.
    
    This API automates risk scoring using a hybrid approach:
    * **Deterministic Rules:** 100% confidence checks for known patterns (e.g., regex).
    * **ML Inference:** Probabilistic detection for context-dependent PII (e.g., Names).
    * **Risk Decision:** A weighted scoring engine that issues `APPROVED`, `REJECTED`, or `NEEDS_REVIEW` verdicts.
    """,
    version="1.0.0",
    openapi_tags=tags_metadata,
    docs_url="/docs",
    redoc_url="/redoc"
)

# --- 3. MIDDLEWARE: THE AUDITOR ---
@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    start_time = time.time()
    
    # Process Request
    response = await call_next(request)
    
    # Calculate duration
    process_time = time.time() - start_time
    
    # Log to file (Audit Trail)
    audit_logger.info(
        f"METHOD={request.method} PATH={request.url.path} "
        f"STATUS={response.status_code} CLIENT={request.client.host} "
        f"DURATION={process_time:.4f}s"
    )
    
    return response

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

# --- ADAPTER (The Fix for Legacy Rules) ---
class PolicyAdapter:
    """
    Wraps the Pydantic PolicyRequest to ensure legacy rules 
    can find attributes where they expect them.
    """
    def __init__(self, pydantic_policy: PolicyRequest):
        self.governing_regulation = pydantic_policy.governing_regulation
        self.regulation_citation = pydantic_policy.regulation_citation
        self.context = pydantic_policy.context
        # BRIDGE: Flatten context attributes for legacy rules
        self.applicable_regulations = pydantic_policy.context.applicable_regulations

# --- ENDPOINTS ---

@app.post("/verify", response_model=ComplianceResponse, tags=["Verification"])
def verify_resource(request: VerifyRequest):
    """
    Submit a FHIR Resource for compliance verification.
    """
    try:
        # 1. Adapt the Policy
        adapted_policy = PolicyAdapter(request.policy)

        # 2. Run the Rules & ML
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
        audit_logger.error(f"ENGINE_ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Governance Engine Error: {str(e)}")

@app.get("/health", tags=["System"])
def health():
    """
    Operational heartbeat check.
    """
    return {"status": "online", "modules": ["Rules", "ML", "Judge", "AuditLog"]}