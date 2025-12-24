import logging
import time
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

# --- IMPORT THE BRAIN ---
from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.decision.judge import DecisionEngine
from verifhir.explainability.mapper import explain_violations
# --- DAY 25 IMPORT: CLOUD ALERTING ---
from verifhir.integration.azure_alerts import trigger_high_risk_alert

# --- 1. SETUP AUDIT LOGGING ---
logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
audit_logger = logging.getLogger("audit")

# --- 2. VISUAL POLISH (Swagger UI Metadata) ---
tags_metadata = [
    {
        "name": "Verification",
        "description": "Core logic. Submits data to the **Hybrid Engine** (Rules + ML).",
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
    
    Automated risk scoring using a hybrid approach:
    * **Deterministic Rules:** 100% confidence checks.
    * **Risk Decision:** Weighted scoring engine (Approved / Rejected / Needs Review).
    * **Cloud Orchestration:** Azure Logic App integration for high-risk alerts.
    """,
    version="1.1.0",
    openapi_tags=tags_metadata,
    docs_url="/docs",
    redoc_url="/redoc"
)

# --- 3. MIDDLEWARE: AUDIT TRAIL ---
@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    
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
    """Wraps Pydantic PolicyRequest for legacy rules."""
    def __init__(self, pydantic_policy: PolicyRequest):
        self.governing_regulation = pydantic_policy.governing_regulation
        self.regulation_citation = pydantic_policy.regulation_citation
        self.context = pydantic_policy.context
        # The Bridge that fixes the crash:
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
        
        # --- DAY 25 INTEGRATION: CLOUD ALERTING ---
        # If the verdict is REJECTED or NEEDS_REVIEW, fire the signal flare.
        if decision.status in ["REJECTED", "NEEDS_REVIEW"]:
            trigger_high_risk_alert(
                decision_data={
                    "status": decision.status,
                    "max_risk_score": decision.max_risk_score,
                    "reason": decision.reason,
                    "violations": decision.violations
                },
                resource_id=request.resource.get("id", "Unknown_ID")
            )
        # ------------------------------------------
        
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
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health", tags=["System"])
def health():
    return {
        "status": "online", 
        "modules": ["Rules", "ML", "Judge", "AuditLog", "CloudAlerts"]
    }