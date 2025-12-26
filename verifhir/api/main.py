import logging
import time
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

# --- IMPORT THE BRAIN ---
from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.decision.judge import DecisionEngine
from verifhir.explainability.mapper import explain_violations
# --- DAY 25 IMPORT: CLOUD ALERTING ---
from verifhir.integration.azure_alerts import trigger_high_risk_alert
# --- DAY 29 IMPORT: TELEMETRY ---
from verifhir.telemetry import init_telemetry, emit_decision_telemetry
# --- HL7 ADAPTER ---
from verifhir.adapters.hl7_adapter import normalize_input

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

# --- DAY 29: INITIALIZE TELEMETRY AT STARTUP ---
init_telemetry()

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
    input_format: str = "FHIR"  # "FHIR" | "HL7v2"

class ComplianceResponse(BaseModel):
    status: str
    max_risk_score: float
    reason: str
    violations: List[Dict[str, Any]]
    input_provenance: Optional[Dict[str, Any]] = None

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
        # Track start time for telemetry
        start_time = time.perf_counter()
        
        # 1. Normalize input (HL7 → FHIR if needed) - SINGLE INGRESS POINT
        # This is the ONLY place where HL7 is processed. After this, only FHIR exists.
        normalized = normalize_input(
            payload=request.resource,
            input_format=request.input_format,
        )
        fhir_bundle = normalized["bundle"]
        input_provenance = normalized["metadata"]  # Preserved for audit record attachment
        
        # 2. Adapt the Policy
        adapted_policy = PolicyAdapter(request.policy)

        # 3. Run the Rules & ML (on normalized FHIR only)
        # Governance logic NEVER sees HL7 - only normalized FHIR
        raw_violations = run_deterministic_rules(adapted_policy, fhir_bundle)
        
        # 4. Judge the Risk
        judge = DecisionEngine()
        decision = judge.decide(raw_violations)
        
        # Calculate latency for telemetry
        latency_ms = int((time.perf_counter() - start_time) * 1000)
        
        # Determine decision_path based on detection methods used
        detection_methods = {v.detection_method for v in raw_violations if v.detection_method}
        has_rules = any(
            method in ["rule-based", "DeterministicRule", "Rule"]
            for method in detection_methods
        )
        has_ml = any(
            method in ["ml-primary", "Presidio_Deterministic", "Presidio_Probabilistic", "azure_ai", "AzureAI-Pii"]
            for method in detection_methods
        )
        
        if has_rules and has_ml:
            decision_path = "hybrid"
        elif has_ml:
            decision_path = "ml-sensor"
        else:
            decision_path = "rules"
        
        # --- DAY 29: EMIT TELEMETRY ---
        emit_decision_telemetry(
            decision_latency_ms=latency_ms,
            risk_score=decision.max_risk_score,
            decision_path=decision_path,
            fallback_triggered=False,  # Fallback is not part of decision flow
        )
        
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
        
        # 5. Explain the Results
        explanation = explain_violations(decision.violations)
        
        # 6. Return the Verdict (input_provenance available for audit if needed)
        return {
            "status": decision.status,
            "max_risk_score": decision.max_risk_score,
            "reason": decision.reason,
            "violations": [v.to_dict() for v in explanation],
            "input_provenance": input_provenance  # For audit traceability
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