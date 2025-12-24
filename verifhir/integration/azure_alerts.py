import os
import logging
import requests
import json
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger("verifhir.integration")

def trigger_high_risk_alert(decision_data: Dict[str, Any], resource_id: str = "Unknown"):
    """
    Sends a payload to Azure Logic Apps (or Power Automate) 
    when a Critical/Major violation is detected.
    """
    webhook_url = os.getenv("AZURE_LOGIC_APP_URL")
    
    # Fail-safe: If no URL is configured, just log it.
    if not webhook_url:
        logger.warning("Alert triggered but AZURE_LOGIC_APP_URL is not set.")
        return

    # Construct the Enterprise Alert Payload
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "alert_level": "HIGH_RISK",
        "resource_id": resource_id,
        "governance_engine": "VeriFHIR v1.0",
        "status": decision_data.get("status"),
        "risk_score": decision_data.get("max_risk_score"),
        "primary_violation": decision_data.get("reason"),
        # We limit the detail sent to Teams to avoid leaking PHI in the alert itself
        "violation_count": len(decision_data.get("violations", []))
    }

    try:
        # Fire and forget (with timeout to prevent hanging)
        response = requests.post(
            webhook_url, 
            json=payload, 
            timeout=2.0,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        logger.info(f"High Risk Alert sent to Cloud Orchestrator. Status: {response.status_code}")
        
    except requests.exceptions.RequestException as e:
        # We log the error but DO NOT raise it. 
        # Governance failure shouldn't stop the pipeline, just the commit.
        logger.error(f"Failed to trigger Cloud Alert: {e}")