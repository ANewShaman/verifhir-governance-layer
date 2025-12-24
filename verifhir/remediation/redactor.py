import os
import logging
import datetime
import json
from typing import Dict, Any, Optional
from dotenv import load_dotenv
from openai import AzureOpenAI, APIError

# --- DAY 23 UPGRADES ---
from opencensus.ext.azure.log_exporter import AzureLogHandler
from verifhir.remediation.fallback import RegexFallbackEngine

load_dotenv()

class RedactionEngine:
    """
    ASSISTIVE COMPLIANCE MODULE (Hybrid AI + Regex).
    """
    PROMPT_VERSION = "v1.0-2025" 

    def __init__(self):
        self.logger = logging.getLogger("verifhir.remediation")
        self.logger.setLevel(logging.INFO)
        
        # 1. TELEMETRY SETUP (Azure App Insights)
        # If connection string exists, logs go to Cloud Dashboard. If not, console only.
        app_insights_conn = os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING")
        if app_insights_conn:
            self.logger.addHandler(AzureLogHandler(connection_string=app_insights_conn))
            self.telemetry_enabled = True
        else:
            self.telemetry_enabled = False

        # 2. CLIENT SETUP
        self.client: Optional[AzureOpenAI] = None
        self.api_key = os.getenv("AZURE_OPENAI_KEY")
        self.endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        self.deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        
        # 3. FALLBACK ENGINE (The Safety Net)
        self.fallback_engine = RegexFallbackEngine()

        self._initialize_client()

    def _initialize_client(self):
        if self.api_key and self.endpoint:
            try:
                self.client = AzureOpenAI(
                    api_key=self.api_key,
                    api_version="2024-02-15-preview",
                    azure_endpoint=self.endpoint
                )
                self.logger.info("RedactionEngine online. Mode: Hybrid (AI + Regex Fallback).")
            except Exception as e:
                self.logger.error(f"Init Failed: {e}. Degrading to REGEX ONLY mode.")
        else:
            self.logger.warning("No Credentials. Degrading to REGEX ONLY mode.")

    def generate_suggestion(self, text: str, regulation: str, country: str = "US") -> Dict[str, Any]:
        """
        Tries AI first. If it fails, falls back to Regex.
        """
        # Safety: Empty check
        if not text or not text.strip():
            return self._create_response(text, text, "No-Op", {})

        # 1. AI PATH
        if self.client:
            try:
                start_time = datetime.datetime.now(datetime.timezone.utc)
                
                # --- TELEMETRY: Log Attempt ---
                # We log custom properties so you can graph "AI vs Fallback" later
                extra_props = {"custom_dimensions": {"method": "AI", "regulation": regulation}}
                
                response = self.client.chat.completions.create(
                    model=self.deployment,
                    messages=[
                        {"role": "system", "content": self._build_system_instruction(regulation, country)},
                        {"role": "user", "content": f"INPUT TEXT:\n{text}"}
                    ],
                    temperature=0.0,
                    max_tokens=1000
                )
                suggestion = response.choices[0].message.content.strip()
                
                self.logger.info(f"AI Redaction Success", extra=extra_props)

                return self._create_response(
                    original=text,
                    suggestion=suggestion,
                    method=f"Azure OpenAI ({self.deployment})",
                    audit_info={"timestamp": start_time.isoformat(), "source": "AI"}
                )

            except Exception as e:
                # 2. FAILURE TRIGGER
                self.logger.error(f"AI Failure: {e}. Triggering Fallback.", extra={"custom_dimensions": {"error": str(e)}})
                return self._execute_fallback(text, reason=str(e))
        
        # 3. OFFLINE PATH
        return self._execute_fallback(text, reason="Service Offline")

    def _execute_fallback(self, text: str, reason: str) -> Dict[str, Any]:
        """
        Day 23: The logic that runs when the brain dies.
        """
        # Run the Regex Engine
        safe_text, rules_applied = self.fallback_engine.redact(text)
        
        # --- TELEMETRY: Log Fallback ---
        self.logger.warning(
            f"Fallback Executed", 
            extra={"custom_dimensions": {"method": "Fallback", "rules": str(rules_applied)}}
        )

        return self._create_response(
            original=text,
            suggestion=safe_text,
            method="Regex Safety Net",
            audit_info={
                "note": "AI Unavailable - Reverted to Strict Rules",
                "failure_reason": reason,
                "rules_applied": rules_applied
            }
        )

    def _build_system_instruction(self, regulation: str, country: str) -> str:
        # (Keep your existing prompt logic from Day 22 here)
        # For brevity in this snippet, I am abbreviating, but KEEP YOUR LOGIC.
        return f"You are a Compliance Bot. Enforce {regulation}."

    def _create_response(self, original: str, suggestion: str, method: str, audit_info: Dict) -> Dict[str, Any]:
        return {
            "original_text": original,
            "suggested_redaction": suggestion,
            "remediation_method": method,
            "is_authoritative": False,
            "audit_metadata": audit_info
        }