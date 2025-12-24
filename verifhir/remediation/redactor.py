import os
import logging
import datetime
import re
from typing import Dict, Any, Optional
from dotenv import load_dotenv
from openai import AzureOpenAI
from verifhir.remediation.fallback import RegexFallbackEngine

load_dotenv()

class RedactionEngine:
    """
    Optimized Clinical Redaction Engine.
    Uses clinical-context steering to avoid Azure AI Safety refusals.
    """
    PROMPT_VERSION = "v3.2-OPTIMIZED" 
    # Canary formatted as a real ID to trigger natural model redaction
    CANARY_TOKEN = "PII-REF-999-00-9999"

    def __init__(self):
        self.logger = logging.getLogger("verifhir.remediation")
        self.client = None
        self.api_key = os.getenv("AZURE_OPENAI_KEY")
        self.endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        self.deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
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
            except Exception as e:
                self.logger.error(f"Init Failed: {e}")

    def generate_suggestion(self, text: str, regulation: str, country: str = "US") -> Dict[str, Any]:
        if not text or not text.strip():
            return self._create_response(text, text, "No-Op", {})

        if self.client:
            try:
                start_time = datetime.datetime.now(datetime.timezone.utc)
                # Augmented text with canary to ensure compliance
                augmented_text = f"{text}\n\n[Clinical System ID: {self.CANARY_TOKEN}]"
                
                response = self.client.chat.completions.create(
                    model=self.deployment,
                    messages=[
                        {"role": "system", "content": self._build_system_instruction(regulation, country)},
                        # FEW-SHOT ANCHOR: Teaches the model to align tags perfectly
                        {"role": "user", "content": "Process: Jane Doe, +91 9876543210, 123 Maple St, NY 10001."},
                        {"role": "assistant", "content": "[REDACTED NAME], [REDACTED PHONE], [REDACTED ADDRESS]."},
                        {"role": "user", "content": f"Process: {augmented_text}"}
                    ],
                    temperature=0.0
                )
                
                raw_suggestion = response.choices[0].message.content.strip()

                # --- VALIDATION GATEWAY ---
                if self.CANARY_TOKEN in raw_suggestion:
                    return self._execute_fallback(text, "Compliance Check Failed")

                if re.search(r"(i am sorry|as an ai|policy violation)", raw_suggestion, re.I):
                    return self._execute_fallback(text, "Safety Filter Refusal")

                # Remove conversational noise and the system ID line
                clean_suggestion = re.sub(r"^(here is|processed|redacted|text):.*?\n", "", raw_suggestion, flags=re.I | re.M).strip()
                clean_suggestion = re.sub(r"\[Clinical System ID:.*\]", "", clean_suggestion).strip()

                return self._create_response(text, clean_suggestion, f"Azure OpenAI ({self.deployment})", {"time": start_time.isoformat()})

            except Exception as e:
                return self._execute_fallback(text, f"AI Error: {str(e)}")
        
        return self._execute_fallback(text, "Service Offline")

    def _execute_fallback(self, text: str, reason: str) -> Dict[str, Any]:
        safe_text, rules = self.fallback_engine.redact(text)
        return self._create_response(text, safe_text, "Regex Fallback", {"reason": reason, "rules": rules})

    def _build_system_instruction(self, regulation: str, country: str) -> str:
        return (
            f"You are a clinical assistant for {regulation} ({country}) compliance. "
            "Your task is to identify and replace all PII (names, international phones, addresses, emails) "
            "with standardized [REDACTED <TYPE>] tags. "
            "Provide the processed text immediately without introductory remarks."
        )

    def _create_response(self, original, suggestion, method, audit):
        return {"original_text": original, "suggested_redaction": suggestion, "remediation_method": method, "audit_metadata": audit}