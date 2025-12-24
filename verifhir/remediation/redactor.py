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
    Falls back to enhanced regex when AI fails canary check or refuses.
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
                self.logger.info("Azure OpenAI client initialized successfully")
            except Exception as e:
                self.logger.error(f"Azure OpenAI Init Failed: {e}")

    def generate_suggestion(self, text: str, regulation: str, country: str = "US") -> Dict[str, Any]:
        """
        Main entry point for redaction suggestions.
        Tries Azure OpenAI first, falls back to regex on failure.
        """
        if not text or not text.strip():
            return self._create_response(text, text, "No-Op", {})

        # Try AI redaction if available
        if self.client:
            try:
                start_time = datetime.datetime.now(datetime.timezone.utc)
                
                # Augmented text with canary to ensure compliance
                augmented_text = f"{text}\n\n[Clinical System ID: {self.CANARY_TOKEN}]"
                
                response = self.client.chat.completions.create(
                    model=self.deployment,
                    messages=[
                        {"role": "system", "content": self._build_system_instruction(regulation, country)},
                        # FEW-SHOT EXAMPLES: Teaches the model proper redaction format
                        {"role": "user", "content": "Process: Jane Doe, +91 9876543210, 123 Maple St, NY 10001."},
                        {"role": "assistant", "content": "[REDACTED NAME], [REDACTED PHONE], [REDACTED ADDRESS]."},
                        {"role": "user", "content": "Process: Patient John Smith (SSN: 123-45-6789) contacted at john.smith@email.com"},
                        {"role": "assistant", "content": "Patient [REDACTED NAME] (SSN: [REDACTED SSN]) contacted at [REDACTED EMAIL]"},
                        {"role": "user", "content": f"Process: {augmented_text}"}
                    ],
                    temperature=0.0,
                    max_tokens=1000
                )
                
                raw_suggestion = response.choices[0].message.content.strip()

                # --- VALIDATION GATEWAY ---
                
                # Check 1: Canary must be redacted
                if self.CANARY_TOKEN in raw_suggestion:
                    self.logger.warning("Canary check failed - token not redacted")
                    return self._execute_fallback(text, "Compliance Check Failed: Canary Exposed")

                # Check 2: Detect safety refusals
                if re.search(r"(i am sorry|as an ai|cannot|policy violation|unable to)", raw_suggestion, re.I):
                    self.logger.warning("AI safety filter triggered")
                    return self._execute_fallback(text, "Safety Filter Refusal")

                # Check 3: Response must contain redaction tags
                if "[REDACTED" not in raw_suggestion:
                    self.logger.warning("No redactions found in AI response")
                    return self._execute_fallback(text, "No Redactions Detected")

                # Clean up the response
                clean_suggestion = self._clean_ai_response(raw_suggestion)

                elapsed = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds()
                
                return self._create_response(
                    text, 
                    clean_suggestion, 
                    f"Azure OpenAI ({self.deployment})", 
                    {
                        "timestamp": start_time.isoformat(),
                        "elapsed_seconds": round(elapsed, 3),
                        "model": self.deployment
                    }
                )

            except Exception as e:
                self.logger.error(f"AI redaction error: {str(e)}")
                return self._execute_fallback(text, f"AI Error: {str(e)}")
        
        # No AI available - use fallback directly
        return self._execute_fallback(text, "Service Offline - AI Unavailable")

    def _clean_ai_response(self, raw_response: str) -> str:
        """Clean up AI response by removing conversational fluff"""
        # Remove common prefixes
        cleaned = re.sub(
            r"^(here is|here's|processed|redacted|the redacted|text|output)[\s:]+",
            "",
            raw_response,
            flags=re.I | re.M
        ).strip()
        
        # Remove the clinical system ID line
        cleaned = re.sub(
            r"\[Clinical System ID:.*?\]",
            "",
            cleaned
        ).strip()
        
        # Remove markdown code blocks if present
        cleaned = re.sub(r"```.*?\n", "", cleaned)
        cleaned = re.sub(r"\n```", "", cleaned)
        
        return cleaned

    def _execute_fallback(self, text: str, reason: str) -> Dict[str, Any]:
        """
        Execute regex-based fallback redaction.
        This is called when AI fails or is unavailable.
        """
        self.logger.info(f"Executing regex fallback: {reason}")
        
        safe_text, rules = self.fallback_engine.redact(text)
        
        return self._create_response(
            text, 
            safe_text, 
            "Regex Fallback Engine", 
            {
                "reason": reason,
                "rules_applied": rules,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
        )

    def _build_system_instruction(self, regulation: str, country: str) -> str:
        """Build the system prompt for AI redaction"""
        return (
            f"You are a clinical data protection assistant for {regulation} ({country}) compliance.\n\n"
            "TASK: Identify and replace ALL personally identifiable information (PII) with standardized tags.\n\n"
            "PII INCLUDES:\n"
            "- Person names → [REDACTED NAME]\n"
            "- Phone numbers (all formats) → [REDACTED PHONE]\n"
            "- Physical addresses → [REDACTED ADDRESS]\n"
            "- Email addresses → [REDACTED EMAIL]\n"
            "- SSN/identification numbers → [REDACTED SSN]\n"
            "- Postal/ZIP codes → [REDACTED ZIP]\n\n"
            "CRITICAL RULES:\n"
            "1. Redact ALL PII without exception\n"
            "2. Use ONLY the exact tag format shown above\n"
            "3. Return ONLY the processed text, no explanations\n"
            "4. Never skip any identifiers, even system IDs\n\n"
            "Process the following text now:"
        )

    def _create_response(self, original: str, suggestion: str, method: str, audit: Dict) -> Dict[str, Any]:
        """Create standardized response object"""
        return {
            "original_text": original,
            "suggested_redaction": suggestion,
            "remediation_method": method,
            "audit_metadata": audit
        }