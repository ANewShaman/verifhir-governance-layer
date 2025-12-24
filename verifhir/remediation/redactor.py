import os
import logging
import datetime
from typing import Dict, Optional, Any
from openai import AzureOpenAI, APIError

# --- THE FIX: Load the .env file ---
from dotenv import load_dotenv
load_dotenv()  # This reads your .env file and sets the variables!
# -----------------------------------

class RedactionEngine:
    """
    ASSISTIVE COMPLIANCE MODULE: Redaction Suggestion Engine.
    """

    PROMPT_VERSION = "v1.0-2025" 

    def __init__(self):
        self.logger = logging.getLogger("verifhir.remediation")
        self.client: Optional[AzureOpenAI] = None
        
        # 1. Configuration & Safety Checks
        self.api_key = os.getenv("AZURE_OPENAI_KEY")
        self.endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        self.deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")

        # 2. Connection Initialization
        self._initialize_client()

    def _initialize_client(self):
        """Attempts to establish a secure connection to Azure OpenAI."""
        if self.api_key and self.endpoint:
            try:
                self.client = AzureOpenAI(
                    api_key=self.api_key,
                    api_version="2024-02-15-preview",
                    azure_endpoint=self.endpoint
                )
                self.logger.info("RedactionEngine online. Connected to Azure OpenAI.")
            except Exception as e:
                self.logger.error(f"Initialization Failed: {e}. Engine entering FAIL-SAFE mode.")
        else:
            self.logger.warning("Missing Azure credentials. Engine entering FAIL-SAFE mode (Mock).")

    def generate_suggestion(self, text: str, regulation: str, country: str = "US") -> Dict[str, Any]:
        """
        Generates a draft redaction for human review.
        """
        # Safety Check: Empty input
        if not text or not text.strip():
            return self._create_response(text, text, "No-Op (Empty Input)")

        # Fail-Safe: Offline Mode
        if not self.client:
            return self._mock_redaction_fallback(text, reason="Service Offline")

        try:
            # 3. Construct Governance-Aligned Prompt
            system_instruction = self._build_system_instruction(regulation, country)
            
            # 4. Execute AI Inference (Strict/Deterministic)
            start_time = datetime.datetime.now(datetime.timezone.utc)
            
            response = self.client.chat.completions.create(
                model=self.deployment,
                messages=[
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": f"INPUT TEXT:\n{text}"}
                ],
                temperature=0.0, # Zero creativity required for compliance
                max_tokens=1000, # Safety limit
                top_p=0.1
            )
            
            suggestion = response.choices[0].message.content.strip()
            
            self.logger.info(f"Generated suggestion for regulation={regulation} model={self.deployment}")

            return self._create_response(
                original=text,
                suggestion=suggestion,
                method=f"Azure OpenAI ({self.deployment})",
                audit_info={
                    "prompt_version": self.PROMPT_VERSION,
                    "timestamp": start_time.isoformat(),
                    "regulation_context": regulation
                }
            )

        except APIError as e:
            self.logger.error(f"Azure API Error: {e}. Reverting to fallback.")
            return self._mock_redaction_fallback(text, reason="Provider API Error")
        except Exception as e:
            self.logger.error(f"Unexpected Redaction Error: {e}. Reverting to fallback.")
            return self._mock_redaction_fallback(text, reason="Internal Error")

    def _build_system_instruction(self, regulation: str, country: str) -> str:
        """
        Constructs the 'System Prompt' with strict bounding instructions.
        """
        base_instruction = (
            "You are a Compliance Assistant. Your task is to redact PII (Personally Identifiable Information) "
            "from the provided text. You must act conservatively and efficiently."
        )

        if regulation == "HIPAA":
            return (
                f"{base_instruction}\n"
                "CONTEXT: HIPAA Privacy Rule (USA).\n"
                "INSTRUCTION: Redact all 18 identifiers defined by HIPAA (names, dates, locations smaller than state, IDs).\n"
                "FORMAT: Replace identifiers with '[REDACTED]'.\n"
                "CONSTRAINT: Do not summarize. Do not explain. Return ONLY the redacted text."
            )
        elif regulation == "GDPR":
            return (
                f"{base_instruction}\n"
                "CONTEXT: GDPR (EU), Subject Jurisdiction: {country}.\n"
                "INSTRUCTION: Apply Data Minimization. Redact direct identifiers (Name, SSN/ID).\n"
                "GUIDANCE: Pseudonymize where possible to preserve context (e.g., change 'John' to 'Patient A').\n"
                "CONSTRAINT: Do not summarize. Do not explain. Return ONLY the redacted text."
            )
        else:
            return (
                f"{base_instruction}\n"
                "INSTRUCTION: Remove all standard PII (Names, Emails, Phones, IDs).\n"
                "FORMAT: Replace with '[REDACTED]'.\n"
                "CONSTRAINT: Return ONLY the redacted text."
            )

    def _mock_redaction_fallback(self, text: str, reason: str) -> Dict[str, Any]:
        """
        Deterministic fallback when AI is unavailable.
        """
        self.logger.warning(f"Using Mock Redaction. Reason: {reason}")
        
        safe_text = text.replace("99999", "[REDACTED-ID]").replace("John Doe", "[REDACTED-NAME]")
        
        return self._create_response(
            original=text,
            suggestion=safe_text,
            method=f"Static Fallback ({reason})",
            audit_info={"note": "AI Unavailable - Manual Review Recommended"}
        )

    def _create_response(self, original: str, suggestion: str, method: str, audit_info: Optional[Dict] = None) -> Dict[str, Any]:
        """Standardizes the output format."""
        return {
            "original_text": original,
            "suggested_redaction": suggestion,
            "remediation_method": method,
            "is_authoritative": False, 
            "audit_metadata": audit_info or {}
        }