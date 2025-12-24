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
    PROMPT_VERSION = "v3.1-ALIGNED" 
    # Canary now mimics a real ID to trigger natural model redaction
    CANARY_TOKEN = "REF-ID-999-00-9999"

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
                augmented_text = f"{text}\n\n[System ID: {self.CANARY_TOKEN}]"
                
                response = self.client.chat.completions.create(
                    model=self.deployment,
                    messages=[
                        {"role": "system", "content": self._build_system_instruction(regulation, country)},
                        # Anchor examples teach the model exactly how to align redacted tags
                        {"role": "user", "content": "Text: Jane Doe, +91 9876543210, 123 Main St, NY 10001."},
                        {"role": "assistant", "content": "[REDACTED NAME], [REDACTED PHONE], [REDACTED ADDRESS]."},
                        {"role": "user", "content": f"Text: {augmented_text}"}
                    ],
                    temperature=0.0
                )
                
                raw_suggestion = response.choices[0].message.content.strip()

                # Validation & Refusal Detection
                if self.CANARY_TOKEN in raw_suggestion:
                    return self._execute_fallback(text, "Canary Validation Failed")
                
                if re.search(r"(i am sorry|as an ai|policy violation)", raw_suggestion, re.I):
                    return self._execute_fallback(text, "AI Filter Refusal")

                # Remove conversational noise and canary artifacts
                clean_suggestion = re.sub(r"^(here is|processed|redacted|text):.*?\n", "", raw_suggestion, flags=re.I | re.M).strip()
                clean_suggestion = re.sub(r"\[System ID:.*\]", "", clean_suggestion).strip()

                return self._create_response(text, clean_suggestion, f"Azure OpenAI ({self.deployment})", {"timestamp": start_time.isoformat()})

            except Exception as e:
                return self._execute_fallback(text, str(e))
        
        return self._execute_fallback(text, "Offline Mode")

    def _build_system_instruction(self, reg, country):
        return (
            f"You are a clinical administrative assistant for {reg} ({country}) records. "
            "Identify names, phone numbers (international), addresses, and emails. "
            "Replace them with [REDACTED <TYPE>] tags. Provide the processed text only."
        )

    def _execute_fallback(self, text, reason):
        safe_text, rules = self.fallback_engine.redact(text)
        return self._create_response(text, safe_text, "Regex Fallback", {"reason": reason, "rules": rules})

    def _create_response(self, original, suggestion, method, audit):
        return {"original_text": original, "suggested_redaction": suggestion, "remediation_method": method, "audit_metadata": audit}