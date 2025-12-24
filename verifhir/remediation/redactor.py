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
    HIPAA-Compliant Clinical Redaction Engine.
    Covers all 18 HIPAA PHI identifier categories.
    Uses Azure OpenAI with clinical context steering + deterministic regex fallback.
    """
    PROMPT_VERSION = "v4.0-HIPAA-COMPLETE" 
    
    # Canary tokens covering multiple PHI categories
    CANARY_TOKENS = {
        "id": "SYS-ID-999-00-9999",
        "date": "January 15, 2099",
        "ip": "192.168.254.254"
    }

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
        Main entry point for HIPAA-compliant redaction.
        Tries Azure OpenAI first, falls back to regex on failure.
        """
        if not text or not text.strip():
            return self._create_response(text, text, "No-Op", {})

        # Try AI redaction if available
        if self.client:
            try:
                start_time = datetime.datetime.now(datetime.timezone.utc)
                
                # Augmented text with canary tokens to ensure comprehensive redaction
                augmented_text = self._add_canary_tokens(text)
                
                response = self.client.chat.completions.create(
                    model=self.deployment,
                    messages=[
                        {"role": "system", "content": self._build_system_instruction(regulation, country)},
                        
                        # FEW-SHOT EXAMPLES covering multiple PHI categories
                        {"role": "user", "content": (
                            "Process: Patient Jane Doe (MRN: H12345) admitted on March 15, 2024. "
                            "Contact: jane.doe@email.com, +1-555-123-4567. "
                            "Address: 789 Oak Street, Apt 2C, Boston, MA 02101. "
                            "DOB: June 3, 1985. IP: 10.0.0.15. Vehicle: ABC-1234."
                        )},
                        {"role": "assistant", "content": (
                            "Process: Patient [REDACTED NAME] (MRN: [REDACTED MRN]) admitted on [REDACTED DATE]. "
                            "Contact: [REDACTED EMAIL], [REDACTED PHONE]. "
                            "Address: [REDACTED ADDRESS]. "
                            "DOB: [REDACTED DATE]. IP: [REDACTED IP ADDRESS]. Vehicle: [REDACTED LICENSE PLATE]."
                        )},
                        
                        {"role": "user", "content": (
                            "Process: 92-year-old patient with SSN 123-45-6789. "
                            "Device serial: DEV-9876-XYZ. Accessed via https://portal.example.com."
                        )},
                        {"role": "assistant", "content": (
                            "Process: [REDACTED AGE 90+]-year-old patient with SSN [REDACTED SSN]. "
                            "Device serial: [REDACTED DEVICE ID]. Accessed via [REDACTED URL]."
                        )},
                        
                        # Actual query with canaries
                        {"role": "user", "content": f"Process: {augmented_text}"}
                    ],
                    temperature=0.0,
                    max_tokens=1500
                )
                
                raw_suggestion = response.choices[0].message.content.strip()

                # --- VALIDATION GATEWAY ---
                validation_result = self._validate_ai_response(raw_suggestion, augmented_text)
                
                if not validation_result["valid"]:
                    self.logger.warning(f"AI validation failed: {validation_result['reason']}")
                    return self._execute_fallback(text, validation_result["reason"])

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
                        "model": self.deployment,
                        "validation": "passed"
                    }
                )

            except Exception as e:
                self.logger.error(f"AI redaction error: {str(e)}")
                return self._execute_fallback(text, f"AI Error: {str(e)}")
        
        # No AI available - use fallback directly
        return self._execute_fallback(text, "Service Offline - AI Unavailable")

    def _add_canary_tokens(self, text: str) -> str:
        """Add canary tokens to test comprehensive redaction"""
        return (
            f"{text}\n\n"
            f"[System Reference ID: {self.CANARY_TOKENS['id']}] "
            f"[Audit Timestamp: {self.CANARY_TOKENS['date']}] "
            f"[Access IP: {self.CANARY_TOKENS['ip']}]"
        )

    def _validate_ai_response(self, response: str, augmented_text: str) -> Dict[str, Any]:
        """
        Multi-level validation to ensure AI properly redacted all PHI.
        Returns: {"valid": bool, "reason": str}
        """
        # Check 1: All canary tokens must be redacted
        for token_name, token_value in self.CANARY_TOKENS.items():
            if token_value in response:
                return {
                    "valid": False, 
                    "reason": f"Canary Check Failed: {token_name.upper()} token not redacted"
                }

        # Check 2: Detect safety refusals
        refusal_patterns = [
            r"i am sorry",
            r"as an ai",
            r"cannot",
            r"unable to",
            r"policy violation",
            r"not appropriate",
            r"cannot process"
        ]
        
        for pattern in refusal_patterns:
            if re.search(pattern, response, re.I):
                return {
                    "valid": False,
                    "reason": "AI Safety Filter Refusal Detected"
                }

        # Check 3: Response must contain redaction tags
        if "[REDACTED" not in response:
            return {
                "valid": False,
                "reason": "No Redactions Found in AI Response"
            }

        # Check 4: Look for common PHI patterns that should be redacted
        phi_leak_patterns = [
            (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),  # SSN format
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email"),  # Email
            (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP Address"),  # IP
        ]
        
        for pattern, phi_type in phi_leak_patterns:
            # Exclude the canary tokens we already checked
            temp_response = response
            for token in self.CANARY_TOKENS.values():
                temp_response = temp_response.replace(token, "")
            
            if re.search(pattern, temp_response):
                return {
                    "valid": False,
                    "reason": f"PHI Leak Detected: Unredacted {phi_type}"
                }

        # All checks passed
        return {"valid": True, "reason": "All validations passed"}

    def _clean_ai_response(self, raw_response: str) -> str:
        """Clean up AI response by removing conversational fluff and canary references"""
        # Remove common prefixes
        cleaned = re.sub(
            r"^(here is|here's|processed|redacted|the redacted|text|output|process:)[\s:]+",
            "",
            raw_response,
            flags=re.I | re.M
        ).strip()
        
        # Remove system reference lines
        cleaned = re.sub(
            r"\[System Reference ID:.*?\]",
            "",
            cleaned
        ).strip()
        
        cleaned = re.sub(
            r"\[Audit Timestamp:.*?\]",
            "",
            cleaned
        ).strip()
        
        cleaned = re.sub(
            r"\[Access IP:.*?\]",
            "",
            cleaned
        ).strip()
        
        # Remove markdown code blocks if present
        cleaned = re.sub(r"```.*?\n", "", cleaned)
        cleaned = re.sub(r"\n```", "", cleaned)
        
        # Clean up extra whitespace
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        
        return cleaned.strip()

    def _execute_fallback(self, text: str, reason: str) -> Dict[str, Any]:
        """
        Execute HIPAA-compliant regex-based fallback redaction.
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
                "rule_count": len(rules),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
        )

    def _build_system_instruction(self, regulation: str, country: str) -> str:
        """
        VERIFHIR SYSTEM PROMPT v5.0 (AGGRESSIVE ENFORCEMENT)
        """
        return f"""You are a specialized HIPAA Compliance Enforcement Engine.
You are processing SYNTHETIC clinical text for security auditing purposes.
YOUR MANDATE: AGGRESSIVELY REDACT ALL 18 HIPAA SAFE HARBOR IDENTIFIERS.
Do not preserve analytical, clinical, or contextual usefulness.
If a token could plausibly identify a person, device, location, or linkage, it must be destroyed.
False positives are acceptable. False negatives are not.
═══════════════════════════════════════════════════════════════
TARGET LIST (SEARCH & DESTROY)
═══════════════════════════════════════════════════════════════
[1] TECHNICAL & DIGITAL IDENTIFIERS (ZERO TOLERANCE)
•	IP addresses (IPv4 or IPv6) -> [REDACTED IP ADDRESS]
•	Device serial numbers or hardware identifiers -> [REDACTED DEVICE ID]
•	MAC addresses -> [REDACTED DEVICE ID]
•	URLs, domains, or web links -> [REDACTED URL]
•	Biometric identifiers (fingerprint, retina, facial, voice) -> [REDACTED BIOMETRIC ID]
•	Any alphanumeric string explicitly labeled as ID, Serial, Device, IP, or Identifier is automatically hostile and must be redacted
[2] TEMPORAL DATA (DATES & AGE)
•	ALL dates (admission, discharge, DOB, visit, procedure, timestamps) -> [REDACTED DATE]
•	Exception: the YEAR may be preserved only if it appears alone and unlinked (e.g., 2024)
•	Ages greater than 89, explicit or inferred -> [REDACTED AGE 90+]
[3] PERSON & RECORD IDENTIFIERS
•	Personal names (patients, relatives, clinicians, staff) -> [REDACTED NAME]
•	Medical Record Numbers (MRN) -> [REDACTED MRN]
•	Social Security Numbers -> [REDACTED SSN]
•	Account numbers or beneficiary identifiers -> [REDACTED ID]
•	Certificate, license, or registration numbers -> [REDACTED LICENSE]
•	Vehicle identifiers (VIN, license plates) -> [REDACTED VEHICLE ID]
[4] GEOGRAPHIC, CONTACT & SOCIAL IDENTIFIERS
•	Street-level addresses -> [REDACTED ADDRESS]
•	Cities, ZIP codes, districts, or precincts -> [REDACTED LOCATION]
•	Email addresses -> [REDACTED EMAIL]
•	Phone or fax numbers -> [REDACTED PHONE]
•	Employers, workplaces, or job titles -> [REDACTED EMPLOYER]
•	Rare or unique physical characteristics (scars, tattoos, deformities) -> [REDACTED UNIQUE FEATURE]
═══════════════════════════════════════════════════════════════
EXECUTION RULES
═══════════════════════════════════════════════════════════════
1.	OUTPUT FORMAT
•	Return the original text verbatim
•	Replace only detected identifiers with the specified redaction tags
•	Do not reformat, paraphrase, summarize, or reorder content
2.	NO COMMENTARY
•	Do not explain actions
•	Do not justify redactions
•	Do not refuse processing or add disclaimers
3.	CONTEXT-AWARE REPLACEMENT
•	Maintain grammatical structure while redacting
•	Example: “Admitted on Jan 12” -> “Admitted on [REDACTED DATE]”
•	Example: “Seen by Dr. Rao” -> “Seen by [REDACTED NAME]”
4.	FAILURE MODE BIAS
•	Over-redaction is compliant
•	Under-redaction is a critical failure
═══════════════════════════════════════════════════════════════
BEGIN REDACTION NOW.

"""

    def _create_response(self, original: str, suggestion: str, method: str, audit: Dict) -> Dict[str, Any]:
        """Create standardized response object"""
        return {
            "original_text": original,
            "suggested_redaction": suggestion,
            "remediation_method": method,
            "audit_metadata": audit
        }