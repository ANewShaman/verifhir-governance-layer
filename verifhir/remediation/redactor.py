import os
import logging
import datetime
import re
from typing import Dict, Any, Optional
from dotenv import load_dotenv
from openai import AzureOpenAI
from verifhir.remediation.fallback import RegexFallbackEngine
from verifhir.remediation import patterns as shared_patterns

TEMPORAL_TIER_BLOCK = """
TEMPORAL HANDLING POLICY (MANDATORY — NO EXCEPTIONS)

CORE PRINCIPLE:
Temporal information MUST be handled based on IDENTIFICATION RISK, not format, granularity, or mere presence.
Dates are NOT inherently identifying. Context determines risk.

ALL temporal references MUST be classified into EXACTLY ONE tier BEFORE any redaction, deletion, or transformation occurs.

────────────────────────────────────────────────────────
TIER 1 — DIRECT IDENTIFIERS (ALWAYS REDACT)

Definition:
Temporal elements that directly identify, uniquely track,
or anchor an individual patient or encounter.

IMPORTANT SCOPE RULE:
Tier 1 applies ONLY to dates directly tied to the patient,
not relatives or family history.

Includes:
• Date of birth (DOB)
• Admission date
• Discharge date
• Exact death date of the patient
• Any date explicitly labeling a patient visit, admission, discharge, or encounter


────────────────────────────────────────────────────────
TIER 2 — HISTORICAL CONTEXT (YEAR-ONLY RETENTION)
────────────────────────────────────────────────────────
Definition:
Past events that provide medical, familial, or background context and do NOT enable unique patient identification.

EXCLUSION RULE:
If a historical date refers to a unique patient encounter
(e.g., hospitalization, admission, inpatient stay),
it MUST be treated as Tier 1 unless the event is explicitly
scoped to a family member or relative.

Includes:
• Diagnosis years
• Family history events (e.g., parental death years)
• Past surgeries or procedures when not tied to a specific encounter
• Historical events unrelated to direct patient tracking

Required Action:
→ PRESERVE YEAR ONLY
→ REMOVE month and day components if present

Permitted Outputs:
• “Diagnosed in 1998”
• “Underwent surgery in 2007”

────────────────────────────────────────────────────────
TIER 3 — CLINICAL TIMELINE (PRESERVE OR CONVERT)
────────────────────────────────────────────────────────
Definition:
Temporal information required to understand treatment sequence
or monitoring cadence that does NOT uniquely identify the patient.

Required Action:
→ If conversion is required, express time RELATIVE TO THE ENCOUNTER DATE.

MANDATORY FORM:
• “X days prior to admission”
• “X weeks prior to admission”
• “X months prior to admission”
• “X days after admission” (if applicable)

DO NOT:
• Reference the current date
• Use vague phrases (“recently”, “some time ago”)
• Guess durations

If no encounter date is available:
→ Use a coarse phrase (“prior to the encounter”) without numbers.
Approved Relative Conversions:
• “3 months ago”
• “several years prior”

────────────────────────────────────────────────────────
NON-HIPAA REGULATION SUPPLEMENT (GDPR, UK_GDPR, LGPD, DPDP, BASE)
────────────────────────────────────────────────────────
For regulations other than HIPAA:
• If a date refers to a historical event (Tier 2) or general medical history (Tier 3),
  do NOT redact the year.
• Preserve the year where appropriate OR convert to a relative duration
  (e.g., “3 years ago”, “5 years prior”).
• Only fully redact dates if they fall under Tier 1
  (Admission date, DOB, Discharge date, or equivalent direct identifiers).

────────────────────────────────────────────────────────
STRICT PROHIBITIONS (ABSOLUTE)
────────────────────────────────────────────────────────
The following outputs are FORBIDDEN under ALL circumstances:

• “Started on [REDACTED DATE]”
• “Diagnosed in [REDACTED DATE]”
• Complete deletion of temporal information without replacement
• Treating all dates as Tier 1 by default

────────────────────────────────────────────────────────
CLASSIFICATION FAILURE RULE (NON-NEGOTIABLE)
────────────────────────────────────────────────────────
If tier classification is UNCERTAIN, AMBIGUOUS, or CONTEXT-INCOMPLETE:

• DO NOT delete the temporal reference
• DO NOT fully redact the temporal reference
• DEFAULT to Tier 3 behavior

Required Fallback Action:
→ CONVERT to a relative, non-identifying temporal expression

This failure-handling rule applies uniformly across ALL regulations and enforcement layers.
"""


load_dotenv()

class RedactionEngine:
    """
    Multi-Regulation Clinical Redaction Engine.
    Supports: HIPAA, GDPR, UK_GDPR, LGPD, DPDP, BASE
    Uses Azure OpenAI with regulation-specific prompts + deterministic regex fallback.
    """
    PROMPT_VERSION = "v5.0-MULTI-REGULATION" 
    
    # Canary tokens covering multiple PHI/PII categories
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

    def _store_regulation_context(self, regulation: str, country: str):
        """Store regulation context for validation checks"""
        self.regulation = regulation
        self.country = country
        # Also update fallback engine's regulation
        if hasattr(self.fallback_engine, 'regulation'):
            self.fallback_engine.regulation = regulation



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
        Main entry point for multi-regulation redaction.
        Tries Azure OpenAI first, falls back to regex on failure.
        
        Args:
            text: Input text to redact
            regulation: One of HIPAA, GDPR, UK_GDPR, LGPD, DPDP, BASE
            country: ISO country code (used for context)
        """
        if not text or not text.strip():
            return self._create_response(text, text, "No-Op", {"regulation": regulation})

        # Validate regulation
        valid_regulations = ["HIPAA", "GDPR", "UK_GDPR", "LGPD", "DPDP", "BASE"]
        if regulation not in valid_regulations:
            self.logger.warning(f"Unknown regulation '{regulation}', defaulting to BASE")
            regulation = "BASE"

        # ADD THIS LINE HERE:
        self._store_regulation_context(regulation, country)

        # Try AI redaction if available
        if self.client:
            try:
                start_time = datetime.datetime.now(datetime.timezone.utc)
                
                # Augmented text with canary tokens
                augmented_text = self._add_canary_tokens(text)
                
                response = self.client.chat.completions.create(
                    model=self.deployment,
                    messages=[
                        {"role": "system", "content": self._build_system_instruction(regulation, country)},
                        
                        # Few-shot examples
                        *self._get_few_shot_examples(regulation),
                        
                        # Actual query with canaries
                        {"role": "user", "content": f"Process: {augmented_text}"}
                    ],
                    temperature=0.0,
                    max_tokens=1500
                )
                
                raw_suggestion = response.choices[0].message.content.strip()

                # Validation gateway
                validation_result = self._validate_ai_response(raw_suggestion, augmented_text)
                
                if not validation_result["valid"]:
                    self.logger.warning(f"AI validation failed: {validation_result['reason']}")
                    return self._execute_fallback(text, validation_result["reason"], regulation, country)

                # Clean up the response
                clean_suggestion = self._clean_ai_response(raw_suggestion)
                # HIPAA: enforce deterministic temporal safety
                if regulation == "HIPAA" and self._hipaa_temporal_violation(clean_suggestion):
                    self.logger.warning("HIPAA temporal violation detected in AI output — falling back")
                    return self._execute_fallback(
                        text,
                        "HIPAA temporal violation in AI output",
                        regulation,
                        country
                    )
                elapsed = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds()
                
                return self._create_response(
                    text, 
                    clean_suggestion, 
                    f"Azure OpenAI ({self.deployment}) - {regulation}", 
                    {
                        "timestamp": start_time.isoformat(),
                        "elapsed_seconds": round(elapsed, 3),
                        "model": self.deployment,
                        "regulation": regulation,
                        "validation": "passed"
                    }
                )

            except Exception as e:
                self.logger.error(f"AI redaction error: {str(e)}")
                return self._execute_fallback(text, f"AI Error: {str(e)}", regulation, country)
        
        # No AI available - use fallback directly
        return self._execute_fallback(text, "Service Offline - AI Unavailable", regulation, country)

    def _add_canary_tokens(self, text: str) -> str:
        """Add canary tokens to test comprehensive redaction"""
        return (
            f"{text}\n\n"
            f"[System Reference ID: {self.CANARY_TOKENS['id']}] "
            f"[Audit Timestamp: {self.CANARY_TOKENS['date']}] "
            f"[Access IP: {self.CANARY_TOKENS['ip']}]"
        )

    def _get_few_shot_examples(self, regulation: str) -> list:
        """Return regulation-specific few-shot examples"""
        
        # Universal examples that work across all regulations
        universal_examples = [
            {"role": "user", "content": (
                "Process: Patient Jane Doe (ID: H12345) admitted on March 15, 2024. "
                "Contact: jane.doe@email.com, +1-555-123-4567. "
                "Address: 789 Oak Street, Apt 2C, Boston, MA 02101. "
                "DOB: June 3, 1985. IP: 10.0.0.15."
            )},
            {"role": "assistant", "content": (
                "Process: Patient [REDACTED NAME] (ID: [REDACTED ID]) admitted on [REDACTED DATE]. "
                "Contact: [REDACTED EMAIL], [REDACTED PHONE]. "
                "Address: [REDACTED ADDRESS]. "
                "DOB: [REDACTED DATE]. IP: [REDACTED IP ADDRESS]."
            )},
        ]
        
        # Regulation-specific examples
        if regulation == "GDPR":
            universal_examples.extend([
                {"role": "user", "content": (
                    "Process: Employee data - Name: Hans Mueller, National ID: DE-1234567890, "
                    "Cookie ID: abc-def-123, Geolocation: 52.5200°N 13.4050°E"
                )},
                {"role": "assistant", "content": (
                    "Process: Employee data - Name: [REDACTED NAME], National ID: [REDACTED ID], "
                    "Cookie ID: [REDACTED ID], Geolocation: [REDACTED LOCATION]"
                )},
            ])
        elif regulation == "LGPD":
            universal_examples.extend([
                {"role": "user", "content": (
                    "Process: Cliente: Maria Silva, CPF: 123.456.789-00, "
                    "Endereço: Rua das Flores 100, São Paulo, CEP: 01310-100"
                )},
                {"role": "assistant", "content": (
                    "Process: Cliente: [REDACTED NAME], CPF: [REDACTED ID], "
                    "Endereço: [REDACTED ADDRESS], CEP: [REDACTED ZIP]"
                )},
            ])
        
        return universal_examples

    def _apply_country_overrides(self, country: str):
        """
        Apply simple jurisdiction-specific behavior by overlaying shared patterns
        or adjusting conservative enforcement. This keeps fallback >= AI strictness
        by enabling country-specific ID patterns where available.
        """
        try:
            # Example: overlay Indian Aadhaar stricter behavior when country == IN
            if country and country.upper() == "IN":
                if "INDIAN_AADHAAR" in shared_patterns.PATTERNS:
                    self.fallback_engine._PATTERNS["INDIAN_AADHAAR"] = shared_patterns.PATTERNS["INDIAN_AADHAAR"]
            # Additional country-specific overlays can be added here
        except Exception:
            self.logger.debug("Country overrides unavailable or failed")

    def _validate_ai_response(self, response: str, augmented_text: str) -> Dict[str, Any]:
        """
        Multi-level validation to ensure AI properly redacted all PII/PHI.
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

        # Check 3: Response must contain redaction tags (positive allowlist)
        if "[REDACTED" not in response:
            return {
                "valid": False,
                "reason": "No Redactions Found in AI Response"
            }

        # Check 4: Look for common PII patterns that should be redacted
        pii_leak_patterns = [
            (r"\b\d{3}-\d{2}-\d{4}\b", "SSN/National ID"),
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email"),
            (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP Address"),
        ]
        
        for pattern, pii_type in pii_leak_patterns:
            temp_response = response
            for token in self.CANARY_TOKENS.values():
                temp_response = temp_response.replace(token, "")
            
            if re.search(pattern, temp_response):
                return {
                    "valid": False,
                    "reason": f"PII Leak Detected: Unredacted {pii_type}"
                }
            

        # Check 5: DPDP-specific validation for Indian PII
        if hasattr(self, 'regulation') and self.regulation == "DPDP":
        # Check for unredacted Aadhaar numbers (12 digits with optional spaces/dashes)
            if re.search(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", response):
                return {
                    "valid": False,
                    "reason": "DPDP Violation: Unredacted Aadhaar number detected"
                }       
    
            # Check for Indian PIN codes (6 digits)
            if re.search(r"\b\d{6}\b", response):
                # Allow if it's part of a redaction tag, otherwise fail
                if not re.search(r"\[REDACTED[^\]]*\d{6}", response):
                    return {
                        "valid": False,
                        "reason": "DPDP Violation: Unredacted PIN code detected"
                    }
    
            # Check for common Indian address patterns
            indian_address_patterns = [
                r"\bFlat\s+(?:No\.?\s*)?\d+",
                r"\bPlot\s+(?:No\.?\s*)?\d+",
                r"\bApartment",
                r"\b\d+(?:st|nd|rd|th)?\s+(?:Cross|Main|Road|Street|Avenue)",
                r"\b(?:MG|Brigade|Residency|Layout|Nagar|Halli|Pally)\s+Road",
            ]
    
            for pattern in indian_address_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    return {
                        "valid": False,
                        "reason": f"DPDP Violation: Unredacted address component detected ({pattern})"
                    }
    
            # Check for common Indian names (multi-word capitalized patterns)
            # Only flag if NOT already inside a redaction tag
            name_pattern = r"\b(?<!REDACTED\s)([A-Z][a-z]{2,})\s+([A-Z][a-z]{2,})\b"
            matches = re.finditer(name_pattern, response)
            for match in matches:
                # Skip if it's a known safe term
                full_match = match.group(0)
                if full_match not in ["Doctor Patient", "Medical Record", "Health Data"]:
                    return {
                        "valid": False,
                        "reason": f"DPDP Violation: Potential unredacted name detected: {full_match}"
                    }
    



        return {"valid": True, "reason": "All validations passed"}

    def _hipaa_temporal_violation(self, text: str) -> bool:
        """
        HIPAA Safe Harbor:
        Any full date (month/day) related to an individual is forbidden.
        """
        # ISO dates
        if re.search(r"\b\d{4}-\d{2}-\d{2}\b", text):
            return True

        # Numeric dates
        if re.search(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b", text):
            return True

        # Month name dates
        if re.search(
            r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec|"
            r"January|February|March|April|May|June|July|August|September|"
            r"October|November|December)\s+\d{1,2},?\s+\d{4}\b",
            text,
            re.I
        ):
            return True

        return False
            

    def _clean_ai_response(self, raw_response: str) -> str:
        """Clean up AI response by removing conversational fluff and canary references"""
        cleaned = re.sub(
            r"^(here is|here's|processed|redacted|the redacted|text|output|process:)[\s:]+",
            "",
            raw_response,
            flags=re.I | re.M
        ).strip()
        
        # Remove system reference lines
        cleaned = re.sub(r"\[System Reference ID:.*?\]", "", cleaned).strip()
        cleaned = re.sub(r"\[Audit Timestamp:.*?\]", "", cleaned).strip()
        cleaned = re.sub(r"\[Access IP:.*?\]", "", cleaned).strip()
        
        # Remove markdown code blocks
        cleaned = re.sub(r"```.*?\n", "", cleaned)
        cleaned = re.sub(r"\n```", "", cleaned)
        
        # Clean up extra whitespace
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        
        return cleaned.strip()

    def _create_response(
        self, 
        original_text: str, 
        suggested_redaction: str, 
        remediation_method: str, 
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a standardized response dictionary for redaction results.
        """
        is_authoritative = "Azure OpenAI" in remediation_method or "OpenAI" in remediation_method
        
        audit_metadata = metadata.copy()
        if "regulation" in audit_metadata:
            audit_metadata["regulation_context"] = audit_metadata["regulation"]
        elif "rules_applied" in audit_metadata:
            audit_metadata["regulation_context"] = "BASE"
        
        return {
            "original_text": original_text,
            "suggested_redaction": suggested_redaction,
            "remediation_method": remediation_method,
            "is_authoritative": is_authoritative,
            "audit_metadata": audit_metadata
        }

    def _execute_fallback(self, text: str, reason: str, regulation: str = "BASE", country: str = "US") -> Dict[str, Any]:
        """Execute regex-based fallback redaction."""
        self.logger.info(f"Executing regex fallback: {reason} (reg={regulation} country={country})")

        # Create regulation-specific fallback engine
        fallback_engine = RegexFallbackEngine()
        fallback_engine.regulation = regulation

        # If DPDP and the input is JSON text, prefer structured traversal (do NOT rely on str(resource)).
        structured_input = None
        if regulation == "DPDP" and isinstance(text, str):
            try:
                import json as _json
                parsed = _json.loads(text)
                # Only use parsed structure if it's a dict or list
                if isinstance(parsed, (dict, list)):
                    structured_input = parsed
            except Exception:
                structured_input = None

        if structured_input is not None:
            safe_text, rules = fallback_engine.redact(structured_input)
        else:
            safe_text, rules = fallback_engine.redact(text)

        for token_name, token_value in self.CANARY_TOKENS.items():
            if token_value in str(safe_text):
                self.logger.warning(f"Fallback did not remove canary token {token_name}; applying explicit redaction")
                safe_text = str(safe_text).replace(token_value, f"[REDACTED {token_name.upper()}]")
                if f"{token_name.upper()}" not in rules:
                    rules.append(f"CANARY_{token_name.upper()}")

        if regulation == "HIPAA" and self._hipaa_temporal_violation(str(safe_text)):
            self.logger.warning("HIPAA temporal violation detected in fallback output — applying extra redaction of dates")
            safe_text = re.sub(r"\b\d{4}-\d{2}-\d{2}\b", "[REDACTED DATE]", str(safe_text))
            safe_text = re.sub(r"\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b", "[REDACTED DATE]", str(safe_text))
            safe_text = re.sub(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b", "[REDACTED DATE]", str(safe_text), flags=re.I)
            if "DATE" not in rules:
                rules.append("DATE")

        meta = {
            "reason": reason,
            "rules_applied": sorted(rules),
            "rule_count": len(rules),
            "regulation": regulation,
            "country": country,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        return self._create_response(text, safe_text, "Regex Fallback Engine", meta)

    def _build_system_instruction(self, regulation: str, country: str) -> str:
        """
        Build regulation-specific system prompts.
        Each prompt enforces aggressive redaction for the target regulation.
        """
        
        # ============================================================
        # HIPAA (United States - Health Insurance Portability and Accountability Act)
        # ============================================================
        if regulation == "HIPAA":
            return f"""You are a HIPAA Safe Harbor Enforcement Engine.
You are processing SYNTHETIC clinical data for privacy auditing purposes.
YOUR MANDATE: AGGRESSIVELY REDACT ALL 18 HIPAA IDENTIFIERS.

IMPORTANT CLARIFICATION:
Temporal data MUST follow the Tier-Based Temporal Handling Policy below.
Do NOT treat all dates as direct identifiers.
Redaction of dates is permitted ONLY after tier classification.

────────────────────────────────────────────────────────
TEMPORAL HANDLING POLICY (MANDATORY)
────────────────────────────────────────────────────────
{TEMPORAL_TIER_BLOCK}

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
Temporal handling is governed exclusively by the Tier-Based Temporal Handling Policy above.

[3] MEDICAL IDENTIFIERS
•	Medical Record Numbers (MRN) -> [REDACTED MRN]
•	Health Plan Beneficiary Numbers -> [REDACTED HEALTH PLAN ID]
•	Account Numbers -> [REDACTED ACCOUNT NUMBER]
•	Certificate/License Numbers -> [REDACTED LICENSE NUMBER]
•	Device Identifiers/Serial Numbers -> [REDACTED DEVICE ID]
•	Biometric Identifiers (fingerprints, voice prints) -> [REDACTED BIOMETRIC ID]
•	Full-face photos and comparable images -> [REDACTED IMAGE]

IMPORTANT CLARIFICATION:
Do NOT redact common symptoms, diagnoses, or clinical observations 
(e.g., breathlessness, anemia, headache, hypertension, diabetes) 
unless they are associated with a rare disease that could identify the patient.

IMPORTANT LOCATION CLARIFICATION FOR GDPR/LGPD/DPDP:
Do NOT redact common City or State names for GDPR, LGPD, or DPDP unless they are uniquely identifying or appear together with other direct identifiers (e.g., full street address, ZIP/PIN). Keep city/state tokens to preserve clinical utility.
Only redact unique medical device IDs, record numbers, biopsy codes, 
or other direct identifiers listed above.

[4] PERSON & RECORD IDENTIFIERS
•	Personal names (patients, relatives, clinicians, staff) -> [REDACTED NAME]
•	Social Security Numbers -> [REDACTED SSN]
•	Account numbers or beneficiary identifiers -> [REDACTED ID]
•	Certificate, license, or registration numbers -> [REDACTED LICENSE]
•	Vehicle identifiers (VIN, license plates) -> [REDACTED VEHICLE ID]

[5] GEOGRAPHIC, CONTACT & SOCIAL IDENTIFIERS
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
•	Example: "Admitted on Jan 12" -> "Admitted on [REDACTED DATE]"
•	Example: "Seen by Dr. Rao" -> "Seen by [REDACTED NAME]"
4.	FAILURE MODE BIAS:
    For HIPAA: Default to full redaction if uncertain.
    For GDPR, UK_GDPR, LGPD, and DPDP: Default to TIER 3 (Relative/Generalization) if uncertain.
    If a year (e.g., 2024) is detected and is NOT a Date of Birth, preserve the year to maintain clinical utility unless the regulation is HIPAA.
═══════════════════════════════════════════════════════════════
BEGIN REDACTION NOW.
"""

        # ============================================================
        # GDPR (European Union - General Data Protection Regulation)
        # ============================================================
        elif regulation == "GDPR":
            return f"""You are a specialized GDPR Compliance Enforcement Engine.
You are processing SYNTHETIC personal data for privacy auditing purposes.
YOUR MANDATE: AGGRESSIVELY REDACT ALL GDPR ARTICLE 4(1) PERSONAL DATA IDENTIFIERS.
Jurisdiction: {country} (European Union)
If a token could directly or indirectly identify a natural person, it must be destroyed.
This includes identifiers, location data, online identifiers, and factors specific to identity.
False positives are acceptable. False negatives are not.

IMPORTANT CLARIFICATION:
Temporal data MUST follow the Tier-Based Temporal Handling Policy below.
Do NOT treat all dates as direct identifiers.
Redaction of dates is permitted ONLY after tier classification.

────────────────────────────────────────────────────────
TEMPORAL HANDLING POLICY (MANDATORY)
────────────────────────────────────────────────────────
{TEMPORAL_TIER_BLOCK}

═══════════════════════════════════════════════════════════════
TARGET LIST (SEARCH & DESTROY)
═══════════════════════════════════════════════════════════════
[1] DIRECT IDENTIFIERS
•	Full names (first, middle, last, maiden) -> [REDACTED NAME]
•	National ID numbers (passport, tax ID, social security equivalents) -> [REDACTED ID]
•	Email addresses -> [REDACTED EMAIL]
•	Phone numbers (mobile, landline, fax) -> [REDACTED PHONE]
•	Postal addresses (street, city, postal code) -> [REDACTED ADDRESS]
•	Financial identifiers (IBAN, credit card, account numbers) -> [REDACTED FINANCIAL ID]

[2] ONLINE & DIGITAL IDENTIFIERS
•	IP addresses (IPv4, IPv6) -> [REDACTED IP ADDRESS]
•	Cookie IDs, session tokens, device fingerprints -> [REDACTED TRACKING ID]
•	MAC addresses, IMEI, device serial numbers -> [REDACTED DEVICE ID]
•	URLs containing personal parameters or tracking -> [REDACTED URL]
•	Social media handles, usernames, profile links -> [REDACTED USERNAME]

[3] LOCATION DATA
•	GPS coordinates, geolocation data -> [REDACTED LOCATION]
•	Precise addresses (street-level) -> [REDACTED ADDRESS]
•	City + postal code combinations -> [REDACTED LOCATION]
•	Travel routes, mobility patterns -> [REDACTED LOCATION]

[4] TEMPORAL & CONTEXTUAL DATA
Temporal handling is governed exclusively by the Tier-Based Temporal Handling Policy above.

[5] SPECIAL CATEGORY DATA (Article 9)
•	Health data (diagnoses, treatments, medical records) -> [REDACTED HEALTH DATA]
•	Biometric data (fingerprints, facial recognition, DNA) -> [REDACTED BIOMETRIC ID]
•	Genetic data -> [REDACTED GENETIC DATA]
•	Racial/ethnic origin -> [REDACTED SENSITIVE DATA]
•	Political opinions, religious beliefs, philosophical beliefs -> [REDACTED SENSITIVE DATA]
•	Trade union membership -> [REDACTED SENSITIVE DATA]
•	Sexual orientation or behavior -> [REDACTED SENSITIVE DATA]

IMPORTANT CLARIFICATION:
Do NOT redact common symptoms, diagnoses, or clinical observations 
(e.g., breathlessness, anemia, headache, hypertension, diabetes) 
unless they are associated with a rare disease that could identify the patient.

[6] INDIRECT IDENTIFIERS (Risk of Re-identification)
•	Employment details (employer name, job title, department) -> [REDACTED EMPLOYER]
•	Educational institution names -> [REDACTED INSTITUTION]
•	Vehicle registration, license plates -> [REDACTED VEHICLE ID]
•	Rare physical characteristics or unique attributes -> [REDACTED UNIQUE FEATURE]
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
•	Example: "Born on 15/03/1985" -> "Born on [REDACTED DATE]"
•	Example: "Lives at 123 Main St" -> "Lives at [REDACTED ADDRESS]"
4.	FAILURE MODE BIAS:
    For GDPR, UK_GDPR, LGPD, and DPDP: Default to TIER 3 (Relative/Generalization) if uncertain.
    If a year (e.g., 2024) is detected and is NOT a Date of Birth, preserve the year to maintain clinical utility unless the regulation is HIPAA.
═══════════════════════════════════════════════════════════════
BEGIN REDACTION NOW.
"""

        # ============================================================
        # UK GDPR (United Kingdom)
        # ============================================================
        elif regulation == "UK_GDPR":
            return f"""You are a specialized UK GDPR Compliance Enforcement Engine.
You are processing SYNTHETIC personal data for privacy auditing purposes.
YOUR MANDATE: AGGRESSIVELY REDACT ALL UK GDPR PERSONAL DATA IDENTIFIERS.
Jurisdiction: United Kingdom (post-Brexit GDPR implementation)
If a token could directly or indirectly identify a natural person, it must be destroyed.
This includes identifiers, location data, online identifiers, and factors specific to identity.
False positives are acceptable. False negatives are not.

IMPORTANT CLARIFICATION:
Temporal data MUST follow the Tier-Based Temporal Handling Policy below.
Do NOT treat all dates as direct identifiers.
Redaction of dates is permitted ONLY after tier classification.

────────────────────────────────────────────────────────
TEMPORAL HANDLING POLICY (MANDATORY)
────────────────────────────────────────────────────────
{TEMPORAL_TIER_BLOCK}

═══════════════════════════════════════════════════════════════
TARGET LIST (SEARCH & DESTROY)
═══════════════════════════════════════════════════════════════
[1] DIRECT IDENTIFIERS
•	Full names (first, middle, last, maiden) -> [REDACTED NAME]
•	National Insurance Number (NI number) -> [REDACTED NI NUMBER]
•	NHS Number -> [REDACTED NHS NUMBER]
•	Passport numbers, driver's license numbers -> [REDACTED ID]
•	Email addresses -> [REDACTED EMAIL]
•	Phone numbers (mobile, landline, fax) -> [REDACTED PHONE]
•	Postal addresses (street, city, postcode) -> [REDACTED ADDRESS]
•	Financial identifiers (sort code, account number, card numbers) -> [REDACTED FINANCIAL ID]

[2] ONLINE & DIGITAL IDENTIFIERS
•	IP addresses (IPv4, IPv6) -> [REDACTED IP ADDRESS]
•	Cookie IDs, session tokens, device fingerprints -> [REDACTED TRACKING ID]
•	MAC addresses, IMEI, device serial numbers -> [REDACTED DEVICE ID]
•	URLs containing personal parameters or tracking -> [REDACTED URL]
•	Social media handles, usernames, profile links -> [REDACTED USERNAME]

[3] LOCATION DATA
•	GPS coordinates, geolocation data -> [REDACTED LOCATION]
•	Precise addresses (street-level) -> [REDACTED ADDRESS]
•	City + postcode combinations -> [REDACTED LOCATION]
•	Travel routes, mobility patterns -> [REDACTED LOCATION]

[4] TEMPORAL & CONTEXTUAL DATA
Temporal handling is governed exclusively by the Tier-Based Temporal Handling Policy above.

[5] SPECIAL CATEGORY DATA (Article 9 / Schedule 1 Part 1)
•	Health data (diagnoses, treatments, medical records) -> [REDACTED HEALTH DATA]
•	Biometric data (fingerprints, facial recognition, DNA) -> [REDACTED BIOMETRIC ID]
•	Genetic data -> [REDACTED GENETIC DATA]
•	Racial/ethnic origin -> [REDACTED SENSITIVE DATA]
•	Political opinions, religious beliefs, philosophical beliefs -> [REDACTED SENSITIVE DATA]
•	Trade union membership -> [REDACTED SENSITIVE DATA]
•	Sexual orientation or behavior -> [REDACTED SENSITIVE DATA]

IMPORTANT CLARIFICATION:
Do NOT redact common symptoms, diagnoses, or clinical observations 
(e.g., breathlessness, anemia, headache, hypertension, diabetes) 
unless they are associated with a rare disease that could identify the patient.

[6] INDIRECT IDENTIFIERS (Risk of Re-identification)
•	Employment details (employer name, job title, department) -> [REDACTED EMPLOYER]
•	Educational institution names -> [REDACTED INSTITUTION]
•	Vehicle registration, license plates -> [REDACTED VEHICLE ID]
•	Rare physical characteristics or unique attributes -> [REDACTED UNIQUE FEATURE]
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
•	Example: "DOB: 15/03/1985" -> "DOB: [REDACTED DATE]"
•	Example: "NI Number: AB123456C" -> "NI Number: [REDACTED NI NUMBER]"
4.	FAILURE MODE BIAS:
    For GDPR, UK_GDPR, LGPD, and DPDP: Default to TIER 3 (Relative/Generalization) if uncertain.
    If a year (e.g., 2024) is detected and is NOT a Date of Birth, preserve the year to maintain clinical utility unless the regulation is HIPAA.
═══════════════════════════════════════════════════════════════
BEGIN REDACTION NOW.
"""

        # ============================================================
        # LGPD (Brazil)
        # ============================================================
        elif regulation == "LGPD":
            return f"""Você é um Motor de Aplicação de Conformidade LGPD especializado.
Você está processando dados pessoais SINTÉTICOS para fins de auditoria de privacidade.
SUA MISSÃO: REDIGIR AGRESSIVAMENTE TODOS OS IDENTIFICADORES DE DADOS PESSOAIS LGPD (Art. 5º, I).
Jurisdição: Brasil (Lei nº 13.709/2018)
Se um token pode identificar direta ou indiretamente uma pessoa natural, ele deve ser destruído.
Isso inclui identificadores, dados de localização, identificadores online e fatores específicos de identidade.
Falsos positivos são aceitáveis. Falsos negativos não são.

IMPORTANTE:
Dados temporais DEVEM seguir a Política de Classificação Temporal por Camadas abaixo.
Datas NÃO são identificadores por padrão.
A redação de datas só é permitida após classificação por risco.

────────────────────────────────────────────────────────
POLÍTICA DE TRATAMENTO TEMPORAL (OBRIGATÓRIA)
────────────────────────────────────────────────────────
{TEMPORAL_TIER_BLOCK}
═══════════════════════════════════════════════════════════════
LISTA DE ALVOS (BUSCAR E DESTRUIR)
═══════════════════════════════════════════════════════════════
[1] IDENTIFICADORES DIRETOS
•	Nomes completos (primeiro, do meio, sobrenome) -> [REDACTED NAME]
•	CPF (Cadastro de Pessoas Físicas) -> [REDACTED CPF]
•	RG (Registro Geral), CNH (Carteira Nacional de Habilitação) -> [REDACTED ID]
•	Passaporte -> [REDACTED ID]
•	Endereços de email -> [REDACTED EMAIL]
•	Telefones (celular, fixo, fax) -> [REDACTED PHONE]
•	Endereços postais (rua, cidade, CEP) -> [REDACTED ADDRESS]
•	Identificadores financeiros (conta bancária, cartão de crédito) -> [REDACTED FINANCIAL ID]

[2] IDENTIFICADORES ONLINE E DIGITAIS
•	Endereços IP (IPv4, IPv6) -> [REDACTED IP ADDRESS]
•	IDs de cookies, tokens de sessão, impressões digitais de dispositivos -> [REDACTED TRACKING ID]
•	Endereços MAC, IMEI, números de série de dispositivos -> [REDACTED DEVICE ID]
•	URLs contendo parâmetros pessoais ou rastreamento -> [REDACTED URL]
•	Perfis de redes sociais, nomes de usuário, links de perfil -> [REDACTED USERNAME]

[3] DADOS DE LOCALIZAÇÃO
•	Coordenadas GPS, dados de geolocalização -> [REDACTED LOCATION]
•	Endereços precisos (nível de rua) -> [REDACTED ADDRESS]
•	Combinações de cidade + CEP -> [REDACTED LOCATION]
•	Rotas de viagem, padrões de mobilidade -> [REDACTED LOCATION]

[4] DADOS TEMPORAIS E CONTEXTUAIS
O tratamento temporal é regido exclusivamente pela Política de Classificação Temporal acima.

[5] DADOS SENSÍVEIS (Art. 5º, II)
•	Dados de saúde (diagnósticos, tratamentos, registros médicos) -> [REDACTED HEALTH DATA]
•	Dados biométricos (impressões digitais, reconhecimento facial, DNA) -> [REDACTED BIOMETRIC ID]
•	Dados genéticos -> [REDACTED GENETIC DATA]
•	Origem racial ou étnica -> [REDACTED SENSITIVE DATA]
•	Convicção religiosa -> [REDACTED SENSITIVE DATA]
•	Opinião política -> [REDACTED SENSITIVE DATA]
•	Filiação a sindicato ou organização religiosa -> [REDACTED SENSITIVE DATA]
•	Dados referentes à saúde ou vida sexual -> [REDACTED SENSITIVE DATA]

IMPORTANTE:
Não redija sintomas, diagnósticos ou observações clínicas comuns 
(ex.: dispneia/breathlessness, anemia, cefaleia, hipertensão, diabetes) 
a menos que estejam associados a uma doença rara que possa identificar o paciente.

IMPORTANTE - LOCALIZAÇÃO:
Não redija nomes comuns de cidade ou estado para LGPD a menos que sejam exclusivamente identificadores ou estejam associados a outros identificadores diretos (por exemplo, endereço completo, CEP). Preserve tokens de cidade/estado para manter a utilidade clínica.

[6] IDENTIFICADORES INDIRETOS (Risco de Reidentificação)
•	Detalhes de emprego (nome do empregador, cargo, departamento) -> [REDACTED EMPLOYER]
•	Nomes de instituições educacionais -> [REDACTED INSTITUTION]
•	Registro de veículo, placas de licença -> [REDACTED VEHICLE ID]
•	Características físicas raras ou atributos únicos -> [REDACTED UNIQUE FEATURE]
═══════════════════════════════════════════════════════════════
REGRAS DE EXECUÇÃO
═══════════════════════════════════════════════════════════════
1.	FORMATO DE SAÍDA
•	Retorne o texto original literalmente
•	Substitua apenas identificadores detectados pelas tags de redação especificadas
•	Não reformate, parafraseie, resuma ou reordene o conteúdo
2.	SEM COMENTÁRIOS
•	Não explique ações
•	Não justifique redações
•	Não recuse processamento ou adicione isenções de responsabilidade
3.	SUBSTITUIÇÃO CONSCIENTE DO CONTEXTO
•	Mantenha a estrutura gramatical ao redigir
•	Exemplo: "Nascido em 15/03/1985" -> "Nascido em [REDACTED DATE]"
•	Exemplo: "Mora em Rua das Flores 100" -> "Mora em [REDACTED ADDRESS]"
4.	VIÉS DE MODO DE FALHA
•	A super-redação está em conformidade com a minimização de dados LGPD (Art. 6º, III)
•	A sub-redação é uma violação crítica da LGPD
═══════════════════════════════════════════════════════════════
COMECE A REDAÇÃO AGORA.
"""

        # ============================================================
        # DPDP (India)
        # ============================================================
        elif regulation == "DPDP":
            return f"""You are a specialized DPDP Compliance Enforcement Engine.
You are processing SYNTHETIC personal data for privacy auditing purposes.
YOUR MANDATE: AGGRESSIVELY REDACT ALL DPDP ACT 2023 PERSONAL DATA IDENTIFIERS.
Jurisdiction: India (Digital Personal Data Protection Act, 2023)
If a token could directly or indirectly identify a Data Principal (individual), it must be destroyed.
This includes identifiers, location data, online identifiers, and factors specific to identity.
False positives are acceptable. False negatives are not.

IMPORTANT CLARIFICATION:
Temporal data MUST follow the Tier-Based Temporal Handling Policy below.
Do NOT treat all dates as direct identifiers.
Redaction of dates is permitted ONLY after tier classification.

────────────────────────────────────────────────────────────────
TEMPORAL HANDLING POLICY (MANDATORY)
────────────────────────────────────────────────────────────────
{TEMPORAL_TIER_BLOCK}

═══════════════════════════════════════════════════════════════
TARGET LIST (SEARCH & DESTROY)
═══════════════════════════════════════════════════════════════
[1] DIRECT IDENTIFIERS (ZERO TOLERANCE)
• Full names (first, middle, last) -> [REDACTED NAME]
• Aadhaar number (12-digit unique ID) -> [REDACTED AADHAAR]
• PAN (Permanent Account Number) -> [REDACTED PAN]
• Voter ID, Passport number, Driving License -> [REDACTED ID]
• Email addresses -> [REDACTED EMAIL]
• Phone numbers (mobile, landline) -> [REDACTED PHONE]
• Postal addresses (street, city, PIN code) -> [REDACTED ADDRESS]
• Financial identifiers (bank account, UPI ID, card numbers) -> [REDACTED FINANCIAL ID]

CRITICAL ADDRESS HANDLING RULE:
• ANY address containing street numbers, apartment numbers, flat numbers, plot numbers, 
  building names, or street names MUST be redacted as [REDACTED ADDRESS]
• This includes: "Flat No. 101, Sunshine Apartments", "Plot 45, 2nd Cross", 
  "789 MG Road", "Indiranagar", etc.
• Only preserve STATE-LEVEL or NATIONAL-LEVEL geographic context if needed for 
  clinical utility (e.g., "Karnataka" or "India" may be preserved)
• City names combined with ANY other address element MUST be fully redacted
• PIN codes MUST ALWAYS be redacted as [REDACTED PIN]

CRITICAL NAME HANDLING RULE:
• ALL personal names must be redacted, including common Indian names
• This includes: "Rajesh Kumar", "Amit Sharma", "Maria Silva", etc.
• Do NOT make exceptions for "common" names - all names are identifiers

[2] ONLINE & DIGITAL IDENTIFIERS
• IP addresses (IPv4, IPv6) -> [REDACTED IP ADDRESS]
• Cookie IDs, session tokens, device fingerprints -> [REDACTED TRACKING ID]
• MAC addresses, IMEI, device serial numbers -> [REDACTED DEVICE ID]
• URLs containing personal parameters or tracking -> [REDACTED URL]
• Social media handles, usernames, profile links -> [REDACTED USERNAME]

[3] LOCATION DATA
• GPS coordinates, geolocation data -> [REDACTED LOCATION]
• Precise addresses (street-level) -> [REDACTED ADDRESS]
• City + PIN code combinations -> [REDACTED LOCATION]
• Travel routes, mobility patterns -> [REDACTED LOCATION]
• Street names, road names, locality names -> [REDACTED ADDRESS]
• Building names, apartment names, complex names -> [REDACTED ADDRESS]

[4] TEMPORAL & CONTEXTUAL DATA
Temporal handling is governed exclusively by the Tier-Based Temporal Handling Policy above.

[5] SENSITIVE PERSONAL DATA (Section 2(g))
• Health data (diagnoses, treatments, medical records) -> [REDACTED HEALTH DATA]
• Biometric data (fingerprints, facial recognition, iris scans) -> [REDACTED BIOMETRIC ID]
• Genetic data -> [REDACTED GENETIC DATA]
• Caste or tribe information -> [REDACTED SENSITIVE DATA]
• Religious or political beliefs -> [REDACTED SENSITIVE DATA]
• Sexual orientation -> [REDACTED SENSITIVE DATA]
• Financial data (account details, credit scores) -> [REDACTED FINANCIAL DATA]

IMPORTANT CLARIFICATION:
Do NOT redact common symptoms, diagnoses, or clinical observations 
(e.g., breathlessness, anemia, headache, hypertension, diabetes) 
unless they are associated with a rare disease that could identify the patient.

[6] INDIRECT IDENTIFIERS (Risk of Re-identification)
• Employment details (employer name, job title, department) -> [REDACTED EMPLOYER]
• Educational institution names -> [REDACTED INSTITUTION]
• Vehicle registration numbers -> [REDACTED VEHICLE ID]
• Unique physical characteristics or attributes -> [REDACTED UNIQUE FEATURE]

═══════════════════════════════════════════════════════════════
EXECUTION RULES
═══════════════════════════════════════════════════════════════
1. OUTPUT FORMAT
• Return the original text verbatim
• Replace only detected identifiers with the specified redaction tags
• Do not reformat, paraphrase, summarize, or reorder content

2. NO COMMENTARY
• Do not explain actions
• Do not justify redactions
• Do not refuse processing or add disclaimers

3. CONTEXT-AWARE REPLACEMENT
• Maintain grammatical structure while redacting
• Example: "Patient Name: Rajesh Kumar" -> "Patient Name: [REDACTED NAME]"
• Example: "Address: Flat No. 101, Sunshine Apartments, MG Road, Bangalore, Karnataka - 560001" 
  -> "Address: [REDACTED ADDRESS], Karnataka - [REDACTED PIN]"
• Example: "Aadhaar: 1234 5678 9012" -> "Aadhaar: [REDACTED AADHAAR]"

4. FAILURE MODE BIAS
• For DPDP: When uncertain about whether to redact, DEFAULT TO REDACTION
• If a token MIGHT be identifying, it MUST be redacted
• Preserve only state-level geographic context when clinically necessary
• For dates: Default to TIER 3 (Relative/Generalization) if uncertain
• If a year (e.g., 2024) is detected and is NOT a Date of Birth, 
  preserve the year to maintain clinical utility

═══════════════════════════════════════════════════════════════
BEGIN REDACTION NOW.
"""

        # ============================================================
        # BASE (Generic Privacy Baseline)
        # ============================================================
        elif regulation == "BASE":
            return f"""You are a Generic Privacy Enforcement Engine.
You are processing SYNTHETIC data for privacy-by-design auditing purposes.
YOUR MANDATE: AGGRESSIVELY REDACT ALL PERSONAL AND LINKABLE IDENTIFIERS.
This is a technology-neutral baseline covering universal privacy principles.
If a token could directly or indirectly identify an individual, organization, device, or location, it must be destroyed.
False positives are acceptable. False negatives are not.

IMPORTANT CLARIFICATION:
Temporal data MUST follow the Tier-Based Temporal Handling Policy below.
Do NOT treat all dates as direct identifiers.
Redaction of dates is permitted ONLY after tier classification.

────────────────────────────────────────────────────────
TEMPORAL HANDLING POLICY (MANDATORY)
────────────────────────────────────────────────────────
{TEMPORAL_TIER_BLOCK}

═══════════════════════════════════════════════════════════════
TARGET LIST (SEARCH & DESTROY)
═══════════════════════════════════════════════════════════════
[1] PERSONAL IDENTIFIERS
•	Names (full names, nicknames, aliases) -> [REDACTED NAME]
•	Government-issued IDs (any national ID, passport, tax ID) -> [REDACTED ID]
•	Email addresses -> [REDACTED EMAIL]
•	Phone numbers (any format) -> [REDACTED PHONE]
•	Postal addresses (street, city, postal/ZIP codes) -> [REDACTED ADDRESS]
•	Financial identifiers (account numbers, card numbers, payment IDs) -> [REDACTED FINANCIAL ID]

[2] DIGITAL IDENTIFIERS
•	IP addresses (IPv4, IPv6) -> [REDACTED IP ADDRESS]
•	Cookie IDs, session tokens, tracking pixels -> [REDACTED TRACKING ID]
•	Device identifiers (MAC, IMEI, serial numbers, UUIDs) -> [REDACTED DEVICE ID]
•	URLs containing personal or tracking data -> [REDACTED URL]
•	Usernames, handles, profile identifiers -> [REDACTED USERNAME]

[3] LOCATION & TEMPORAL DATA
Temporal handling is governed exclusively by the Tier-Based Temporal Handling Policy above.

[4] BIOMETRIC & HEALTH DATA
•	Biometric identifiers (fingerprints, facial data, retinal scans, voice prints) -> [REDACTED BIOMETRIC ID]
•	Health information (diagnoses, treatments, medical records) -> [REDACTED HEALTH DATA]
•	Genetic or DNA data -> [REDACTED GENETIC DATA]

IMPORTANT CLARIFICATION:
Do NOT redact common symptoms, diagnoses, or clinical observations 
(e.g., breathlessness, anemia, headache, hypertension, diabetes) 
unless they are associated with a rare disease that could identify the patient.

[5] ORGANIZATIONAL & CONTEXTUAL DATA
•	Employer names, workplace details -> [REDACTED EMPLOYER]
•	Educational institution names -> [REDACTED INSTITUTION]
•	Vehicle identifiers (license plates, VINs) -> [REDACTED VEHICLE ID]
•	Unique characteristics (rare features, distinctive marks) -> [REDACTED UNIQUE FEATURE]

[6] SENSITIVE ATTRIBUTES
•	Race, ethnicity, caste -> [REDACTED SENSITIVE DATA]
•	Religious, political, or philosophical beliefs -> [REDACTED SENSITIVE DATA]
•	Sexual orientation or gender identity -> [REDACTED SENSITIVE DATA]
•	Union membership or affiliations -> [REDACTED SENSITIVE DATA]
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
•	Example: "Born on Jan 12, 1990" -> "Born on [REDACTED DATE]"
•	Example: "Contact: alice@example.com" -> "Contact: [REDACTED EMAIL]"
4.	FAILURE MODE BIAS:
    For GDPR, UK_GDPR, LGPD, and DPDP: Default to TIER 3 (Relative/Generalization) if uncertain.
    If a year (e.g., 2024) is detected and is NOT a Date of Birth, preserve the year to maintain clinical utility unless the regulation is HIPAA.
═══════════════════════════════════════════════════════════════
BEGIN REDACTION NOW.
"""

        # Fallback for unknown regulations
        else:
            self.logger.warning(f"No prompt defined for regulation: {regulation}, using BASE")
            return self._build_system_instruction("BASE", country)