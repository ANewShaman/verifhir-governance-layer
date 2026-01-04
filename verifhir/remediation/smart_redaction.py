"""
Day 36 Part B: Smart Redaction Engine (AI-Assisted, Advisory)

This module provides context-aware redaction suggestions that preserve clinical utility
while ensuring HIPAA compliance. The output is advisory only and never auto-applies changes.

Key constraints:
- Advisory only — never auto-applies changes
- Must not replace existing deterministic redaction
- Output is a suggested remediation artifact
- Uses Azure OpenAI (same tenant/config as existing AI usage)
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv
from openai import AzureOpenAI

load_dotenv()

logger = logging.getLogger("verifhir.remediation.smart_redaction")


def suggest_smart_redaction(text: str, violations: List[Any], regulation: str) -> Dict[str, Any]:
    """
    Generates context-aware redactions that preserve clinical utility.
    
    This function uses Azure OpenAI to suggest redactions that:
    - Remove all direct identifiers
    - Generalize ages to ranges (e.g., 89 → late 80s)
    - Preserve temporal relationships (3 years → several years)
    - Maintain clinical context (family history, treatment flow)
    - Use [REDACTED <TYPE>] ONLY for direct identifiers (Tier 1).
    - Temporal data MUST follow tier rules:
      - Tier 1 → redact
      - Tier 2 → keep year only
      - Tier 3 → convert to relative time

    
    Args:
        text: The original text to redact
        violations: List of detected violations (for context, not used directly)
        regulation: Regulatory framework (HIPAA, GDPR, etc.)
    
    Returns:
        {
            "redacted_text": str,
            "reasoning": str,
            "preserved_elements": List[str]
        }
        
    Behavior:
        - If Azure OpenAI fails, returns fallback response
        - Logs fallback via telemetry
        - Clearly labels output as fallback-generated
    """
    
    # Initialize Azure OpenAI client (same config as RedactionEngine)
    api_key = os.getenv("AZURE_OPENAI_KEY")
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    
    client = None
    if api_key and endpoint:
        try:
            client = AzureOpenAI(
                api_key=api_key,
                api_version="2024-02-15-preview",
                azure_endpoint=endpoint
            )
        except Exception as e:
            logger.error(f"Azure OpenAI client initialization failed: {e}")
    
    if not client:
        # Fallback behavior (mandatory)
        logger.warning("Azure OpenAI unavailable, using fallback redaction")
        return _fallback_redaction(text, regulation)
    
    try:
        # Build system prompt (encoded verbatim as per requirements)
        system_prompt = """You are a clinical documentation assistant specializing in HIPAA-compliant redaction.

Rules:
You are a clinical documentation assistant providing NON-AUTHORITATIVE redaction suggestions.

IMPORTANT:
- This output is advisory only.
- Deterministic redaction has already been applied.
- You must not override deterministic decisions.

CORE PRINCIPLE:
Identification risk is CONTEXTUAL, not absolute.
TEMPORAL CONVERSION RULE (MANDATORY):
- You MUST NOT calculate numeric relative times.
- Do NOT say "9 months ago", "1 year ago", or similar.
- If a date requires conversion, express it ONLY as relative to the encounter.
- Use placeholders such as:
  • "X days prior to admission"
  • "X weeks prior to admission"
  • "X months prior to admission"
- The deterministic redaction layer will perform all numeric calculations.

GENERAL RULES:
- Remove all direct identifiers.
- Generalize ages to ranges when appropriate (e.g., 89 → late 80s).
- Maintain clinical context (family history, treatment flow).
- Preserve temporal relationships rather than deleting them.

TEMPORAL HANDLING (MANDATORY):
- Tier 1 (DOB, admission, discharge): use [REDACTED DATE].
- Tier 2 (historical context): preserve YEAR ONLY.
- Tier 3 (clinical timeline): preserve the date or convert to an
  encounter-relative temporal expression ONLY
  (e.g., "X weeks prior to admission", "X months prior to admission").
- Vague terms such as "recently" are NOT permitted.

LINKAGE SAFETY RULE (MANDATORY):
If a clinical timeline date appears in the same record as ANY direct patient identifier
(DOB, admission date, discharge date),
you MUST convert the clinical timeline date to a relative temporal expression.

FORBIDDEN OUTPUTS:
- "Started on [REDACTED DATE]"
- "Diagnosed in [REDACTED DATE]"
- Deleting temporal information without replacement.

REQUIRED BEHAVIOR:
- Preserve clinical timelines.
- Prefer encounter-relative temporal placeholders when uncertain
  (e.g., "X weeks prior to admission", "X months prior to admission"). The value of X MUST be supplied by the deterministic redaction layer.
- Do NOT use vague terms such as "recently".
- Do NOT calculate or guess numeric values.

Output format (strict JSON):
{
    "redacted": "...",
    "reasoning": "...",
    "preserved": ["temporal context", "family history"]
}"""

        user_prompt = f"""Redact the following clinical text while preserving clinical utility:

{text}

Return only valid JSON matching the specified format."""

        response = client.chat.completions.create(
            model=deployment,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.0,
            max_tokens=2000,
            response_format={"type": "json_object"}
        )
        
        raw_response = response.choices[0].message.content.strip()
        
        # Parse JSON response
        try:
            result = json.loads(raw_response)
            
            # Validate response structure
            if "redacted" not in result:
                logger.warning("AI response missing 'redacted' field, using fallback")
                return _fallback_redaction(text, regulation)
            
            return {
                "redacted_text": result.get("redacted", text),
                "reasoning": result.get("reasoning", "AI-generated redaction suggestion"),
                "preserved_elements": result.get("preserved", [])
            }
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI JSON response: {e}")
            return _fallback_redaction(text, regulation)
            
    except Exception as e:
        logger.error(f"Azure OpenAI redaction failed: {e}")
        return _fallback_redaction(text, regulation)


def _fallback_redaction(text: str, regulation: str) -> Dict[str, Any]:
    """
    Fallback behavior when Azure OpenAI is unavailable.
    
    Uses existing regex/deterministic redaction and clearly labels output.
    """
    from verifhir.remediation.fallback import RegexFallbackEngine
    
    fallback_engine = RegexFallbackEngine()
    redacted_text, rules_applied = fallback_engine.redact(text)
    
    return {
        "redacted_text": redacted_text if isinstance(redacted_text, str) else str(redacted_text),
        "reasoning": f"Fallback-generated redaction using deterministic rules. Rules applied: {', '.join(rules_applied)}",
        "preserved_elements": ["fallback mode - clinical context preservation limited"]
    }

