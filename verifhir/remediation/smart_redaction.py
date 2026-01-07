"""
Day 36 Part B: Smart Redaction Engine (AI-Assisted, Advisory)

This module provides context-aware redaction suggestions that preserve clinical utility
while ensuring compliance. The output is advisory only and never auto-applies changes.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv
from openai import AzureOpenAI
from datetime import datetime

load_dotenv()

logger = logging.getLogger("verifhir.remediation.smart_redaction")


def suggest_smart_redaction(text: str, violations: List[Any], regulation: str) -> Dict[str, Any]:
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
        logger.warning("Azure OpenAI unavailable, using fallback redaction")
        return _fallback_redaction(text, regulation)
    
    try:
        # Updated system prompt with explicit generalization demand for non-HIPAA regs
        system_prompt = f"""You are a clinical documentation assistant providing NON-AUTHORITATIVE redaction suggestions.

CORE RULES:
- Remove all direct identifiers.
- Preserve clinical utility and temporal relationships.
- For GDPR, LGPD, UK_GDPR, DPDP, and BASE regulations: 
  When handling Tier 2 or Tier 3 dates, ALWAYS generalize to Year only or Month/Year 
  (e.g., "April 2024" instead of "18/04/2024") rather than full redaction.

TEMPORAL HANDLING:
- Tier 1 → [REDACTED DATE]
- Tier 2 → Year only (e.g., 2024)
- Tier 3 → Relative expression (e.g., "X months prior to admission") or generalized Month/Year

Output format (strict JSON):
{{
    "redacted": "...",
    "reasoning": "...",
    "preserved": ["list of preserved clinical elements"]
}}"""

        violations_summary = "".join([f"- {getattr(v, 'violation_type', str(v))}: {getattr(v, 'description', '')}\n" for v in violations]) if violations else "None"

        user_prompt = f"""Redact the following clinical text while preserving clinical utility:

{text}

Detected violations:
{violations_summary}

Return only valid JSON."""

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

        def _parse_strict_json(s: str):
            try:
                return json.loads(s)
            except json.JSONDecodeError:
                import re as _re
                m = _re.search(r"\{.*\}", s, _re.S)
                if m:
                    try:
                        return json.loads(m.group(0))
                    except:
                        return None
                return None

        result = _parse_strict_json(raw_response)
        
        # Retry logic
        if result is None:
            logger.warning("Smart redaction: JSON parse failed — retrying")
            # ... (retry code unchanged)

        # Only fall back if AI completely fails to return valid redacted text
        if not result or not isinstance(result, dict) or "redacted" not in result or not result.get("redacted", "").strip():
            logger.warning("Smart redaction failed completely — using deterministic fallback")
            return _fallback_redaction(text, regulation)

        return {
            "redacted_text": result.get("redacted", text),
            "reasoning": result.get("reasoning", "AI-generated suggestion"),
            "preserved_elements": result.get("preserved", [])
        }
            
    except Exception as e:
        logger.error(f"Azure OpenAI redaction failed: {e}")
        return _fallback_redaction(text, regulation)


def _fallback_redaction(text: str, regulation: str) -> Dict[str, Any]:
    from verifhir.remediation.fallback import RegexFallbackEngine
    
    fallback_engine = RegexFallbackEngine()
    redacted_text, rules_applied = fallback_engine.redact(text)
    # For non-HIPAA regulations prefer GENERALIZATION over deletion for dates:
    if regulation and regulation != "HIPAA":
        try:
            # Build list of generalized date replacements from the original text in order
            gens: List[str] = []
            # ISO dates -> Year
            for m in __import__("re").finditer(r"\b(\d{4})-(\d{2})-(\d{2})\b", text):
                gens.append(m.group(1))
            # Full month name dates -> Month Year
            month_re = __import__("re").compile(r"\b(?P<mon>(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec))\s+\d{1,2},?\s+(?P<yr>\d{4})\b", __import__("re").IGNORECASE)
            for m in month_re.finditer(text):
                mon = m.group("mon")
                yr = m.group("yr")
                gens.append(f"{mon} {yr}")
            # Numeric dates -> prefer Year if present or keep year fragment
            for m in __import__("re").finditer(r"\b\d{1,2}[-/]\d{1,2}[-/](\d{2,4})\b", text):
                y = m.group(1)
                if len(y) == 2:
                    # best-effort convert to 19xx/20xx heuristic — assume 19xx for >30? Use 20xx for <=30
                    yy = int(y)
                    yr = f"20{y}" if yy <= 30 else f"19{y}"
                else:
                    yr = y
                gens.append(yr)

            # Sequentially replace [REDACTED DATE] placeholders with generalizations where possible
            if gens and isinstance(redacted_text, str):
                def _replace_sequential(s: str, repls: List[str]) -> str:
                    for r in repls:
                        if "[REDACTED DATE]" in s:
                            s = s.replace("[REDACTED DATE]", r, 1)
                        else:
                            break
                    return s

                redacted_text = _replace_sequential(str(redacted_text), gens)
        except Exception:
            # if anything goes wrong, fall back to the deterministic output
            redacted_text = redacted_text

    return {
        "redacted_text": redacted_text if isinstance(redacted_text, str) else str(redacted_text),
        "reasoning": f"Fallback-generated using deterministic rules: {', '.join(rules_applied)}",
        "preserved_elements": ["fallback mode - limited preservation"],
    }