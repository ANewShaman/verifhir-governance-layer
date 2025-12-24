import re
from typing import List, Tuple, Dict, Pattern

class RegexFallbackEngine:
    """
    Deterministic Safety Net for Redaction.
    Expanded for international alignment and address detection.
    """
    
    _PATTERNS: Dict[str, Pattern] = {
        # Standard US SSN
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        
        # International & Local Phones: +91, +01, (XXX), or XXX.XXX.XXXX
        "PHONE": re.compile(r"(?:\+|00)[1-9][0-9 \-\(\)\.]{7,15}|\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        
        # Emails
        "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        
        # Dates (MM/DD/YYYY or DD-MM-YYYY)
        "DATE": re.compile(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"),
        
        # General Address Pattern (Number, Street Name, Suffix, State, ZIP)
        "ADDRESS": re.compile(
            r"\d{1,5}\s(?:[A-Z][a-z\d]*\s?){1,5}(?:Street|St|Ave|Rd|Blvd|Dr|Ln|Ct|Cir|Way|Pkwy|Sq|Apt|Ste)\.?\s?,?\s?(?:[A-Z][a-z]*\s?){1,3}?,?\s?[A-Z]{2}\s?\d{5}",
            re.IGNORECASE
        ),
        
        # Medical Identifiers
        "ID_GENERIC": re.compile(r"\b(MRN|ID|id|mrn)[\s:-]+\d+\b")
    }

    def redact(self, text: str) -> Tuple[str, List[str]]:
        if not text:
            return text, []

        redacted_text = text
        applied_rules = []

        for rule_name, pattern in self._PATTERNS.items():
            if pattern.search(redacted_text):
                # FIX: Static replacement token [REDACTED <TYPE>] ensures perfect alignment
                replacement_token = f"[REDACTED {rule_name}]"
                redacted_text = pattern.sub(replacement_token, redacted_text)
                applied_rules.append(rule_name)

        return redacted_text, applied_rules