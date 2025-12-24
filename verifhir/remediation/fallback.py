import re
from typing import List, Tuple, Dict, Pattern

class RegexFallbackEngine:
    """
    Deterministic Safety Net for Redaction.
    
    Role:
        Provides a conservative, rule-based fallback mechanism when intelligent
        redaction services (AI/ML) are unavailable or fail.
    
    Principles:
        1. Determinism: Output is mathematically predictable based on input.
        2. Fail-Closed: Biased towards over-redaction of matching patterns.
        3. Transparency: Redactions are explicitly labeled by type.
    """
    
    # Pre-compiled patterns to ensure performance and avoid runtime compilation overhead.
    # Ordered dict logic is preserved in modern Python, ensuring deterministic application order.
    _PATTERNS: Dict[str, Pattern] = {
        # Strict SSN: XXX-XX-XXXX (US Standard)
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        
        # Email: Standard RFC 5322ish structure
        "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        
        # Date: Matches MM/DD/YYYY or DD-MM-YYYY formats commonly found in clinical notes
        "DATE": re.compile(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"),
        
        # Phone: XXX-XXX-XXXX (US Standard)
        "PHONE": re.compile(r"\b\d{3}-\d{3}-\d{4}\b"),
        
        # Generic MRN/ID: Catch-all for structured IDs like 'MRN-12345' or 'ID: 999'
        "ID_GENERIC": re.compile(r"\b(MRN|ID|id|mrn)[\s:-]+\d+\b")
    }

    def redact(self, text: str) -> Tuple[str, List[str]]:
        """
        Executes the fallback redaction strategy.

        Args:
            text: The raw input text string.

        Returns:
            A tuple containing:
            1. The text with sensitive patterns replaced by [REDACTED-<TYPE>].
            2. A list of rule names that triggered a modification.
        """
        # Defensive check: Handle empty or None input safely
        if not text:
            return text, []

        redacted_text = text
        applied_rules = []

        # Deterministic Pass: Iterate through patterns in defined order
        for rule_name, pattern in self._PATTERNS.items():
            # Optimization: Check for match before incurring substitution cost
            if pattern.search(redacted_text):
                # Apply redaction
                replacement_token = f"[REDACTED-{rule_name}]"
                redacted_text = pattern.sub(replacement_token, redacted_text)
                
                # Audit Trail: Record that this rule was active
                applied_rules.append(rule_name)

        return redacted_text, applied_rules