import re
from typing import List, Tuple, Dict, Pattern

class RegexFallbackEngine:
    """
    Deterministic Safety Net with Enhanced Name & Address Detection.
    Works on both structured (labeled) and unstructured (raw) clinical text.
    """
    
    def __init__(self):
        # Compile patterns once for performance
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Initialize all regex patterns"""
        self._PATTERNS: Dict[str, Pattern] = {
            # --- TIER 1: ANCHORED PATTERNS (High Confidence - Labeled Data) ---
            "NAME_ANCHORED": re.compile(
                r"(?i)(?:patient|pt|name|patient name|pt name)[\s:]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",
                re.MULTILINE
            ),
            
            "ADDRESS_ANCHORED": re.compile(
                r"(?i)(?:address|addr|home|resides at|residence|location)[\s:]+(.+?)(?=\.|,\s*(?:email|phone|contact|ssn)|$)",
                re.MULTILINE | re.DOTALL
            ),

            # --- TIER 2: UNSTRUCTURED PATTERNS (No Labels) ---
            
            # PERSON NAME: Detects capitalized full names (2-4 words)
            # Matches: "Rahul Sharma", "John Michael Smith"
            # Avoids: Single words, acronyms, months, common false positives
            "NAME_UNSTRUCTURED": re.compile(
                r"\b(?!(?:January|February|March|April|May|June|July|August|September|October|November|December|"
                r"Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|"
                r"Dr|Mr|Mrs|Ms|MD|PhD|RN|Hospital|Clinic|Department|Unit|COVID|HIPAA|FHIR|SSN|"
                r"Street|Avenue|Road|Boulevard|Lane|Drive)\b)"
                r"([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,3})\b"
            ),

            # EMAIL: Standard email pattern
            "EMAIL": re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            ),

            # PHONE: International (+91, +1, etc.) and US formats
            "PHONE": re.compile(
                r"(?:\+|00)[1-9]\d{0,3}[\s.-]?\(?\d+\)?[\s.-]?\d{3,}[\s.-]?\d{3,}|"
                r"\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}"
            ),

            # ADDRESS: Street addresses with number + street name + suffix
            # Matches: "123 Maple Avenue", "456 Oak St", "12 Main Road, Apt 4B"
            "ADDRESS_STREET": re.compile(
                r"\b\d{1,6}\s+[A-Z][A-Za-z0-9\s\.,']+?\s+"
                r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|"
                r"Court|Ct|Place|Pl|Circle|Cir|Parkway|Pkwy|Terrace|Ter)"
                r"(?:\s*,?\s*(?:Apt|Apartment|Unit|Suite|Ste|Floor|Fl|#)\s*[A-Za-z0-9]+)?"
                r"(?:\s*,?\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?",
                re.IGNORECASE
            ),

            # ZIP/POSTAL with City: "NY 10001", "Delhi 110021"
            "ZIP_CITY": re.compile(
                r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+\d{5,6}(?:-\d{4})?\b"
            ),

            # SSN: US Social Security Number
            "SSN": re.compile(
                r"\b\d{3}-\d{2}-\d{4}\b"
            ),
        }
        
        # Define processing order (most specific first)
        self._PATTERN_ORDER = [
            "SSN",
            "EMAIL", 
            "PHONE",
            "ADDRESS_ANCHORED",
            "ADDRESS_STREET",
            "ZIP_CITY",
            "NAME_ANCHORED",
            "NAME_UNSTRUCTURED"
        ]

    def redact(self, text: str) -> Tuple[str, List[str]]:
        """
        Redacts PII from text using pattern matching.
        Returns: (redacted_text, list_of_applied_rules)
        """
        if not text or not text.strip():
            return text, []

        redacted_text = text
        applied_rules = []
        redaction_positions = []  # Track what's already redacted

        # Process patterns in order
        for rule_name in self._PATTERN_ORDER:
            if rule_name not in self._PATTERNS:
                continue
                
            pattern = self._PATTERNS[rule_name]
            matches = list(pattern.finditer(redacted_text))
            
            # Process matches in reverse to maintain index validity
            for match in reversed(matches):
                # Determine which group to use
                if "ANCHORED" in rule_name:
                    # Anchored patterns capture the data after the label
                    if match.lastindex and match.lastindex >= 1:
                        target_text = match.group(1).strip()
                        start = match.start(1)
                        end = match.end(1)
                    else:
                        continue
                else:
                    # Unstructured patterns capture the entire match
                    target_text = match.group(0).strip()
                    start = match.start(0)
                    end = match.end(0)

                # Skip if empty or already redacted
                if not target_text or "[REDACTED" in target_text:
                    continue
                
                # Skip if this position overlaps with existing redaction
                if self._overlaps_redaction(start, end, redaction_positions):
                    continue
                
                # Additional validation for names
                if "NAME" in rule_name:
                    if not self._is_valid_name(target_text):
                        continue
                
                # Additional validation for addresses
                if "ADDRESS" in rule_name:
                    if not self._is_valid_address(target_text):
                        continue

                # Create redaction tag
                tag_type = rule_name.split('_')[0]  # "NAME_ANCHORED" -> "NAME"
                replacement = f"[REDACTED {tag_type}]"
                
                # Apply redaction
                redacted_text = redacted_text[:start] + replacement + redacted_text[end:]
                applied_rules.append(tag_type)
                
                # Track this redaction position
                redaction_positions.append((start, start + len(replacement)))

        return redacted_text, list(set(applied_rules))
    
    def _overlaps_redaction(self, start: int, end: int, positions: List[Tuple[int, int]]) -> bool:
        """Check if a span overlaps with any existing redaction"""
        for pos_start, pos_end in positions:
            if not (end <= pos_start or start >= pos_end):
                return True
        return False
    
    def _is_valid_name(self, text: str) -> bool:
        """Validate that detected name is likely a real person name"""
        # Must be between 2-50 characters
        if len(text) < 2 or len(text) > 50:
            return False
        
        # Split into words
        words = text.strip().split()
        
        # Must have 2-4 words
        if len(words) < 2 or len(words) > 4:
            return False
        
        # Each word should be 2+ characters
        if any(len(w) < 2 for w in words):
            return False
        
        # Reject common false positives
        false_positives = {
            'New York', 'Los Angeles', 'San Francisco', 'North Carolina',
            'South Carolina', 'West Virginia', 'Rhode Island',
            'Patient Admitted', 'Date Time', 'Social Security', 'Health Care',
            'Emergency Room', 'Blood Pressure', 'Heart Rate'
        }
        
        if text in false_positives:
            return False
        
        return True
    
    def _is_valid_address(self, text: str) -> bool:
        """Validate that detected address is likely real"""
        # Must be between 5-200 characters
        if len(text) < 5 or len(text) > 200:
            return False
        
        # Should not be just a label
        if text.lower().strip() in ['address', 'home', 'residence']:
            return False
        
        return True