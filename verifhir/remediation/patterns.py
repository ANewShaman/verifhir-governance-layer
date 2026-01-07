"""
Shared identifier and pattern source-of-truth for deterministic redaction.

This module centralizes commonly used regexes so all components (fallback,
rule-engine, controls) use the same authoritative patterns. Kept intentionally
small and focused to avoid surprising changes elsewhere.
"""
import re

# Public PATTERNS dict used by fallback and rule engine
PATTERNS = {
    # Identifiers
    # Brazil CPF (strict dot/dash formatting: XXX.XXX.XXX-XX)
    "BRAZIL_CPF": re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "MRN": re.compile(r"(?i)(?:MRN|medical record number|record number|patient id|patient number)[\s:#]+([A-Z0-9\-]{6,})", re.MULTILINE),
    # New: Loose standalone MRN detection (common in clinical notes)
    "MRN_UNSTRUCTURED": re.compile(r"\b\d{7,10}\b"),
    # Generic loose numeric identifier (7-10 digits) used only for HIPAA MRN-like detection
    "GENERIC_ID": re.compile(r"\b\d{7,10}\b"),
    "INDIAN_AADHAAR": re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
    "INDIAN_PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
    "NHS_NUMBER": re.compile(r"\b\d{3}[\s-]?\d{3}[\s-]?\d{4}\b"),
    # Addresses
    "ADDRESS_STREET": re.compile(
        r"\b\d{1,6}\s+[A-Z][A-Za-z0-9\s\.,']+?\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Place|Pl|Circle|Cir|Parkway|Pkwy|Terrace|Ter)"
        r"(?:\s*,?\s*(?:Apt|Apartment|Unit|Suite|Ste|Floor|Fl|#)\s*[A-Za-z0-9]+)?"
        r"(?:\s*,?\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?"  # Optional state + 5-digit ZIP
        r"(?:\s*,?\s*\d{5}\b)?",  # Standalone 5-digit ZIP capture improvement
        re.IGNORECASE
    ),
    "ZIP_CITY": re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+\d{5,6}(?:-\d{4})?\b"),
    # Dates (used by fallback enforcement logic)
    "DATE_ISO": re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),
    "DATE_NUMERIC": re.compile(r"\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b"),
    "DATE_FULL": re.compile(
        r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December|"
        r"Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\s+\d{1,2},?\s+\d{4}\b",
        re.IGNORECASE
    ),
}

PATTERN_ORDER = [
    "DATE_FULL", "DATE_NUMERIC", "DATE_ISO",
    "BRAZIL_CPF", "SSN", "INDIAN_AADHAAR", "INDIAN_PAN", "NHS_NUMBER",
    "MRN", "MRN_UNSTRUCTURED",  # Added new pattern
    "GENERIC_ID",
    "ADDRESS_STREET", "ZIP_CITY",
]