"""
Compliance-Critical Deterministic Redaction Engine.

This module implements a structure-agnostic, recursive PHI/PII redaction engine
that serves as the final safety net when AI is unavailable or untrusted.

PRODUCTION COMPLIANCE CODE - Correctness and auditability take priority.
"""

import re
import json
import logging
from typing import Any, List, Tuple, Dict, Pattern, Set, Optional
from datetime import datetime

logger = logging.getLogger("verifhir.remediation.fallback")

class RegexFallbackEngine:
    """
    Deterministic Safety Net for PHI/PII Redaction.
    
    Architecture:
    - Structure-agnostic: Handles strings, dicts, lists, JSON, FHIR bundles
    - Recursive: Traverses nested objects completely
    - Deterministic: Regex-only, no AI or heuristics
    - Compliance-first: Accuracy > performance, false positives acceptable
    
    This engine MUST:
    1. Never silently fail
    2. Preserve JSON validity
    3. Return consistent (redacted_data, rules_applied) tuple
    4. Always return a result (convert unsupported types to string if needed)
    """
    
    def __init__(self):
        """Initialize the engine with compiled regex patterns."""
        self.current_year = datetime.now().year
        self._compile_patterns()
        logger.info("RegexFallbackEngine initialized with deterministic rules")

    def _classify_temporal_context(self, surrounding_text: str) -> str:
        text = surrounding_text.lower()

        if any(k in text for k in ["dob", "date of birth", "born", "admitted", "discharged", "patient died", "date of death"]): 
            return "TIER_1"

        elif any(k in text for k in ["diagnosed", "diagnosis", "surgery", "operation", "family history", "father", "mother"]):
            return "TIER_2"

        if any(k in text for k in ["started", "prescribed", "last checked", "follow up", "lab"]):
            return "TIER_3"

        return "UNCLASSIFIED"
    
    def _classify_date_semantic_context(self, surrounding_text: str) -> str:
        """
        Classify WHAT the date refers to.
        This is NOT the same as temporal tier.
        """
        text = surrounding_text.lower()

        if any(k in text for k in [
            "lab", "laboratory", "collection", "specimen",
            "result", "measured", "test", "report"
        ]):
            return "LAB"
        
        if any(k in text for k in [
            "started", "prescribed", "medication",
            "dose", "therapy", "treatment"
        ]):
            return "MEDICATION"

        if any(k in text for k in [
            "father", "mother", "parent", "family history",
            "sibling", "relative"
        ]):
            return "FAMILY_HISTORY"

        return "GENERAL"

    
    def _has_tier1_temporal(self, text: str) -> bool:
        """
        Detect presence of Tier 1 temporal identifiers (DOB, admission, discharge, death).
        """
        tier1_patterns = [
            self._PATTERNS["DATE_BIRTH_ANCHORED"],
            self._PATTERNS["DATE_ADMISSION"],
            self._PATTERNS["DATE_DISCHARGE"],
            self._PATTERNS["DATE_DEATH_ANCHORED"],
        ]
        return any(p.search(text) for p in tier1_patterns)
    
    def _compile_patterns(self):
        """Initialize all regex patterns covering PHI/PII categories."""
        self._PATTERNS: Dict[str, Pattern] = {
            # ============================================================
            # NAMES
            # ============================================================
            "NAME_ANCHORED": re.compile(
                r"(?i)(?:patient|pt|name|patient name|pt name|full name)[\s:]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",
                re.MULTILINE
            ),
            
            "NAME_UNSTRUCTURED": re.compile(
                r"\b(?!(?:January|February|March|April|May|June|July|August|September|October|November|December|"
                r"Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|"
                r"Dr|Mr|Mrs|Ms|MD|PhD|RN|Hospital|Clinic|Department|Unit|COVID|HIPAA|FHIR|"
                r"Street|Avenue|Road|Boulevard|Lane|Drive)\b)"
                r"([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,3})\b"
            ),

            # ============================================================
            # ADDRESSES
            # ============================================================
            "ADDRESS_ANCHORED": re.compile(
                r"(?i)(?:address|addr|home|resides at|residence|location)[\s:]+(.+?)(?=\.|,\s*(?:email|phone|contact|ssn|dob)|$)",
                re.MULTILINE | re.DOTALL
            ),

            "ADDRESS_STREET": re.compile(
                r"\b\d{1,6}\s+[A-Z][A-Za-z0-9\s\.,']+?\s+"
                r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|"
                r"Court|Ct|Place|Pl|Circle|Cir|Parkway|Pkwy|Terrace|Ter)"
                r"(?:\s*,?\s*(?:Apt|Apartment|Unit|Suite|Ste|Floor|Fl|#)\s*[A-Za-z0-9]+)?"
                r"(?:\s*,?\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?",
                re.IGNORECASE
            ),

            "ZIP_CITY": re.compile(
                r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+\d{5,6}(?:-\d{4})?\b"
            ),

            # ============================================================
            # DATES
            # ============================================================
            "DATE_FULL": re.compile(
                r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December|"
                r"Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)"
                r"\s+\d{1,2},?\s+\d{4}\b",
                re.IGNORECASE
            ),
            
            "DATE_NUMERIC": re.compile(
                r"\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b"
            ),
            
            "DATE_ISO": re.compile(
                r"\b\d{4}-\d{2}-\d{2}\b"
            ),
            
            "DATE_BIRTH_ANCHORED": re.compile(
                r"(?i)(?:DOB|date of birth|birth date|born on?)[\s:]+(.+?)(?=\.|,|$)",
                re.MULTILINE
            ),
            
            "DATE_DEATH_ANCHORED": re.compile(
                r"(?i)(?:DOD|date of death|death date|died on?|deceased on?)[\s:]+(.+?)(?=\.|,|$)",
                re.MULTILINE
            ),
            
            "DATE_ADMISSION": re.compile(
                r"(?i)(?:admitted|admission date|admit date)[\s:]+(.+?)(?=\.|,|$)",
                re.MULTILINE
            ),
            
            "DATE_DISCHARGE": re.compile(
                r"(?i)(?:discharged|discharge date)[\s:]+(.+?)(?=\.|,|$)",
                re.MULTILINE
            ),
            
            "AGE_OVER_89": re.compile(
                r"\b(?:age|aged)\s+([9]\d|1[0-9]{2})\b",
                re.IGNORECASE
            ),

            # ============================================================
            # CONTACT INFORMATION
            # ============================================================
            "EMAIL": re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            ),

            "PHONE": re.compile(
                r"(?:\+|00)[1-9]\d{0,3}[\s.-]?\(?\d+\)?[\s.-]?\d{3,}[\s.-]?\d{3,}|"
                r"\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}"
            ),
            
            "FAX": re.compile(
                r"(?i)(?:fax|facsimile)[\s:]+[\+\d\s\(\)\-\.]{10,}",
                re.MULTILINE
            ),

            # ============================================================
            # IDENTIFYING NUMBERS - US
            # ============================================================
            "SSN": re.compile(
                r"\b\d{3}-\d{2}-\d{4}\b"
            ),
            
            "MRN": re.compile(
                r"(?i)(?:MRN|medical record number|record number|patient id|patient number)[\s:#]+([A-Z0-9\-]{6,})",
                re.MULTILINE
            ),
            
            "ACCOUNT_NUMBER": re.compile(
                r"(?i)(?:account|acct|member|policy|certificate|license|licence)[\s#:]+([A-Z0-9\-]{6,})",
                re.MULTILINE
            ),
            
            "HEALTH_PLAN_ID": re.compile(
                r"(?i)(?:beneficiary|insurance|plan|subscriber)[\s#:]+(?:number|id|no\.?)[\s:]*([A-Z0-9\-]{6,})",
                re.MULTILINE
            ),

            # ============================================================
            # IDENTIFYING NUMBERS - INDIA
            # ============================================================
            "INDIAN_AADHAAR": re.compile(
                r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"
            ),
            
            "INDIAN_PAN": re.compile(
                r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"
            ),

            # ============================================================
            # IDENTIFYING NUMBERS - UK
            # ============================================================
            "NHS_NUMBER": re.compile(
                r"\b\d{3}[\s-]?\d{3}[\s-]?\d{4}\b"
            ),

            # ============================================================
            # DEVICE & BIOMETRIC IDENTIFIERS
            # ============================================================
            "IP_ADDRESS": re.compile(
                r"\b(?:IP|ip access|ip address)?[\s:]*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
            ),
            
            "DEVICE_ID": re.compile(
                r"(?i)(?:device|serial|imei|mac|uuid)[\s#:]+([A-Z0-9\-:]{8,})",
                re.MULTILINE
            ),
            
            "BIOMETRIC": re.compile(
                r"(?i)(?:fingerprint|voiceprint|retinal scan|iris scan|facial recognition|biometric)[\s:]+([A-Z0-9\-]{8,})",
                re.MULTILINE
            ),

            # ============================================================
            # DIGITAL FOOTPRINTS
            # ============================================================
            "WEB_URL": re.compile(
                r"(?i)(?:https?://|www\.)[A-Za-z0-9\-\._~:/\?#\[\]@!$&'\(\)\*\+,;=%]+",
                re.MULTILINE
            ),
            
            "VEHICLE_ID": re.compile(
                r"(?i)(?:license plate|plate number|vin|vehicle id)[\s:#]+([A-Z0-9\-]{5,})",
                re.MULTILINE
            ),
            
            "LICENSE_PLATE": re.compile(
                r"\b[A-Z]{2,3}[\s\-]?\d{3,4}[A-Z]?\b|\b\d{3}[\s\-]?[A-Z]{3}\b"
            ),

            # ============================================================
            # IMAGES & MEDIA REFERENCES
            # ============================================================
            "IMAGE_REFERENCE": re.compile(
                r"(?i)(?:photo|photograph|image|picture|scan|x-ray|mri|ct scan)[\s:]+(?:attached|included|see|ref)",
                re.MULTILINE
            ),
            
            "FILE_ATTACHMENT": re.compile(
                r"(?i)(?:attachment|attached file|document)[\s:]+([A-Za-z0-9\-_\.]+\.(?:jpg|jpeg|png|pdf|dcm|dicom))",
                re.MULTILINE
            ),
        }
        
        # Define processing order (most specific → general)
        self._PATTERN_ORDER = [
            # Dates first (most specific)
            "DATE_BIRTH_ANCHORED",
            "DATE_DEATH_ANCHORED", 
            "DATE_ADMISSION",
            "DATE_DISCHARGE",

            "DATE_FULL",
            "DATE_NUMERIC",
            "DATE_ISO",
            
            # IDs and numbers (specific patterns first)
            "SSN",
            "INDIAN_AADHAAR",
            "INDIAN_PAN",
            "NHS_NUMBER",
            "MRN",
            "ACCOUNT_NUMBER",
            "HEALTH_PLAN_ID",
            
            # Contact info
            "EMAIL",
            "PHONE",
            "FAX",
            
            # Addresses
            "ADDRESS_ANCHORED",
            "ADDRESS_STREET",
            "ZIP_CITY",
            
            # Device & Biometric
            "IP_ADDRESS",
            "DEVICE_ID",
            "BIOMETRIC",
            
            # Digital footprints
            "WEB_URL",
            "VEHICLE_ID",
            "LICENSE_PLATE",
            
            # Images & Media
            "IMAGE_REFERENCE",
            "FILE_ATTACHMENT",
            
            # Names last (most general)
            "NAME_ANCHORED",
            "NAME_UNSTRUCTURED"
        ]

    def _extract_encounter_anchor(self, text: str) -> Optional[datetime]:
        """
        Extract the encounter anchor date.
        Priority: discharge > admission > report date.
        """
        # 1. Check for Discharge
        discharge_match = self._PATTERNS["DATE_DISCHARGE"].search(text)
        if discharge_match:
            return self._parse_date_safe(discharge_match.group(1))

        # 2. Check for Admission
        admission_match = self._PATTERNS["DATE_ADMISSION"].search(text)
        if admission_match:
            return self._parse_date_safe(admission_match.group(1))

        # 3. FIX: Check for "Date:" or "Report Date" to act as anchor for standalone labs
        # This allows Tier 3 dates to be calculated relative to the report itself
        report_date_match = re.search(r"(?i)(?:date|report date|collected)[\s:]+(\d{4}-\d{2}-\d{2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})", text)
        if report_date_match:
            return self._parse_date_safe(report_date_match.group(1))

        return None

    def _parse_date_safe(self, date_text: str) -> Optional[datetime]:
        """
        Parse a date string safely across common formats.
        """
        for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%B %d, %Y", "%b %d, %Y"):
            try:
                return datetime.strptime(date_text.strip(), fmt)
            except Exception:
                continue
        return None

    def _relative_to_anchor(self, target_date: datetime, anchor: datetime) -> str:
        """
        Convert a date into a relative phrase anchored to the encounter.
        """
        delta_days = (anchor - target_date).days

        if delta_days < 0:
            return "after admission"

        if delta_days < 14:
            return "shortly prior to admission"
        elif delta_days < 60:
            weeks = max(1, delta_days // 7)
            return f"{weeks} weeks prior to admission"
        elif delta_days < 365:
            months = max(1, delta_days // 30)
            return f"{months} months prior to admission"
        else:
            years = max(1, delta_days // 365)
            return f"{years} years prior to admission"

    def redact(self, data: Any) -> Tuple[Any, List[str]]:
        """
        Main entry point for redaction.
        
        Structure-agnostic: Handles strings, dicts, lists, and nested structures.
        Recursively traverses all values, applying regex rules to strings only.
        Preserves JSON validity and structure.
        
        Args:
            data: Input data (string, dict, list, or any nested structure)
            
        Returns:
            Tuple of (redacted_data, rules_applied):
            - redacted_data: Same structure as input with redacted string values
            - rules_applied: Unique list of rule category names (e.g., ["SSN", "EMAIL", "NAME"])
            
        Guarantees:
            - Never returns None
            - Always returns a result (converts unsupported types to string if needed)
            - Preserves structure and JSON validity
            - rules_applied is a unique, sorted list
        """
        applied_rules: Set[str] = set()
        
        try:
            redacted_data = self._redact_any(data, applied_rules)
            
            # Return sorted list for deterministic output
            rules_list = sorted(list(applied_rules))
            return redacted_data, rules_list
            
        except Exception as e:
            # NO SILENT FAILURES: Log error but still attempt redaction
            logger.error(f"Error during redaction: {e}", exc_info=True)
            
            # Fallback: convert to string and redact anyway
            try:
                data_str = str(data) if data is not None else ""
                redacted_str, fallback_rules = self._redact_string(data_str, set())
                return redacted_str, sorted(list(fallback_rules))
            except Exception as fallback_error:
                logger.error(f"Fallback redaction also failed: {fallback_error}", exc_info=True)
                # Last resort: return original with empty rules
                return data, []

    def _redact_any(self, value: Any, applied_rules: Set[str]) -> Any:
        """
        Recursive redaction function that handles any data type.
        
        Args:
            value: Any value (string, dict, list, etc.)
            applied_rules: Set to accumulate applied rule names
            
        Returns:
            Redacted value of the same type
        """
        # Handle None
        if value is None:
            return None
        
        # Handle strings (apply regex rules)
        if isinstance(value, str):
            return self._redact_string(value, applied_rules)
        
        # Handle dicts (recurse into values, preserve keys)
        if isinstance(value, dict):
            return {
                key: self._redact_any(val, applied_rules)
                for key, val in value.items()
            }
        
        # Handle lists (recurse into elements, preserve order)
        if isinstance(value, list):
            return [self._redact_any(item, applied_rules) for item in value]
        
        # Handle tuples (recurse into elements, preserve type)
        if isinstance(value, tuple):
            return tuple(self._redact_any(item, applied_rules) for item in value)
        
        # Handle sets (recurse into elements, preserve type)
        if isinstance(value, set):
            return {self._redact_any(item, applied_rules) for item in value}
        
        # For other types (int, float, bool, etc.), convert to string and redact
        # This ensures we don't miss PHI that might be encoded in unexpected types
        try:
            value_str = str(value)
            redacted_str = self._redact_string(value_str, applied_rules)
            # Try to convert back to original type if possible
            if isinstance(value, (int, float)):
                try:
                    return type(value)(redacted_str)
                except (ValueError, TypeError):
                    return redacted_str
            elif isinstance(value, bool):
                # Don't try to convert redacted strings back to bool
                return redacted_str
            else:
                return redacted_str
        except Exception as e:
            logger.warning(f"Could not redact value of type {type(value)}: {e}")
            return value

    def _redact_string(self, text: str, applied_rules: Set[str]) -> str:
        """
        Apply all regex patterns to a string value.
        
        Args:
            text: Input string to redact
            applied_rules: Set to accumulate applied rule names
            
        Returns:
            Redacted string with PHI/PII replaced by [REDACTED <TYPE>] tags
        """
        if not text or not isinstance(text, str):
            return text if text is not None else ""
        
        # Convert to string if not already (defensive)
        text = str(text)
        
        redacted_text = text

        # Process patterns in order (most specific → general)
        for rule_name in self._PATTERN_ORDER:
            if rule_name not in self._PATTERNS:
                continue
                
            pattern = self._PATTERNS[rule_name]
            matches = list(pattern.finditer(redacted_text))
            
            # Process matches in reverse to maintain index validity
            for match in reversed(matches):
                # Determine which group to use
                if "ANCHORED" in rule_name and match.lastindex and match.lastindex >= 1:
                    # Anchored patterns capture the data after the label
                    target_text = match.group(1).strip() if match.lastindex >= 1 else match.group(0).strip()
                    start = match.start(1) if match.lastindex >= 1 else match.start(0)
                    end = match.end(1) if match.lastindex >= 1 else match.end(0)
                    # Check the full match region for existing redactions
                    full_match_text = match.group(0)
                else:
                    # Unstructured patterns capture the entire match
                    target_text = match.group(0).strip()
                    start = match.start(0)
                    end = match.end(0)
                    full_match_text = match.group(0)

                # Skip if empty
                if not target_text:
                    continue
                
                # Skip if already redacted (check both target and full match region)
                if "[REDACTED" in target_text or "[REDACTED" in full_match_text:
                    continue
                
                # Apply validation rules (to reduce false positives)
                if "NAME" in rule_name and not self._is_valid_name(target_text):
                    continue
                
                if "ADDRESS" in rule_name and not self._is_valid_address(target_text):
                    continue
                
                if "AGE_OVER_89" in rule_name:
                    try:
                        age = int(match.group(1))
                        if age < 90:
                            continue
                    except (ValueError, IndexError):
                        continue
        

            # --- CONTEXT-AWARE TEMPORAL HANDLING ---
                if rule_name.startswith("DATE"):
                    tier = self._classify_temporal_context(text)
                    semantic = self._classify_date_semantic_context(text)
                    has_tier1 = self._has_tier1_temporal(text)
                    anchor = self._extract_encounter_anchor(text)
                    parsed_date = self._parse_date_safe(target_text)

                    # 1. TIER 1 — ALWAYS REDACT (DOB, Admission)
                    if tier == "TIER_1":
                        replacement = "[REDACTED DATE]"
                        
                    # 2. TIER 2 — HISTORICAL (Keep Year Only)
                    elif tier == "TIER_2":
                        year_match = re.search(r"\b\d{4}\b", target_text)
                        replacement = year_match.group(0) if year_match else "[REDACTED DATE]"

                    # 3. TIER 3 — CLINICAL TIMELINE (Lab Results)
                    elif tier == "TIER_3":
                        # MANDATORY LINKAGE SAFETY: If Tier 1 (DOB) is present, 
                        # we MUST convert to relative even if anchor is missing.
                        if has_tier1:
                            if anchor and parsed_date:
                                replacement = self._relative_to_anchor(parsed_date, anchor)
                            else:
                                # Safe fallback per policy: use coarse phrase
                                replacement = "prior to the encounter"
                        else:
                            # No Tier 1 identifiers? We can safely show the clinical date.
                            # But usually, in HIPAA/GDPR, we prefer [REDACTED DATE] or relative.
                            replacement = "[REDACTED DATE]"
                    else:
                        replacement = "[REDACTED DATE]"

                    # CRITICAL: Apply the replacement to the string
                    redacted_text = (
                        redacted_text[:start]
                        + replacement
                        + redacted_text[end:]
                    )
                    applied_rules.add("DATE")
                    continue # Move to next match


    def _determine_tag_type(self, rule_name: str) -> str:
        """
        Map rule names to human-readable tag types.
        
        Returns consistent, auditable category names for rules_applied list.
        """
        tag_map = {
            "NAME": "NAME",
            "ADDRESS": "ADDRESS",
            "ZIP": "ZIP",
            "DATE": "DATE",
            "AGE": "AGE_90_PLUS",
            "EMAIL": "EMAIL",
            "PHONE": "PHONE",
            "FAX": "FAX",
            "SSN": "SSN",
            "MRN": "MRN",
            "ACCOUNT": "ACCOUNT_NUMBER",
            "HEALTH": "HEALTH_PLAN_ID",
            "INDIAN_AADHAAR": "AADHAAR",
            "INDIAN_PAN": "PAN",
            "NHS": "NHS_NUMBER",
            "IP": "IP_ADDRESS",
            "DEVICE": "DEVICE_ID",
            "BIOMETRIC": "BIOMETRIC_ID",
            "WEB": "URL",
            "VEHICLE": "VEHICLE_ID",
            "LICENSE": "LICENSE_PLATE",
            "IMAGE": "IMAGE_REFERENCE",
            "FILE": "FILE_ATTACHMENT"
        }
        
        # Find matching prefix
        for key, value in tag_map.items():
            if key in rule_name:
                return value
        
        # Default fallback
        return rule_name.split('_')[0] if '_' in rule_name else rule_name
    
    def _is_valid_name(self, text: str) -> bool:
        """
        Validate that detected name is likely a real person name.
        
        Note: False positives are acceptable, but this reduces obvious false positives.
        """
        if not text or len(text) < 2 or len(text) > 50:
            return False
        
        words = text.strip().split()
        if len(words) < 2 or len(words) > 4:
            return False
        
        if any(len(w) < 2 for w in words):
            return False
        
        # Reject common false positives
        false_positives = {
            'New York', 'Los Angeles', 'San Francisco', 'North Carolina',
            'South Carolina', 'West Virginia', 'Rhode Island',
            'Patient Admitted', 'Date Time', 'Social Security', 'Health Care',
            'Emergency Room', 'Blood Pressure', 'Heart Rate', 'Primary Care'
        }
        
        if text in false_positives:
            return False
        
        return True
    
    def _is_valid_address(self, text: str) -> bool:
        """
        Validate that detected address is likely real.
        
        Note: False positives are acceptable, but this reduces obvious false positives.
        """
        if not text or len(text) < 5 or len(text) > 200:
            return False
        
        if text.lower().strip() in ['address', 'home', 'residence', 'location']:
            return False
        
        return True