import re
from typing import List, Tuple, Dict, Pattern
from datetime import datetime

class RegexFallbackEngine:
    """
    HIPAA-Compliant Deterministic Safety Net.
    Covers all 18 HIPAA PHI identifiers with both anchored and unstructured detection.
    """
    
    def __init__(self):
        # Current year for age-over-89 detection
        self.current_year = datetime.now().year
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Initialize all regex patterns covering 18 HIPAA identifier categories"""
        self._PATTERNS: Dict[str, Pattern] = {
            # ============================================================
            # CATEGORY 1: NAMES (Already covered, keeping for completeness)
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
            # CATEGORY 2: GEOGRAPHIC SUBDIVISIONS (Beyond full addresses)
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
            # CATEGORY 3: DATES (All dates except year)
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
            
            # Birth/Death dates with labels
            "DATE_BIRTH_ANCHORED": re.compile(
                r"(?i)(?:DOB|date of birth|birth date|born on?)[\s:]+(.+?)(?=\.|,|$)",
                re.MULTILINE
            ),
            
            "DATE_DEATH_ANCHORED": re.compile(
                r"(?i)(?:DOD|date of death|death date|died on?|deceased on?)[\s:]+(.+?)(?=\.|,|$)",
                re.MULTILINE
            ),
            
            # Admission/Discharge
            "DATE_ADMISSION": re.compile(
                r"(?i)(?:admitted|admission date|admit date)[\s:]+(.+?)(?=\.|,|$)",
                re.MULTILINE
            ),
            
            "DATE_DISCHARGE": re.compile(
                r"(?i)(?:discharged|discharge date)[\s:]+(.+?)(?=\.|,|$)",
                re.MULTILINE
            ),
            
            # Age over 89 detection
            "AGE_OVER_89": re.compile(
                r"\b(?:age|aged)\s+([9]\d|1[0-9]{2})\b",
                re.IGNORECASE
            ),

            # ============================================================
            # CATEGORY 4: CONTACT INFORMATION
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
            # CATEGORY 5: IDENTIFYING NUMBERS
            # ============================================================
            "SSN": re.compile(
                r"\b\d{3}-\d{2}-\d{4}\b"
            ),
            
            # Medical Record Number (MRN)
            "MRN": re.compile(
                r"(?i)(?:MRN|medical record number|record number|patient id|patient number)[\s:#]+([A-Z0-9\-]{6,})",
                re.MULTILINE
            ),
            
            # Account/Member/Certificate Numbers
            "ACCOUNT_NUMBER": re.compile(
                r"(?i)(?:account|acct|member|policy|certificate|license|licence)[\s#:]+([A-Z0-9\-]{6,})",
                re.MULTILINE
            ),
            
            # Health Plan Beneficiary Number
            "HEALTH_PLAN_ID": re.compile(
                r"(?i)(?:beneficiary|insurance|plan|subscriber)[\s#:]+(?:number|id|no\.?)[\s:]*([A-Z0-9\-]{6,})",
                re.MULTILINE
            ),

            # ============================================================
            # CATEGORY 6: DEVICE & BIOMETRIC IDENTIFIERS
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
            # CATEGORY 7: DIGITAL FOOTPRINTS
            # ============================================================
            "WEB_URL": re.compile(
                r"(?i)(?:https?://|www\.)[A-Za-z0-9\-\._~:/\?#\[\]@!$&'\(\)\*\+,;=%]+",
                re.MULTILINE
            ),
            
            "VEHICLE_ID": re.compile(
                r"(?i)(?:license plate|plate number|vin|vehicle id)[\s:#]+([A-Z0-9\-]{5,})",
                re.MULTILINE
            ),
            
            # License plate patterns (various formats)
            "LICENSE_PLATE": re.compile(
                r"\b[A-Z]{2,3}[\s\-]?\d{3,4}[A-Z]?\b|\b\d{3}[\s\-]?[A-Z]{3}\b"
            ),

            # ============================================================
            # CATEGORY 8: IMAGES & MEDIA REFERENCES
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
            "DATE_ISO",
            "DATE_FULL",
            "DATE_NUMERIC",
            "AGE_OVER_89",
            
            # IDs and numbers
            "SSN",
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

    def redact(self, text: str) -> Tuple[str, List[str]]:
        """
        Redacts all HIPAA PHI identifiers from text.
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
                if "ANCHORED" in rule_name or match.lastindex and match.lastindex >= 1:
                    # Anchored patterns capture the data after the label
                    target_text = match.group(1).strip() if match.lastindex >= 1 else match.group(0).strip()
                    start = match.start(1) if match.lastindex >= 1 else match.start(0)
                    end = match.end(1) if match.lastindex >= 1 else match.end(0)
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
                
                # Apply validation rules
                if "NAME" in rule_name and not self._is_valid_name(target_text):
                    continue
                
                if "ADDRESS" in rule_name and not self._is_valid_address(target_text):
                    continue
                
                if "AGE_OVER_89" in rule_name:
                    age = int(match.group(1))
                    if age < 90:
                        continue
                
                # Determine tag type
                tag_type = self._determine_tag_type(rule_name)
                replacement = f"[REDACTED {tag_type}]"
                
                # Apply redaction
                redacted_text = redacted_text[:start] + replacement + redacted_text[end:]
                applied_rules.append(tag_type)
                
                # Track this redaction position (adjust for new length)
                redaction_positions.append((start, start + len(replacement)))

        return redacted_text, list(set(applied_rules))
    
    def _determine_tag_type(self, rule_name: str) -> str:
        """Map rule names to human-readable tag types"""
        tag_map = {
            "NAME": "NAME",
            "ADDRESS": "ADDRESS",
            "ZIP": "ZIP",
            "DATE": "DATE",
            "AGE": "AGE 90+",
            "EMAIL": "EMAIL",
            "PHONE": "PHONE",
            "FAX": "FAX",
            "SSN": "SSN",
            "MRN": "MRN",
            "ACCOUNT": "ACCOUNT NUMBER",
            "HEALTH": "HEALTH PLAN ID",
            "IP": "IP ADDRESS",
            "DEVICE": "DEVICE ID",
            "BIOMETRIC": "BIOMETRIC ID",
            "WEB": "URL",
            "VEHICLE": "VEHICLE ID",
            "LICENSE": "LICENSE PLATE",
            "IMAGE": "IMAGE REFERENCE",
            "FILE": "FILE ATTACHMENT"
        }
        
        # Find matching prefix
        for key, value in tag_map.items():
            if key in rule_name:
                return value
        
        # Default fallback
        return rule_name.split('_')[0]
    
    def _overlaps_redaction(self, start: int, end: int, positions: List[Tuple[int, int]]) -> bool:
        """Check if a span overlaps with any existing redaction"""
        for pos_start, pos_end in positions:
            if not (end <= pos_start or start >= pos_end):
                return True
        return False
    
    def _is_valid_name(self, text: str) -> bool:
        """Validate that detected name is likely a real person name"""
        if len(text) < 2 or len(text) > 50:
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
        """Validate that detected address is likely real"""
        if len(text) < 5 or len(text) > 200:
            return False
        
        if text.lower().strip() in ['address', 'home', 'residence', 'location']:
            return False
        
        return True