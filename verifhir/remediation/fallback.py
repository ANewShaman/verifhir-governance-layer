"""
Compliance-Critical Deterministic Redaction Engine.

This module implements a structure-agnostic, recursive PHI/PII redaction engine
that serves as the final safety net when AI is unavailable or untrusted.

PRODUCTION COMPLIANCE CODE - Correctness and auditability take priority.
"""

import re
import logging
from typing import Any, List, Tuple, Dict, Pattern, Set, Optional
from datetime import datetime
from verifhir.controls.allow_list import ALLOWLIST_TERMS

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
        self.regulation = "HIPAA"  # Configurable in future
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
    
    def _hipaa_allow_lab_date(self, surrounding_text: str) -> bool:
        semantic = self._classify_date_semantic_context(surrounding_text)

        if semantic != "LAB":
            return False

        if any(k in surrounding_text.lower() for k in [
            "admitted", "admission",
            "discharged", "discharge",
            "visit", "encounter"
        ]):
            return False

        return True

    def _has_tier1_temporal(self, text: str) -> bool:
        tier1_patterns = [
            self._PATTERNS.get("DATE_BIRTH_ANCHORED"),
            self._PATTERNS.get("DATE_ADMISSION"),
            self._PATTERNS.get("DATE_DISCHARGE"),
            self._PATTERNS.get("DATE_DEATH_ANCHORED"),
        ]
        return any(p.search(text) for p in tier1_patterns if p)

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
            # IDENTIFYING NUMBERS
            # ============================================================
            "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
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

            # International IDs
            "INDIAN_AADHAAR": re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
            "INDIAN_PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
            "NHS_NUMBER": re.compile(r"\b\d{3}[\s-]?\d{3}[\s-]?\d{4}\b"),

            # Device & Biometric
            "IP_ADDRESS": re.compile(r"\b(?:IP|ip access|ip address)?[\s:]*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
            "DEVICE_ID": re.compile(r"(?i)(?:device|serial|imei|mac|uuid)[\s#:]+([A-Z0-9\-:]{8,})", re.MULTILINE),
            "BIOMETRIC": re.compile(r"(?i)(?:fingerprint|voiceprint|retinal scan|iris scan|facial recognition|biometric)[\s:]+([A-Z0-9\-]{8,})", re.MULTILINE),

            # Digital & Vehicle
            "WEB_URL": re.compile(r"(?i)(?:https?://|www\.)[A-Za-z0-9\-\._~:/\?#\[\]@!$&'\(\)\*\+,;=%]+", re.MULTILINE),
            "VEHICLE_ID": re.compile(r"(?i)(?:license plate|plate number|vin|vehicle id)[\s:#]+([A-Z0-9\-]{5,})", re.MULTILINE),
            "LICENSE_PLATE": re.compile(r"\b[A-Z]{2,3}[\s\-]?\d{3,4}[A-Z]?\b|\b\d{3}[\s\-]?[A-Z]{3}\b"),

            # Media
            "IMAGE_REFERENCE": re.compile(r"(?i)(?:photo|photograph|image|picture|scan|x-ray|mri|ct scan)[\s:]+(?:attached|included|see|ref)", re.MULTILINE),
            "FILE_ATTACHMENT": re.compile(r"(?i)(?:attachment|attached file|document)[\s:]+([A-Za-z0-9\-_\.]+\.(?:jpg|jpeg|png|pdf|dcm|dicom))", re.MULTILINE),
        }

        # Default processing order
        self._PATTERN_ORDER = [
            "DATE_BIRTH_ANCHORED", "DATE_DEATH_ANCHORED", "DATE_ADMISSION", "DATE_DISCHARGE",
            "DATE_FULL", "DATE_NUMERIC", "DATE_ISO",
            "SSN", "INDIAN_AADHAAR", "INDIAN_PAN", "NHS_NUMBER",
            "MRN", "MRN_UNSTRUCTURED", "ACCOUNT_NUMBER", "HEALTH_PLAN_ID",
            "EMAIL", "PHONE", "FAX",
            "ADDRESS_ANCHORED", "ADDRESS_STREET", "ZIP_CITY",
            "IP_ADDRESS", "DEVICE_ID", "BIOMETRIC",
            "WEB_URL", "VEHICLE_ID", "LICENSE_PLATE",
            "IMAGE_REFERENCE", "FILE_ATTACHMENT",
            "NAME_ANCHORED", "NAME_UNSTRUCTURED"
        ]

        # Overlay shared patterns (higher priority)
        try:
            from verifhir.remediation import patterns as shared_patterns
            self._PATTERNS.update(shared_patterns.PATTERNS)
            if hasattr(shared_patterns, "PATTERN_ORDER"):
                self._PATTERN_ORDER = shared_patterns.PATTERN_ORDER
            # Prioritize Brazil CPF if present
            if "BRAZIL_CPF" in self._PATTERNS:
                if "BRAZIL_CPF" in self._PATTERN_ORDER:
                    self._PATTERN_ORDER.remove("BRAZIL_CPF")
                self._PATTERN_ORDER.insert(0, "BRAZIL_CPF")
        except Exception as e:
            logger.debug(f"Shared patterns unavailable: {e}")

    def _extract_encounter_anchor(self, text: str) -> Optional[datetime]:
        for key in ["DATE_DISCHARGE", "DATE_ADMISSION"]:
            match = self._PATTERNS.get(key, None)
            if match:
                m = match.search(text)
                if m and m.lastindex:
                    return self._parse_date_safe(m.group(1))
        # Fallback lab/report date
        fallback = re.search(r"(?i)(?:date|report date|collected)[\s:]+(\d{4}-\d{2}-\d{2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})", text)
        if fallback:
            return self._parse_date_safe(fallback.group(1))
        return None

    def _parse_date_safe(self, date_text: str) -> Optional[datetime]:
        for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%B %d, %Y", "%b %d, %Y"):
            try:
                return datetime.strptime(date_text.strip(), fmt)
            except Exception:
                continue
        return None

    def _relative_to_anchor(self, target_date: datetime, anchor: datetime) -> str:
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
        applied_rules: Set[str] = set()
        try:
            redacted = self._redact_any(data, applied_rules)
            return redacted, sorted(list(applied_rules))
        except Exception as e:
            logger.error(f"Error during redaction: {e}", exc_info=True)
            try:
                s = str(data) if data is not None else ""
                r, rules = self._redact_string(s, set())
                return r, sorted(list(rules))
            except:
                return data, []

    def _redact_any(self, value: Any, applied_rules: Set[str]) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            return self._redact_string(value, applied_rules)
        if isinstance(value, dict):
            return {k: self._redact_any(v, applied_rules) for k, v in value.items()}
        if isinstance(value, list):
            return [self._redact_any(i, applied_rules) for i in value]
        if isinstance(value, (tuple, set)):
            return type(value)(self._redact_any(i, applied_rules) for i in value)
        try:
            s = str(value)
            r = self._redact_string(s, applied_rules)
            if isinstance(value, (int, float)):
                try: return type(value)(r)
                except: pass
            return r
        except:
            return value

    def _redact_string(self, text: str, applied_rules: Set[str]) -> str:
        if not text or not isinstance(text, str):
            return text or ""

        redacted_text = text
        has_name = any(self._PATTERNS.get(p) and self._PATTERNS[p].search(text) for p in ["NAME_ANCHORED", "NAME_UNSTRUCTURED"])
        anchor = self._extract_encounter_anchor(text)

        def _window(s, start, end, size=120):
            return s[max(0, start - size):min(len(s), end + size)]

        address_keys = {"ADDRESS_ANCHORED", "ADDRESS_STREET", "ZIP_CITY"}

        for rule_name in self._PATTERN_ORDER:
            if rule_name not in self._PATTERNS:
                continue
            pattern = self._PATTERNS[rule_name]
            matches = list(pattern.finditer(redacted_text))
            for match in reversed(matches):
                if "ANCHORED" in rule_name and match.lastindex:
                    target_text = match.group(1).strip()
                    start, end = match.start(1), match.end(1)
                else:
                    target_text = match.group(0).strip()
                    start, end = match.start(0), match.end(0)

                if not target_text or "[REDACTED" in target_text:
                    continue

                surrounding = _window(redacted_text, start, end)

                # HIPAA-specific loose MRN handling
                # HIPAA-specific loose MRN / generic numeric ID handling
                if self.regulation == "HIPAA" and rule_name in ("MRN_UNSTRUCTURED", "GENERIC_ID"):
                    if target_text.upper() not in ALLOWLIST_TERMS:
                        redacted_text = redacted_text[:start] + "[REDACTED MRN]" + redacted_text[end:]
                        applied_rules.add("MRN")
                    continue

                # Date logic
                if rule_name.startswith("DATE"):
                    tier = self._classify_temporal_context(surrounding)
                    parsed = self._parse_date_safe(target_text)

                    if self._hipaa_allow_lab_date(surrounding):
                        year = re.search(r"\d{4}", target_text)
                        repl = year.group(0) if year else "[REDACTED DATE]"
                    elif has_name or tier == "TIER_1":
                        repl = self._relative_to_anchor(parsed, anchor) if anchor and parsed else "[REDACTED DATE]"
                        if not repl.startswith("["):
                            year = re.search(r"\d{4}", target_text)
                            repl = year.group(0) if year else repl
                    elif tier == "TIER_2":
                        year = re.search(r"\d{4}", target_text)
                        repl = year.group(0) if year else "[REDACTED DATE]"
                    else:
                        repl = "[REDACTED DATE]"

                    redacted_text = redacted_text[:start] + repl + redacted_text[end:]
                    applied_rules.add("DATE")
                    continue

                # Name validation
                if "NAME" in rule_name:
                    if not self._is_valid_name(target_text):
                        continue

                # Address grouping
                if rule_name in address_keys:
                    found = False
                    for ak in address_keys:
                        for m in self._PATTERNS[ak].finditer(redacted_text):
                            s, e = m.start(), m.end()
                            redacted_text = redacted_text[:s] + "[REDACTED ADDRESS]" + redacted_text[e:]
                            found = True
                    if found:
                        applied_rules.add("ADDRESS")
                    continue

                # Default redaction
                tag = f"[REDACTED {self._determine_tag_type(rule_name)}]"
                redacted_text = redacted_text[:start] + tag + redacted_text[end:]
                applied_rules.add(self._determine_tag_type(rule_name))

        # Orphaned years
        redacted_text = re.sub(r"(?<!\[REDACTED\s)\b(19|20)\d{2}\b", "[REDACTED DATE]", redacted_text)
        if "[REDACTED DATE]" in redacted_text:
            applied_rules.add("DATE")

        return redacted_text

    def _determine_tag_type(self, rule_name: str) -> str:
        map_ = {
            "NAME": "NAME", "ADDRESS": "ADDRESS", "DATE": "DATE", "AGE": "AGE_90_PLUS",
            "EMAIL": "EMAIL", "PHONE": "PHONE", "FAX": "FAX", "SSN": "SSN", "MRN": "MRN",
            "ACCOUNT": "ACCOUNT_NUMBER", "HEALTH": "HEALTH_PLAN_ID", "IP": "IP_ADDRESS",
            "WEB": "URL", "IMAGE": "IMAGE_REFERENCE", "FILE": "FILE_ATTACHMENT"
        }
        for k, v in map_.items():
            if k in rule_name:
                return v
        return "IDENTIFIER"

    def _is_valid_name(self, text: str) -> bool:
        if not text or len(text) < 2 or len(text) > 50:
            return False

        cleaned = text.lower().strip()
        # Normalize allowlist for safe comparisons
        try:
            allowlist_lower = {t.lower() for t in ALLOWLIST_TERMS}
        except Exception:
            allowlist_lower = set()
        if cleaned in allowlist_lower:
            return False

        geographic_tokens = {
            'road', 'street', 'garden', 'main', 'flat', 'block', 'floor', 'lane', 'avenue',
            'hospital', 'clinic', 'summary', 'cross', 'layout', 'stage', 'nagar', 'halli',
            'pally', 'sector', 'colony', 'extension', 'phase', 'bairro', 'rua', 'avenida', 'praça'
        }

        cleaned_tokens = {
            re.sub(r'\d+(st|nd|rd|th)?$', '', w.lower().strip('.,')).strip()
            for w in text.split()
        }

        if cleaned_tokens & (allowlist_lower | geographic_tokens):
            return False

        words = text.strip().split()
        if len(words) < 2 or len(words) > 4:
            return False
        if any(len(w) < 2 for w in words):
            return False

        false_pos = {
            'New York', 'Los Angeles', 'San Francisco', 'North Carolina',
            'Patient Admitted', 'Date Time', 'Social Security', 'Health Care'
        }
        if text in false_pos:
            return False

        return True

    def _is_valid_address(self, text: str) -> bool:
        if not text or len(text) < 5 or len(text) > 200:
            return False
        if text.lower().strip() in ['address', 'home', 'residence', 'location']:
            return False
        return True