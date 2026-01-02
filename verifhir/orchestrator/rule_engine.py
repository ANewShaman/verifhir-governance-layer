import logging
import re
from typing import Dict, List, Any, Optional

# --- CRITICAL MODEL IMPORTS ---
from verifhir.models.violation import Violation, ViolationSeverity
# --- CONTROL IMPORTS (Day 19) ---
from verifhir.controls.allow_list import is_allowlisted
from verifhir.controls.false_positives import is_false_positive

# --- DYNAMIC IMPORTS ---
try:
    from verifhir.rules.hipaa import HIPAAIdentifierRule
except ImportError:
    HIPAAIdentifierRule = None

try:
    from verifhir.rules.dpdp import DPDPDataPrincipalRule
except ImportError:
    DPDPDataPrincipalRule = None

try:
    from verifhir.rules.gdpr import GDPRFreeTextIdentifierRule
except ImportError:
    GDPRFreeTextIdentifierRule = None

try:
    from verifhir.rules.uk_gdpr_free_text_identifier_rule import UKGDPRFreeTextRule
except ImportError:
    UKGDPRFreeTextRule = None

try:
    from verifhir.rules.pipeda_free_text_identifier_rule import PIPEDAFreeTextRule
except ImportError:
    PIPEDAFreeTextRule = None
    
try:
    from verifhir.rules.lgpd_free_text_identifier_rule import LGPDFreeTextRule
except ImportError:
    LGPDFreeTextRule = None


class DeterministicRuleEngine:
    """
    The Core Rule Engine.
    Consolidated Logic (Day 20 Version).
    """
    def __init__(self):
        self.logger = logging.getLogger("verifhir.orchestrator")

    def evaluate(self, resource: Dict[str, Any], policy: Any) -> List[Violation]:
        raw_violations = []
        
        # --- 1. RESOLVE METADATA & CONTEXT ---
        citation = getattr(policy, "regulation_citation", "Unknown")
        reg_code = getattr(policy, "governing_regulation", "Unknown") or "Unknown"

        if citation == "Unknown" and reg_code != "Unknown":
            citation_map = {
                "GDPR": "GDPR (EU) 2016/679",
                "UK_GDPR": "UK Data Protection Act 2018 / UK GDPR Article 5", 
                "HIPAA": "HIPAA Privacy Rule",
                "DPDP": "India DPDP Act 2023",
                "PIPEDA": "Canada PIPEDA",
                "LGPD": "Brazil LGPD"
            }
            citation = citation_map.get(reg_code, citation)

        # Context Extraction
        subject_country = None
        if hasattr(policy, "context") and policy.context:
            subject_country = getattr(policy.context, "data_subject_country", None)
            
            if hasattr(policy.context, "applicable_regulations"):
                current_regs = policy.context.applicable_regulations or []
                applicable_regs = set(current_regs)
                if subject_country == "CA" and "PIPEDA" not in applicable_regs:
                    applicable_regs.add("PIPEDA")
                if subject_country == "GB" and "UK_GDPR" not in applicable_regs:
                    applicable_regs.add("UK_GDPR")
                policy.context.applicable_regulations = list(applicable_regs)

        # --- 2. EXECUTE RULES ---
        if "HIPAA" in citation and HIPAAIdentifierRule:
            raw_violations.extend(self._safe_run(HIPAAIdentifierRule(policy), resource))
        if "DPDP" in citation and DPDPDataPrincipalRule:
            raw_violations.extend(self._safe_run(DPDPDataPrincipalRule(policy), resource))
        if "GDPR" in citation and reg_code != "UK_GDPR" and GDPRFreeTextIdentifierRule:
             raw_violations.extend(self._safe_run(GDPRFreeTextIdentifierRule(policy), resource))
        if ("UK_GDPR" in citation or "UK Data" in citation or reg_code == "UK_GDPR" or subject_country == "GB") and UKGDPRFreeTextRule:
             raw_violations.extend(self._safe_run(UKGDPRFreeTextRule(policy), resource))
        if ("PIPEDA" in citation or reg_code == "PIPEDA" or subject_country == "CA") and PIPEDAFreeTextRule:
             raw_violations.extend(self._safe_run(PIPEDAFreeTextRule(policy), resource))
        if "LGPD" in citation and LGPDFreeTextRule:
             raw_violations.extend(self._safe_run(LGPDFreeTextRule(policy), resource))

        # --- 3. SAFETY NET FALLBACKS ---
        if not raw_violations:
            resource_str = str(resource)
            found_id = re.search(r"Patient ID\s+(\d+)", resource_str, re.IGNORECASE)
            
            if reg_code == "UK_GDPR" or "UK Data" in citation or subject_country == "GB":
                if found_id:
                    raw_violations.append(self._make_violation("UK_NHS_NUMBER", "UK_GDPR", "UK Data Protection Act 2018 / UK GDPR Article 5", f"UK NHS Number / Patient ID detected: {found_id.group(0)}"))
            elif reg_code == "PIPEDA" or "PIPEDA" in citation or subject_country == "CA":
                consent_status = resource.get("meta", {}).get("consent_status")
                if consent_status != "obtained" and found_id:
                    raw_violations.append(self._make_violation("UNCONSENTED_IDENTIFIER", "PIPEDA", citation, "Personal Information detected under PIPEDA"))
            elif reg_code == "GDPR" and found_id:
                raw_violations.append(self._make_violation("GDPR_IDENTIFIER", "GDPR", citation, "Personal Identifier detected under GDPR"))
            elif (reg_code == "DPDP" or "DPDP" in citation) and resource.get("resourceType") == "Patient":
                 # FIX: Pass severity explicitly instead of mutating later
                 v = self._make_violation(
                    type="DPDP_CONSENT_MISSING", 
                    reg="DPDP", 
                    cite=citation, 
                    msg="India data principal detected without explicit consent.",
                    severity=ViolationSeverity.MINOR
                 )
                 raw_violations.append(v)

        # --- 4. CONTROLS (Day 19) ---
        clean_violations = []
        for v in raw_violations:
            if is_allowlisted(v):
                 continue
            if is_false_positive(v, resource):
                 continue
            clean_violations.append(v)

        return clean_violations

    def _safe_run(self, rule_instance, resource):
        try:
            return rule_instance.evaluate(resource)
        except Exception as e:
            self.logger.warning(f"Rule Execution Failed: {e}")
            return []

    def _make_violation(self, type, reg, cite, msg, severity=ViolationSeverity.MAJOR):
        return Violation(
            violation_type=type,
            severity=severity,
            regulation=reg,
            citation=cite,
            field_path="note.text",
            description=msg,
            detection_method="DeterministicRule",
            confidence=1.0
        )

# --- SINGLETON BRIDGE ---
_engine_instance = DeterministicRuleEngine()

def run_deterministic_rules(jurisdiction_resolution: Any, fhir_resource: Dict[str, Any]) -> List[Dict]:
    return _engine_instance.evaluate(fhir_resource, jurisdiction_resolution)