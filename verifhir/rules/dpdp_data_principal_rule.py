from typing import List
from verifhir.rules.base_rule import ComplianceRule
from verifhir.models.violation import Violation, ViolationSeverity

class DPDPDataPrincipalRule(ComplianceRule):
    """
    Enforces India DPDP Act regarding consent for Data Principals.
    """
    def evaluate(self, resource: dict) -> List[Violation]:
        if "DPDP" not in self.context.applicable_regulations:
            return []
        
        violations = []
        
        # Logic: If address is in India, strictly check for consent provenance
        if resource.get("resourceType") == "Patient":
            for addr in resource.get("address", []):
                if addr.get("country") == "IN":
                    # Check for explicit consent metadata
                    consent = resource.get("meta", {}).get("consent_status")
                    if consent != "obtained":
                        violations.append(Violation(
                            violation_type="DPDP_CONSENT_MISSING",
                            severity=ViolationSeverity.MINOR, # Minor because it's metadata, not a leak
                            regulation="DPDP",
                            citation="DPDP Act Section 6",
                            field_path="Patient.address",
                            description="India data principal detected without explicit consent artifact.",
                            detection_method="rule-based"
                        ))
        return violations