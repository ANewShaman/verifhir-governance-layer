"""
False Positive Control
----------------------
Context-aware suppression logic.
"""
from typing import Dict, Any, Optional

def is_false_positive(violation: Any, resource: Optional[Dict] = None) -> bool:
    """
    Checks for context-based false positives (e.g. 'Page 12' vs 'Patient 12').
    """
    # If we don't have the resource, we can't do context checks.
    if not resource:
        return False

    resource_str = str(resource).lower()
    
    # Safely handle violation description
    desc_lower = ""
    if hasattr(violation, 'description') and violation.description:
        desc_lower = violation.description.lower()

    # Tightened suppression: suppress ONLY when explicit context mismatch exists
    # e.g., 'page' present and NO clinical keywords nearby.
    clinical_indicators = ["patient", "admit", "discharge", "mrn", "dob", "clinic", "hospital", "visit", "encounter", "age"]
    if "page" in resource_str and not any(k in resource_str for k in clinical_indicators):
         # If the violation is an Identifier type, suppression may be applied
         if hasattr(violation, 'violation_type') and ("identifier" in violation.violation_type.lower() or "id" in desc_lower):
             # Gate suppression by regulation strictness if available on violation
             reg = getattr(violation, 'regulation', '').upper() if hasattr(violation, 'regulation') else ''
             # HIPAA is strict — do not suppress under HIPAA
             if reg == 'HIPAA':
                 return False
             # For other regulations, allow suppression when clear non-clinical context
             return True

    return False