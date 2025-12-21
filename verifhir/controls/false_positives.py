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

    # False Positive: "Page 12" looking like an ID
    if "page" in resource_str and "patient" not in resource_str:
         # If the violation is an Identifier type, suppression is likely safe here
         if hasattr(violation, 'violation_type') and ("identifier" in violation.violation_type.lower() or "id" in desc_lower):
             return True

    return False