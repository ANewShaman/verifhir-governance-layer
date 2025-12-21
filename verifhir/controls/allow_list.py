"""
Allowlist Control
-----------------
Simple, static set of allowed terms.
"""
from typing import Any

# Global set of terms that are always safe
ALLOWLIST_TERMS = {
    "support@verifhir.com",
    "admin@hospital.org",
    "protocol id",
    "page",
    "room",
    "bed",
    "version",
    "sample data"
}

def is_allowlisted(violation: Any) -> bool:
    """Checks if violation description contains allowed terms."""
    if not violation or not violation.description:
        return False
        
    desc_lower = violation.description.lower()
    for allowed in ALLOWLIST_TERMS:
        if allowed in desc_lower:
            return True
    return False