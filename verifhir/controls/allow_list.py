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
    "sample data",
    # Additional clinical / common place terms to avoid misclassification
    "emergency room",
    "history of",
    "follow up",
    "stable",
    "unremarkable",
    # common street/place words that may be mis-detected as names
    "road",
    "street",
    "main",
    "garden",
    "floor",
    "block",
    # additional geographic/place terms requested
    "flat",
    "lane",
    "avenue",
    "hospital",
    "clinic",
    "summary"
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