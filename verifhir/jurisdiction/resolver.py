import os
import json
from typing import List, Optional
from verifhir.jurisdiction.schemas import JurisdictionContext, JurisdictionResolution

# --- CONFIGURATION ---
SNAPSHOT_DIR = os.path.join(os.path.dirname(__file__), "..", "regulations", "snapshots")
DEFAULT_SNAPSHOT = "adequacy_v2.json"

# UPDATED: Global Hierarchy (Most Restrictive -> Least)
RESTRICTIVENESS_ORDER = [
    "GDPR",
    "UK_GDPR",
    "LGPD",
    "HIPAA",
    "PIPEDA",
    "APPI",
    "POPIA",
    "UAE_PDPL",
    "MY_HEALTH_RECORDS_AU",
    "DPDP"
]

def _load_snapshot(filename: str) -> dict:
    path = os.path.join(SNAPSHOT_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Regulation snapshot not found: {path}")
    with open(path, "r") as f:
        return json.load(f)

def resolve_jurisdiction(
    source_country: str,
    destination_country: str,
    data_subject_country: str,
    snapshot_version: str = DEFAULT_SNAPSHOT
) -> JurisdictionResolution:
    
    snapshot = _load_snapshot(snapshot_version)
    regs_db = snapshot["regulations"]
    
    applicable = set()
    reasoning = {}

    # --- 1. DETECT APPLICABLE REGULATIONS ---
    # Note: Explicit checks used for transparency. 
    # In production, this would loop through regs_db.items().

    # GDPR (EU Residents)
    if data_subject_country in regs_db["GDPR"]["countries"]:
        applicable.add("GDPR")
        reasoning["GDPR"] = "EU residency triggers GDPR scope."

    # UK GDPR (GB Residents)
    if data_subject_country in regs_db["UK_GDPR"]["countries"]:
        applicable.add("UK_GDPR")
        reasoning["UK_GDPR"] = "UK residency triggers UK GDPR scope."

    # HIPAA (US Origin)
    if source_country == "US":
        applicable.add("HIPAA")
        reasoning["HIPAA"] = "US origin implies HIPAA covered entity context."

    # DPDP (India Processing)
    if destination_country == "IN" or source_country == "IN":
        applicable.add("DPDP")
        reasoning["DPDP"] = "Processing within India triggers DPDP Act."
        
    # PIPEDA (Canada)
    if data_subject_country == "CA" or destination_country == "CA":
        applicable.add("PIPEDA")
        reasoning["PIPEDA"] = "Canadian commercial data context."

    # LGPD (Brazil)
    if data_subject_country == "BR" or destination_country == "BR":
        applicable.add("LGPD")
        reasoning["LGPD"] = "Brazilian data processing context."

    # --- TIER 2 (Scope Only) ---
    if data_subject_country == "JP" or destination_country == "JP":
        applicable.add("APPI")
        reasoning["APPI"] = "Japanese personal information scope."

    if data_subject_country == "ZA" or destination_country == "ZA":
        applicable.add("POPIA")
        reasoning["POPIA"] = "South African data subject scope."

    if destination_country == "AE":
        applicable.add("UAE_PDPL")
        reasoning["UAE_PDPL"] = "UAE processing context."

    if data_subject_country == "AU":
        applicable.add("MY_HEALTH_RECORDS_AU")
        reasoning["MY_HEALTH_RECORDS_AU"] = "Australian health record context."

    # --- 2. DETERMINE GOVERNING REGULATION ---
    sorted_regs = sorted(
        list(applicable),
        key=lambda r: RESTRICTIVENESS_ORDER.index(r) if r in RESTRICTIVENESS_ORDER else 99
    )
    
    # CRITICAL FIX: Return None if no regulation applies, do not guess "UNCERTAIN"
    governing = sorted_regs[0] if sorted_regs else None

    return JurisdictionResolution(
        context=JurisdictionContext(source_country, destination_country, data_subject_country),
        applicable_regulations=sorted_regs,
        reasoning=reasoning,
        regulation_snapshot_version=snapshot_version,
        governing_regulation=governing
    )