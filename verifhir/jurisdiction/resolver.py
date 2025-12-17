from typing import List, Dict, Optional
from .schemas import JurisdictionContext, JurisdictionResolution
from verifhir.regulations.loader import load_adequacy_snapshot


# Architectural policy: deterministic strictness hierarchy
# Top = most restrictive = governing regulation
RESTRICTIVENESS_ORDER = ["GDPR", "HIPAA", "DPDP"]


def resolve_jurisdiction(
    source_country: str,
    destination_country: str,
    data_subject_country: str,
    intermediate_countries: Optional[List[str]] = None
) -> JurisdictionResolution:
    """
    Resolve applicable and governing regulatory frameworks using a
    versioned adequacy snapshot. Deterministic, explainable, auditable.
    """

    if intermediate_countries is None:
        intermediate_countries = []

    # 1. Load versioned policy snapshot
    snapshot = load_adequacy_snapshot("adequacy_v1.json")
    frameworks = snapshot["frameworks"]

    # 2. Extract regulatory scopes from snapshot
    gdpr_countries = set(frameworks["GDPR"]["countries"])
    hipaa_countries = set(frameworks["HIPAA"]["countries"])
    dpdp_countries = set(frameworks["DPDP"]["countries"])

    # All jurisdictions touched by the transfer
    touch_points = {source_country, destination_country}
    touch_points.update(intermediate_countries)

    applicable: List[str] = []
    reasoning: Dict[str, str] = {}

    # 3. Regulation triggers (cumulative)

    # GDPR — residency based (MVP scope)
    if data_subject_country in gdpr_countries:
        applicable.append("GDPR")
        reasoning["GDPR"] = frameworks["GDPR"]["notes"]

    # HIPAA — US healthcare origin
    if source_country in hipaa_countries:
        if "HIPAA" not in applicable:
            applicable.append("HIPAA")
            reasoning["HIPAA"] = frameworks["HIPAA"]["notes"]

    # DPDP — any touchpoint involving India
    if not dpdp_countries.isdisjoint(touch_points):
        if "DPDP" not in applicable:
            applicable.append("DPDP")
            reasoning["DPDP"] = frameworks["DPDP"]["notes"]

    # 4. Determine governing regulation (most restrictive wins)
    governing: Optional[str] = None

    for rule in RESTRICTIVENESS_ORDER:
        if rule in applicable:
            governing = rule
            break

    # Defensive fallback (future-proofing)
    if governing is None and applicable:
        governing = applicable[0]

    # Normalize order for deterministic output
    applicable = sorted(applicable)

    return JurisdictionResolution(
        context=JurisdictionContext(
            source_country=source_country,
            destination_country=destination_country,
            data_subject_country=data_subject_country,
            intermediate_countries=intermediate_countries
        ),
        applicable_regulations=applicable,
        reasoning=reasoning,
        regulation_snapshot_version=snapshot["snapshot_version"],
        governing_regulation=governing
    )
