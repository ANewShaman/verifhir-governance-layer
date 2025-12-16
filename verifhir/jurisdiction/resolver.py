from typing import List, Dict
from verifhir.regulations.loader import load_adequacy_snapshot
from verifhir.jurisdiction.schemas import (
    JurisdictionContext,
    JurisdictionResolution,
    GoverningRule,
)

# Deterministic company policy:
# Order defines which regulation governs when multiple apply.
RESTRICTIVENESS_ORDER = [
    "GDPR",
    "HIPAA",
    "DPDP",
]


def resolve_jurisdiction(
    source_country: str,
    destination_countries: List[str],
    data_subject_country: str
) -> JurisdictionResolution:
    """
    Resolve applicable and governing regulatory frameworks for a
    potentially multi-hop cross-border data transfer.

    This function is:
    - Deterministic
    - Snapshot-driven
    - Replayable
    - Free of legal interpretation
    """

    # 1. Load versioned regulatory snapshot (policy as data)
    snapshot = load_adequacy_snapshot("adequacy_v1.json")
    frameworks = snapshot["frameworks"]

    # 2. Extract scope data from snapshot
    gdpr_countries = set(frameworks["GDPR"]["countries"])
    hipaa_countries = set(frameworks["HIPAA"]["countries"])
    dpdp_countries = set(frameworks["DPDP"]["countries"])

    # 3. Build factual context (descriptive only)
    context = JurisdictionContext(
        source_country=source_country,
        destination_country=" → ".join(destination_countries),
        data_subject_country=data_subject_country,
    )

    applicable = set()
    reasoning: Dict[str, str] = {}

    # 4. Apply deterministic applicability rules

    # GDPR — based on data subject residency
    if data_subject_country in gdpr_countries:
        applicable.add("GDPR")
        reasoning["GDPR"] = frameworks["GDPR"]["notes"]

    # HIPAA — based on source country
    if source_country in hipaa_countries:
        applicable.add("HIPAA")
        reasoning["HIPAA"] = frameworks["HIPAA"]["notes"]

    # DPDP — if any hop touches India
    for hop in destination_countries:
        if hop in dpdp_countries:
            applicable.add("DPDP")
            reasoning["DPDP"] = frameworks["DPDP"]["notes"]
            break

    # 5. Determine governing regulation (most restrictive wins)
    governing = GoverningRule.NONE

    for rule in RESTRICTIVENESS_ORDER:
        if rule in applicable:
            governing = GoverningRule(rule)
            break

    # 6. Return immutable, auditable resolution
    return JurisdictionResolution(
        context=context,
        applicable_regulations=sorted(applicable),
        governing_regulation=governing,
        reasoning=reasoning,
        regulation_snapshot_version=snapshot["snapshot_version"],
    )
