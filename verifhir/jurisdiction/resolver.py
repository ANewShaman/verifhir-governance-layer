from typing import List, Dict
from .schemas import JurisdictionContext, JurisdictionResolution
from verifhir.regulations.loader import load_adequacy_snapshot


def resolve_jurisdiction(
    source_country: str,
    destination_country: str,
    data_subject_country: str
) -> JurisdictionResolution:
    """
    Resolve applicable regulatory frameworks using a versioned adequacy snapshot.
    No regulatory scope is hardcoded in this function.
    """

    # 1. Load the snapshot (policy)
    snapshot = load_adequacy_snapshot("adequacy_v1.json")
    frameworks = snapshot["frameworks"]

    # 2. Extract scope data from snapshot
    gdpr_countries = set(frameworks["GDPR"]["countries"])
    hipaa_countries = set(frameworks["HIPAA"]["countries"])
    dpdp_countries = set(frameworks["DPDP"]["countries"])

    context = JurisdictionContext(
        source_country=source_country,
        destination_country=destination_country,
        data_subject_country=data_subject_country
    )

    applicable: List[str] = []
    reasoning: Dict[str, str] = {}

    # 3. Apply deterministic logic using snapshot data

    if data_subject_country in gdpr_countries:
        applicable.append("GDPR")
        reasoning["GDPR"] = frameworks["GDPR"]["notes"]

    if source_country in hipaa_countries:
        applicable.append("HIPAA")
        reasoning["HIPAA"] = frameworks["HIPAA"]["notes"]

    if destination_country in dpdp_countries:
        applicable.append("DPDP")
        reasoning["DPDP"] = frameworks["DPDP"]["notes"]

    return JurisdictionResolution(
        context=context,
        applicable_regulations=applicable,
        reasoning=reasoning,
        regulation_snapshot_version=snapshot["snapshot_version"]
    )
