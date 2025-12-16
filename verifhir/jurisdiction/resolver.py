from typing import List, Dict
from .schemas import JurisdictionContext, JurisdictionResolution


# Static regulatory triggers (explicit and conservative)
GDPR_COUNTRIES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE"
}

HIPAA_COUNTRY = "US"
DPDP_COUNTRY = "IN"


def resolve_jurisdiction(
    source_country: str,
    destination_country: str,
    data_subject_country: str
) -> JurisdictionResolution:
    """
    Resolve which regulatory frameworks apply to a dataset transfer.
    This function is deterministic and does not perform legal interpretation.
    """

    context = JurisdictionContext(
        source_country=source_country,
        destination_country=destination_country,
        data_subject_country=data_subject_country
    )

    applicable: List[str] = []
    reasoning: Dict[str, str] = {}

    # GDPR trigger: data subject residency
    if data_subject_country in GDPR_COUNTRIES:
        applicable.append("GDPR")
        reasoning["GDPR"] = (
            "Applies because the data subject is a resident of the European Union."
        )

    # HIPAA trigger: source country
    if source_country == HIPAA_COUNTRY:
        applicable.append("HIPAA")
        reasoning["HIPAA"] = (
            "Applies because the data originates from the United States healthcare system."
        )

    # DPDP trigger: destination country
    if destination_country == DPDP_COUNTRY:
        applicable.append("DPDP")
        reasoning["DPDP"] = (
            "Applies because the data is transferred to India, invoking DPDP obligations."
        )

    return JurisdictionResolution(
        context=context,
        applicable_regulations=applicable,
        reasoning=reasoning
    )
