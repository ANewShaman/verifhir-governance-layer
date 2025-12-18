from verifhir.rules.base_free_text_identifier_rule import BaseFreeTextIdentifierRule

class UKGDPRFreeTextIdentifierRule(BaseFreeTextIdentifierRule):
    """
    Enforces UK GDPR Article 5(1)(c) using the standard identifier logic.
    """
    REGULATION = "UK_GDPR"
    CITATION = "UK GDPR Article 5(1)(c) - Data Minimisation"
    DESCRIPTION = "Identifying information found in free-text field (UK jurisdiction)."