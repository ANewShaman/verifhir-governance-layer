from verifhir.rules.base_free_text_identifier_rule import BaseFreeTextIdentifierRule

class GDPRFreeTextIdentifierRule(BaseFreeTextIdentifierRule):
    """
    Enforces GDPR Article 5(1)(c) - Data Minimization.
    Refactored to use the shared BaseFreeTextIdentifierRule logic.
    """
    REGULATION = "GDPR"
    CITATION = "GDPR Article 5(1)(c)"
    DESCRIPTION = "Free-text field may contain identifying information."