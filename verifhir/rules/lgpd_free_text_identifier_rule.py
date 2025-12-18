from verifhir.rules.base_free_text_identifier_rule import BaseFreeTextIdentifierRule

class LGPDFreeTextIdentifierRule(BaseFreeTextIdentifierRule):
    """
    Enforces LGPD Article 6 (Principles).
    Uses the shared regex which now supports 'CPF'.
    """
    REGULATION = "LGPD"
    CITATION = "LGPD Article 6 - Data Minimisation"
    DESCRIPTION = "Personal identifier (e.g., CPF) detected in free text."