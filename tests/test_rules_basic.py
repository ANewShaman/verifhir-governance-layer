from verifhir.rules.gdpr import GDPRFreeTextIdentifierRule


def test_gdpr_rule_detects_numeric_text():
    rule = GDPRFreeTextIdentifierRule()

    fake_fhir = {
        "note": [
            {"text": "Patient ID 12345 reported symptoms"}
        ]
    }

    violations = rule.evaluate(fake_fhir)

    assert len(violations) == 1
    assert violations[0].regulation == "GDPR"
