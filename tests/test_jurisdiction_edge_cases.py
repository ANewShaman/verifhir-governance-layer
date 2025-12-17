from verifhir.jurisdiction.resolver import resolve_jurisdiction


def test_no_applicable_regulations():
    """Verify system handles 'lawless' zones safely."""
    result = resolve_jurisdiction(
        source_country="BR",
        destination_country="JP",
        data_subject_country="JP"
    )

    assert result.applicable_regulations == []
    assert result.governing_regulation is None


def test_single_regulation_only():
    """Verify simple US → Canada flow."""
    result = resolve_jurisdiction(
        source_country="US",
        destination_country="CA",
        data_subject_country="CA"
    )

    assert result.applicable_regulations == ["HIPAA"]
    assert result.governing_regulation == "HIPAA"


def test_gdpr_supremacy():
    """
    US hospital sends data of a German patient.
    Both HIPAA and GDPR apply. GDPR must govern.
    """
    result = resolve_jurisdiction(
        source_country="US",
        destination_country="US",
        data_subject_country="DE"
    )

    assert "GDPR" in result.applicable_regulations
    assert "HIPAA" in result.applicable_regulations
    assert result.governing_regulation == "GDPR"


def test_dpdp_trigger_via_intermediate():
    """
    US → India (server) → Singapore.
    DPDP applies, but HIPAA governs.
    """
    result = resolve_jurisdiction(
        source_country="US",
        destination_country="SG",
        data_subject_country="US",
        intermediate_countries=["IN"]
    )

    assert "DPDP" in result.applicable_regulations
    assert "HIPAA" in result.applicable_regulations
    assert result.governing_regulation == "HIPAA"
