from verifhir.jurisdiction.resolver import resolve_jurisdiction


def test_eu_to_us_to_india():
    result = resolve_jurisdiction(
        source_country="US",
        destination_country="IN",
        data_subject_country="DE"
    )

    assert "GDPR" in result.applicable_regulations
    assert "HIPAA" in result.applicable_regulations
    assert "DPDP" in result.applicable_regulations

    assert "GDPR" in result.reasoning
    assert "HIPAA" in result.reasoning
    assert "DPDP" in result.reasoning

    # Governance guarantee: decision is bound to a snapshot
    assert result.regulation_snapshot_version.startswith("adequacy_v1")
