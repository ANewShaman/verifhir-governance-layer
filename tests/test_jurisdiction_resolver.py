from verifhir.jurisdiction.resolver import resolve_jurisdiction
from verifhir.jurisdiction.schemas import GoverningRule


def test_multihop_all_regulations_apply_most_restrictive_wins():
    """
    EU data subject, US source, transfer path touches India.
    All regulations apply; GDPR must govern.
    """
    result = resolve_jurisdiction(
        source_country="US",
        destination_countries=["GB", "IN"],
        data_subject_country="DE"
    )

    assert set(result.applicable_regulations) == {"GDPR", "HIPAA", "DPDP"}
    assert result.governing_regulation == GoverningRule.GDPR
    assert result.regulation_snapshot_version == "adequacy_v1_2025-01-01"


def test_single_hop_us_to_india_with_eu_subject():
    """
    Single-hop transfer still works via list abstraction.
    """
    result = resolve_jurisdiction(
        source_country="US",
        destination_countries=["IN"],
        data_subject_country="FR"
    )

    assert set(result.applicable_regulations) == {"GDPR", "HIPAA", "DPDP"}
    assert result.governing_regulation == GoverningRule.GDPR


def test_us_to_us_non_eu_subject_hipaa_only():
    """
    US-only transfer with non-EU data subject.
    HIPAA should apply and govern.
    """
    result = resolve_jurisdiction(
        source_country="US",
        destination_countries=["US"],
        data_subject_country="CA"
    )

    assert result.applicable_regulations == ["HIPAA"]
    assert result.governing_regulation == GoverningRule.HIPAA


def test_eu_subject_non_us_non_india_transfer_gdpr_only():
    """
    EU resident, transfer path excludes US and India.
    GDPR applies due to residency.
    """
    result = resolve_jurisdiction(
        source_country="JP",
        destination_countries=["SG"],
        data_subject_country="IT"
    )

    assert result.applicable_regulations == ["GDPR"]
    assert result.governing_regulation == GoverningRule.GDPR


def test_unregulated_transfer_defaults_to_none():
    """
    No countries involved trigger any regulation.
    System must not crash and must return NONE.
    """
    result = resolve_jurisdiction(
        source_country="BR",
        destination_countries=["ZA"],
        data_subject_country="JP"
    )

    assert result.applicable_regulations == []
    assert result.governing_regulation == GoverningRule.NONE
