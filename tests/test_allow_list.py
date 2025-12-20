from verifhir.controls.allow_list import ALLOWLIST


def test_allowlist_allows_registered_value():
    ALLOWLIST.register(
        field_path="Patient.identifier.value",
        values=["SAFE123"],
        regulation="HIPAA",
    )

    assert ALLOWLIST.is_allowed(
        field_path="Patient.identifier.value",
        value="SAFE123",
        regulation="HIPAA",
    ) is True


def test_allowlist_does_not_allow_unregistered_value():
    assert ALLOWLIST.is_allowed(
        field_path="Patient.identifier.value",
        value="UNSAFE999",
        regulation="HIPAA",
    ) is False


def test_global_allowlist_applies_to_any_regulation():
    ALLOWLIST.register(
        field_path="Observation.note.text",
        values=["RESEARCH_SAMPLE"],
        regulation="*",
    )

    assert ALLOWLIST.is_allowed(
        field_path="Observation.note.text",
        value="RESEARCH_SAMPLE",
        regulation="GDPR",
    ) is True
