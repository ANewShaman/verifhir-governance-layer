from verifhir.ml.presidio_phi import detect_phi_presidio
from verifhir.models.violation import ViolationSeverity


def test_presidio_augments_when_azure_flagged():
    text = "Patient MRN is 12345678"
    violations = detect_phi_presidio(
        text=text,
        field_path="Observation.note",
        azure_flagged=True
    )
    assert len(violations) >= 1
    assert violations[0].severity == ViolationSeverity.MAJOR


def test_presidio_ignored_without_azure_or_free_text():
    text = "MRN 12345678"
    violations = detect_phi_presidio(
        text=text,
        field_path="Patient.name",
        azure_flagged=False
    )
    assert violations == []


def test_presidio_weight_never_critical():
    text = "Device ID XYZ-999"
    violations = detect_phi_presidio(
        text=text,
        field_path="DiagnosticReport.conclusion",
        azure_flagged=True
    )
    for v in violations:
        assert v.severity != ViolationSeverity.CRITICAL
