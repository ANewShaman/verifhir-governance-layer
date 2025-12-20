from verifhir.ml.azure_phi import detect_phi

def test_azure_phi_smoke():
    text = "Patient John Doe with ID 12345 visited yesterday."
    entities = detect_phi(text)

    # If keys are missing, entities == []
    # If keys exist, entities may contain PII spans
    assert isinstance(entities, list)
