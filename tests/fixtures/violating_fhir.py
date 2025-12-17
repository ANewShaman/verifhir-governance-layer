GDPR_VIOLATION_FHIR = {
    "resourceType": "Observation",
    "status": "final",
    "note": [
        {"text": "Patient ID 12345 reported symptoms."}
    ]
}

DPDP_VIOLATION_FHIR = {
    "resourceType": "Patient",
    "address": [
        {
            "line": ["221B Baker Street"],
            "city": "Mumbai",
            "country": "IN"
        }
    ]
}
