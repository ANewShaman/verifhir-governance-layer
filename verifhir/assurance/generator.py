from typing import List
from verifhir.models.negative_assurance import NegativeAssertion
from verifhir.assurance.categories import ASSURABLE_CATEGORIES
from verifhir.assurance.sensor_map import SENSOR_SUPPORT
from verifhir.explainability.view import ExplainableViolation


def generate_negative_assertions(
    detections: List[ExplainableViolation],
    sensors_used: List[str],
) -> List[NegativeAssertion]:

    detected_categories = set()

    for v in detections:
        text = f"{v.description} {v.field_path}".lower()

        for category, keywords in ASSURABLE_CATEGORIES.items():
            for kw in keywords:
                if kw in text:
                    detected_categories.add(category)

    assertions: List[NegativeAssertion] = []

    for category in ASSURABLE_CATEGORIES.keys():
        if category in detected_categories:
            continue

        supporting_sensors = [
            sensor
            for sensor in sensors_used
            if category in SENSOR_SUPPORT.get(sensor, set())
        ]

        if not supporting_sensors:
            continue

        assertions.append(
            NegativeAssertion(
                category=category,
                status="NOT_DETECTED",
                supported_by=supporting_sensors,
                scope_note="Within detector coverage"
            )
        )

    return assertions
