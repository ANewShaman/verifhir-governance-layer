import os
from typing import List
from dotenv import load_dotenv

from azure.ai.textanalytics import TextAnalyticsClient
from azure.core.credentials import AzureKeyCredential

from verifhir.models.violation import Violation, ViolationSeverity

# Load environment variables
load_dotenv()


class AzurePHIEngine:
    """
    Azure AI Language PHI detector.

    IMPORTANT DESIGN CONSTRAINTS:
    - Azure is ASSISTIVE, not authoritative.
    - This engine NEVER returns raw SDK objects.
    - All outputs are normalized into Violation objects.
    - Severity is conservative and policy-agnostic.
    """

    def detect_phi(self, text: str, field_path: str) -> List[Violation]:
        """
        Detect PHI/PII in free text using Azure AI Language.

        Returns:
            List[Violation]: Canonical violation objects suitable for fusion.
        """

        # Basic input guard
        if not text or not isinstance(text, str):
            return []

        key = os.getenv("AZURE_LANGUAGE_KEY")
        endpoint = os.getenv("AZURE_LANGUAGE_ENDPOINT")

        # Fail-safe: no credentials, no detection
        if not key or not endpoint or "PLACEHOLDER" in key:
            print("⚠️ [Azure AI] Keys missing or placeholder. Skipping Azure detection.")
            return []

        try:
            client = TextAnalyticsClient(
                endpoint=endpoint,
                credential=AzureKeyCredential(key),
            )

            # Force language to avoid scoring variance during demos/judging
            response = client.recognize_pii_entities(
                [text],
                language="en",
            )[0]

            if response.is_error:
                print(f"[Azure AI] Error: {response.error.code}")
                return []

            violations: List[Violation] = []

            for entity in response.entities:
                # Conservative severity mapping
                # Azure confidence ≠ legal criticality
                if entity.confidence_score >= 0.85:
                    severity = ViolationSeverity.MAJOR
                else:
                    severity = ViolationSeverity.MINOR

                violations.append(
                    Violation(
                        violation_type=entity.category,
                        severity=severity,
                        regulation="General Privacy",
                        citation="Azure AI Language Detection",
                        field_path=field_path,
                        description=f"Azure AI detected {entity.category}",
                        detection_method="ml-primary",
                        confidence=entity.confidence_score,
                    )
                )

            return violations

        except Exception as e:
            print(f"[Azure AI] Connection failed: {e}")
            return []
