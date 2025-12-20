import os
from dotenv import load_dotenv
from azure.ai.textanalytics import TextAnalyticsClient
from azure.core.credentials import AzureKeyCredential

# Load environment variables from .env
load_dotenv()

class AzurePHIEngine:
    def detect_phi(self, text: str):
        """
        Uses Azure AI Language to detect PII/PHI.
        
        IMPORTANT:
        - This is an ASSISTIVE signal only.
        - It does NOT replace deterministic rules.
        - Fail-safe behavior: returns [] if unavailable.
        """

        key = os.getenv("AZURE_LANGUAGE_KEY")
        endpoint = os.getenv("AZURE_LANGUAGE_ENDPOINT")

        # Fail-safe: Missing or placeholder keys
        if not key or not endpoint or "PLACEHOLDER" in key:
            print("⚠️ [Azure AI] Keys missing or placeholder. Skipping AI detection.")
            return []

        try:
            client = TextAnalyticsClient(
                endpoint=endpoint,
                credential=AzureKeyCredential(key)
            )

            # NOTE:
            # We explicitly force language="en" for MVP demos.
            # Azure supports multilingual detection, but we freeze language
            # to avoid score variance during judging.
            response = client.recognize_pii_entities(
                [text],
                language="en"
            )[0]

            if response.is_error:
                print(f"[Azure AI] Error: {response.error.code}")
                return []

            # Return raw entities (caller decides what to do)
            return response.entities

        except Exception as e:
            print(f"[Azure AI] Connection Failed: {e}")
            return []