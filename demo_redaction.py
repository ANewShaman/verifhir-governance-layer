import logging
import json
import time
from verifhir.remediation.redactor import RedactionEngine

# Setup clean logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("verifhir.test")

def print_separator(title):
    print(f"\n{'-'*60}")
    print(f"TEST SCENARIO: {title}")
    print(f"{'-'*60}")

def run_tests():
    print("\n[SYSTEM] Initializing Redaction Engine...")
    engine = RedactionEngine()

    # --- SCENARIO 1: HIPAA (Aggressive Redaction) ---
    print_separator("HIPAA Compliance (USA)")
    clinical_text = (
        "Patient John Doe (DOB: 05/12/1980) arrived at Mt. Sinai Hospital "
        "complaining of chest pain. SSN: 123-45-6789. "
        "Admitted to Ward 4B on Jan 12, 2024."
    )
    print(f"INPUT:\n{clinical_text}\n")
    
    start = time.time()
    result = engine.generate_suggestion(clinical_text, "HIPAA")
    duration = time.time() - start

    print(f"OUTPUT SUGGESTION:\n{result['suggested_redaction']}")
    print(f"\nMETADATA:")
    print(f" - Method: {result['remediation_method']}")
    print(f" - Latency: {duration:.2f}s")
    print(f" - Authoritative: {result['is_authoritative']} (PASS if False)")
    print(f" - Audit Key: {result['audit_metadata']['regulation_context']}")

    # --- SCENARIO 2: GDPR (Contextual Redaction) ---
    print_separator("GDPR Compliance (Germany)")
    # Same text, different rules
    print(f"INPUT:\n{clinical_text}\n")
    
    result = engine.generate_suggestion(clinical_text, "GDPR", "DE")
    
    print(f"OUTPUT SUGGESTION:\n{result['suggested_redaction']}")
    print(f"\nANALYSIS:")
    print("Check: Did it preserve context (e.g. 'Patient A' or dates)?")
    print(f"Method Used: {result['remediation_method']}")

    # --- SCENARIO 3: Input Validation (Empty/Malicious) ---
    print_separator("Input Validation Check")
    empty_input = "   "
    print(f"INPUT: '{empty_input}' (Whitespace only)")
    
    result = engine.generate_suggestion(empty_input, "HIPAA")
    
    print(f"OUTPUT: '{result['suggested_redaction']}'")
    print(f"Method: {result['remediation_method']}")
    
    if result['remediation_method'] == "No-Op (Empty Input)":
        print("RESULT: PASS (System correctly rejected waste)")
    else:
        print("RESULT: FAIL (System processed empty text)")

    # --- SCENARIO 4: Disaster Recovery (Simulated Outage) ---
    print_separator("Fail-Safe Mode (Simulated Service Outage)")
    
    # We deliberately break the client to simulate an Azure outage
    print("[SYSTEM] Simulating network failure by disconnecting client...")
    real_client = engine.client
    engine.client = None  # Force offline mode
    
    result = engine.generate_suggestion("Patient John Doe (ID: 99999)", "HIPAA")
    
    print(f"OUTPUT: {result['suggested_redaction']}")
    print(f"Method: {result['remediation_method']}")
    
    if "Static Fallback" in result['remediation_method']:
        print("RESULT: PASS (System safely degraded to rules)")
    else:
        print("RESULT: FAIL (System crashed or used AI when offline)")

    # Restore client just in case
    engine.client = real_client

if __name__ == "__main__":
    run_tests()