import logging
import json
import time
from verifhir.remediation.redactor import RedactionEngine

# --- VISUAL STYLING (ANSI CODES) ---
class Color:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Setup clean logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("verifhir.test")

def print_separator(title):
    print(f"\n{Color.CYAN}{'-'*60}{Color.END}")
    print(f"{Color.BOLD}{Color.CYAN}TEST SCENARIO: {title}{Color.END}")
    print(f"{Color.CYAN}{'-'*60}{Color.END}")

def run_tests():
    print(f"\n{Color.BLUE}[SYSTEM] Initializing Redaction Engine...{Color.END}")
    engine = RedactionEngine()

    # --- SCENARIO 1: HIPAA (Aggressive Redaction) ---
    print_separator("HIPAA Compliance (USA)")
    clinical_text = (
        "Patient John Doe (DOB: 05/12/1980) arrived at Mt. Sinai Hospital "
        "complaining of chest pain. SSN: 123-45-6789. "
        "Admitted to Ward 4B on Jan 12, 2024."
    )
    print(f"{Color.YELLOW}INPUT:\n{clinical_text}{Color.END}\n")
    
    start = time.time()
    result = engine.generate_suggestion(clinical_text, "HIPAA")
    duration = time.time() - start

    print(f"{Color.GREEN}OUTPUT SUGGESTION:\n{result['suggested_redaction']}{Color.END}")
    print(f"\n{Color.BOLD}METADATA:{Color.END}")
    # FIXED: Changed Color.Blue to Color.BLUE
    print(f" - Method: {Color.BLUE}{result['remediation_method']}{Color.END}")
    print(f" - Latency: {duration:.2f}s")
    
    # Visual check for Authoritative flag
    auth_color = Color.RED if result['is_authoritative'] else Color.GREEN
    print(f" - Authoritative: {auth_color}{result['is_authoritative']} (PASS if False){Color.END}")
    print(f" - Audit Key: {result['audit_metadata']['regulation_context']}")

    # --- SCENARIO 2: GDPR (Contextual Redaction) ---
    print_separator("GDPR Compliance (Germany)")
    # Same text, different rules
    print(f"{Color.YELLOW}INPUT:\n{clinical_text}{Color.END}\n")
    
    result = engine.generate_suggestion(clinical_text, "GDPR", "DE")
    
    print(f"{Color.GREEN}OUTPUT SUGGESTION:\n{result['suggested_redaction']}{Color.END}")
    print(f"\n{Color.BOLD}ANALYSIS:{Color.END}")
    print("Check: Did it preserve context (e.g. 'Patient A' or dates)?")
    print(f"Method Used: {Color.BLUE}{result['remediation_method']}{Color.END}")

    # --- SCENARIO 3: Input Validation (Empty/Malicious) ---
    print_separator("Input Validation Check")
    empty_input = "   "
    print(f"{Color.YELLOW}INPUT: '{empty_input}' (Whitespace only){Color.END}")
    
    result = engine.generate_suggestion(empty_input, "HIPAA")
    
    print(f"OUTPUT: '{result['suggested_redaction']}'")
    print(f"Method: {result['remediation_method']}")
    
    if result['remediation_method'] == "No-Op (Empty Input)":
        print(f"{Color.BOLD}{Color.GREEN}RESULT: PASS (System correctly rejected waste){Color.END}")
    else:
        print(f"{Color.BOLD}{Color.RED}RESULT: FAIL (System processed empty text){Color.END}")

    # --- SCENARIO 4: Disaster Recovery (Simulated Outage) ---
    print_separator("Fail-Safe Mode (Simulated Service Outage)")
    
    # We deliberately break the client to simulate an Azure outage
    print(f"{Color.RED}[SYSTEM] Simulating network failure by disconnecting client...{Color.END}")
    real_client = engine.client
    engine.client = None  # Force offline mode
    
    result = engine.generate_suggestion("Patient John Doe (ID: 99999)", "HIPAA")
    
    print(f"OUTPUT: {result['suggested_redaction']}")
    print(f"Method: {Color.BLUE}{result['remediation_method']}{Color.END}")
    
    if "Static Fallback" in result['remediation_method']:
        print(f"{Color.BOLD}{Color.GREEN}RESULT: PASS (System safely degraded to rules){Color.END}")
    else:
        print(f"{Color.BOLD}{Color.RED}RESULT: FAIL (System crashed or used AI when offline){Color.END}")

    # Restore client just in case
    engine.client = real_client

if __name__ == "__main__":
    run_tests()