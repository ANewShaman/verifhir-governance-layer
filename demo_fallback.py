import logging
import json
from verifhir.remediation.redactor import RedactionEngine

# --- FAIL-SAFE RESILIENCE TEST ---
# Objective: Verify that the system degrades gracefully to deterministic
#            rules when the AI dependency is unreachable.

print("\n" + "="*60)
print("TEST: FAIL-SAFE BEHAVIOR (SIMULATED OUTAGE)")
print("="*60)

# 1. SETUP
print("\n[1] Initializing Redaction Engine...")
# Suppress connection logs for cleanliness during this specific test
logging.getLogger("verifhir.remediation").setLevel(logging.ERROR) 
engine = RedactionEngine()

# 2. DEFINE INPUT
# Contains specific patterns (SSN, Date, Email) known to the Regex Fallback Engine
risky_text = "Patient John Doe (SSN: 123-45-6789) admitted on 01/12/2024. Email: john@example.com"
print(f"\n[2] Input Data:\n    '{risky_text}'")

# 3. SABOTAGE (The "Chaos Monkey" Step)
print("\n[3] SABOTAGE: Forcing Azure Client to None (Simulated Network/Auth Failure)...")
engine.client = None 

# 4. EXECUTE
print("[4] Requesting Redaction (Expect Fallback Trigger)...")
result = engine.generate_suggestion(risky_text, "HIPAA")

# 5. VERIFICATION & AUDIT
print("\n" + "-"*30)
print("       TEST RESULTS")
print("-" * 30)

print(f"REMEDIATION METHOD : {result['remediation_method']}")
print(f"SUGGESTED OUTPUT   : {result['suggested_redaction']}")
print(f"IS AUTHORITATIVE   : {result['is_authoritative']}")

# Safe retrieval of audit metadata
audit_meta = result.get('audit_metadata', {})
rules = audit_meta.get('rules_applied', 'N/A')
failure_reason = audit_meta.get('failure_reason', 'Unknown')

print(f"AUDIT - RULES USED : {rules}")
print(f"AUDIT - FAIL REASON: {failure_reason}")

# 6. ASSERTIONS (Fail Loudly if Unsafe)
print("\n[6] Running Assertions...")

# Assert 1: System acknowledged the failure and used a fallback method
assert "Fallback" in result['remediation_method'] or "Regex" in result['remediation_method'], \
    f"FAIL: Remediation method '{result['remediation_method']}' does not indicate fallback."

# Assert 2: PII was actually redacted (checking for redaction tokens)
assert "[REDACTED-SSN]" in result['suggested_redaction'], \
    "FAIL: SSN pattern was NOT redacted in fallback mode."

assert "[REDACTED-DATE]" in result['suggested_redaction'], \
    "FAIL: Date pattern was NOT redacted in fallback mode."

# Assert 3: System did not claim authority
assert result['is_authoritative'] is False, \
    "FAIL: System claimed authoritative decision during fallback."

print("\nSUCCESS: System failed safely and protected PII under outage conditions.")
print("="*60 + "\n")