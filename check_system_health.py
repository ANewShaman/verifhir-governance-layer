import sys
import os
from verifhir.jurisdiction.resolver import resolve_jurisdiction
from verifhir.orchestrator.rule_engine import run_deterministic_rules

# ANSI Colors
OK = '\033[92m'
FAIL = '\033[91m'
RESET = '\033[0m'

def audit_tier1_coverage():
    print(f"\n=== TIER 1 COVERAGE AUDIT ===\n")
    
    targets = [
        ("US", "US", "US", "HIPAA"),   
        ("DE", "IN", "DE", "GDPR"),    
        ("IN", "IN", "IN", "DPDP"),    
        ("GB", "US", "GB", "UK_GDPR"), 
        ("CA", "US", "CA", "PIPEDA"),  
        ("BR", "US", "BR", "LGPD"),    
    ]
    
    passed_count = 0
    
    for src, dst, sub, expected_reg in targets:
        print(f"Checking {expected_reg}...", end=" ")
        
        j = resolve_jurisdiction(src, dst, sub)
        if j.governing_regulation != expected_reg:
            print(f"{FAIL}FAIL (Jurisdiction Mismatch){RESET}")
            continue

        # FIX: Changed resourceType to "Patient" so DPDP rule fires.
        # (Other rules don't care about type, only the 'note' field)
        bad_resource = {
            "resourceType": "Patient", 
            "note": [{"text": "Patient ID 12345 MRN: 999 CPF: 123"}], 
            "address": [{"country": "IN"}], 
            "meta": {} 
        }
        
        violations = run_deterministic_rules(j, bad_resource)
        
        found = any(v.regulation == expected_reg for v in violations)
        
        if found:
            print(f"{OK}PASS (Enforcing){RESET}")
            passed_count += 1
        else:
            print(f"{FAIL}FAIL (No Rule Active!){RESET}")

    print(f"\nStatus: {passed_count}/6 Countries Enforcing.")
    if passed_count == 6:
        print(f"{OK}SYSTEM INTEGRITY: 100% (READY FOR AI){RESET}")
    else:
        print(f"{FAIL}SYSTEM INCOMPLETE{RESET}")

if __name__ == "__main__":
    audit_tier1_coverage()