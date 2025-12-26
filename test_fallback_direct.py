"""
Direct test script for RegexFallbackEngine in fallback.py

Tests the fallback engine directly with various data types and edge cases.
"""

import json
import logging
from verifhir.remediation.fallback import RegexFallbackEngine

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class Color:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_separator(title: str):
    """Print a formatted separator"""
    print(f"\n{Color.BOLD}{'='*70}{Color.END}")
    print(f"{Color.BOLD}{title:^70}{Color.END}")
    print(f"{Color.BOLD}{'='*70}{Color.END}\n")


def test_string_redaction():
    """Test redaction of simple strings"""
    print_separator("TEST: String Redaction")
    
    engine = RegexFallbackEngine()
    
    test_cases = [
        {
            "name": "SSN, Email, Date",
            "input": "Patient John Doe (SSN: 123-45-6789) admitted on 01/12/2024. Email: john@example.com",
            "expected_rules": ["DATE", "EMAIL", "NAME", "SSN"]
        },
        {
            "name": "Phone Number",
            "input": "Contact patient at (555) 123-4567 or 555-987-6543",
            "expected_rules": ["PHONE"]
        },
        {
            "name": "Address",
            "input": "Patient resides at 123 Main Street, New York, NY 10001",
            "expected_rules": ["ADDRESS"]
        },
        {
            "name": "Indian Aadhaar",
            "input": "Patient Aadhaar: 1234 5678 9012",
            "expected_rules": ["AADHAAR"]
        },
        {
            "name": "NHS Number",
            "input": "UK Patient NHS: 123-456-7890",
            "expected_rules": ["NHS_NUMBER"]
        },
        {
            "name": "DOB Anchored",
            "input": "Patient DOB: January 15, 1990",
            "expected_rules": ["DATE"]
        },
        {
            "name": "MRN",
            "input": "Medical Record Number: MR-123456",
            "expected_rules": ["MRN"]
        },
        {
            "name": "Age 90+",
            "input": "Patient age 95, admitted for observation",
            "expected_rules": ["AGE_90_PLUS"]
        },
    ]
    
    passed = 0
    failed = 0
    
    for i, test in enumerate(test_cases, 1):
        print(f"{Color.BLUE}[Test {i}] {test['name']}{Color.END}")
        print(f"  Input: {test['input']}")
        
        redacted, rules = engine.redact(test['input'])
        
        print(f"  Output: {redacted}")
        print(f"  Rules Applied: {rules}")
        
        # Check if expected rules are present
        missing_rules = set(test['expected_rules']) - set(rules)
        unexpected_rules = set(rules) - set(test['expected_rules'])
        
        if not missing_rules and not unexpected_rules:
            print(f"  {Color.GREEN}[PASS]{Color.END}")
            passed += 1
        else:
            print(f"  {Color.RED}[FAIL]{Color.END}")
            if missing_rules:
                print(f"    Missing expected rules: {missing_rules}")
            if unexpected_rules:
                print(f"    Unexpected rules: {unexpected_rules}")
            failed += 1
        print()
    
    print(f"{Color.BOLD}Results: {passed} passed, {failed} failed{Color.END}")
    return passed, failed


def test_nested_structures():
    """Test redaction of nested dictionaries and lists"""
    print_separator("TEST: Nested Structures")
    
    engine = RegexFallbackEngine()
    
    # Test nested dictionary
    nested_dict = {
        "patient": {
            "name": "John Doe",
            "ssn": "123-45-6789",
            "email": "john@example.com",
            "address": "123 Main St, New York, NY 10001",
            "contact": {
                "phone": "(555) 123-4567",
                "dob": "01/15/1990"
            }
        },
        "metadata": {
            "mrn": "MR-123456",
            "admission_date": "2024-01-12"
        }
    }
    
    print("Input Dictionary:")
    print(json.dumps(nested_dict, indent=2))
    print()
    
    redacted, rules = engine.redact(nested_dict)
    
    print("Redacted Dictionary:")
    print(json.dumps(redacted, indent=2))
    print()
    print(f"Rules Applied: {rules}")
    
    # Verify structure is preserved
    assert isinstance(redacted, dict), "Result should be a dictionary"
    assert "patient" in redacted, "Patient key should be preserved"
    assert "metadata" in redacted, "Metadata key should be preserved"
    
    # Test list
    print("\n" + "-"*70)
    print("Testing List Structure:")
    
    list_data = [
        "Patient John Doe",
        {"ssn": "123-45-6789", "email": "john@example.com"},
        ["Contact: (555) 123-4567", "DOB: 01/15/1990"]
    ]
    
    print("Input List:")
    print(json.dumps(list_data, indent=2))
    print()
    
    redacted_list, rules_list = engine.redact(list_data)
    
    print("Redacted List:")
    print(json.dumps(redacted_list, indent=2))
    print()
    print(f"Rules Applied: {rules_list}")
    
    assert isinstance(redacted_list, list), "Result should be a list"
    assert len(redacted_list) == len(list_data), "List length should be preserved"
    
    print(f"{Color.GREEN}[PASS] Structure preservation tests passed{Color.END}")


def test_edge_cases():
    """Test edge cases and error handling"""
    print_separator("TEST: Edge Cases")
    
    engine = RegexFallbackEngine()
    
    edge_cases = [
        ("None", None),
        ("Empty string", ""),
        ("Whitespace only", "   "),
        ("No PHI", "This is a normal sentence with no sensitive information."),
        ("Numbers only", "12345"),
        ("Special characters", "!@#$%^&*()"),
    ]
    
    for name, input_data in edge_cases:
        print(f"{Color.BLUE}Testing: {name}{Color.END}")
        print(f"  Input: {repr(input_data)}")
        
        try:
            redacted, rules = engine.redact(input_data)
            print(f"  Output: {repr(redacted)}")
            print(f"  Rules: {rules}")
            
            # Verify it never returns None (unless input was None)
            if input_data is not None:
                assert redacted is not None, "Should never return None for non-None input"
            
            print(f"  {Color.GREEN}[PASS]{Color.END}")
        except Exception as e:
            print(f"  {Color.RED}[FAIL]: {e}{Color.END}")
        print()


def test_fhir_bundle():
    """Test with a FHIR-like bundle structure"""
    print_separator("TEST: FHIR Bundle Structure")
    
    engine = RegexFallbackEngine()
    
    fhir_bundle = {
        "resourceType": "Bundle",
        "entry": [
            {
                "resource": {
                    "resourceType": "Patient",
                    "name": [{"given": ["John"], "family": "Doe"}],
                    "telecom": [{"system": "email", "value": "john@example.com"}],
                    "identifier": [{"system": "SSN", "value": "123-45-6789"}],
                    "address": [{"line": ["123 Main St"], "city": "New York", "postalCode": "10001"}],
                    "birthDate": "1990-01-15"
                }
            }
        ]
    }
    
    print("Input FHIR Bundle:")
    print(json.dumps(fhir_bundle, indent=2))
    print()
    
    redacted, rules = engine.redact(fhir_bundle)
    
    print("Redacted FHIR Bundle:")
    print(json.dumps(redacted, indent=2))
    print()
    print(f"Rules Applied: {rules}")
    
    # Verify structure is preserved
    assert isinstance(redacted, dict), "Result should be a dictionary"
    assert "resourceType" in redacted, "resourceType should be preserved"
    assert "entry" in redacted, "entry should be preserved"
    
    print(f"{Color.GREEN}[PASS] FHIR bundle test passed{Color.END}")


def stress_test_fallback():
    """Stress test the fallback engine with many requests"""
    print_separator("STRESS TEST: Multiple Requests")
    
    import time
    import random
    
    engine = RegexFallbackEngine()
    
    test_samples = [
        "Patient John Doe (SSN: 123-45-6789) admitted today.",
        "Contact abuse@example.com for help.",
        "Meeting on 12/25/2024 regarding Subject 89P13.",
        "Patient Jane Smith (DOB: 01/01/1990) refused medication.",
        "Phone: (555) 123-4567, Address: 123 Main St, NY 10001",
        "MRN: MR-123456, Age: 95, Email: patient@hospital.com",
    ]
    
    num_requests = 100
    print(f"Running {num_requests} redaction requests...")
    
    start_time = time.time()
    results = []
    
    for i in range(num_requests):
        sample = random.choice(test_samples)
        redacted, rules = engine.redact(sample)
        results.append({
            "input": sample,
            "output": redacted,
            "rules": rules
        })
    
    elapsed = time.time() - start_time
    
    print(f"\n{Color.BOLD}Stress Test Results:{Color.END}")
    print(f"  Total Requests: {num_requests}")
    print(f"  Total Time: {elapsed:.2f}s")
    print(f"  Throughput: {num_requests / elapsed:.2f} req/sec")
    print(f"  Average Latency: {elapsed / num_requests * 1000:.2f} ms/request")
    
    # Verify all requests succeeded
    assert len(results) == num_requests, "All requests should complete"
    print(f"{Color.GREEN}[PASS] All {num_requests} requests completed successfully{Color.END}")


def main():
    """Run all tests"""
    print(f"\n{Color.BOLD}{Color.BLUE}")
    print("="*70)
    print("RegexFallbackEngine Direct Test Suite")
    print("="*70)
    print(f"{Color.END}\n")
    
    try:
        # Test basic string redaction
        passed_str, failed_str = test_string_redaction()
        
        # Test nested structures
        test_nested_structures()
        
        # Test edge cases
        test_edge_cases()
        
        # Test FHIR bundle
        test_fhir_bundle()
        
        # Stress test
        stress_test_fallback()
        
        print_separator("TEST SUITE COMPLETE")
        print(f"{Color.GREEN}All tests completed!{Color.END}\n")
        
    except Exception as e:
        print(f"\n{Color.RED}{Color.BOLD}Test suite failed with error:{Color.END}")
        print(f"{Color.RED}{e}{Color.END}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
