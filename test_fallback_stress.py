"""
Stress test specifically for RegexFallbackEngine

Tests the fallback engine under load with various data types.
"""

import concurrent.futures
import time
import random
import json
import logging
from verifhir.remediation.fallback import RegexFallbackEngine

# Disable internal logging for cleaner output
logging.getLogger("verifhir.remediation.fallback").setLevel(logging.CRITICAL)

# Configuration
TOTAL_REQUESTS = 200
CONCURRENCY = 20

# Test data samples
STRING_SAMPLES = [
    "Patient John Doe (SSN: 123-45-6789) admitted on 01/12/2024. Email: john@example.com",
    "Contact patient at (555) 123-4567 or 555-987-6543",
    "Patient resides at 123 Main Street, New York, NY 10001",
    "Patient DOB: January 15, 1990",
    "Medical Record Number: MR-123456",
    "Patient age 95, admitted for observation",
    "Patient Aadhaar: 1234 5678 9012",
    "UK Patient NHS: 123-456-7890",
    "Patient: Jane Smith, SSN: 987-65-4321, Email: jane@example.com",
    "Phone: (555) 123-4567, Address: 123 Main St, NY 10001",
    "",  # Empty string
    "   ",  # Whitespace only
    "Normal text with no PHI",  # No PHI
]

DICT_SAMPLES = [
    {"patient": {"name": "John Doe", "ssn": "123-45-6789", "email": "john@example.com"}},
    {"contact": {"phone": "(555) 123-4567", "address": "123 Main St, NY 10001"}},
    {"metadata": {"mrn": "MR-123456", "dob": "1990-01-15"}},
    {"patient": {"name": "Jane Smith"}, "contact": {"phone": "(555) 987-6543"}},
]

LIST_SAMPLES = [
    ["Patient John Doe", "SSN: 123-45-6789", "Email: john@example.com"],
    [{"name": "John Doe"}, {"ssn": "123-45-6789"}],
    ["Contact: (555) 123-4567", "DOB: 01/15/1990"],
]


def simulate_request(req_id):
    """Simulates one single request hitting the fallback engine."""
    engine = RegexFallbackEngine()
    
    # Randomly choose data type
    data_type = random.choice(["string", "dict", "list", "mixed"])
    
    if data_type == "string":
        data = random.choice(STRING_SAMPLES)
    elif data_type == "dict":
        data = random.choice(DICT_SAMPLES)
    elif data_type == "list":
        data = random.choice(LIST_SAMPLES)
    else:  # mixed
        data = {
            "text": random.choice(STRING_SAMPLES),
            "structured": random.choice(DICT_SAMPLES),
            "array": random.choice(LIST_SAMPLES)
        }
    
    start = time.time()
    try:
        redacted, rules = engine.redact(data)
        duration = time.time() - start
        
        return {
            "id": req_id,
            "status": "SUCCESS",
            "data_type": data_type,
            "rules_count": len(rules),
            "rules": rules,
            "latency": duration,
            "input_size": len(str(data)),
            "output_size": len(str(redacted))
        }
    except Exception as e:
        return {
            "id": req_id,
            "status": "FAIL",
            "error": str(e),
            "data_type": data_type
        }


def main():
    print(f"{'='*70}")
    print(f"STRESS TEST: RegexFallbackEngine")
    print(f"{'='*70}")
    print(f"Total Requests: {TOTAL_REQUESTS}")
    print(f"Concurrency: {CONCURRENCY}")
    print(f"{'='*70}\n")
    
    start_all = time.time()
    results = []
    
    # Execute requests in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = [executor.submit(simulate_request, i) for i in range(TOTAL_REQUESTS)]
        
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            results.append(res)
            
            # Visual feedback
            if res['status'] == 'FAIL':
                print("X", end="", flush=True)
            else:
                print(".", end="", flush=True)
            
            # Print progress every 50 requests
            if len(results) % 50 == 0:
                print(f" ({len(results)}/{TOTAL_REQUESTS})")
    
    total_time = time.time() - start_all
    
    # Analyze results
    print("\n\n" + "="*70)
    print("RESULTS ANALYSIS")
    print("="*70)
    
    successes = [r for r in results if r['status'] == "SUCCESS"]
    failures = [r for r in results if r['status'] == "FAIL"]
    
    print(f"\nPerformance Metrics:")
    print(f"  Total Time:      {total_time:.2f}s")
    print(f"  Throughput:      {TOTAL_REQUESTS / total_time:.2f} req/sec")
    print(f"  Avg Latency:     {sum(r['latency'] for r in successes) / len(successes) * 1000:.2f} ms")
    print(f"  Success Rate:    {len(successes)}/{TOTAL_REQUESTS} ({len(successes)/TOTAL_REQUESTS*100:.1f}%)")
    print(f"  Failures:        {len(failures)}")
    
    if successes:
        print(f"\nRule Detection Statistics:")
        all_rules = []
        for r in successes:
            all_rules.extend(r.get('rules', []))
        
        from collections import Counter
        rule_counts = Counter(all_rules)
        
        print(f"  Total Rules Detected: {len(all_rules)}")
        print(f"  Unique Rule Types: {len(rule_counts)}")
        print(f"  Avg Rules per Request: {len(all_rules) / len(successes):.2f}")
        
        print(f"\n  Top Rule Types:")
        for rule, count in rule_counts.most_common(10):
            print(f"    {rule}: {count} times")
        
        print(f"\nData Type Distribution:")
        data_type_counts = {}
        for r in successes:
            dt = r.get('data_type', 'unknown')
            data_type_counts[dt] = data_type_counts.get(dt, 0) + 1
        
        for dt, count in sorted(data_type_counts.items()):
            print(f"  {dt}: {count} requests")
        
        # Size statistics
        print(f"\nSize Statistics:")
        avg_input_size = sum(r['input_size'] for r in successes) / len(successes)
        avg_output_size = sum(r['output_size'] for r in successes) / len(successes)
        print(f"  Avg Input Size:  {avg_input_size:.0f} chars")
        print(f"  Avg Output Size: {avg_output_size:.0f} chars")
        print(f"  Size Ratio:      {avg_output_size / avg_input_size if avg_input_size > 0 else 0:.2f}x")
    
    if failures:
        print(f"\nFailures:")
        for i, fail in enumerate(failures[:5], 1):  # Show first 5 failures
            print(f"  {i}. Request {fail['id']}: {fail.get('error', 'Unknown error')}")
        if len(failures) > 5:
            print(f"  ... and {len(failures) - 5} more")
    
    # Latency percentiles
    if successes:
        latencies = sorted([r['latency'] * 1000 for r in successes])
        print(f"\nLatency Percentiles (ms):")
        print(f"  P50 (Median): {latencies[len(latencies)//2]:.2f}")
        print(f"  P95:          {latencies[int(len(latencies)*0.95)]:.2f}")
        print(f"  P99:          {latencies[int(len(latencies)*0.99)]:.2f}")
        print(f"  Max:          {latencies[-1]:.2f}")
    
    print("\n" + "="*70)
    
    # Determine exit code
    if failures:
        print(f"[WARNING] Stress test completed with {len(failures)} failures")
        return 1
    else:
        print("[SUCCESS] All requests completed successfully!")
        return 0


if __name__ == "__main__":
    exit(main())

