import concurrent.futures
import time
import random
import logging
from verifhir.remediation.redactor import RedactionEngine

# Disable internal logging for the stress test to keep the console clean
logging.getLogger("verifhir.remediation").setLevel(logging.CRITICAL)

# Configuration
TOTAL_REQUESTS = 100
CONCURRENCY = 10 

# Mock Data (Mixed realistic and junk)
SAMPLES = [
    "Patient John Doe (SSN: 123-45-6789) admitted today.",
    "Order 66 executed by Trooper FN-2187.",
    "Contact abuse@example.com for help.",
    "Meeting on 12/25/2024 regarding Subject 89P13.",
    "   ", # Empty string
    "Patient Jane Smith (DOB: 01/01/1990) refused medication."
]

def simulate_doctor_request(req_id):
    """Simulates one single request hitting the engine."""
    # Re-initialize engine per thread to simulate distinct requests
    engine = RedactionEngine() 
    text = random.choice(SAMPLES)
    
    start = time.time()
    try:
        # 50/50 chance of HIPAA or GDPR
        reg = random.choice(["HIPAA", "GDPR"])
        result = engine.generate_suggestion(text, reg)
        duration = time.time() - start
        
        return {
            "id": req_id,
            "status": "SUCCESS",
            "method": result['remediation_method'],
            "latency": duration
        }
    except Exception as e:
        return {
            "id": req_id,
            "status": "FAIL",
            "error": str(e)
        }

print(f"--- STARTING STRESS TEST: {TOTAL_REQUESTS} Requests (Threads: {CONCURRENCY}) ---")
print("Simulating high-velocity traffic and Azure rejection/throttling...")

start_all = time.time()
results = []

# The ThreadPool fires requests in parallel
with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
    futures = [executor.submit(simulate_doctor_request, i) for i in range(TOTAL_REQUESTS)]
    
    for future in concurrent.futures.as_completed(futures):
        res = future.result()
        results.append(res)
        
        # Visual feedback
        if res['status'] == 'FAIL':
            print("X", end="", flush=True)
        elif "Azure" in res['method']:
            print(".", end="", flush=True) # AI Hit
        else:
            print("!", end="", flush=True) # Fallback Hit

print("\n\n--- RESULTS ANALYSIS ---")
total_time = time.time() - start_all
successes = [r for r in results if r['status'] == "SUCCESS"]
failures = [r for r in results if r['status'] == "FAIL"]

# UPDATED: Matching the new method names from redactor.py
ai_hits = [r for r in successes if "Azure" in r['method']]
fallback_hits = [r for r in successes if "Fallback" in r['method'] or "Regex" in r['method']]

print(f"Total Time:      {total_time:.2f}s")
print(f"Throughput:      {TOTAL_REQUESTS / total_time:.2f} req/sec")
print(f"Success Rate:    {len(successes)}/{TOTAL_REQUESTS}")
print(f"AI Responses:    {len(ai_hits)} (Smart Redaction)")
print(f"Fallback Hit:    {len(fallback_hits)} (Safety Net Triggered)")
print(f"System Crashes:  {len(failures)}")

if failures:
    print(f"First Failure: {failures[0]}")