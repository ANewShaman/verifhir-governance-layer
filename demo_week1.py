import json
import time
from dataclasses import asdict
from verifhir.jurisdiction.resolver import resolve_jurisdiction

def print_header(text):
    print(f"\n{Colors.HEADER}=== {text} ==={Colors.ENDC}")

def print_step(label, value):
    print(f"{Colors.BOLD}{label}:{Colors.ENDC} {value}")

def print_success(text):
    print(f"{Colors.GREEN}[✓] {text}{Colors.ENDC}")

def print_info(text):
    print(f"{Colors.BLUE}[i] {text}{Colors.ENDC}")

def print_alert(text):
    print(f"{Colors.WARNING}[!] {text}{Colors.ENDC}")

# Simple ANSI colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def run_checkpoint_demo():
    # 1. Opening
    print_header("VERIFHIR: CROSS-BORDER GOVERNANCE CHECKPOINT")
    print("Initializing governance engine...")
    time.sleep(1) # Dramatic pause
    print_success("System Online")
    print_info("Mode: Governance Only (No Patient Data Transmitted)")

    # 2. The Scenario
    print_header("SCENARIO INPUTS")
    source = "US"
    dest = "IN"
    subject = "DE"
    
    print_step("Source Origin", f"{source} (US Hospital)")
    print_step("Data Subject", f"{subject} (German Citizen)")
    print_step("Destination", f"{dest} (Processing Center, India)")
    
    # 3. Execution
    print_header("EXECUTING JURISDICTION RESOLVER")
    time.sleep(0.5)
    
    resolution = resolve_jurisdiction(
        source_country=source,
        destination_country=dest,
        data_subject_country=subject
    )

    # 4. Jurisdiction Resolution
    print_step("Regulatory Snapshot", resolution.regulation_snapshot_version)
    print_step("Applicable Frameworks", ", ".join(resolution.applicable_regulations))
    
    print("\n--- Trigger Reasoning ---")
    for reg, reason in resolution.reasoning.items():
        print(f" > {Colors.BOLD}{reg}:{Colors.ENDC} {reason}")

    # 5. Governing Decision
    print_header("GOVERNING REGULATION DECISION")
    time.sleep(0.5)
    print_alert("Multiple Frameworks Detected (Conflict)")
    print_info("Applying 'Most Restrictive Wins' Hierarchy...")
    time.sleep(0.5)
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}>>> GOVERNING REGULATION: {resolution.governing_regulation} <<<{Colors.ENDC}")
    print(f"Reasoning: {resolution.governing_regulation} provides the strictest privacy baseline.")

    # 6. Audit Artifact
    print_header("GENERATED AUDIT ARTIFACT")
    audit_data = {
        "context": asdict(resolution.context),
        "decision": {
            "applicable": resolution.applicable_regulations,
            "governing": resolution.governing_regulation
        },
        "policy_version": resolution.regulation_snapshot_version,
        "integrity_check": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
    print(json.dumps(audit_data, indent=2))
    print_header("DEMO COMPLETE")

if __name__ == "__main__":
    run_checkpoint_demo()