import json
import time
from dataclasses import asdict
from verifhir.jurisdiction.resolver import resolve_jurisdiction
from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.scoring.utils import violations_to_risk_components
from verifhir.scoring.aggregator import aggregate_risk_components
from verifhir.scoring.decision import build_rule_only_decision

# Simple ANSI colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.HEADER}=== {text} ==={Colors.ENDC}")

def run_compliance_demo():
    print_header("VERIFHIR: WEEK 2 GOVERNANCE PIPELINE")
    
    # 1. Setup Scenario
    print(f"{Colors.BOLD}Scenario:{Colors.ENDC} US Hospital -> India Processing (German Patient)")
    fake_fhir = {
        "resourceType": "Observation",
        "id": "obs-1",
        "note": [{"text": "Patient ID 99999 shows signs of recovery."}]
    }
    print(f"{Colors.BOLD}Input Data:{Colors.ENDC} {json.dumps(fake_fhir, indent=2)}")

    # 2. Jurisdiction (Week 1 Logic)
    print_header("STEP 1: JURISDICTION RESOLUTION")
    jurisdiction = resolve_jurisdiction("US", "IN", "DE")
    print(f"Governing Regulation: {Colors.BLUE}{jurisdiction.governing_regulation}{Colors.ENDC}")

    # 3. Rule Execution (Week 2 Logic)
    print_header("STEP 2: DETERMINISTIC RULE EXECUTION")
    violations = run_deterministic_rules(jurisdiction, fake_fhir)
    for v in violations:
        print(f"{Colors.FAIL}[Violation]{Colors.ENDC} {v.violation_type} (Severity: {v.severity.value})")

    # 4. Risk Aggregation
    print_header("STEP 3: RISK SCORING")
    risks = violations_to_risk_components(violations)
    summary = aggregate_risk_components(risks)
    print(f"Total Risk Score: {Colors.WARNING}{summary['total_risk_score']}{Colors.ENDC}")

    # 5. Final Decision
    print_header("STEP 4: COMPLIANCE DECISION")
    decision = build_rule_only_decision(
        summary["total_risk_score"], 
        risks
    )
    
    # Print the "Golden Output"
    result_color = Colors.GREEN if decision.outcome.name == "APPROVED" else Colors.FAIL
    print(f"Outcome: {result_color}{decision.outcome.name}{Colors.ENDC}")
    print(f"Rationale: {decision.rationale}")
    
    # Dump full JSON artifact for audit proof
    print("\n--- Full Decision Artifact ---")
    print(json.dumps(asdict(decision), indent=2, default=str))

if __name__ == "__main__":
    run_compliance_demo()