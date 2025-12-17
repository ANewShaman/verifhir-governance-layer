import json
import shutil
from dataclasses import asdict
from verifhir.jurisdiction.resolver import resolve_jurisdiction
from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.scoring.utils import violations_to_risk_components
from verifhir.scoring.aggregator import aggregate_risk_components
from verifhir.scoring.decision import build_rule_only_decision

# --- PROFESSIONAL UI THEME ---
class Colors:
    HEADER = '\033[95m'      # Keeping header distinct but readable
    BLUE = '\033[94m'        # Standard Info
    OKCYAN = '\033[96m'      # (Unused in formal mode)
    OKGREEN = '\033[92m'     # Success
    WARNING = '\033[93m'     # Warning (Gold/Amber)
    FAIL = '\033[91m'        # Critical (Red)
    ENDC = '\033[0m'         # Reset
    BOLD = '\033[1m'         # Emphasis
    UNDERLINE = '\033[4m'    # Links/Headers
    
    # Formal Mapping
    LABEL = BLUE             # For keys like "Source Country"
    VALUE = ENDC             # For values (Plain white/grey)
    HIGHLIGHT = BOLD         # For important values

def print_separator(char="-"):
    width = shutil.get_terminal_size().columns
    print(Colors.BLUE + (char * width) + Colors.ENDC)

def print_section(title):
    print("\n")
    print_separator("=")
    print(f"{Colors.BOLD}{Colors.HEADER}  {title.upper()}{Colors.ENDC}")
    print_separator("=")

def print_kv(key, value, color=Colors.VALUE):
    # Fixed width formatting for clean alignment
    print(f"{Colors.LABEL}{key:<25}{Colors.ENDC} : {color}{value}{Colors.ENDC}")

# --- MAIN DEMO ---
def run_clean_demo():
    # 1. SETUP
    print_section("SCENARIO INITIALIZATION")
    
    source = "US"
    dest = "IN"
    subject = "DE"
    
    fhir_data = {
        "resourceType": "Observation",
        "id": "obs-report-101",
        "status": "final",
        "note": [{"text": "Patient ID 99999 reported feeling anxious about the transfer."}]
    }

    print_kv("Source Country", source)
    print_kv("Destination Country", dest)
    print_kv("Data Subject Origin", subject, Colors.HIGHLIGHT)
    print_kv("Resource Type", fhir_data["resourceType"])
    print_kv("Input Snippet", fhir_data["note"][0]["text"], Colors.HIGHLIGHT)

    # 2. JURISDICTION
    print_section("STEP 1: JURISDICTION ENGINE")
    jurisdiction = resolve_jurisdiction(source, dest, subject)
    
    print_kv("Applicable Laws", ", ".join(jurisdiction.applicable_regulations))
    print_kv("Governing Regulation", jurisdiction.governing_regulation, Colors.HIGHLIGHT)
    print_kv("Reasoning", jurisdiction.reasoning[jurisdiction.governing_regulation])

    # 3. RULES
    print_section("STEP 2: RULE ENFORCEMENT")
    violations = run_deterministic_rules(jurisdiction, fhir_data)

    if not violations:
        print(f"{Colors.OKGREEN}✔ No rules violated.{Colors.ENDC}")
    else:
        for idx, v in enumerate(violations, 1):
            severity_color = Colors.FAIL if v.severity.value == "MAJOR" else Colors.WARNING
            print(f"{idx}. {Colors.BOLD}{v.violation_type}{Colors.ENDC}")
            print(f"   ├─ Severity : {severity_color}{v.severity.value}{Colors.ENDC}")
            print(f"   ├─ Citation : {v.citation}")
            print(f"   └─ Message  : {v.description}")

    # 4. SCORING
    print_section("STEP 3: RISK SCORING")
    risks = violations_to_risk_components(violations)
    summary = aggregate_risk_components(risks)
    
    score = summary['total_risk_score']
    # Professional Traffic Light
    if score <= 1.0:
        score_color = Colors.OKGREEN
    elif score <= 6.0:
        score_color = Colors.WARNING  # Amber/Gold
    else:
        score_color = Colors.FAIL     # Red
    
    print_kv("Total Risk Score", f"{score:.2f}", score_color + Colors.BOLD)
    print_kv("Contributing Factors", summary['component_count'])

    # 5. VERDICT
    print_section("STEP 4: FINAL VERDICT")
    decision = build_rule_only_decision(score, risks)

    if decision.outcome.name == "APPROVED":
        outcome_color = Colors.OKGREEN
    elif decision.outcome.name == "APPROVED_WITH_REDACTIONS":
        outcome_color = Colors.WARNING
    else:
        outcome_color = Colors.FAIL

    print(f"{Colors.BOLD}DECISION:{Colors.ENDC}  [{outcome_color}{decision.outcome.name}{Colors.ENDC}]")
    print(f"{Colors.BOLD}RATIONALE:{Colors.ENDC} {decision.rationale}")
    
    print_separator("=")
    print("\n")

if __name__ == "__main__":
    run_clean_demo()