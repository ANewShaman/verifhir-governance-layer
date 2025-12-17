from pprint import pprint

from verifhir.jurisdiction.resolver import resolve_jurisdiction
from verifhir.orchestrator.rule_engine import run_deterministic_rules
from verifhir.scoring.utils import violations_to_risk_components
from verifhir.scoring.aggregator import aggregate_risk_components
from verifhir.scoring.decision import build_rule_only_decision


def run_demo():
    print("\n=== VERIFHIR — RULE-ONLY GOVERNANCE DEMO ===\n")

    # --------------------------------------------------
    # 1. Input Scenario (What a user provides)
    # --------------------------------------------------
    print("1. INPUT METADATA")
    print("-----------------")

    source_country = "US"
    destination_country = "US"
    data_subject_country = "DE"

    print(f"Source Country      : {source_country}")
    print(f"Destination Country : {destination_country}")
    print(f"Data Subject        : {data_subject_country}")

    # Example FHIR resource (contains identifier in free text)
    fhir_resource = {
        "resourceType": "Observation",
        "note": [
            {"text": "Patient ID 99999 reported symptoms"}
        ]
    }

    # --------------------------------------------------
    # 2. Jurisdiction Resolution
    # --------------------------------------------------
    print("\n2. JURISDICTION RESOLUTION")
    print("--------------------------")

    jurisdiction = resolve_jurisdiction(
        source_country=source_country,
        destination_country=destination_country,
        data_subject_country=data_subject_country
    )

    pprint(jurisdiction)

    # --------------------------------------------------
    # 3. Rule Execution (Governed by Regulation)
    # --------------------------------------------------
    print("\n3. RULE EXECUTION")
    print("-----------------")

    violations = run_deterministic_rules(jurisdiction, fhir_resource)

    if not violations:
        print("No violations detected.")
    else:
        print(f"Detected {len(violations)} violation(s):")
        for v in violations:
            pprint(v)

    # --------------------------------------------------
    # 4. Risk Component Construction
    # --------------------------------------------------
    print("\n4. RISK COMPONENTS")
    print("------------------")

    risk_components = violations_to_risk_components(violations)

    for rc in risk_components:
        pprint(rc)

    # --------------------------------------------------
    # 5. Risk Aggregation
    # --------------------------------------------------
    print("\n5. RISK AGGREGATION")
    print("------------------")

    score_summary = aggregate_risk_components(risk_components)
    pprint(score_summary)

    # --------------------------------------------------
    # 6. Compliance Decision (Rule-Only)
    # --------------------------------------------------
    print("\n6. COMPLIANCE DECISION")
    print("---------------------")

    decision = build_rule_only_decision(
        total_risk_score=score_summary["total_risk_score"],
        risk_components=risk_components
    )

    pprint(decision)

    print("\n=== END OF DEMO ===\n")


if __name__ == "__main__":
    run_demo()
