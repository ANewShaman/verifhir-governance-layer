# VeriFHIR

VeriFHIR is a pre-execution compliance and governance layer for cross-border healthcare data sharing.

It evaluates whether a specific healthcare dataset can be shared across jurisdictions in compliance with applicable privacy regulations, and documents the decision in an auditable, tamper-evident manner.

VeriFHIR answers one question only:

> “Is this dataset compliant to share across borders, under which regulations, and why?”

---

## What VeriFHIR Does

- Evaluates regulatory compliance *before* healthcare data leaves an organization
- Resolves applicable jurisdictions and regulatory conflicts deterministically
- Applies regulation-specific, rule-based validation on FHIR datasets
- Detects hidden PHI in unstructured clinical text using AI-assisted tools
- Produces explainable compliance risk scores
- Suggests compliant redaction options (never auto-applied)
- Requires explicit human approval for every decision
- Generates immutable audit records for traceability

---

## What VeriFHIR Does NOT Do (Non-Goals)

VeriFHIR intentionally does **not**:

- Store or host patient data
- Operate FHIR servers
- Replace EHR systems (Epic, Cerner, etc.)
- Manage patient consent or identity
- Transmit, route, or deliver datasets
- Enforce decisions autonomously
- Perform real-time or streaming analysis

These exclusions are intentional to maintain a narrow, auditable governance boundary.

---

## Design Principles

- Deterministic before probabilistic
- Human-in-the-loop by default
- Explainability over automation
- Governance before intelligence
- Auditability as a first-class requirement

---

## Status

This repository contains an MVP implementation focused on correctness, transparency, and regulatory reasoning—not scale or production throughput.
