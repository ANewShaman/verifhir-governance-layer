# VeriFHIR — Architecture Overview

## Purpose

VeriFHIR is a governance checkpoint that evaluates regulatory compliance for cross-border healthcare data sharing *before* data movement occurs.

It is not a data pipeline, storage system, or delivery mechanism.

---

## High-Level Flow

FHIR Dataset (JSON)
↓  
Jurisdiction Resolver  
↓  
Applicable Regulation Set  
↓  
Deterministic Rule Engine  
↓  
PHI Detection (AI-assisted)  
↓  
Explainable Risk Scoring  
↓  
Human Review & Approval  
↓  
Immutable Audit Record

---

## Component Responsibilities

### Jurisdiction Resolver
Determines which privacy regulations apply based on:
- Source jurisdiction
- Destination jurisdiction
- Data subject residency
- Multi-hop transfer paths

Outputs an ordered, explainable set of applicable regulations.

---

### Deterministic Rule Engine
Applies regulation-specific rules to structured FHIR data.
- Explicit logic
- Regulation citations
- No probabilistic behavior

---

### PHI Detection
AI-assisted detection of personal and health identifiers in unstructured text.
- Used to augment, not replace, deterministic rules
- All findings remain explainable and reviewable

---

### Risk Scoring
Produces a transparent risk score derived from:
- Rule violations
- Detection confidence
- Severity weights

Scores are advisory and never self-enforcing.

---

### Human Approval
Every dataset requires explicit human approval.
- No automatic approvals exist
- Reviewer rationale is recorded

---

### Audit Record
Each decision produces a tamper-evident audit record containing:
- Jurisdictions evaluated
- Rules applied
- Violations detected
- Human decision and rationale

Audit records are immutable and retention-controlled.

---

## Explicit Boundary

VeriFHIR evaluates compliance decisions.
It does not execute, transmit, or enforce them.
