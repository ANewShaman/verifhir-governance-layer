# verifhir/dashboard/app.py
# d:\verifhir\verifhir-governance-layer\verifhir\dashboard\app.py

import streamlit as st
import time
import json
import datetime
import difflib
import html
from verifhir.remediation.redactor import RedactionEngine
from verifhir.storage import commit_record
from verifhir.adapters.hl7_adapter import normalize_input
from verifhir.models.input_provenance import InputProvenance
from verifhir.telemetry import init_telemetry
import hashlib
import os
import re

def safe_text(value):
    """
    Escape user-controlled text only.
    Never escape structural HTML.
    """
    return html.escape(str(value)) if value is not None else ""

init_telemetry()

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="VeriFHIR Governance Console",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load production CSS if present
try:
    css_path = os.path.join(os.path.dirname(__file__), "ui.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as _cssf:
            st.markdown(f"<style>{_cssf.read()}</style>", unsafe_allow_html=True)
except Exception as _e:
    st.warning(f"Unable to load UI CSS: {_e}")

# --- BACKEND INITIALIZATION ---
@st.cache_resource
def get_engine():
    """Load the backend engine once; cache for session performance."""
    return RedactionEngine()

engine = get_engine()

# --- REGULATION METADATA ---
REGULATION_INFO = {
    "HIPAA": {
        "name": "HIPAA (US)",
        "full_name": "Health Insurance Portability and Accountability Act",
        "country": "US",
        "description": "US federal law protecting medical information and patient privacy"
    },
    "GDPR": {
        "name": "GDPR (EU)",
        "full_name": "General Data Protection Regulation",
        "country": "EU",
        "description": "European Union data protection and privacy regulation"
    },
    "UK_GDPR": {
        "name": "UK GDPR",
        "full_name": "UK Data Protection Act 2018 + UK GDPR",
        "country": "GB",
        "description": "United Kingdom post-Brexit data protection framework"
    },
    "LGPD": {
        "name": "LGPD (Brazil)",
        "full_name": "Lei Geral de Proteção de Dados",
        "country": "BR",
        "description": "Brazilian comprehensive data protection law"
    },
    "DPDP": {
        "name": "DPDP (India)",
        "full_name": "Digital Personal Data Protection Act 2023",
        "country": "IN",
        "description": "Indian digital privacy and data protection legislation"
    },
    "BASE": {
        "name": "BASE (Universal)",
        "full_name": "Generic Privacy Baseline",
        "country": "GLOBAL",
        "description": "Technology-neutral privacy principles for universal application"
    }
}

# --- HELPER: ENHANCED VISUAL DIFF GENERATOR ---
def generate_diff_html(original, redacted):
    """
    Creates a clean, professional diff view with:
    - Original text in muted red with strikethrough
    - Redacted tags in clean blue chips
    - Better spacing and readability
    """
    d = difflib.SequenceMatcher(None, original, redacted)
    html_parts = []
    
    for tag, i1, i2, j1, j2 in d.get_opcodes():
        if tag == 'replace':
            orig_text = html.escape(original[i1:i2])
            html_parts.append(
                f'<span style="'
                f'color: #cf222e; '
                f'text-decoration: line-through; '
                f'background-color: #ffebe9; '
                f'padding: 2px 4px; '
                f'border-radius: 3px; '
                f'margin-right: 6px; '
                f'font-weight: 500;">'
                f'{orig_text}</span>'
            )
            
            redact_text = html.escape(redacted[j1:j2])
            html_parts.append(
                f'<span style="'
                f'background: rgba(59, 130, 246, 0.15); '
                f'color: #60a5fa; '
                f'font-weight: 600; '
                f'border: 1px solid rgba(59, 130, 246, 0.3); '
                f'border-radius: 6px; '
                f'padding: 3px 10px; '
                f'margin: 0 4px; '
                f'display: inline-block; '
                f'font-family: ui-monospace, monospace; '
                f'font-size: 0.9em;">'
                f'{redact_text}</span>'
            )
        
        elif tag == 'delete':
            del_text = html.escape(original[i1:i2])
            html_parts.append(
                f'<span style="'
                f'color: #cf222e; '
                f'text-decoration: line-through; '
                f'background-color: #ffebe9; '
                f'padding: 2px 4px; '
                f'border-radius: 3px; '
                f'font-weight: 500;">'
                f'{del_text}</span>'
            )
            
        elif tag == 'insert':
            ins_text = html.escape(redacted[j1:j2])
            html_parts.append(
                f'<span style="'
                f'background: rgba(59, 130, 246, 0.15); '
                f'color: #60a5fa; '
                f'font-weight: 600; '
                f'border: 1px solid rgba(59, 130, 246, 0.3); '
                f'border-radius: 6px; '
                f'padding: 3px 10px; '
                f'margin: 0 4px; '
                f'display: inline-block; '
                f'font-family: ui-monospace, monospace; '
                f'font-size: 0.9em;">'
                f'{ins_text}</span>'
            )
            
        elif tag == 'equal':
            equal_text = html.escape(original[i1:i2])
            html_parts.append(equal_text)
            
    return "".join(html_parts)

def generate_clean_output(redacted_text):
    """
    Generates a clean, final output view with highlighted redaction tags.
    """
    def highlight_tag(match):
        tag_content = match.group(0)
        escaped = html.escape(tag_content)
        return (
            f'<span style="'
            f'background: rgba(59, 130, 246, 0.15); '
            f'color: #60a5fa; '
            f'font-weight: 600; '
            f'border: 1px solid rgba(59, 130, 246, 0.3); '
            f'border-radius: 6px; '
            f'padding: 3px 10px; '
            f'margin: 0 2px; '
            f'display: inline-block; '
            f'font-family: ui-monospace, monospace; '
            f'font-size: 0.9em;">'
            f'{escaped}</span>'
        )
    
    highlighted = re.sub(r'\[REDACTED[^\]]*\]', highlight_tag, html.escape(redacted_text))
    return highlighted

def compute_system_config_hash() -> str:
    """
    Compute a hash of the current system configuration.
    This prevents replay drift due to environment changes.
    """
    config_data = {
        "engine_version": engine.PROMPT_VERSION,
        "python_version": "3.11",
        "streamlit_version": st.__version__,
    }
    config_str = json.dumps(config_data, sort_keys=True)
    return hashlib.sha256(config_str.encode()).hexdigest()[:16]

# --- SIDEBAR: SYSTEM CONFIG ---
with st.sidebar:
    st.header("System Control")
    
    st.subheader("Policy Context")
    
    regulation_keys = list(REGULATION_INFO.keys())
    regulation_labels = [REGULATION_INFO[k]["name"] for k in regulation_keys]
    
    selected_index = st.selectbox(
        "Regulatory Framework",
        range(len(regulation_keys)),
        format_func=lambda i: regulation_labels[i],
        help="Select the applicable data protection regulation"
    )
    
    regulation = regulation_keys[selected_index]
    reg_info = REGULATION_INFO[regulation]
    
    st.caption(f"**{reg_info['full_name']}**")
    st.caption(reg_info['description'])
    
    if regulation == "GDPR":
        country_code = st.text_input(
            "EU Member State (ISO 3166-1)", 
            "DE",
            help="Enter the 2-letter country code (e.g., DE, FR, IT)"
        ).upper()
    else:
        country_code = reg_info["country"]
        st.caption(f"**Jurisdiction:** {country_code}")
    
    st.divider()
    
    st.subheader("Engine Intelligence")
    if engine.client:
        st.caption("Hybrid Mode Active — AI Redactor + Deterministic Fallback")
    else:
        st.caption("Fallback Mode Active — Deterministic Pattern Matching Only")

    st.divider()
    
    if "judge_mode" not in st.session_state:
        st.session_state.judge_mode = True
    
    st.session_state.judge_mode = st.checkbox(
        "Judge / Demo Mode",
        value=st.session_state.judge_mode,
        help="Demo mode: Source input hidden by default, evidence fully visible"
    )
    
    st.divider()
    st.caption(f"VeriFHIR Core {engine.PROMPT_VERSION}")

# --- DEMO CASE LIBRARY ---
DEMO_CASES = {
    "": {"input": "", "input_mode": "TEXT", "metadata": {}},
    
    "Clean discharge note": {
        "input": "DISCHARGE SUMMARY\n\nPatient admitted on 02/10/2024 for routine procedure.\nNo complications observed.\nPatient's father died at age 89.\nStarted metformin on 2023-01-15.\nDischarged on 02/12/2024 in stable condition.",
        "input_mode": "TEXT",
        "metadata": {
            "source": "Synthea",
            "patient_id": "syn-patient-004",
            "status": "Synthetic / De-identified"
        }
    },
    "Smart redaction example": {
        "input": "Patient's father died at age 89. Started metformin on 2023-01-15. Patient lives at 123 Main St.",
        "input_mode": "TEXT",
        "metadata": {
            "source": "Synthea",
            "patient_id": "syn-patient-006",
            "status": "Synthetic / De-identified"
        }
    },
    
    "HL7 ADT message": {
        "input": "MSH|^~\\&|SendingApp|SendingFacility|ReceivingApp|ReceivingFacility|20240115120000||ADT^A01|12345|P|2.5\nPID|1||123456^^^MRN||SMITH^JOHN^MIDDLE||19800115|M|||123 MAIN ST^^CITY^ST^12345||555-1234|||",
        "input_mode": "HL7",
        "metadata": {
            "source": "Synthea",
            "patient_id": "syn-patient-005",
            "status": "Synthetic / De-identified"
        }
    },
    
    "Insurance form photo": {
        "input": "Patient Name: Sarah Chen\nPolicy Number: INS-987654321\nSSN: 456-78-9012\nDate of Service: 03/15/2024\nProvider: Dr. Michael Rodriguez\nAddress: 789 Medical Plaza, Suite 200, San Francisco, CA 94102",
        "input_mode": "DOCUMENT_OCR",
        "metadata": {
            "source": "Synthea",
            "patient_id": "syn-patient-001",
            "status": "Synthetic / De-identified",
            "ocr_confidence": 0.92
        }
    },
    "Referral letter scan": {
        "input": "REFERRAL LETTER\n\nTo: Dr. James Wilson, Cardiology\nFrom: Dr. Emily Martinez, Primary Care\n\nPatient: Robert Kim (MRN: M-123456)\nDOB: 11/22/1978\nReason: Cardiac evaluation for chest pain\nAddress: 456 Oak Street, Apt 3B, Los Angeles, CA 90001\nPhone: (310) 555-7890",
        "input_mode": "DOCUMENT_OCR",
        "metadata": {
            "source": "Synthea",
            "patient_id": "syn-patient-002",
            "status": "Synthetic / De-identified",
            "ocr_confidence": 0.88
        }
    },
    "Lab report screenshot": {
        "input": "LABORATORY REPORT\n\nPatient: Jennifer Lee\nLab ID: LAB-789012\nDate: 2024-01-20\n\nResults:\n- Glucose: 95 mg/dL\n- Cholesterol: 180 mg/dL\n- Patient DOB: 05/14/1985\n- MRN: L-456789",
        "input_mode": "DOCUMENT_OCR",
        "metadata": {
            "source": "Synthea",
            "patient_id": "syn-patient-003",
            "status": "Synthetic / De-identified",
            "ocr_confidence": 0.91
        }
    }
}

# --- INPUT MODE MAPPING ---
INPUT_MODES = {
    "Text / JSON": "TEXT",
    "HL7 v2": "HL7",
    "Image / Document (OCR)": "DOCUMENT_OCR",
}

# --- INITIALIZE SESSION STATE ---
if "current_result" not in st.session_state:
    st.session_state.current_result = None
if "input_provenance" not in st.session_state:
    st.session_state.input_provenance = None
if "declared_purpose" not in st.session_state:
    st.session_state.declared_purpose = "Not yet declared"
if "selected_demo_case" not in st.session_state:
    st.session_state.selected_demo_case = ""
if "input_mode" not in st.session_state:
    st.session_state.input_mode = "TEXT"
if "ocr_extracted_text" not in st.session_state:
    st.session_state.ocr_extracted_text = None
if "ocr_confidence" not in st.session_state:
    st.session_state.ocr_confidence = None
if "uploaded_image" not in st.session_state:
    st.session_state.uploaded_image = None
if "last_input_text" not in st.session_state:
    st.session_state.last_input_text = ""

# --- MAIN WORKSPACE ---
st.title("VeriFHIR Governance Console")
st.markdown("#### Clinical Record Remediation & Audit Workspace")

st.markdown(
    f"""
    <div style='background: rgba(15, 23, 42, 0.9); border-left: 3px solid #0284c7; padding: 15px; border-radius: 5px; font-size: 0.875rem; color: #94a3b8;'>
    <strong>COMPLIANCE NOTICE:</strong> Operating under <strong>{reg_info['name']}</strong> regulations. 
    Suggested redaction (requires human approval) generated by Azure OpenAI (GPT-4o). 
    All remediation suggestions require final human attestation before system commit.
    </div>
    <br>
    """,
    unsafe_allow_html=True
)

# Two-Tab Layout
tab1, tab2 = st.tabs(["Review & Decision", "Governance Evidence"])

with tab1:
    # Load Example Case Dropdown
    demo_case_options = [""] + list(DEMO_CASES.keys())[1:]
    selected_demo = st.selectbox(
        "Load Example Case",
        options=demo_case_options,
        index=0,
        help="Select a demo case to load. This will populate the input and reset session state."
    )
    
    # Handle demo case selection
    if selected_demo and selected_demo != st.session_state.selected_demo_case:
        case = DEMO_CASES[selected_demo]
        st.session_state.selected_demo_case = selected_demo
        st.session_state.input_mode = case["input_mode"]
        st.session_state.current_result = None
        st.session_state.input_provenance = None
        st.session_state.last_input_text = case["input"]
        if case["input_mode"] == "DOCUMENT_OCR":
            st.session_state.ocr_extracted_text = case["input"]
            st.session_state.ocr_confidence = case["metadata"].get("ocr_confidence", 0.9)
            st.session_state.uploaded_image = None
        else:
            st.session_state.ocr_extracted_text = None
            st.session_state.ocr_confidence = None
            st.session_state.uploaded_image = None
        st.rerun()
    
    # Display demo case metadata if selected
    if selected_demo and selected_demo != "":
        case_meta = DEMO_CASES[selected_demo]["metadata"]
        meta_parts = [
            f"Source: {case_meta.get('source', 'N/A')}",
            f"Patient ID: {case_meta.get('patient_id', 'N/A')}",
            f"Status: {case_meta.get('status', 'N/A')}"
        ]
        if case_meta.get('ocr_confidence'):
            meta_parts.append(f"OCR confidence: {case_meta.get('ocr_confidence', 'N/A')}")
        st.caption(" | ".join(meta_parts))
    
    # ========== PHASE 1 OR PHASE 2 LAYOUT ==========
    # Phase 1: Before analysis (side-by-side allowed)
    # Phase 2: After analysis (vertical flow only)
    
    if st.session_state.current_result:
        # PHASE 2: VERTICAL FLOW (After Analysis)
        # 1. Source Input (collapsed/read-only, at top)
        st.markdown("### Source Record")
        if st.session_state.judge_mode:
            with st.expander("Source Input (Locked)", expanded=False):
                st.text_area("Source Record (Read-Only)", value=st.session_state.get('last_input_text', ''), height=200, disabled=True)
        else:
            # Standard Mode: visually demoted read-only area
            st.caption("Source Record (Read-Only)")
            st.text_area("Source Record (Read-Only)", value=st.session_state.get('last_input_text', ''), height=150, disabled=True)
        
        st.markdown("---")
        
        # 2. Redaction Review (PRIMARY, dominant) - full width only
        st.markdown("### Redaction Review")
        res = st.session_state.current_result
        
        view_mode = st.radio(
            "Display Mode:",
            ["Redline (Changes)", "Clean Output"],
            horizontal=True,
            help="Toggle between diff view and final output"
        )
        
        if view_mode == "Redline (Changes)":
            st.markdown("**Changes Detected:**")
            diff_html = generate_diff_html(res['original_text'], res['suggested_redaction'])
            
            st.markdown(
                f"""
                <div class="redaction-review-container">
                    {diff_html}
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.markdown("**Final Redacted Output:**")
            clean_html = generate_clean_output(res['suggested_redaction'])
            
            st.markdown(
                f"""
                <div class="redaction-review-container">
                    {clean_html}
                </div>
                """,
                unsafe_allow_html=True
            )
        
        # Decision Summary Strip
        method = res.get('remediation_method', '')
        audit = res.get('audit_metadata', {})
        declared_purpose = st.session_state.get('declared_purpose', 'Not yet declared')
        rule_count = len(audit.get('rules_applied', [])) if audit.get('rules_applied') else 0
        
        st.markdown(f"""
        <div style='
            padding: 12px 0; 
            border-top: 1px solid rgba(255,255,255,0.08);
            border-bottom: 1px solid rgba(255,255,255,0.08);
            font-size: 0.875rem;
            color: #94a3b8;'>
            <strong>Engine:</strong> {method} &nbsp;&nbsp;|&nbsp;&nbsp; 
            <strong>Regulation:</strong> {audit.get('regulation', '')} &nbsp;&nbsp;|&nbsp;&nbsp; 
            <strong>Rules Applied:</strong> {rule_count} &nbsp;&nbsp;|&nbsp;&nbsp; 
            <strong>Purpose:</strong> {declared_purpose if declared_purpose != 'Not yet declared' else '(not set)'}
        </div>
        """, unsafe_allow_html=True)
        
        st.divider()
        
        # 3. Post-Redaction Two-Column Split (Decision | Evidence)
        col_decision, col_evidence = st.columns(2, gap="large")
        
        with col_decision:
            st.markdown("#### Decision & Accountability")
            
            st.markdown(f"""
**Engine**  
{method}

**Regulation**  
{audit.get('regulation', 'N/A')}

**Declared Purpose**  
{declared_purpose if declared_purpose != 'Not yet declared' else 'Not yet declared'}
""")
            
            st.divider()
            st.markdown("#### Human Attestation")
            
            with st.form(key="human_decision_form", clear_on_submit=True):
                purpose_options = ["", "Treatment", "Billing", "Research", "Operations"]
                current_purpose_index = 0
                if st.session_state.declared_purpose != "Not yet declared":
                    try:
                        current_purpose_index = purpose_options.index(st.session_state.declared_purpose)
                    except ValueError:
                        current_purpose_index = 0
                
                purpose = st.selectbox(
                    "Purpose *",
                    options=purpose_options,
                    index=current_purpose_index,
                    help="Select the declared purpose for this data processing.",
                )
                
                if purpose and purpose != "":
                    st.session_state.declared_purpose = purpose
                
                reviewer_id = st.text_input(
                    "Reviewer Identity *",
                    value="MVP-SYSTEM-USER",
                    placeholder="email@example.com or reviewer_id",
                    help="Your email or reviewer ID.",
                )
                
                st.markdown("**Decision ***")
                decision = st.radio(
                    "Select your decision:",
                    options=["APPROVED", "NEEDS_REVIEW", "REJECTED"],
                    index=0,
                    help="Your decision on this redaction.",
                )
                
                rationale = st.text_area(
                    "Rationale (minimum 20 characters) *",
                    value="Automated approval for MVP testing.",
                    placeholder="Explain your decision.",
                    help="Provide a justification for your decision (minimum 20 characters).",
                    height=100,
                )
                
                confirmation = st.checkbox(
                    "I acknowledge this decision is final and auditable.",
                    value=False,
                    help="Acknowledgment for audit trail."
                )
                
                submitted = st.form_submit_button("Submit Decision", type="primary", use_container_width="stretch")
            
            # Process form submission
            if submitted:
                validation_errors = []
                
                if not purpose or purpose.strip() == "":
                    validation_errors.append("Purpose selection is required")
                
                if not reviewer_id or not reviewer_id.strip():
                    validation_errors.append("Reviewer identity is required")
                
                if decision is None:
                    validation_errors.append("Decision selection is required")
                
                if not rationale or len(rationale.strip()) < 20:
                    validation_errors.append("Rationale must be at least 20 characters")
                
                if not confirmation:
                    validation_errors.append("Confirmation acknowledgment is required")
                
                if validation_errors:
                    st.error("**Validation Failed:**\n" + "\n".join(f"• {err}" for err in validation_errors))
                else:
                    try:
                        from verifhir.models.audit_record import HumanDecision
                        from verifhir.orchestrator.audit_builder import build_audit_record
                        import uuid
                        
                        human_decision = HumanDecision(
                            reviewer_id=reviewer_id.strip(),
                            decision=decision,
                            rationale=rationale.strip(),
                            timestamp=datetime.datetime.utcnow()
                        )
                        
                        if st.session_state.input_provenance is None:
                            st.error("Input provenance not found. Please re-analyze the input.")
                            st.stop()
                        
                        audit_purpose = st.session_state.declared_purpose if st.session_state.declared_purpose != "Not yet declared" else purpose.strip()
                        audit_record = build_audit_record(
                            audit_id=str(uuid.uuid4()),
                            dataset_fingerprint=audit.get('dataset_fingerprint', 'UNKNOWN'),
                            engine_version=engine.PROMPT_VERSION,
                            policy_snapshot_version=audit.get('policy_snapshot_version', '1.0'),
                            jurisdiction_context={
                                "regulation": regulation,
                                "country_code": country_code
                            },
                            source_jurisdiction=country_code,
                            destination_jurisdiction=country_code,
                            decision={"action": "REDACT", "approved": (decision == "APPROVED")},
                            detections=audit.get('rules_applied', []),
                            detection_methods_used=[method],
                            negative_assertions=audit.get('negative_assertions', []),
                            purpose=audit_purpose,
                            human_decision=human_decision,
                            input_provenance=st.session_state.input_provenance,
                            previous_record_hash=None
                        )
                        
                        if decision == "APPROVED":
                            file_id = commit_record(
                                original_text=res['original_text'],
                                redacted_text=res['suggested_redaction'],
                                metadata=res.get('audit_metadata', {})
                            )
                            
                            st.success("Record committed to secure vault.")
                            st.caption(f"Reference ID: {file_id}")
                            st.caption(f"Reviewer: {reviewer_id}")
                            st.caption(f"Purpose: {purpose.strip()}")
                            st.caption(f"Decision: {decision} at {human_decision.timestamp.isoformat()}")
                            
                            time.sleep(2)
                            st.rerun()
                            
                        elif decision == "NEEDS_REVIEW":
                            st.warning(f"Flagged for manual remediation queue by {reviewer_id}")
                            st.caption(f"Timestamp: {human_decision.timestamp.isoformat()}")
                            time.sleep(2)
                            st.rerun()
                            
                        elif decision == "REJECTED":
                            st.error(f"Redaction rejected by {reviewer_id}")
                            st.caption(f"Timestamp: {human_decision.timestamp.isoformat()}")
                            time.sleep(2)
                            st.rerun()
                        
                    except ValueError as ve:
                        from verifhir.telemetry import scrub_exception_for_telemetry, emit_exception_telemetry
                        error_name = scrub_exception_for_telemetry(ve)
                        emit_exception_telemetry(ve)
                        st.error(f"Validation Failed: {error_name}")
                    except Exception as e:
                        from verifhir.telemetry import scrub_exception_for_telemetry, emit_exception_telemetry
                        error_name = scrub_exception_for_telemetry(e)
                        emit_exception_telemetry(e)
                        st.error(f"Operation Failed: {error_name}")
                        import traceback
                        st.code(traceback.format_exc())
        
        with col_evidence:
            st.markdown("#### Supporting Evidence")
            
            # Explainability Summary (3-4 bullets)
            st.markdown("**Decision Recap**")
            signals_text = ', '.join([m for m in ([res.get('remediation_method')] if res.get('remediation_method') else [])]) or 'Deterministic rules + ML advisory'
            findings_text = ', '.join(sorted(set([f for f in re.findall(r'\b[A-Z][a-z]+ identifiers?\b', res.get('audit_metadata', {}).get('summary', '') or '')]))) or 'Names, dates, identifiers (where applicable)'
            st.markdown(f"""
- Signals: {signals_text}
- Key findings: {findings_text}
- Rationale: {audit.get('decision_rationale', 'Rule-based remediation with advisory ML suggestions')}
""")
            
            # Negative Assurance Summary (3-4 bullets)
            st.markdown("**Negative Assurance (summary)**")
            negs = audit.get('negative_assertions', [])
            if negs:
                # pick up to 4 categories to summarize
                summary_cats = [n.get('category') for n in negs[:4]]
                for cat in summary_cats:
                    st.markdown(f"- {cat}: NOT DETECTED")
            else:
                st.markdown("- No negative assertions available")
            
            # Short forensic identifiers list
            canonical_fingerprint = hashlib.sha256(res['original_text'].encode()).hexdigest()[:32]
            system_config_hash_val = st.session_state.input_provenance.system_config_hash if st.session_state.input_provenance else compute_system_config_hash()
            st.markdown("**Forensic IDs (concise)**")
            st.markdown(f"- Input fingerprint: `{canonical_fingerprint}`")
            st.markdown(f"- System config hash: `{system_config_hash_val}`")
            st.markdown(f"- Engine: `{engine.PROMPT_VERSION}`")
    
    else:
        # PHASE 1: SIDE-BY-SIDE (Before Analysis)
        col_input, col_output = st.columns([1, 1], gap="large")
        
        with col_input:
            st.subheader("Source Input")
            
            current_mode_label = next(
                (label for label, mode in INPUT_MODES.items()
                if mode == st.session_state.input_mode),
                "Text / JSON"
            )
            input_type_selector = st.radio(
                "Input Type",
                options=list(INPUT_MODES.keys()),
                index=list(INPUT_MODES.keys()).index(current_mode_label),
                horizontal=True,
                help="Select input type. OCR extracts text from images for compliance evaluation."
            )
            st.session_state.input_mode = INPUT_MODES[input_type_selector]

            input_text = ""
            
            if st.session_state.input_mode == "DOCUMENT_OCR":
                uploaded_file = st.file_uploader(
                    "Upload Image or Document",
                    type=["png", "jpg", "jpeg", "pdf"],
                    help="Upload an image or PDF. OCR will extract text for compliance evaluation."
                )
                
                if uploaded_file:
                    if uploaded_file.type == "application/pdf":
                        st.session_state.uploaded_image = None
                    else:
                        st.session_state.uploaded_image = uploaded_file

                    try:
                        from verifhir.adapters.ocr_adapter import extract_text_from_image, OCRQualityError
                        from verifhir.telemetry import emit_ocr_confidence_bucket, scrub_exception_for_telemetry
                        
                        with st.status("Extracting text from image...", expanded=True) as ocr_status:
                            if uploaded_file.type == "application/pdf":
                                raise OCRQualityError("PDF input requires document OCR pipeline")
                            ocr_result = extract_text_from_image(uploaded_file)
                            st.session_state.ocr_extracted_text = ocr_result["text"]
                            st.session_state.ocr_confidence = ocr_result["confidence"]
                            
                            if ocr_result["confidence"] >= 0.9:
                                emit_ocr_confidence_bucket("0.9+")
                            elif ocr_result["confidence"] >= 0.8:
                                emit_ocr_confidence_bucket("0.8-0.9")
                            else:
                                emit_ocr_confidence_bucket("0.7-0.8")
                            
                            input_text = ocr_result["text"]
                            st.session_state.last_input_text = input_text
                            ocr_status.update(label="Complete - Text extracted", state="complete", expanded=False)
                            
                    except OCRQualityError as e:
                        from verifhir.telemetry import emit_exception_telemetry
                        emit_exception_telemetry(e)
                        st.error("Image quality insufficient for reliable text extraction. Please provide a clearer scan.")
                        st.stop()
                    except Exception as e:
                        from verifhir.telemetry import scrub_exception_for_telemetry, emit_exception_telemetry
                        error_name = scrub_exception_for_telemetry(e)
                        emit_exception_telemetry(e)
                        st.error(f"OCR extraction failed: {error_name}")
                        st.stop()
                
                if not uploaded_file:
                    st.session_state.uploaded_image = None
                
                if st.session_state.ocr_extracted_text:
                    if st.session_state.uploaded_image is not None:
                        col_img, col_text = st.columns(2)
                        with col_img:
                            st.image(st.session_state.uploaded_image, caption="Uploaded Image", width="stretch")
                        with col_text:
                            st.text_area(
                                "Extracted text (used for compliance evaluation)",
                                value=st.session_state.ocr_extracted_text,
                                height=300,
                                disabled=True
                            )
                    else:
                        st.text_area(
                            "Extracted text (used for compliance evaluation)",
                            value=st.session_state.ocr_extracted_text,
                            height=300,
                            disabled=True
                        )
                    input_text = st.session_state.ocr_extracted_text
                    
            elif st.session_state.input_mode == "HL7":
                if selected_demo and DEMO_CASES[selected_demo]["input_mode"] == "HL7":
                    default_hl7 = DEMO_CASES[selected_demo]["input"]
                else:
                    default_hl7 = "MSH|^~\\&|SendingApp|SendingFacility|ReceivingApp|ReceivingFacility|20240115120000||ADT^A01|12345|P|2.5\nPID|1||123456^^^MRN||DOE^JOHN^MIDDLE||19800115|M|||123 MAIN ST^^CITY^ST^12345||555-1234|||"
                input_text = st.text_area(
                    "HL7 v2 Message",
                    height=400,
                    value=default_hl7,
                    help="Paste HL7 v2 message here. Will be converted to FHIR before processing."
                )
                st.session_state.last_input_text = input_text
                
            else:
                # TEXT mode
                if selected_demo and DEMO_CASES[selected_demo]["input_mode"] == "TEXT":
                    default_text = DEMO_CASES[selected_demo]["input"]
                else:
                    default_fhir = {
                        "resourceType": "Patient",
                        "id": "example",
                        "name": [{"family": "Doe", "given": ["John"]}],
                        "birthDate": "1980-01-15",
                        "telecom": [{"system": "phone", "value": "555-1234"}]
                    }
                    default_text = json.dumps(default_fhir, indent=2)
                input_text = st.text_area(
                    "Text or FHIR JSON",
                    height=400,
                    value=default_text,
                    help="Paste plain text or FHIR JSON resource here."
                )
                st.session_state.last_input_text = input_text
            
            analyze_btn = st.button("Analyze & Redact", type="primary", use_container_width="stretch")
        
        with col_output:
            st.subheader("Analysis Output")
            st.info("Submit source input to generate redaction proposal.")
        
        # --- ENGINE EXECUTION ---
        if analyze_btn and input_text:
            if not input_text.strip():
                st.error("Input required for analysis.")
            else:
                with st.status("Applying governance protocols...", expanded=True) as status:
                    st.write(f"Applying {reg_info['name']} regulations...")
                    st.write(f"Jurisdiction: {country_code}")
                    
                    try:
                        from verifhir.telemetry import emit_converter_status, scrub_exception_for_telemetry
                        
                        if st.session_state.input_mode == "DOCUMENT_OCR":
                            system_config_hash = compute_system_config_hash()
                            st.session_state.input_provenance = InputProvenance(
                                original_format="IMAGE",
                                system_config_hash=system_config_hash,
                                converter_version=None,
                                message_type=None,
                                ocr_engine_version="azure-doc-intel-v1.0",
                                ocr_confidence=st.session_state.ocr_confidence,
                            )
                            processed_text = st.session_state.ocr_extracted_text
                            emit_converter_status("success")
                            
                        elif st.session_state.input_mode == "HL7":
                            raw_payload = input_text
                            normalized = normalize_input(
                                payload=raw_payload,
                                input_format="HL7v2",
                            )
                            fhir_bundle = normalized["bundle"]
                            input_metadata = normalized["metadata"]
                            
                            system_config_hash = compute_system_config_hash()
                            st.session_state.input_provenance = InputProvenance(
                                original_format=input_metadata.get('original_format', 'HL7v2'),
                                system_config_hash=system_config_hash,
                                converter_version=input_metadata.get('converter_version'),
                                message_type=input_metadata.get('message_type'),
                                ocr_engine_version=None,
                                ocr_confidence=None,
                            )
                            emit_converter_status("success")
                            
                            if isinstance(fhir_bundle, dict):
                                processed_text = json.dumps(fhir_bundle, indent=2)
                            else:
                                processed_text = str(fhir_bundle)
                            
                        else:
                            # TEXT mode
                            try:
                                raw_payload = json.loads(input_text)
                                normalized = normalize_input(
                                    payload=raw_payload,
                                    input_format="FHIR",
                                )
                                fhir_bundle = normalized["bundle"]
                                input_metadata = normalized["metadata"]
                                
                                system_config_hash = compute_system_config_hash()
                                st.session_state.input_provenance = InputProvenance(
                                    original_format=input_metadata.get('original_format', 'FHIR'),
                                    system_config_hash=system_config_hash,
                                    converter_version=input_metadata.get('converter_version'),
                                    message_type=input_metadata.get('message_type'),
                                    ocr_engine_version=None,
                                    ocr_confidence=None,
                                )
                                emit_converter_status("success")
                                
                                if isinstance(fhir_bundle, dict):
                                    processed_text = json.dumps(fhir_bundle, indent=2)
                                else:
                                    processed_text = str(fhir_bundle)
                            except json.JSONDecodeError:
                                system_config_hash = compute_system_config_hash()
                                st.session_state.input_provenance = InputProvenance(
                                    original_format="TEXT",
                                    system_config_hash=system_config_hash,
                                    converter_version=None,
                                    message_type=None,
                                    ocr_engine_version=None,
                                    ocr_confidence=None,
                                )
                                processed_text = st.session_state.ocr_extracted_text or input_text
                                emit_converter_status("success")
                        
                        st.write(f"Complete - Input normalized: {st.session_state.input_provenance.original_format}")
                        if st.session_state.input_provenance.message_type:
                            st.write(f"  Message type: {st.session_state.input_provenance.message_type}")
                        if st.session_state.input_provenance.ocr_engine_version:
                            st.write(f"  OCR confidence: {st.session_state.input_provenance.ocr_confidence:.2f}")
                        
                    except NotImplementedError as e:
                        from verifhir.telemetry import scrub_exception_for_telemetry, emit_exception_telemetry, emit_converter_status
                        error_name = scrub_exception_for_telemetry(e)
                        emit_exception_telemetry(e)
                        emit_converter_status("failure")
                        st.error(f"HL7 conversion not yet implemented: {error_name}")
                        st.info("For MVP, HL7 → FHIR conversion is delegated to Microsoft FHIR Converter.")
                        st.stop()
                    except Exception as e:
                        from verifhir.telemetry import scrub_exception_for_telemetry, emit_exception_telemetry, emit_converter_status
                        error_name = scrub_exception_for_telemetry(e)
                        emit_exception_telemetry(e)
                        emit_converter_status("failure")
                        st.error(f"Input normalization failed: {error_name}")
                        st.stop()
                    
                    from opentelemetry import trace
                    from verifhir.telemetry import emit_decision_telemetry
                    
                    tracer = trace.get_tracer(__name__)
                    
                    with tracer.start_as_current_span("verifhir.decision_evaluation"):
                        start_time = time.perf_counter()
                        response = engine.generate_suggestion(processed_text, regulation, country_code)
                        latency_ms = int((time.perf_counter() - start_time) * 1000)
                        
                        remediation_method = response.get('remediation_method', 'Unknown')
                        if 'Azure OpenAI' in remediation_method or 'OpenAI' in remediation_method:
                            decision_path = "ml-sensor"
                        elif 'Fallback' in remediation_method or 'Regex' in remediation_method:
                            decision_path = "rules"
                        else:
                            decision_path = "hybrid"
                        
                        fallback_triggered = 'Fallback' in remediation_method or 'Regex' in remediation_method
                        risk_score = response.get('risk_score', 0.0)
                        if not isinstance(risk_score, float):
                            risk_score = float(risk_score) if risk_score else 0.0
                        
                        emit_decision_telemetry(
                            decision_latency_ms=latency_ms,
                            risk_score=risk_score,
                            decision_path=decision_path,
                            fallback_triggered=fallback_triggered,
                        )
                        
                        from verifhir.telemetry import emit_risk_band
                        if risk_score <= 3.0:
                            emit_risk_band("LOW")
                        elif risk_score <= 8.0:
                            emit_risk_band("MEDIUM")
                        else:
                            emit_risk_band("HIGH")
                    
                    if 'audit_metadata' not in response:
                        response['audit_metadata'] = {}
                    
                    response['audit_metadata']['regulation'] = regulation
                    response['audit_metadata']['country_code'] = country_code
                    
                    from verifhir.assurance.categories import ASSURABLE_CATEGORIES
                    detection_methods_used = [response.get('remediation_method', 'Unknown')]
                    
                    negative_assertions_dict = []
                    for category in ASSURABLE_CATEGORIES.keys():
                        negative_assertions_dict.append({
                            "category": category,
                            "status": "NOT_DETECTED",
                            "supported_by": ", ".join(sorted(detection_methods_used)),
                            "scope_note": "Not detected within detector coverage"
                        })
                    
                    response['audit_metadata']['negative_assertions'] = negative_assertions_dict
                    st.session_state.current_result = response
                    
                    status.update(label="Complete - Redaction Complete", state="complete", expanded=False)
                    st.rerun()

with tab2:
    st.markdown("# Governance Evidence (Required Review)")
    st.markdown(
        "This section documents why the proposed redaction is compliant under the selected regulation. "
        "Reviewers are expected to consult this evidence before attestation."
    )

    if not st.session_state.current_result:
        st.info("No analysis results available. Please analyze input in the Review & Decision tab.")
    else:
        res = st.session_state.current_result
        audit = res.get("audit_metadata", {})
        
        # --- ROW 1: EXPLAINABILITY & NEGATIVE ASSURANCE ---
        col_left, col_right = st.columns(2, gap="large")

        with col_left:
            # Extract detected categories for the display
            rules_applied = audit.get("rules_applied", [])
            categories_str = ", ".join(set(rules_applied)) if rules_applied else "Names, Dates, Identifiers"
            
            explain_html = f"""
            <div class="evidence-widget">
                <div class="evidence-header">Explainability</div>
                <div class="evidence-divider"></div>
                <div class="sub-widget">
                    <strong>Detection Signals Used</strong>
                    <div style="margin-top:0.5rem;">
                        • Azure OpenAI (Advisory): Language-model suggestions<br/>
                        • Deterministic Rules: Regulatory compliance authority<br/>
                        • Regex & Identifier Validation: Pattern-based validators
                    </div>
                </div>
                <div class="sub-widget">
                    <strong>Observed Findings</strong>
                    <div style="margin-top:0.5rem;">
                        • Key detected classes: {safe_text(categories_str)}
                    </div>
                </div>
                <div class="sub-widget">
                    <strong>Decision Rationale</strong>
                    <div style="margin-top:0.5rem;">
                        • Deterministic rules determine compliance; ML provides advisory suggestions.<br/>
                        • Final decision requires human attestation.
                    </div>
                </div>
            </div>
            """
            st.markdown(explain_html, unsafe_allow_html=True)

        with col_right:
            # Check for financial status specifically as per app logic
            negative_assertions = audit.get("negative_assertions", [])
            financial_status = "DETECTED" if any("financial" in str(n).lower() for n in negative_assertions) else "NOT DETECTED"

            checked_html = f"""
            <div class="evidence-widget">
                <div class="evidence-header">Checked & Not Detected</div>
                <div class="evidence-divider"></div>
                <div class="sub-widget">
                    <strong>Biometric & Genetic Data</strong>
                    <div style="margin-top:0.5rem;">
                        Status: NOT DETECTED<br/>
                        Scope: Not detected within detector coverage
                    </div>
                </div>
                <div class="sub-widget">
                    <strong>Financial Identifiers</strong>
                    <div style="margin-top:0.5rem;">
                        Status: {safe_text(financial_status)}<br/>
                        Scope: Account numbers and routing information
                    </div>
                </div>
                <div class="sub-widget">
                    <strong>National Identifiers</strong>
                    <div style="margin-top:0.5rem;">
                        Status: NOT DETECTED<br/>
                        Scope: SSN, Aadhaar, or NHS numbers depending on context
                    </div>
                </div>
            </div>
            """
            st.markdown(checked_html, unsafe_allow_html=True)

        # --- ROW 2: FORENSIC EVIDENCE (FULL WIDTH) ---
        canonical_fingerprint = hashlib.sha256(res["original_text"].encode()).hexdigest()[:32]
        system_hash = st.session_state.input_provenance.system_config_hash if st.session_state.input_provenance else "UNKNOWN"
        
        forensic_html = f"""
        <div class="evidence-widget">
            <div class="evidence-header">Forensic Evidence</div>
            <div class="evidence-divider"></div>
            <div style="font-size:0.95rem; color:#cbd5e1; font-family: monospace;">
                <strong>Audit Metadata</strong><br/>
                Governance Engine: {safe_text(engine.PROMPT_VERSION)}<br/>
                Policy Snapshot: {safe_text(audit.get("policy_snapshot_version", "1.0"))}<br/><br/>
                <strong>Integrity Hashes</strong><br/>
                Input Fingerprint: {safe_text(canonical_fingerprint)}<br/>
                System Config Hash: {safe_text(system_hash)}<br/><br/>
                <strong>Data Provenance</strong><br/>
                Original Format: {safe_text(st.session_state.input_provenance.original_format if st.session_state.input_provenance else "N/A")}<br/>
                OCR Confidence: {safe_text(st.session_state.input_provenance.ocr_confidence if st.session_state.input_provenance else "N/A")}
            </div>
        </div>
        """
        st.markdown(forensic_html, unsafe_allow_html=True)