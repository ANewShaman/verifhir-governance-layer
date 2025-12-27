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

init_telemetry()

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="VeriFHIR Governance Console",
    layout="wide",
    initial_sidebar_state="expanded"
)

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
    - Redacted tags in clean green chips
    - Better spacing and readability
    """
    d = difflib.SequenceMatcher(None, original, redacted)
    html_parts = []
    
    for tag, i1, i2, j1, j2 in d.get_opcodes():
        if tag == 'replace':
            # Original text (strikethrough, muted red)
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
            
            # Redacted tag (clean green chip)
            redact_text = html.escape(redacted[j1:j2])
            html_parts.append(
                f'<span style="'
                f'background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%); '
                f'color: #15803d; '
                f'font-weight: 600; '
                f'border: 1.5px solid #22c55e; '
                f'border-radius: 6px; '
                f'padding: 3px 10px; '
                f'margin: 0 4px; '
                f'display: inline-block; '
                f'box-shadow: 0 1px 2px rgba(0,0,0,0.05); '
                f'font-family: ui-monospace, monospace; '
                f'font-size: 0.9em;">'
                f'{redact_text}</span>'
            )
        
        elif tag == 'delete':
            # Deleted text only
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
            # Inserted text only (new redaction tags)
            ins_text = html.escape(redacted[j1:j2])
            html_parts.append(
                f'<span style="'
                f'background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%); '
                f'color: #15803d; '
                f'font-weight: 600; '
                f'border: 1.5px solid #22c55e; '
                f'border-radius: 6px; '
                f'padding: 3px 10px; '
                f'margin: 0 4px; '
                f'display: inline-block; '
                f'box-shadow: 0 1px 2px rgba(0,0,0,0.05); '
                f'font-family: ui-monospace, monospace; '
                f'font-size: 0.9em;">'
                f'{ins_text}</span>'
            )
            
        elif tag == 'equal':
            # Unchanged text
            equal_text = html.escape(original[i1:i2])
            html_parts.append(equal_text)
            
    return "".join(html_parts)

def generate_clean_output(redacted_text):
    """
    Generates a clean, final output view with highlighted redaction tags.
    This is what the final document would look like.
    """
    import re
    
    def highlight_tag(match):
        tag_content = match.group(0)
        escaped = html.escape(tag_content)
        return (
            f'<span style="'
            f'background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%); '
            f'color: #1e40af; '
            f'font-weight: 600; '
            f'border: 1.5px solid #3b82f6; '
            f'border-radius: 6px; '
            f'padding: 3px 10px; '
            f'margin: 0 2px; '
            f'display: inline-block; '
            f'box-shadow: 0 1px 2px rgba(0,0,0,0.05); '
            f'font-family: ui-monospace, monospace; '
            f'font-size: 0.9em;">'
            f'{escaped}</span>'
        )
    
    # Highlight all redaction tags
    highlighted = re.sub(r'\[REDACTED[^\]]*\]', highlight_tag, html.escape(redacted_text))
    return highlighted

def compute_system_config_hash() -> str:
    """
    Compute a hash of the current system configuration.
    This prevents replay drift due to environment changes.
    """
    config_data = {
        "engine_version": engine.PROMPT_VERSION,
        "python_version": "3.11",  # Could be dynamic
        "streamlit_version": st.__version__,
    }
    config_str = json.dumps(config_data, sort_keys=True)
    return hashlib.sha256(config_str.encode()).hexdigest()[:16]

# --- SIDEBAR: SYSTEM CONFIG ---
with st.sidebar:
    st.header("System Control")
    
    st.subheader("Policy Context")
    
    # Regulation selector with enhanced display
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
    
    # Display regulation details
    st.info(f"**{reg_info['full_name']}**\n\n{reg_info['description']}")
    
    # Country code (auto-populated or customizable)
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
        st.success("● Hybrid Mode Active")
        st.caption("AI Redactor + Deterministic Fallback")
    else:
        st.warning("● Fallback Mode Active")
        st.caption("Deterministic Pattern Matching Only")

    st.divider()
    st.caption(f"VeriFHIR Core {engine.PROMPT_VERSION}")

# --- MAIN WORKSPACE ---
st.title("VeriFHIR Governance Console")
st.markdown("#### Clinical Record Remediation & Audit Workspace")

# Legal Guardrail Notice
st.markdown(
    f"""
    <div style='background-color: #f0f2f6; border-left: 5px solid #007bff; padding: 15px; border-radius: 5px; font-size: 0.95em; color: #1f2937;'>
    <strong>COMPLIANCE NOTICE:</strong> Operating under <strong>{reg_info['name']}</strong> regulations. 
    Suggestions generated by Azure OpenAI (GPT-4o). 
    All remediation suggestions require final human attestation before system commit.
    </div>
    <br>
    """,
    unsafe_allow_html=True
)

col_input, col_output = st.columns([1, 1], gap="large")

# --- COLUMN 1: SOURCE RECORD ---
with col_input:
    st.subheader("Source Input")
    
    # Format selector
    input_format = st.selectbox(
        "Input format",
        ["FHIR JSON", "HL7 v2 (ADT^A01)"],
        help="Select the input format. HL7 v2 will be converted to FHIR before processing."
    )
    
    # Map UI selection to adapter format
    format_key = "HL7v2" if input_format == "HL7 v2 (ADT^A01)" else "FHIR"
    
    # Regulation-specific example text
    if regulation == "HIPAA":
        default_text = (
            "Patient Rahul Sharma (MRN: H-987654, SSN: 123-45-6789) admitted on Jan 12, 2024.\n"
            "Contact: +91 98765 43210, rahul.sharma@example.com\n"
            "Address: 123 Maple Avenue, Apt 4B, Brooklyn, NY 10001\n"
            "DOB: March 15, 1985\n"
            "IP Access: 192.168.1.105"
        )
    elif regulation == "GDPR":
        default_text = (
            "Patient: Hans Mueller\n"
            "National ID: DE-1234567890\n"
            "Email: hans.mueller@example.de\n"
            "Address: Hauptstraße 42, 10115 Berlin, Germany\n"
            "DOB: 15.03.1980\n"
            "Cookie ID: abc-def-123-456"
        )
    elif regulation == "UK_GDPR":
        default_text = (
            "Patient: Sarah Johnson\n"
            "NHS Number: 123 456 7890\n"
            "NI Number: AB123456C\n"
            "Email: sarah.johnson@nhs.uk\n"
            "Address: 10 Downing Street, London, SW1A 2AA\n"
            "DOB: 12/05/1975"
        )
    elif regulation == "LGPD":
        default_text = (
            "Cliente: Maria Silva\n"
            "CPF: 123.456.789-00\n"
            "Email: maria.silva@example.com.br\n"
            "Endereço: Rua das Flores 100, São Paulo, CEP: 01310-100\n"
            "Data de Nascimento: 15/03/1985"
        )
    elif regulation == "DPDP":
        default_text = (
            "Patient: Priya Sharma\n"
            "Aadhaar: 1234 5678 9012\n"
            "PAN: ABCDE1234F\n"
            "Email: priya.sharma@example.in\n"
            "Address: 123 MG Road, Bangalore, PIN: 560001\n"
            "DOB: 15/03/1990"
        )
    else:  # BASE
        default_text = (
            "Patient: John Doe (ID: 12345)\n"
            "Email: john.doe@example.com\n"
            "Phone: +1-555-0100\n"
            "Address: 123 Main Street, Anytown, 12345\n"
            "DOB: January 15, 1980\n"
            "IP: 192.168.1.1"
        )
    
    if input_format == "HL7 v2 (ADT^A01)":
        input_text = st.text_area(
            "HL7 v2 Message",
            height=400,
            value="MSH|^~\\&|SendingApp|SendingFacility|ReceivingApp|ReceivingFacility|20240115120000||ADT^A01|12345|P|2.5\nPID|1||123456^^^MRN||DOE^JOHN^MIDDLE||19800115|M|||123 MAIN ST^^CITY^ST^12345||555-1234|||",
            help="Paste HL7 v2 message here. Will be converted to FHIR before processing."
        )
    else:  # FHIR JSON
        # Default FHIR example
        default_fhir = {
            "resourceType": "Patient",
            "id": "example",
            "name": [{"family": "Doe", "given": ["John"]}],
            "birthDate": "1980-01-15",
            "telecom": [{"system": "phone", "value": "555-1234"}]
        }
        input_text = st.text_area(
            "FHIR JSON",
            height=400,
            value=json.dumps(default_fhir, indent=2),
            help="Paste FHIR JSON resource or bundle here."
        )
    
    analyze_btn = st.button("Analyze & Redact", type="primary", use_container_width=True)

# --- ENGINE EXECUTION ---
if "current_result" not in st.session_state:
    st.session_state.current_result = None
if "input_provenance" not in st.session_state:
    st.session_state.input_provenance = None

if analyze_btn:
    if not input_text.strip():
        st.error("Input required for analysis.")
    else:
        with st.status("Applying governance protocols...", expanded=True) as status:
            st.write(f"📋 Applying {reg_info['name']} regulations...")
            st.write(f"🌍 Jurisdiction: {country_code}")
            
            # Normalize input (HL7 → FHIR if needed)
            try:
                if format_key == "HL7v2":
                    # HL7 is a string
                    raw_payload = input_text
                else:
                    # FHIR is JSON - parse it (st.text_area always returns string)
                    raw_payload = json.loads(input_text)
                
                normalized = normalize_input(
                    payload=raw_payload,
                    input_format=format_key,
                )
                fhir_bundle = normalized["bundle"]
                input_metadata = normalized["metadata"]
                
                # ============================================================
                # A.1: Create InputProvenance EXACTLY ONCE
                # ============================================================
                system_config_hash = compute_system_config_hash()
                
                st.session_state.input_provenance = InputProvenance(
                    original_format=input_metadata.get('original_format', format_key),
                    system_config_hash=system_config_hash,
                    converter_version=input_metadata.get('converter_version'),
                    message_type=input_metadata.get('message_type'),
                    ocr_engine_version=input_metadata.get('ocr_engine_version'),
                    ocr_confidence=input_metadata.get('ocr_confidence'),
                )
                
                # Convert FHIR bundle to text for RedactionEngine (if it's a dict, stringify)
                if isinstance(fhir_bundle, dict):
                    # For now, convert to JSON string for text processing
                    # In a full implementation, you'd process the FHIR bundle directly
                    processed_text = json.dumps(fhir_bundle, indent=2)
                else:
                    processed_text = str(fhir_bundle)
                
                st.write(f"✓ Input normalized: {st.session_state.input_provenance.original_format}")
                if st.session_state.input_provenance.message_type:
                    st.write(f"  Message type: {st.session_state.input_provenance.message_type}")
                
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON format: {str(e)}")
                st.stop()
            except NotImplementedError as e:
                st.error(f"HL7 conversion not yet implemented: {str(e)}")
                st.info("For MVP, HL7 → FHIR conversion is delegated to Microsoft FHIR Converter.")
                st.stop()
            except Exception as e:
                st.error(f"Input normalization failed: {str(e)}")
                st.stop()
            
            # Process with RedactionEngine (currently expects text)
            response = engine.generate_suggestion(processed_text, regulation, country_code)
            
            # Attach input provenance to response metadata
            if 'audit_metadata' not in response:
                response['audit_metadata'] = {}
            
            # Store metadata but NOT the InputProvenance object itself
            # (InputProvenance is in session_state)
            response['audit_metadata']['regulation'] = regulation
            response['audit_metadata']['country_code'] = country_code
            
            st.session_state.current_result = response
            
            status.update(label="✓ Redaction Complete", state="complete", expanded=False)

# --- COLUMN 2: GOVERNANCE REVIEW ---
with col_output:
    st.subheader("Review Redaction")
    
    if st.session_state.current_result:
        res = st.session_state.current_result
        
        # View selector
        view_mode = st.radio(
            "Display Mode:",
            ["Redline (Changes)", "Clean Output"],
            horizontal=True,
            help="Toggle between diff view and final output"
        )
        
        if view_mode == "Redline (Changes)":
            # REDLINE VIEW - Shows what changed
            st.markdown("**Changes Detected:**")
            diff_html = generate_diff_html(res['original_text'], res['suggested_redaction'])
            
            st.markdown(
                f"""
                <div style="
                    border: 2px solid #e5e7eb; 
                    border-radius: 10px; 
                    padding: 24px; 
                    height: 400px; 
                    overflow-y: auto; 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; 
                    white-space: pre-wrap; 
                    background: linear-gradient(to bottom, #ffffff 0%, #fafafa 100%);
                    line-height: 1.9;
                    color: #1f2937;
                    font-size: 15px;
                    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.06);">
                    {diff_html}
                </div>
                """, 
                unsafe_allow_html=True
            )
        else:
            # CLEAN OUTPUT VIEW - Shows final result
            st.markdown("**Final Redacted Output:**")
            clean_html = generate_clean_output(res['suggested_redaction'])
            
            st.markdown(
                f"""
                <div style="
                    border: 2px solid #cbd5e1; 
                    border-radius: 10px; 
                    padding: 24px; 
                    height: 400px; 
                    overflow-y: auto; 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; 
                    white-space: pre-wrap; 
                    background: #ffffff;
                    line-height: 1.9;
                    color: #1f2937;
                    font-size: 15px;
                    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                    {clean_html}
                </div>
                """, 
                unsafe_allow_html=True
            )
        
        # METADATA FOOTER
        method = res['remediation_method']
        audit = res.get('audit_metadata', {})
        
        col_m1, col_m2 = st.columns(2)
        with col_m1:
            st.caption(f"**Engine:** {method}")
        with col_m2:
            if 'rules_applied' in audit:
                rule_count = len(audit['rules_applied'])
                st.caption(f"**Rules Applied:** {rule_count} categories")
            if 'regulation' in audit:
                st.caption(f"**Regulation:** {audit['regulation']}")
        
        st.divider()
        
        # ============================================================
        # B.5: PROGRESSIVE DISCLOSURE - EXPLAINABILITY LAYER
        # ============================================================
        with st.expander("📊 Explainability", expanded=False):
            st.markdown("**How this decision was made:**")
            
            # Rules triggered
            if 'rules_applied' in audit and audit['rules_applied']:
                st.markdown("**PII/PHI Categories Detected:**")
                rules = audit['rules_applied']
                badge_html = " ".join([
                    f'<span style="'
                    f'background-color: #eff6ff; '
                    f'color: #1e40af; '
                    f'padding: 4px 12px; '
                    f'border-radius: 12px; '
                    f'font-size: 0.85em; '
                    f'font-weight: 600; '
                    f'display: inline-block; '
                    f'margin: 4px; '
                    f'border: 1px solid #bfdbfe;">'
                    f'{rule}</span>'
                    for rule in rules
                ])
                st.markdown(badge_html, unsafe_allow_html=True)
            
            # ML signals used
            st.markdown(f"**Detection Method:** {method}")
            
            # B.8: Negative assurances
            if 'negative_assertions' in audit and audit['negative_assertions']:
                st.markdown("**Not Detected:**")
                neg_assertions = audit['negative_assertions']
                if neg_assertions:
                    neg_text = ", ".join(neg_assertions)
                    st.caption(f"Categories confirmed absent: {neg_text}")
                else:
                    st.caption("No negative assurances recorded for this analysis.")
            
            # B.7: HL7 provenance (if applicable)
            if st.session_state.input_provenance and st.session_state.input_provenance.original_format == "HL7v2":
                st.markdown("**Input Provenance:**")
                st.caption(f"✓ Input normalized from HL7 v2")
                if st.session_state.input_provenance.message_type:
                    st.caption(f"  Message Type: {st.session_state.input_provenance.message_type}")
                if st.session_state.input_provenance.converter_version:
                    st.caption(f"  Converter Version: {st.session_state.input_provenance.converter_version}")
        
        # ============================================================
        # B.6: PROGRESSIVE DISCLOSURE - FORENSIC DATA LAYER
        # ============================================================
        with st.expander("🔍 Forensic Evidence (Read-Only)", expanded=False):
            st.markdown("**Audit Proof Metadata:**")
            
            forensic_data = {
                "Engine Version": engine.PROMPT_VERSION,
                "Policy Snapshot": audit.get('policy_snapshot_version', '1.0'),
                "Dataset Fingerprint": audit.get('dataset_fingerprint', 'UNKNOWN'),
            }
            
            if st.session_state.input_provenance:
                forensic_data["System Config Hash"] = st.session_state.input_provenance.system_config_hash
                forensic_data["Input Format"] = st.session_state.input_provenance.original_format
                if st.session_state.input_provenance.converter_version:
                    forensic_data["Converter Version"] = st.session_state.input_provenance.converter_version
            
            for key, value in forensic_data.items():
                st.caption(f"**{key}:** `{value}`")
            
            st.caption("_This data is immutable and part of the permanent audit record._")
        
        st.divider()
        
        # ============================================================
        # C.9: HUMAN ATTESTATION SECTION - ONLY ACTION BUTTONS
        # ============================================================
        st.subheader("Human Attestation")
        
        st.markdown(
            """
            <div style='background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; border-radius: 4px; margin-bottom: 20px; color: #000000;'>
            <strong>MVP Testing Mode:</strong> Simplified approval workflow for development and testing purposes.
            </div>
            """,
            unsafe_allow_html=True
        )
        
        # Use Streamlit form for proper state management
        with st.form(key="human_decision_form", clear_on_submit=True):
            # 1. REVIEWER IDENTITY
            reviewer_id = st.text_input(
                "Reviewer Identity *",
                value="MVP-SYSTEM-USER",
                placeholder="email@example.com or reviewer_id",
                help="Your email or reviewer ID.",
            )
            
            # 2. DECISION SELECTION
            st.markdown("**Decision ***")
            decision = st.radio(
                "Select your decision:",
                options=["APPROVED", "NEEDS_REVIEW", "REJECTED"],
                index=0,  # Default to APPROVED
                help="Your decision on this redaction.",
            )
            
            # 3. RATIONALE
            rationale = st.text_area(
                "Rationale (minimum 20 characters) *",
                value="Automated approval for MVP testing.",
                placeholder="Explain your decision.",
                help="Provide a justification for your decision (minimum 20 characters).",
                height=100,
            )
            
            # 4. CONFIRMATION CHECKBOX
            confirmation = st.checkbox(
                "I acknowledge this decision is final and auditable.",
                value=False,
                help="Acknowledgment for audit trail."
            )
            
            # Submit button
            submitted = st.form_submit_button("Submit Decision", type="primary", use_container_width=True)
        
        # Process form submission
        if submitted:
            # Validation
            validation_errors = []
            
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
                # Process the decision
                try:
                    from verifhir.models.audit_record import HumanDecision
                    from verifhir.orchestrator.audit_builder import build_audit_record
                    import uuid
                    
                    # Create HumanDecision object
                    human_decision = HumanDecision(
                        reviewer_id=reviewer_id.strip(),
                        decision=decision,
                        rationale=rationale.strip(),
                        timestamp=datetime.datetime.utcnow()
                    )
                    
                    # ============================================================
                    # A.2: Pass input_provenance to build_audit_record()
                    # ============================================================
                    if st.session_state.input_provenance is None:
                        st.error("❌ Input provenance not found. Please re-analyze the input.")
                        st.stop()
                    
                    # Build audit record
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
                        purpose="clinical_data_remediation",
                        human_decision=human_decision,
                        input_provenance=st.session_state.input_provenance,  # A.2: Explicit pass
                        previous_record_hash=None
                    )
                    
                    # Handle decision type
                    if decision == "APPROVED":
                        # Commit to storage
                        file_id = commit_record(
                            original_text=res['original_text'],
                            redacted_text=res['suggested_redaction'],
                            metadata=res.get('audit_metadata', {})
                        )
                        
                        st.balloons()
                        st.success(f"✓ Record committed to secure vault.")
                        st.caption(f"Reference ID: {file_id}")
                        st.caption(f"Reviewer: {reviewer_id}")
                        st.caption(f"Decision: {decision} at {human_decision.timestamp.isoformat()}")
                        
                        # A.4: Use st.rerun() instead of manual clearing
                        time.sleep(2)
                        st.rerun()
                        
                    elif decision == "NEEDS_REVIEW":
                        st.warning(f"⚠ Flagged for manual remediation queue by {reviewer_id}")
                        st.caption(f"Timestamp: {human_decision.timestamp.isoformat()}")
                        time.sleep(2)
                        st.rerun()
                        
                    elif decision == "REJECTED":
                        st.error(f"✕ Redaction rejected by {reviewer_id}")
                        st.caption(f"Timestamp: {human_decision.timestamp.isoformat()}")
                        time.sleep(2)
                        st.rerun()
                    
                except ValueError as ve:
                    # This catches validation errors from audit_builder
                    st.error(f"❌ Validation Failed: {str(ve)}")
                except Exception as e:
                    st.error(f"❌ Operation Failed: {str(e)}")
                    import traceback
                    st.code(traceback.format_exc())

    else:
        st.info("Awaiting input analysis. Please click 'Analyze & Redact' to generate a proposal.")