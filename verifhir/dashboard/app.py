import streamlit as st
import time
import json
import datetime
import difflib
from verifhir.remediation.redactor import RedactionEngine

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

# --- HELPER: VISUAL DIFF GENERATOR ---
def generate_diff_html(original, redacted):
    """
    Compares original and redacted text, returning HTML with red/green highlights.
    """
    d = difflib.SequenceMatcher(None, original, redacted)
    html = []
    for tag, i1, i2, j1, j2 in d.get_opcodes():
        if tag == 'replace':
            # Deleted part in Red Strikethrough, Added part in Green
            html.append(f'<span style="background-color: #ffcccc; text-decoration: line-through; color: #cc0000;">{original[i1:i2]}</span>')
            html.append(f'<span style="background-color: #ccffcc; color: #006600; font-weight: bold;">{redacted[j1:j2]}</span>')
        elif tag == 'delete':
            html.append(f'<span style="background-color: #ffcccc; text-decoration: line-through; color: #cc0000;">{original[i1:i2]}</span>')
        elif tag == 'insert':
            html.append(f'<span style="background-color: #ccffcc; color: #006600; font-weight: bold;">{redacted[j1:j2]}</span>')
        elif tag == 'equal':
            html.append(original[i1:i2])
    return "".join(html)

# --- HELPER: AUDIT DIALOG ---
@st.dialog("Technical Audit Metadata")
def show_audit_dialog(data):
    st.json(data)
    st.caption(f"Timestamp: {datetime.datetime.now().isoformat()}")
    st.caption("This raw data is for technical audit purposes only.")

# --- SIDEBAR: SYSTEM CONFIG ---
with st.sidebar:
    st.header("System Configuration")
    
    # 1. Policy Context
    st.subheader("Policy Context")
    regulation = st.selectbox(
        "Regulatory Framework", 
        ["HIPAA", "GDPR"],
        help="Determines the specific reduction ruleset applied to the record."
    )
    
    country_code = "US"
    if regulation == "GDPR":
        country_code = st.text_input("Jurisdiction (ISO 3166-1)", "DE").upper()
    
    st.divider()
    
    # 2. Engine Status
    st.subheader("Engine Status")
    if engine.client:
        st.info("System Mode: Hybrid (AI + Deterministic)")
        st.caption("Connection: Azure OpenAI Service Active")
    else:
        st.error("System Mode: Fallback (Deterministic Only)")
        st.caption("Connection: Offline / Local Rules Active")

    st.divider()
    st.caption(f"VeriFHIR Core v{engine.PROMPT_VERSION}")

# --- MAIN WORKSPACE ---
st.title("VeriFHIR Governance Console")
st.markdown("#### Clinical Record Remediation Workspace")

# Legal Notice
st.markdown(
    """
    <div style='background-color: #f8f9fa; border-left: 4px solid #6c757d; padding: 10px; font-size: 0.9em; color: #495057;'>
    <strong>NOTICE:</strong> This interface provides AI-assisted redaction suggestions. 
    Output does not constitute a final legal determination. 
    Human review is mandatory pursuant to organizational data governance policies.
    </div>
    <br>
    """,
    unsafe_allow_html=True
)

col_input, col_output = st.columns([1, 1], gap="large")

# --- COLUMN 1: INPUT RECORD ---
with col_input:
    st.subheader("Input Record")
    
    default_text = (
        "Patient John Doe (SSN: 123-45-6789) admitted on Jan 12, 2024 to Mt Sinai. "
        "Contact: john.doe@example.com for follow-up."
    )
    
    input_text = st.text_area(
        "Raw Clinical Text",
        height=400,
        value=default_text,
        help="Original unstructured data from the source system."
    )
    
    # Primary Action (Kept neutral blue)
    analyze_btn = st.button("Analyze Record", type="primary", use_container_width=True)

# --- STATE MANAGEMENT ---
if "current_result" not in st.session_state:
    st.session_state.current_result = None

if analyze_btn:
    if not input_text.strip():
        st.error("Operation halted: Input record is empty.")
    else:
        with st.status("Processing governance rules...", expanded=True) as status:
            st.write(f"Loading context: {regulation}")
            time.sleep(0.3)
            
            response = engine.generate_suggestion(input_text, regulation, country_code)
            st.session_state.current_result = response
            
            st.write("Generating visual diff...")
            status.update(label="Analysis Complete", state="complete", expanded=False)

# --- COLUMN 2: REMEDIATION DRAFT ---
with col_output:
    st.subheader("Review Redaction")
    
    if st.session_state.current_result:
        res = st.session_state.current_result
        original = res['original_text']
        redacted = res['suggested_redaction']

        # 1. VISUAL DIFF VIEW
        st.markdown("**Change Preview (Redline):**")
        diff_html = generate_diff_html(original, redacted)
        
        # Render the HTML Diff inside a scrollable container
        st.markdown(
            f"""
            <div style="
                border: 1px solid #ccc; 
                border-radius: 5px; 
                padding: 10px; 
                height: 400px; 
                overflow-y: auto; 
                font-family: monospace; 
                white-space: pre-wrap; 
                background-color: #f9f9f9;
                line-height: 1.5;">
                {diff_html}
            </div>
            """, 
            unsafe_allow_html=True
        )
        
        # 2. METHODOLOGY INDICATOR
        method = res['remediation_method']
        st.caption(f"Methodology Applied: {method}")
        
        st.divider()
        
        # 3. DECISION CONTROLS (Neutral Buttons)
        st.subheader("Decision & Audit")
        
        btn_col1, btn_col2 = st.columns(2)
        
        with btn_col1:
            if st.button("Approve & Commit", use_container_width=True):
                st.info(f"Transaction ID {id(res)}: Record committed to audit log.")
                
        with btn_col2:
            if st.button("Reject & Flag", use_container_width=True):
                st.warning("Transaction flagged for manual remediation queue.")

        st.divider()

        # 4. POP-UP AUDIT LOG
        if st.button("View Technical Audit Metadata", use_container_width=True):
            show_audit_dialog(res)

    else:
        st.caption("No active record analysis. Submit a record to begin review.")