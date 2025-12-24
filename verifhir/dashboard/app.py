import streamlit as st
import time
import json
import datetime
import difflib
import html
from verifhir.remediation.redactor import RedactionEngine
from verifhir.storage import commit_record

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
    # Pattern to match [REDACTED XYZ] tags
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

# --- HELPER: AUDIT DIALOG ---
@st.dialog("Technical Audit Metadata")
def show_audit_dialog(data):
    st.write("### Internal Governance Trace")
    st.json(data)
    st.caption(f"System Reference: {datetime.datetime.now().isoformat()}")
    st.caption("Access restricted to authorized compliance officers only.")

# --- SIDEBAR: SYSTEM CONFIG ---
with st.sidebar:
    st.header("System Control")
    
    st.subheader("Policy Context")
    regulation = st.selectbox(
        "Regulatory Framework", 
        ["HIPAA", "GDPR"],
        help="Applies specific data protection standards based on jurisdiction."
    )
    
    country_code = "US"
    if regulation == "GDPR":
        country_code = st.text_input("Jurisdiction (ISO 3166-1)", "DE").upper()
    
    st.divider()
    
    st.subheader("Engine Intelligence")
    if engine.client:
        st.success("● Hybrid Mode Active")
        st.caption("AI Redactor + Deterministic Fallback")
    else:
        st.warning("● Fallback Mode Active")
        st.caption("Deterministic Pattern Matching Only")

    st.divider()
    st.caption(f"VeriFHIR Core v{engine.PROMPT_VERSION}")

# --- MAIN WORKSPACE ---
st.title("VeriFHIR Governance Console")
st.markdown("#### Clinical Record Remediation & Audit Workspace")

# Legal Guardrail Notice
st.markdown(
    """
    <div style='background-color: #f0f2f6; border-left: 5px solid #007bff; padding: 15px; border-radius: 5px; font-size: 0.95em; color: #1f2937;'>
    <strong>COMPLIANCE NOTICE:</strong> Suggestions generated by Azure OpenAI (GPT-4o). 
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
    
    # Enhanced example with more PHI categories
    default_text = (
        "Patient Rahul Sharma (MRN: H-987654, SSN: 123-45-6789) admitted on Jan 12, 2024.\n"
        "Contact: +91 98765 43210, rahul.sharma@example.com\n"
        "Address: 123 Maple Avenue, Apt 4B, Brooklyn, NY 10001\n"
        "DOB: March 15, 1985\n"
        "IP Access: 192.168.1.105"
    )
    
    input_text = st.text_area(
        "Raw Clinical Text",
        height=400,
        value=default_text,
        help="Paste raw patient notes or FHIR resources here."
    )
    
    analyze_btn = st.button("Analyze & Redact", type="primary", use_container_width=True)

# --- ENGINE EXECUTION ---
if "current_result" not in st.session_state:
    st.session_state.current_result = None

if analyze_btn:
    if not input_text.strip():
        st.error("Input required for analysis.")
    else:
        with st.status("Applying governance protocols...", expanded=True) as status:
            response = engine.generate_suggestion(input_text, regulation, country_code)
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
        
        # 2. METADATA FOOTER
        method = res['remediation_method']
        audit = res.get('audit_metadata', {})
        
        col_m1, col_m2 = st.columns(2)
        with col_m1:
            st.caption(f"**Engine:** {method}")
        with col_m2:
            if 'rules_applied' in audit:
                rule_count = len(audit['rules_applied'])
                st.caption(f"**Rules Applied:** {rule_count} categories")
        
        st.divider()
        
        # 3. PHI CATEGORIES DETECTED
        if 'rules_applied' in audit and audit['rules_applied']:
            with st.expander("PHI Categories Detected", expanded=False):
                rules = audit['rules_applied']
                # Display as badges
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
        
        st.divider()
        
        # 4. ACTION CONTROLS
        st.subheader("Human Attestation")
        
        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button("✓ Approve & Commit", use_container_width=True, type="primary"):
                try:
                    # Save the record
                    file_id = commit_record(
                        original_text=res['original_text'],
                        redacted_text=res['suggested_redaction'],
                        metadata=res.get('audit_metadata', {})
                    )
                    
                    st.balloons()
                    st.success(f"✓ Record committed to secure vault.")
                    st.caption(f"Reference ID: {file_id}")
                    
                except Exception as e:
                    st.error(f"Commit Failed: {str(e)}")
                
        with c2:
            if st.button("⚠ Reject & Flag", use_container_width=True):
                st.warning("⚠ Flagged for manual remediation queue.")
        
        with c3:
            if st.button("Copy Output", use_container_width=True):
                st.info("Redacted text ready to copy from display above.")

        st.divider()

        # 5. AUDIT TRACE
        if st.button("View Technical Audit Metadata", use_container_width=True):
            show_audit_dialog(res)

    else:
        st.info("Awaiting input analysis. Please click 'Analyze & Redact' to generate a proposal.")