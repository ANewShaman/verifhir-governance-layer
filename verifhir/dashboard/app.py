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
    
    # DAY 39: Judge / Demo Mode Toggle
    if "judge_mode" not in st.session_state:
        st.session_state.judge_mode = True  # Default: ON
    
    st.session_state.judge_mode = st.checkbox(
        "Judge / Demo Mode",
        value=st.session_state.judge_mode,
        help="Demo mode: Source input hidden by default, evidence fully visible"
    )
    
    st.divider()
    st.caption(f"VeriFHIR Core {engine.PROMPT_VERSION}")

# --- DEMO CASE LIBRARY (NORMALIZED) ---
DEMO_CASES = {
    "": {"input": "", "input_mode": "TEXT", "metadata": {}},
    
    # GROUP A: TEXT CASES
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
    
    # GROUP B: HL7 CASES
    "HL7 ADT message": {
        "input": "MSH|^~\\&|SendingApp|SendingFacility|ReceivingApp|ReceivingFacility|20240115120000||ADT^A01|12345|P|2.5\nPID|1||123456^^^MRN||SMITH^JOHN^MIDDLE||19800115|M|||123 MAIN ST^^CITY^ST^12345||555-1234|||",
        "input_mode": "HL7",
        "metadata": {
            "source": "Synthea",
            "patient_id": "syn-patient-005",
            "status": "Synthetic / De-identified"
        }
    },
    
    # GROUP C: DOCUMENT_OCR CASES
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
# --- INPUT MODE MAPPING (BUG FIX 2) ---
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

# Compliance Context Banner
st.markdown(
    f"""
    <div style='background-color: #f0f2f6; border-left: 5px solid #007bff; padding: 15px; border-radius: 5px; font-size: 0.95em; color: #1f2937;'>
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
            st.session_state.uploaded_image = None  # Demo cases have no real image
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
    
    col_input, col_output = st.columns([1, 1], gap="large")
    
    # Initialize variables
    input_text = ""
    analyze_btn = False
    
    # --- COLUMN 1: SOURCE RECORD ---
    with col_input:
        # Source Input (Conditional - hidden/collapsed in Judge Mode after analysis)
        if st.session_state.current_result and st.session_state.judge_mode:
            with st.expander("Source Input (Locked)", expanded=False):
                st.text_area("Input (Read-Only)", value=st.session_state.get('last_input_text', ''), height=200, disabled=True)
        else:
            st.subheader("Source Input")
            
            # Three-way input selector
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
            # Map selection to input_mode using the mapping (BUG FIX 2)
            st.session_state.input_mode = INPUT_MODES[input_type_selector]

            # Input handling based on mode
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
                            
                            # Emit OCR confidence bucket
                            if ocr_result["confidence"] >= 0.9:
                                emit_ocr_confidence_bucket("0.9+")
                            elif ocr_result["confidence"] >= 0.8:
                                emit_ocr_confidence_bucket("0.8-0.9")
                            else:
                                emit_ocr_confidence_bucket("0.7-0.8")
                            
                            input_text = ocr_result["text"]
                            st.session_state.last_input_text = input_text
                            ocr_status.update(label="✓ Text extracted", state="complete", expanded=False)
                            
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
                # Display extracted text or demo OCR text
                if st.session_state.ocr_extracted_text:
                    # Only show image if we have an actual uploaded file
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
                        # Demo case - show extracted text only
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
                
            else:  # TEXT mode
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
    
    # --- ENGINE EXECUTION ---
    if analyze_btn and input_text:
        if not input_text.strip():
            st.error("Input required for analysis.")
        else:
            with st.status("Applying governance protocols...", expanded=True) as status:
                st.write(f"📋 Applying {reg_info['name']} regulations...")
                st.write(f"🌍 Jurisdiction: {country_code}")
                
                # Normalize input based on input_mode
                try:
                    from verifhir.telemetry import emit_converter_status, scrub_exception_for_telemetry
                    
                    if st.session_state.input_mode == "DOCUMENT_OCR":
                        # OCR text is treated as plain text
                        system_config_hash = compute_system_config_hash()
                        st.session_state.input_provenance = InputProvenance(
                            original_format="IMAGE",
                            system_config_hash=system_config_hash,
                            converter_version=None,
                            message_type=None,
                            ocr_engine_version="azure-doc-intel-v1.0",
                            ocr_confidence=st.session_state.ocr_confidence,
                        )
                        processed_text = input_text
                        emit_converter_status("success")
                        
                    elif st.session_state.input_mode == "HL7":
                        # HL7 processing
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
                            
                    else:  # TEXT mode - accept both plain text and JSON
                        # Try to parse as JSON first
                        try:
                            raw_payload = json.loads(input_text)
                            # Successfully parsed as JSON - treat as FHIR
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
                            # Not valid JSON - treat as plain text
                            system_config_hash = compute_system_config_hash()
                            st.session_state.input_provenance = InputProvenance(
                                original_format="TEXT",
                                system_config_hash=system_config_hash,
                                converter_version=None,
                                message_type=None,
                                ocr_engine_version=None,
                                ocr_confidence=None,
                            )
                            processed_text = input_text
                            emit_converter_status("success")
                    
                    st.write(f"✓ Input normalized: {st.session_state.input_provenance.original_format}")
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
                
                # Decision evaluation with telemetry
                from opentelemetry import trace
                from verifhir.telemetry import emit_decision_telemetry
                import time
                
                tracer = trace.get_tracer(__name__)
                
                with tracer.start_as_current_span("verifhir.decision_evaluation"):
                    start_time = time.perf_counter()
                    
                    # Process with RedactionEngine
                    response = engine.generate_suggestion(processed_text, regulation, country_code)
                    
                    latency_ms = int((time.perf_counter() - start_time) * 1000)
                    
                    # Determine decision path from response
                    remediation_method = response.get('remediation_method', 'Unknown')
                    if 'Azure OpenAI' in remediation_method or 'OpenAI' in remediation_method:
                        decision_path = "ml-sensor"
                    elif 'Fallback' in remediation_method or 'Regex' in remediation_method:
                        decision_path = "rules"
                    else:
                        decision_path = "hybrid"
                    
                    # Determine if fallback was triggered
                    fallback_triggered = 'Fallback' in remediation_method or 'Regex' in remediation_method
                    
                    # Extract risk score
                    risk_score = response.get('risk_score', 0.0)
                    if not isinstance(risk_score, float):
                        risk_score = float(risk_score) if risk_score else 0.0
                    
                    emit_decision_telemetry(
                        decision_latency_ms=latency_ms,
                        risk_score=risk_score,
                        decision_path=decision_path,
                        fallback_triggered=fallback_triggered,
                    )
                    
                    # Risk band distribution
                    from verifhir.telemetry import emit_risk_band
                    if risk_score <= 3.0:
                        emit_risk_band("LOW")
                    elif risk_score <= 8.0:
                        emit_risk_band("MEDIUM")
                    else:
                        emit_risk_band("HIGH")
                
                # Attach audit metadata
                if 'audit_metadata' not in response:
                    response['audit_metadata'] = {}
                
                response['audit_metadata']['regulation'] = regulation
                response['audit_metadata']['country_code'] = country_code
                
                # Generate negative assertions
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
                
                status.update(label="✓ Redaction Complete", state="complete", expanded=False)
    
    # --- COLUMN 2: GOVERNANCE REVIEW (TAB 1) ---
    with col_output:
        st.subheader("Redaction Review")
    
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
                # REDLINE VIEW
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
                # CLEAN OUTPUT VIEW
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
            
            # Decision Summary Strip
            method = res['remediation_method']
            audit = res.get('audit_metadata', {})
            declared_purpose = st.session_state.get('declared_purpose', 'Not yet declared')
            
            st.divider()
            col_sum1, col_sum2, col_sum3, col_sum4 = st.columns(4)
            with col_sum1:
                st.caption(f"**Engine:** {method}")
            with col_sum2:
                if 'regulation' in audit:
                    st.caption(f"**Regulation:** {audit['regulation']}")
            with col_sum3:
                if 'rules_applied' in audit:
                    rule_count = len(audit['rules_applied'])
                    st.caption(f"**Rules Applied:** {rule_count}")
            with col_sum4:
                if declared_purpose != 'Not yet declared':
                    st.caption(f"**Purpose:** {declared_purpose}")
            
            st.divider()
            
            # Human Attestation
            st.subheader("Human Attestation")
            
            with st.form(key="human_decision_form", clear_on_submit=True):
                # Purpose selector
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
                    help="Select the declared purpose for this data processing. This will be cryptographically bound to the audit record.",
                )
                
                if purpose and purpose != "":
                    st.session_state.declared_purpose = purpose
                
                # Reviewer identity
                reviewer_id = st.text_input(
                    "Reviewer Identity *",
                    value="MVP-SYSTEM-USER",
                    placeholder="email@example.com or reviewer_id",
                    help="Your email or reviewer ID.",
                )
                
                # Decision selection
                st.markdown("**Decision ***")
                decision = st.radio(
                    "Select your decision:",
                    options=["APPROVED", "NEEDS_REVIEW", "REJECTED"],
                    index=0,
                    help="Your decision on this redaction.",
                )
                
                # Rationale
                rationale = st.text_area(
                    "Rationale (minimum 20 characters) *",
                    value="Automated approval for MVP testing.",
                    placeholder="Explain your decision.",
                    help="Provide a justification for your decision (minimum 20 characters).",
                    height=100,
                )
                
                # Confirmation checkbox
                confirmation = st.checkbox(
                    "I acknowledge this decision is final and auditable.",
                    value=False,
                    help="Acknowledgment for audit trail."
                )
                
                # Submit button
                submitted = st.form_submit_button("Submit Decision", type="primary", use_container_width="stretch")
            
            # Process form submission
            if submitted:
                # Validation
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
                        
                        if st.session_state.input_provenance is None:
                            st.error("❌ Input provenance not found. Please re-analyze the input.")
                            st.stop()
                        
                        # Build audit record
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
                            st.caption(f"Purpose: {purpose.strip()}")
                            st.caption(f"Decision: {decision} at {human_decision.timestamp.isoformat()}")
                            
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
                        from verifhir.telemetry import scrub_exception_for_telemetry, emit_exception_telemetry
                        error_name = scrub_exception_for_telemetry(ve)
                        emit_exception_telemetry(ve)
                        st.error(f"❌ Validation Failed: {error_name}")
                    except Exception as e:
                        from verifhir.telemetry import scrub_exception_for_telemetry, emit_exception_telemetry
                        error_name = scrub_exception_for_telemetry(e)
                        emit_exception_telemetry(e)
                        st.error(f"❌ Operation Failed: {error_name}")
                        import traceback
                        st.code(traceback.format_exc())

        else:
            st.info("Awaiting input analysis. Please click 'Analyze & Redact' to generate a proposal.")

with tab2:
    # Governance Evidence (Read-Only)
    if not st.session_state.current_result:
        st.info("No analysis results available. Please analyze input in the Review & Decision tab.")
    else:
        res = st.session_state.current_result
        audit = res.get('audit_metadata', {})
        declared_purpose = st.session_state.get('declared_purpose', 'Not yet declared')
        
        # Explainability
        st.markdown(
            """
            <div style='background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin: 20px 0;'>
            <h3 style='color: #212529; margin-top: 0; font-size: 1.1em; font-weight: 500;'>Explainability</h3>
            <h4 style='color: #495057; margin-top: 16px; margin-bottom: 12px; font-size: 0.95em; font-weight: 400;'>How this decision was made</h4>
            """,
            unsafe_allow_html=True
        )
        
        st.markdown("**1. Detection signals used**")
        st.markdown("* Azure OpenAI (verifhir-gpt-4o): contextual PHI observation (advisory)")
        st.markdown("* Deterministic rules: jurisdictional and regulatory constraints")
        st.markdown("* Regex-based validation: identifier pattern checks (if triggered)")
        
        st.markdown("**2. Observed findings**")
        st.markdown("* Financial identifiers observed (e.g., policy number, billing reference)")
        st.markdown("* Personal names observed")
        st.markdown("* Dates observed")
        
        st.markdown("**3. Not observed (within scope)**")
        st.markdown("* No biometric identifiers observed within detector coverage")
        st.markdown("* No genetic data observed within detector coverage")
        
        st.markdown("**4. Decision rationale**")
        st.markdown("* Presence of financial identifiers increased compliance risk")
        if declared_purpose != 'Not yet declared':
            st.markdown(f"* Declared purpose = \"{declared_purpose}\" restricted allowable identifiers")
        else:
            st.markdown("* Declared purpose will be recorded during human attestation")
        st.markdown(f"* Applicable regulations enforced: {regulation} + destination jurisdiction rules")
        
        st.markdown("**5. Role of AI (bounded)**")
        st.markdown("* Azure OpenAI provided advisory observations only")
        st.markdown("* All regulatory decisions were determined by deterministic rules")
        st.markdown("* Final outcome required explicit human review and attestation")
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Negative Assurance Visibility
        negative_assertions = audit.get('negative_assertions', [])
        if negative_assertions:
            st.markdown(
                """
                <div style='background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin: 20px 0;'>
                <h3 style='color: #212529; margin-top: 0; font-size: 1.1em; font-weight: 500;'>Checked & Not Detected (Within Detector Coverage)</h3>
                """,
                unsafe_allow_html=True
            )
            
            category_display_map = {
                "Biometric Identifiers": "Biometric identifiers",
                "Genetic Data": "Genetic data",
                "National Identifiers": "National identifiers",
                "Financial Account Numbers": "Financial account numbers"
            }
            
            required_categories = ["Biometric Identifiers", "Genetic Data", "National Identifiers", "Financial Account Numbers"]
            
            for assertion in negative_assertions:
                if isinstance(assertion, dict):
                    category_name = assertion.get('category', '')
                else:
                    category_name = getattr(assertion, 'category', '')
                
                if category_name in required_categories:
                    display_name = category_display_map.get(category_name, category_name)
                    
                    st.markdown(f"**{display_name}**")
                    st.markdown("* Status: NOT DETECTED")
                    
                    # OCR Scope Override
                    if st.session_state.input_provenance and st.session_state.input_provenance.ocr_engine_version:
                        ocr_conf = st.session_state.input_provenance.ocr_confidence or 0.0
                        st.markdown(f"* Scope note: Not detected within detector coverage of extracted text (OCR confidence: {ocr_conf:.2f})")
                    else:
                        st.markdown("* Scope note: Not detected within detector coverage")
                    st.markdown("---")
            
            st.markdown("</div>", unsafe_allow_html=True)
        
        # Forensic Evidence
        st.markdown(
            """
            <div style='background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin: 20px 0;'>
            <h3 style='color: #212529; margin-top: 0; font-size: 1.1em; font-weight: 500;'>Forensic Evidence (Read-Only)</h3>
            """,
            unsafe_allow_html=True
        )
        
        st.markdown("**Audit Proof Metadata**")
        
        canonical_fingerprint = hashlib.sha256(res['original_text'].encode()).hexdigest()[:32]
        system_config_hash_val = st.session_state.input_provenance.system_config_hash if st.session_state.input_provenance else compute_system_config_hash()
        
        st.markdown(f"* Governance Engine Version: `{engine.PROMPT_VERSION}`")
        st.markdown(f"* Policy Snapshot Version: `{audit.get('policy_snapshot_version', '1.0')}`")
        st.markdown(f"* Canonical Input Fingerprint: `<{canonical_fingerprint}>`")
        st.markdown(f"* System Configuration Hash: `<{system_config_hash_val}>`")
        
        st.markdown("**Input Provenance**")
        if st.session_state.input_provenance:
            original_format_display = st.session_state.input_provenance.original_format
            normalization_applied = "None"
            if original_format_display == "HL7v2":
                normalization_applied = "HL7→FHIR"
            elif st.session_state.input_provenance.ocr_engine_version:
                normalization_applied = "OCR"
            
            converter_version = st.session_state.input_provenance.converter_version or "<version if applicable>"
            ocr_version = st.session_state.input_provenance.ocr_engine_version or "<version if applicable>"
            ocr_confidence = f"{st.session_state.input_provenance.ocr_confidence}" if st.session_state.input_provenance.ocr_confidence else "<value if applicable>"
            
            st.markdown(f"* Original Format: `{original_format_display}`")
            st.markdown(f"* Normalization Applied: `{normalization_applied}`")
            st.markdown(f"* Converter / OCR Engine Version: `{converter_version if original_format_display == 'HL7v2' else ocr_version}`")
            st.markdown(f"* OCR Confidence: `<{ocr_confidence}>`")
        else:
            st.markdown("* Original Format: `FHIR | HL7v2 | IMAGE`")
            st.markdown("* Normalization Applied: `None | HL7→FHIR | OCR`")
            st.markdown("* Converter / OCR Engine Version: `<version if applicable>`")
            st.markdown("* OCR Confidence: `<value if applicable>`")
        
        st.markdown("**Immutability Notice** This metadata is cryptographically bound to the audit record and stored immutably. Any change to input, purpose, rules, or system configuration invalidates this record.")
        
        st.markdown("</div>", unsafe_allow_html=True)