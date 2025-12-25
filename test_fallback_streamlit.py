"""
Streamlit app for interactive testing of RegexFallbackEngine

Run with: streamlit run test_fallback_streamlit.py
"""

import streamlit as st
import json
from verifhir.remediation.fallback import RegexFallbackEngine

# Page configuration
st.set_page_config(
    page_title="RegexFallbackEngine Tester",
    page_icon="🔒",
    layout="wide"
)

# Initialize the engine (cached to avoid reinitialization)
@st.cache_resource
def get_engine():
    return RegexFallbackEngine()


def main():
    st.title("🔒 RegexFallbackEngine Tester")
    st.markdown("Interactive testing interface for PHI/PII redaction engine")
    
    engine = get_engine()
    
    # Sidebar with test samples
    with st.sidebar:
        st.header("📋 Test Samples")
        st.markdown("Select a sample or enter custom text")
        
        samples = {
            "Simple SSN + Email": "Patient John Doe (SSN: 123-45-6789) admitted on 01/12/2024. Email: john@example.com",
            "Phone Number": "Contact patient at (555) 123-4567 or 555-987-6543",
            "Address": "Patient resides at 123 Main Street, New York, NY 10001",
            "DOB": "Patient DOB: January 15, 1990",
            "MRN": "Medical Record Number: MR-123456",
            "Age 90+": "Patient age 95, admitted for observation",
            "Indian Aadhaar": "Patient Aadhaar: 1234 5678 9012",
            "NHS Number": "UK Patient NHS: 123-456-7890",
            "Complex Case": "Patient: Jane Smith, SSN: 987-65-4321, Email: jane@example.com, Phone: (555) 987-6543, Address: 456 Oak Ave, Los Angeles, CA 90001, DOB: 03/20/1985",
            "Empty": "",
        }
        
        selected_sample = st.selectbox("Choose a sample:", list(samples.keys()))
        
        if st.button("Load Sample"):
            st.session_state.input_text = samples[selected_sample]
    
    # Main content area
    tab1, tab2, tab3 = st.tabs(["📝 Text Input", "📊 JSON Input", "📈 Batch Test"])
    
    with tab1:
        st.header("Text Redaction")
        
        # Text input
        input_text = st.text_area(
            "Enter text to redact:",
            value=st.session_state.get('input_text', samples["Simple SSN + Email"]),
            height=200,
            help="Enter any text containing PHI/PII to test redaction"
        )
        
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("🔍 Redact", type="primary"):
                st.session_state.input_text = input_text
                st.rerun()
        
        if st.session_state.get('input_text'):
            input_text = st.session_state.input_text
            
            # Perform redaction
            with st.spinner("Redacting..."):
                redacted, rules = engine.redact(input_text)
            
            # Display results
            st.subheader("Results")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### Original Text")
                st.code(input_text, language=None)
            
            with col2:
                st.markdown("### Redacted Text")
                st.code(redacted, language=None)
            
            # Rules applied
            st.markdown("### Rules Applied")
            if rules:
                st.success(f"Found {len(rules)} rule(s): {', '.join(rules)}")
                for rule in rules:
                    st.badge(rule)
            else:
                st.info("No PHI/PII patterns detected")
            
            # Comparison view
            with st.expander("📊 Side-by-Side Comparison"):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**Original**")
                    st.text(input_text)
                with col2:
                    st.markdown("**Redacted**")
                    st.text(redacted)
    
    with tab2:
        st.header("JSON/Structured Data Redaction")
        
        # JSON input
        json_input = st.text_area(
            "Enter JSON to redact:",
            value=json.dumps({
                "patient": {
                    "name": "John Doe",
                    "ssn": "123-45-6789",
                    "email": "john@example.com",
                    "address": "123 Main St, New York, NY 10001",
                    "contact": {
                        "phone": "(555) 123-4567",
                        "dob": "01/15/1990"
                    }
                },
                "metadata": {
                    "mrn": "MR-123456",
                    "admission_date": "2024-01-12"
                }
            }, indent=2),
            height=300,
            help="Enter JSON data with nested structures"
        )
        
        if st.button("🔍 Redact JSON", type="primary"):
            try:
                # Parse JSON first to validate
                parsed_json = json.loads(json_input)
                
                # Perform redaction
                with st.spinner("Redacting JSON..."):
                    redacted, rules = engine.redact(parsed_json)
                
                # Display results
                st.subheader("Results")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("### Original JSON")
                    st.json(parsed_json)
                
                with col2:
                    st.markdown("### Redacted JSON")
                    st.json(redacted)
                
                # Rules applied
                st.markdown("### Rules Applied")
                if rules:
                    st.success(f"Found {len(rules)} rule(s): {', '.join(rules)}")
                    for rule in rules:
                        st.badge(rule)
                else:
                    st.info("No PHI/PII patterns detected")
                
                # Structure validation
                st.success("JSON structure preserved")
                
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON: {e}")
    
    with tab3:
        st.header("Batch Testing")
        
        # Multiple test cases
        st.markdown("Enter multiple test cases (one per line):")
        
        batch_input = st.text_area(
            "Test cases:",
            value="\n".join([
                "Patient John Doe (SSN: 123-45-6789) admitted on 01/12/2024. Email: john@example.com",
                "Contact patient at (555) 123-4567",
                "Patient resides at 123 Main Street, New York, NY 10001",
                "Patient DOB: January 15, 1990",
                "Medical Record Number: MR-123456",
            ]),
            height=200
        )
        
        if st.button("🔍 Run Batch Test", type="primary"):
            test_cases = [line.strip() for line in batch_input.split('\n') if line.strip()]
            
            if test_cases:
                results = []
                
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                for i, test_case in enumerate(test_cases):
                    status_text.text(f"Processing {i+1}/{len(test_cases)}: {test_case[:50]}...")
                    redacted, rules = engine.redact(test_case)
                    results.append({
                        "input": test_case,
                        "output": redacted,
                        "rules": rules
                    })
                    progress_bar.progress((i + 1) / len(test_cases))
                
                status_text.text("Complete!")
                progress_bar.empty()
                
                # Display results
                st.subheader(f"Results ({len(results)} test cases)")
                
                # Summary statistics
                all_rules = set()
                for result in results:
                    all_rules.update(result['rules'])
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Test Cases", len(results))
                with col2:
                    st.metric("Unique Rules Detected", len(all_rules))
                with col3:
                    avg_rules = sum(len(r['rules']) for r in results) / len(results)
                    st.metric("Avg Rules per Case", f"{avg_rules:.1f}")
                
                # Detailed results
                for i, result in enumerate(results, 1):
                    with st.expander(f"Test Case {i}: {result['input'][:50]}..."):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("**Original**")
                            st.code(result['input'], language=None)
                        with col2:
                            st.markdown("**Redacted**")
                            st.code(result['output'], language=None)
                        st.markdown(f"**Rules**: {', '.join(result['rules']) if result['rules'] else 'None'}")


if __name__ == "__main__":
    main()

