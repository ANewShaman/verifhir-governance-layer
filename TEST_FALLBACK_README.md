# Testing RegexFallbackEngine (fallback.py)

This directory contains comprehensive test scripts for the `RegexFallbackEngine` in `verifhir/remediation/fallback.py`.

## Available Test Scripts

### 1. `test_fallback_direct.py` - Comprehensive Direct Tests

Direct test suite that tests the fallback engine with various data types and edge cases.

**Usage:**
```bash
python test_fallback_direct.py
```

**What it tests:**
- String redaction with various PHI/PII patterns (SSN, Email, Phone, Address, Dates, etc.)
- Nested dictionary structures
- List structures
- Edge cases (None, empty strings, whitespace, no PHI)
- FHIR bundle structures
- Basic stress test (100 requests)

**Output:**
- Detailed test results with pass/fail status
- Shows original vs redacted text
- Lists rules applied for each test case
- Performance metrics for stress test

---

### 2. `test_fallback_stress.py` - Stress Test

Stress test specifically for the fallback engine under load with various data types.

**Usage:**
```bash
python test_fallback_stress.py
```

**Configuration:**
- Default: 200 requests with 20 concurrent threads
- Tests strings, dictionaries, lists, and mixed structures
- Random selection of test samples

**Output:**
- Performance metrics (throughput, latency, success rate)
- Rule detection statistics
- Data type distribution
- Size statistics
- Latency percentiles (P50, P95, P99, Max)

---

### 3. `test_fallback_streamlit.py` - Interactive Streamlit App

Interactive web-based testing interface for the fallback engine.

**Prerequisites:**
```bash
pip install streamlit
```

**Usage:**
```bash
streamlit run test_fallback_streamlit.py
```

**Features:**
- **Text Input Tab**: Test simple text redaction
  - Enter custom text or select from sample templates
  - View original vs redacted text side-by-side
  - See rules applied with badges

- **JSON Input Tab**: Test structured data redaction
  - Enter JSON data with nested structures
  - Validates JSON structure
  - Preserves JSON structure after redaction

- **Batch Test Tab**: Test multiple cases at once
  - Enter multiple test cases (one per line)
  - View summary statistics
  - Detailed results for each test case

**Sample Templates Included:**
- Simple SSN + Email
- Phone Number
- Address
- DOB (Date of Birth)
- MRN (Medical Record Number)
- Age 90+
- Indian Aadhaar
- NHS Number
- Complex cases with multiple PHI types

---

## Quick Start

### Option 1: Run Direct Tests
```bash
python test_fallback_direct.py
```

### Option 2: Run Stress Test
```bash
python test_fallback_stress.py
```

### Option 3: Run Interactive Streamlit App
```bash
pip install streamlit  # If not already installed
streamlit run test_fallback_streamlit.py
```

---

## Test Results Examples

### Direct Test Output
- Shows individual test cases with input/output
- Color-coded pass/fail indicators
- Performance metrics for stress portion

### Stress Test Output
- Throughput: ~1000+ req/sec (typical)
- Average latency: <1ms
- Success rate: 100% (typical)
- Rule detection statistics showing which PHI types were detected most frequently

---

## Notes

1. **False Positives**: The fallback engine is designed to be aggressive (better safe than sorry). It may detect additional PHI patterns beyond what you expect - this is intentional for compliance safety.

2. **Performance**: The regex-based engine is very fast, typically processing thousands of requests per second.

3. **Structure Preservation**: The engine preserves JSON/dictionary/list structures while redacting string values within them.

4. **Rule Categories**: The engine detects and tags various PHI/PII types:
   - NAME, SSN, EMAIL, PHONE, ADDRESS, DATE
   - MRN, ACCOUNT_NUMBER, HEALTH_PLAN_ID
   - AADHAAR, PAN, NHS_NUMBER
   - IP_ADDRESS, DEVICE_ID, BIOMETRIC_ID
   - URL, VEHICLE_ID, LICENSE_PLATE
   - And more...

---

## Troubleshooting

**Unicode errors on Windows:**
- The scripts use ASCII-compatible characters for cross-platform compatibility
- If you see encoding errors, ensure your terminal supports UTF-8

**Streamlit not found:**
- Install with: `pip install streamlit`
- Or use the direct test scripts instead

**Import errors:**
- Ensure you're running from the project root directory
- The scripts import from `verifhir.remediation.fallback`

