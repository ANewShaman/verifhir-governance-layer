import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from verifhir.ml.azure_phi import detect_phi

def test_azure_brain():
    print("\nTESTING AZURE AI BRAIN (Day 15)")
    text = "Patient Sarah Connor (SSN: 123-45-6789) has an appointment."
    
    entities = detect_phi(text)
    
    if not entities:
        print("FAILURE: No entities found. Check .env keys.")
    else:
        print(f"SUCCESS: Detected {len(entities)} sensitive items!")
        for e in entities:
            print(f"Found: {e.text} | Type: {e.category}")

if __name__ == "__main__":
    test_azure_brain()