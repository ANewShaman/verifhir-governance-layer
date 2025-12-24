import logging
from typing import List, Optional
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from verifhir.models.violation import Violation, ViolationSeverity

# Setup Logger
logger = logging.getLogger("verifhir.ml.presidio")

# --- CONFIGURATION ---
# Map Presidio Entities to our Severity Levels
ENTITY_MAPPING = {
    # CRITICAL (Government/Financial IDs - Deterministic)
    "US_SSN": ViolationSeverity.CRITICAL,
    "INDIAN_AADHAAR": ViolationSeverity.CRITICAL,
    "INDIAN_PAN": ViolationSeverity.CRITICAL,
    "US_MRN": ViolationSeverity.CRITICAL,
    "MEDICAL_RECORD_NUMBER": ViolationSeverity.CRITICAL,
    "US_BANK_NUMBER": ViolationSeverity.CRITICAL,
    "CREDIT_CARD": ViolationSeverity.CRITICAL,
    
    # MAJOR (Direct Identifiers - Probabilistic)
    "PERSON": ViolationSeverity.MAJOR,
    "EMAIL_ADDRESS": ViolationSeverity.MAJOR,
    "PHONE_NUMBER": ViolationSeverity.MAJOR,
    "IP_ADDRESS": ViolationSeverity.MAJOR,
    "LOCATION": ViolationSeverity.MAJOR,  # Cities/Addresses
    
    # MINOR (Contextual/Noise)
    "DATE_TIME": ViolationSeverity.MINOR,
    "NRP": ViolationSeverity.MINOR,  # Nationality/Religion/Political
}


class PresidioEngine:
    """
    TRUE HYBRID Governance Engine (Deterministic + Probabilistic).
    Acts as the 'Privacy Firewall' - running locally without API calls.
    
    ARCHITECTURE:
    1. PROBABILISTIC (The Brain): Uses spaCy NER models (en_core_web_lg/sm)
       to detect context-heavy PII like PERSON, LOCATION, NRP.
    2. DETERMINISTIC (The Rulebook): Uses PatternRecognizer to strictly
       enforce Regex patterns for Government IDs (Aadhaar, PAN, MRN, SSN).
    
    Both strategies run in parallel during a single analysis pass.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PresidioEngine, cls).__new__(cls)
            cls._instance._initialize_engine()
        return cls._instance

    def _initialize_engine(self):
        """Initialize the hybrid engine with Spacy NER and custom pattern recognizers."""
        try:
            # 1. Initialize Registry
            registry = RecognizerRegistry()
            registry.load_predefined_recognizers()

            # 2. Add Custom Deterministic Recognizers (The Rulebook)
            self._add_deterministic_recognizers(registry)

            # 3. Initialize Probabilistic NLP Engine (The Brain)
            # Try en_core_web_lg first, fallback to en_core_web_sm
            nlp_engine = self._initialize_spacy_engine()

            # 4. Create AnalyzerEngine with hybrid configuration
            self.analyzer = AnalyzerEngine(
                registry=registry,
                nlp_engine=nlp_engine,
                supported_languages=["en"]
            )
            
            logger.info("Presidio Hybrid Engine Initialized Successfully (Spacy + Pattern Recognizers).")
            
        except Exception as e:
            logger.error(f"Presidio Init Failed: {e}", exc_info=True)
            self.analyzer = None

    def _initialize_spacy_engine(self):
        """
        Initialize Spacy NLP Engine for probabilistic detection.
        Tries en_core_web_lg first, falls back to en_core_web_sm.
        """
        # Configuration for large model
        nlp_configuration_lg = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
        }
        
        # Configuration for small model (fallback)
        nlp_configuration_sm = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        
        try:
            # Try large model first
            nlp_engine_provider = NlpEngineProvider(nlp_configuration=nlp_configuration_lg)
            nlp_engine = nlp_engine_provider.create_engine()
            logger.info("Loaded Spacy model: en_core_web_lg")
            return nlp_engine
        except Exception as e:
            logger.warning(f"Large model (en_core_web_lg) not found: {e}. Falling back to en_core_web_sm.")
            try:
                # Fallback to small model
                nlp_engine_provider = NlpEngineProvider(nlp_configuration=nlp_configuration_sm)
                nlp_engine = nlp_engine_provider.create_engine()
                logger.info("Loaded Spacy model: en_core_web_sm")
                return nlp_engine
            except Exception as e2:
                logger.error(f"Both Spacy models failed to load: {e2}. Engine may not function correctly.")
                # Return default engine as last resort
                nlp_engine_provider = NlpEngineProvider(nlp_configuration=nlp_configuration_sm)
                return nlp_engine_provider.create_engine()

    def _add_deterministic_recognizers(self, registry):
        """
        Add deterministic pattern recognizers for Government IDs.
        These enforce strict regex patterns regardless of context.
        """
        
        # 1. INDIAN AADHAAR (xxxx-xxxx-xxxx)
        # Pattern: \d{4}-\d{4}-\d{4} with context words
        aadhaar_pattern = Pattern(
            name="Aadhaar",
            regex=r"\d{4}-\d{4}-\d{4}",
            score=0.9
        )
        aadhaar_recognizer = PatternRecognizer(
            supported_entity="INDIAN_AADHAAR",
            patterns=[aadhaar_pattern],
            context=["Aadhaar", "UID"]
        )
        registry.add_recognizer(aadhaar_recognizer)

        # 2. INDIAN PAN (ABCDE1234F)
        # Pattern: [A-Z]{5}[0-9]{4}[A-Z]{1}
        pan_pattern = Pattern(
            name="PAN",
            regex=r"[A-Z]{5}[0-9]{4}[A-Z]{1}",
            score=0.9
        )
        pan_recognizer = PatternRecognizer(
            supported_entity="INDIAN_PAN",
            patterns=[pan_pattern]
        )
        registry.add_recognizer(pan_recognizer)

        # 3. US MEDICAL RECORD NUMBER (MRN)
        # Pattern: MRN[:\s]+\d+ (extended to handle "MRN is 123" format)
        mrn_pattern = Pattern(
            name="MRN",
            regex=r"MRN[:\s]+(?:\w+\s+)?\d+",
            score=0.9
        )
        mrn_recognizer = PatternRecognizer(
            supported_entity="US_MRN",
            patterns=[mrn_pattern]
        )
        registry.add_recognizer(mrn_recognizer)

        # 4. US SSN (Standard pattern)
        # Pattern: \d{3}-\d{2}-\d{4}
        # Note: Presidio may already have this, but we add it explicitly for clarity
        ssn_pattern = Pattern(
            name="SSN",
            regex=r"\b\d{3}-\d{2}-\d{4}\b",
            score=0.9
        )
        ssn_recognizer = PatternRecognizer(
            supported_entity="US_SSN",
            patterns=[ssn_pattern]
        )
        registry.add_recognizer(ssn_recognizer)

        logger.debug("Added deterministic pattern recognizers: Aadhaar, PAN, MRN, SSN")

    def analyze(self, text: str, field_path: str = "text_content") -> List[Violation]:
        """
        Main entry point for hybrid analysis.
        Runs both probabilistic (Spacy NER) and deterministic (Pattern) detection
        in a single pass with confidence threshold of 0.4.
        
        Args:
            text: Input text to analyze
            field_path: Path to the field being analyzed
            
        Returns:
            List of Violation objects with appropriate severity levels
        """
        if not self.analyzer or not text:
            return []

        try:
            # Run Hybrid Analysis (Both strategies run in parallel)
            # Confidence threshold set to 0.4 for high sensitivity
            results = self.analyzer.analyze(
                text=text,
                language="en",
                score_threshold=0.4  # High sensitivity threshold
            )
            
            violations = []
            for res in results:
                entity_type = res.entity_type
                
                # Map entity to severity (default to MINOR if unknown)
                severity = ENTITY_MAPPING.get(entity_type, ViolationSeverity.MINOR)
                
                # Determine detection method based on entity type
                # Government IDs = deterministic, Names/Locations = probabilistic
                if entity_type in ["INDIAN_AADHAAR", "INDIAN_PAN", "US_MRN", "US_SSN"]:
                    detection_method = "Presidio_Deterministic"
                else:
                    detection_method = "Presidio_Probabilistic"
                
                violations.append(Violation(
                    violation_type=entity_type,
                    severity=severity,
                    regulation="Global_Privacy",  # Generic tag, specialized by caller
                    citation="PII Detection",
                    field_path=field_path,
                    description=f"Detected {entity_type} (Confidence: {round(res.score, 2)})",
                    detection_method=detection_method,
                    confidence=res.score
                ))
            
            return violations

        except Exception as e:
            logger.error(f"Presidio Analysis Failed: {e}", exc_info=True)
            return []


# --- EXPORT FUNCTION FOR COMPATIBILITY ---
_engine = PresidioEngine()


def detect_phi_presidio(text: str, field_path: str = "unknown", azure_flagged: bool = True) -> List[Violation]:
    """
    Wrapper function to maintain compatibility with existing codebase.
    
    This function implements a TRUE HYBRID Governance Engine that runs:
    1. PROBABILISTIC detection using Spacy NER (PERSON, LOCATION, NRP)
    2. DETERMINISTIC detection using PatternRecognizer (Government IDs)
    
    Both strategies execute in parallel during a single analysis pass.
    
    Args:
        text: Input text to analyze for PII/PHI
        field_path: Path to the field being analyzed (default: "unknown")
        azure_flagged: Legacy parameter (ignored - Presidio runs on everything)
        
    Returns:
        List of Violation objects with severity levels:
        - CRITICAL: Government IDs (Aadhaar, PAN, MRN, SSN)
        - MAJOR: Names, Locations, etc.
        - MINOR: Contextual entities (NRP, DATE_TIME)
    """
    # Note: azure_flagged parameter is ignored. Presidio runs on everything because it's local.
    violations = _engine.analyze(text=text, field_path=field_path)
    return violations
