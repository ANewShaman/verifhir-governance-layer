from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class InputProvenance:
    """
    Immutable record of how input entered the system.

    DAY 32 CHANGE:
    - system_config_hash is now MANDATORY
    - Prevents replay drift due to environment changes
    """
    original_format: str                  # "FHIR" | "HL7v2" | "IMAGE_OCR"
    system_config_hash: str               # 🔒 REQUIRED (Day 32)

    converter_version: Optional[str] = None
    message_type: Optional[str] = None
    ocr_engine_version: Optional[str] = None
    ocr_confidence: Optional[float] = None
