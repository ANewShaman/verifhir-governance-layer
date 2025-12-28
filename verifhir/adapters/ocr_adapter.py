"""
Day 38: Multi-Modal Input Support (OCR with Epistemic Humility)

OCR adapter using Azure AI Document Intelligence.
Quality gate: confidence < 0.7 raises OCRQualityError.
"""
import os
import logging
from typing import Dict
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("verifhir.adapters.ocr")

try:
    from azure.ai.documentintelligence import DocumentIntelligenceClient
    from azure.core.credentials import AzureKeyCredential
    from azure.core.exceptions import AzureError
    AZURE_DOC_INTEL_AVAILABLE = True
except ImportError:
    AZURE_DOC_INTEL_AVAILABLE = False
    logger.warning("Azure AI Document Intelligence not available")


class OCRQualityError(Exception):
    """Raised when OCR confidence is below quality threshold."""
    pass


def extract_text_from_image(file) -> Dict[str, str | float]:
    """
    DAY 38: Extract text from image using Azure AI Document Intelligence.
    
    Quality Gate (MANDATORY):
    - If OCR confidence < 0.7, raises OCRQualityError
    
    Args:
        file: File-like object or bytes containing image data
        
    Returns:
        {
            "text": str,
            "confidence": float,
            "ocr_engine_version": "azure-doc-intel-v1.0"
        }
        
    Raises:
        OCRQualityError: If confidence < 0.7
    """
    if not AZURE_DOC_INTEL_AVAILABLE:
        raise OCRQualityError(
            "Image quality insufficient for reliable text extraction. "
            "Please provide a clearer scan."
        )
    
    endpoint = os.getenv("AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT")
    key = os.getenv("AZURE_DOCUMENT_INTELLIGENCE_KEY")
    
    if not endpoint or not key:
        logger.error("Azure Document Intelligence credentials not configured")
        raise OCRQualityError(
            "Image quality insufficient for reliable text extraction. "
            "Please provide a clearer scan."
        )
    
    try:
        client = DocumentIntelligenceClient(
            endpoint=endpoint,
            credential=AzureKeyCredential(key)
        )
        
        # Read file content
        if hasattr(file, 'read'):
            file_content = file.read()
        elif isinstance(file, bytes):
            file_content = file
        else:
            raise ValueError("Invalid file type")
        
        # Analyze document
        poller = client.begin_analyze_document(
            model_id="prebuilt-read",
            analyze_request=file_content,
            content_type="application/octet-stream"
        )
        result = poller.result()
        
        # Extract text and compute average confidence
        extracted_text = ""
        confidences = []
        
        if result.content:
            extracted_text = result.content
        
        # Calculate average confidence from pages
        if result.pages:
            for page in result.pages:
                if hasattr(page, 'confidence') and page.confidence is not None:
                    confidences.append(page.confidence)
        
        # Use document-level confidence if available, otherwise average page confidence
        if hasattr(result, 'confidence') and result.confidence is not None:
            overall_confidence = result.confidence
        elif confidences:
            overall_confidence = sum(confidences) / len(confidences)
        else:
            # Default to 0.5 if no confidence available (will trigger quality gate)
            overall_confidence = 0.5
        
        # Quality Gate (MANDATORY)
        if overall_confidence < 0.7:
            raise OCRQualityError(
                "Image quality insufficient for reliable text extraction. "
                "Please provide a clearer scan."
            )
        
        return {
            "text": extracted_text,
            "confidence": overall_confidence,
            "ocr_engine_version": "azure-doc-intel-v1.0"
        }
        
    except OCRQualityError:
        raise
    except AzureError as e:
        logger.error(f"Azure Document Intelligence error: {type(e).__name__}")
        raise OCRQualityError(
            "Image quality insufficient for reliable text extraction. "
            "Please provide a clearer scan."
        )
    except Exception as e:
        logger.error(f"OCR extraction error: {type(e).__name__}")
        raise OCRQualityError(
            "Image quality insufficient for reliable text extraction. "
            "Please provide a clearer scan."
        )

