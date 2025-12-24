import os
import json
import logging
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

# Configure local "Vault" path
VAULT_DIR = Path("secure_vault")
VAULT_DIR.mkdir(exist_ok=True)

logger = logging.getLogger("verifhir.storage")

def commit_record(original_text: str, redacted_text: str, metadata: Dict[str, Any]) -> str:
    """
    Saves the approved record to the local secure vault.
    Returns the filename (Record ID).
    """
    try:
        # 1. Generate a unique ID based on content hash (Immutability check prep)
        content_hash = hashlib.sha256(redacted_text.encode()).hexdigest()[:16]
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # 2. Construct the record
        record = {
            "record_id": content_hash,
            "timestamp": timestamp,
            "status": "COMMITTED",
            "metadata": metadata,
            "data": {
                "original_text_length": len(original_text),
                # In production, we might not save the original, only the redacted
                "redacted_text": redacted_text 
            }
        }
        
        # 3. Save to JSON
        filename = f"record_{content_hash}_{int(datetime.now().timestamp())}.json"
        file_path = VAULT_DIR / filename
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
            
        logger.info(f"Record committed to vault: {filename}")
        return filename

    except Exception as e:
        logger.error(f"Storage Commit Failed: {e}")
        raise e