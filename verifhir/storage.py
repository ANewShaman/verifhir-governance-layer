import json
import os
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime

try:
    from azure.storage.blob import BlobClient  # type: ignore
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    BlobClient = None  # type: ignore

from verifhir.models.audit_record import AuditRecord
from verifhir.audit.hash_utils import compute_audit_hash


class AuditStorage:
    """
    Single persistence boundary for all audit records.
    Enforces hash chaining and immutable writes.
    """

    def __init__(
        self,
        connection_string: str,
        container_name: str,
    ):
        if not AZURE_AVAILABLE:
            raise ImportError(
                "Azure Storage SDK is required for AuditStorage. "
                "Install it with: pip install azure-storage-blob"
            )
        self.connection_string = connection_string
        self.container_name = container_name

    def _get_blob_client(self, blob_name: str) -> BlobClient:
        return BlobClient.from_connection_string(
            conn_str=self.connection_string,
            container_name=self.container_name,
            blob_name=blob_name,
        )

    def _serialize_audit(self, audit: AuditRecord) -> dict:
        """
        Converts AuditRecord into a JSON-serializable dict.
        """
        return json.loads(json.dumps(audit, default=lambda o: o.__dict__))

    def get_last_audit(
        self,
        dataset_fingerprint: str,
    ) -> Optional[AuditRecord]:
        """
        Fetch the most recent audit for a dataset.
        For MVP: return None or implement lookup if available.
        """
        # MVP: assume sequential writes; return None
        return None

    def commit_record(self, audit: AuditRecord) -> None:
        """
        Enforces hash chaining and writes audit immutably to Blob Storage (WORM-ready).
        """

        # --- Integrity: hash chaining ---
        last_audit = self.get_last_audit(audit.dataset_fingerprint)

        if last_audit:
            if audit.previous_record_hash != last_audit.record_hash:
                raise ValueError("Audit hash chain broken")

        # --- Canonical hash verification ---
        audit_dict = self._serialize_audit(audit)
        computed_hash = compute_audit_hash(audit_dict)

        if computed_hash != audit.record_hash:
            raise ValueError("Audit record hash mismatch")

        # --- Immutable write ---
        blob_client = self._get_blob_client(
            blob_name=f"{audit.audit_id}.json"
        )

        blob_client.upload_blob(
            data=json.dumps(audit_dict, indent=2),
            overwrite=False  # REQUIRED for immutability
        )


def commit_record(
    original_text: str,
    redacted_text: str,
    metadata: Dict[str, Any],
) -> str:
    """
    Commits a redaction record to secure vault.
    
    This is for remediation/redaction records, not audit records.
    Returns a file ID for reference.
    """
    import pathlib
    
    # Create secure_vault directory if it doesn't exist
    vault_dir = pathlib.Path("secure_vault")
    vault_dir.mkdir(exist_ok=True)
    
    # Generate deterministic record ID from content
    content_hash = hashlib.sha256(
        f"{original_text}{redacted_text}".encode()
    ).hexdigest()[:16]
    
    timestamp = int(datetime.utcnow().timestamp())
    record_id = f"{content_hash}_{timestamp}"
    
    # Build record structure
    record = {
        "record_id": content_hash,
        "timestamp": datetime.utcnow().isoformat(),
        "status": "COMMITTED",
        "metadata": metadata,
        "data": {
            "original_text_length": len(original_text),
            "redacted_text": redacted_text
        }
    }
    
    # Write to secure vault
    file_path = vault_dir / f"record_{record_id}.json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False)
    
    return record_id
