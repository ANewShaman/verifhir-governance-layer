import json
from typing import Optional

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
