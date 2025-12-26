import json
import hashlib
from typing import Dict, Any

EXCLUDED_HASH_FIELDS = {
    "record_hash",
    "previous_record_hash",
}

def compute_audit_hash(audit_payload: Dict[str, Any]) -> str:
    """
    Deterministically compute a SHA-256 hash over the audit record,
    excluding self-referential hash fields.
    """
    canonical_payload = {
        k: audit_payload[k]
        for k in sorted(audit_payload.keys())
        if k not in EXCLUDED_HASH_FIELDS
    }

    serialized = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
