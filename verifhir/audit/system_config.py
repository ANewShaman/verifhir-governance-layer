import hashlib
import json
import os

def compute_system_config_hash() -> str:
    """
    Computes a deterministic hash of environment-level configuration
    that may affect audit outcomes.
    """

    relevant_env = {
        "ENGINE_VERSION": os.getenv("ENGINE_VERSION"),
        "POLICY_SNAPSHOT_VERSION": os.getenv("POLICY_SNAPSHOT_VERSION"),
        "RISK_THRESHOLD": os.getenv("RISK_THRESHOLD"),
    }

    payload = json.dumps(relevant_env, sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
