import json
from pathlib import Path
from typing import Dict


SNAPSHOT_DIR = Path(__file__).parent / "snapshots"


def load_adequacy_snapshot(filename: str) -> Dict:
    """
    Load a versioned adequacy snapshot from disk.
    Snapshots are static and reviewable.
    """

    snapshot_path = SNAPSHOT_DIR / filename

    if not snapshot_path.exists():
        raise FileNotFoundError(f"Adequacy snapshot not found: {filename}")

    with open(snapshot_path, "r", encoding="utf-8") as f:
        snapshot = json.load(f)

    if "snapshot_version" not in snapshot:
        raise ValueError("Invalid snapshot: missing snapshot_version")

    return snapshot
