from dataclasses import dataclass
from enum import Enum
from typing import List, Dict


@dataclass(frozen=True)
class JurisdictionContext:
    """
    Captures the factual transfer context.
    This is descriptive only — no logic belongs here.
    """
    source_country: str
    destination_country: str  # Multi-hop path represented as a string (e.g. "US → GB → IN")
    data_subject_country: str


class GoverningRule(str, Enum):
    """
    Explicit governance outcome.
    NONE represents an unregulated or non-covered transfer.
    """
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    DPDP = "DPDP"
    NONE = "NONE"


@dataclass(frozen=True)
class JurisdictionResolution:
    """
    Result of deterministic jurisdiction analysis.
    """
    context: JurisdictionContext

    applicable_regulations: List[str]
    governing_regulation: GoverningRule

    reasoning: Dict[str, str]
    regulation_snapshot_version: str
