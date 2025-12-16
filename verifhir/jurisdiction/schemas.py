from dataclasses import dataclass
from typing import List, Dict


@dataclass(frozen=True)
class JurisdictionContext:
    source_country: str
    destination_country: str
    data_subject_country: str


@dataclass(frozen=True)
class JurisdictionResolution:
    context: JurisdictionContext
    applicable_regulations: List[str]
    reasoning: Dict[str, str]
