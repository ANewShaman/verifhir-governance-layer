from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass(frozen=True)
class JurisdictionContext:
    source_country: str
    destination_country: str
    data_subject_country: str
    intermediate_countries: List[str] = field(default_factory=list)

@dataclass(frozen=True)
class JurisdictionResolution:
    context: JurisdictionContext
    applicable_regulations: List[str]
    reasoning: Dict[str, str]
    regulation_snapshot_version: str
    # New Field: The single regulation that sets the baseline stringency
    governing_regulation: Optional[str] = None