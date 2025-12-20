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
    governing_regulation: Optional[str] = None

    # --- COMPATIBILITY HELPERS ---
    # These properties allow the Compliance Engine to read this object easily.

    @property
    def name(self):
        return self.governing_regulation or "Unregulated"

    @property
    def regulation_citation(self):
        citations = {
            "GDPR": "GDPR (EU) 2016/679",
            "HIPAA": "HIPAA Privacy Rule", 
            "DPDP": "India DPDP Act 2023",
            "LGPD": "Brazil LGPD",
            "UK_GDPR": "UK Data Protection Act 2018",
            "PIPEDA": "Canada PIPEDA"
        }
        return citations.get(self.governing_regulation, "Unknown Regulation")

    @property
    def is_transfer_allowed(self):
        # For this demo, we assume compliance unless explicitly blocked
        return True