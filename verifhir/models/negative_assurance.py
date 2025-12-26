from dataclasses import dataclass
from typing import List

@dataclass(frozen=True)
class NegativeAssertion:
    category: str
    status: str               # always "NOT_DETECTED"
    supported_by: List[str]
    scope_note: str
