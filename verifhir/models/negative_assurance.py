from dataclasses import dataclass
from typing import Literal

@dataclass(frozen=True)
class NegativeAssertion:
    category: str
    status: Literal["NOT_DETECTED"]
    supported_by: str
    scope_note: str
