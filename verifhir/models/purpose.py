from enum import Enum

class Purpose(str, Enum):
    TREATMENT = "TREATMENT"
    BILLING = "BILLING"
    RESEARCH = "RESEARCH"
    OPERATIONS = "OPERATIONS"
