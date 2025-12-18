import re

# Centralized pattern for identifying common medical IDs in unstructured text.
# Matches: "ID 123", "MRN: 999", "SSN # 000", etc.
IDENTIFIER_REGEX = re.compile(
    r"(id|mrn|ssn)\s*[:#]?\s*\d+",
    re.IGNORECASE
)