import re

# Centralized pattern for identifying common medical IDs.
# Added 'cpf' for Brazil (LGPD) support.
IDENTIFIER_REGEX = re.compile(
    r"(id|mrn|ssn|cpf)\s*[:#]?\s*[\d\.\-]+", # Updated to allow dots/dashes common in CPF
    re.IGNORECASE
)