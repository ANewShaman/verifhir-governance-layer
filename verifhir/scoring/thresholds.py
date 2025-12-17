# Deterministic, rule-only thresholds.
# These act as the "Policy Gate" for the system.
# They are externalized here so they can be tuned without changing code logic.

LOW_RISK_MAX = 3.0
MEDIUM_RISK_MAX = 8.0

# Interpretation:
# 0.0 - 3.0  -> LOW (Approve)
# 3.1 - 8.0  -> MEDIUM (Redact)
# 8.1+       -> HIGH (Reject)