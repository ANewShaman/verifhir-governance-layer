import os
from azure.monitor.opentelemetry import configure_azure_monitor
from opentelemetry.trace import get_current_span

def init_telemetry():
    """
    Initialize Azure Application Insights via OpenTelemetry.
    Safe by default: does not log payloads or PHI.
    """
    connection_string = os.getenv("AZURE_APPINSIGHTS_CONNECTION_STRING")

    if not connection_string:
        return  # Telemetry disabled (local / tests)

    configure_azure_monitor(
        connection_string=connection_string
    )


def emit_decision_telemetry(
    decision_latency_ms: int,
    risk_score: float,
    decision_path: str,
    fallback_triggered: bool,
):
    """
    Emit a single telemetry event for compliance decisions.
    
    This is the ONLY custom event we emit. All attributes are locked:
    - decision_latency_ms: int
    - risk_score: float
    - decision_path: enum string ("rules" / "ml-sensor" / "hybrid")
    - fallback_triggered: bool
    
    No PHI, no payloads, no identifiers.
    """
    span = get_current_span()
    if not span:
        return  # No active span - telemetry disabled or not in trace context

    span.add_event(
        name="verifhir.decision",
        attributes={
            "decision_latency_ms": decision_latency_ms,
            "risk_score": risk_score,
            "decision_path": decision_path,
            "fallback_triggered": fallback_triggered,
        }
    )
