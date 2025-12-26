from verifhir.telemetry import emit_decision_telemetry

def test_emit_decision_telemetry_does_not_crash():
    """
    Test that telemetry function safely no-ops when no active span exists.
    
    This proves telemetry is safe even when disabled (local / tests).
    """
    # Should safely no-op if no active span
    emit_decision_telemetry(
        decision_latency_ms=123,
        risk_score=0.42,
        decision_path="rules",
        fallback_triggered=False,
    )
    
    # Test with different values
    emit_decision_telemetry(
        decision_latency_ms=456,
        risk_score=0.85,
        decision_path="hybrid",
        fallback_triggered=True,
    )
    
    # Test with ml-sensor path
    emit_decision_telemetry(
        decision_latency_ms=789,
        risk_score=0.15,
        decision_path="ml-sensor",
        fallback_triggered=False,
    )
    
    # If we get here without exception, the test passes
    assert True

