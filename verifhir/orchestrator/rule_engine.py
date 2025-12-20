from typing import Dict, Any, List, Optional

# Global variable to hold the singleton instance
_engine_instance = None

def get_engine():
    """
    Lazy loader for the engine. 
    Only imports and creates the class when absolutely necessary.
    """
    global _engine_instance
    if _engine_instance is None:
        # Import INSIDE the function to avoid circular dependency crashes
        # ENSURE the file in verifhir/rules/ is named 'rules_wrapper.py'
        from verifhir.rules.rules_wrapper import DeterministicRuleEngine
        _engine_instance = DeterministicRuleEngine()
    return _engine_instance

def run_deterministic_rules(jurisdiction_resolution: Any, fhir_resource: Dict[str, Any]) -> List[Dict]:
    """
    COMPATIBILITY BRIDGE
    --------------------
    The old tests call this function. We redirect them to the new Class.
    """
    engine = get_engine()
    return engine.evaluate(fhir_resource, jurisdiction_resolution)