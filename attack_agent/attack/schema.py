"""Attack Agent output schema (JSON Schema, draft-07)."""

SCHEMA = {
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Attack Agent Output Schema",
  "version": "1.0",
  "type": "object",
  "required": ["attacks"],
  "properties": {
    "attacks": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "attack_id", "source_hypothesis_id", "root_function",
          "attacker_model", "production_relevance", "attack_strategy",
          "strategy_status", "entry_point", "controlled_inputs",
          "propagation_path", "sensitive_sink", "capability_obtained",
          "capability_status", "affected_assets", "expected_consequence", "attack_steps",
          "evidence", "fact_ids", "assumptions", "uncertainty",
          "attack_gates", "attack_graph", "validator_plan",
          "exploitability_score", "exploitability_band"
        ],
        "properties": {
          "attack_id": {"type": "string"},
          "source_hypothesis_id": {"type": "string"},
          "linked_hypothesis_ids": {"type": "array", "items": {"type": "string"}},
          "root_function": {"type": "string"},
          "attacker_model": {"type": "string"},
          "production_relevance": {"type": "string", "enum": ["PRODUCTION", "TEST/MOCK", "DEPENDENCY", "UNKNOWN"]},
          "attack_strategy": {"type": "string"},
          "strategy_status": {"type": "string", "enum": ["PROVEN", "INFERRED", "POSSIBLE", "UNKNOWN"]},
          "entry_point": {"type": "object"},
          "controlled_inputs": {"type": "array", "items": {"type": "object"}},
          "propagation_path": {"type": "array", "items": {"type": "object"}},
          "sensitive_sink": {"type": "object"},
          "capability_obtained": {"type": "string"},
          "capability_status": {"type": "string", "enum": ["PROVEN", "INFERRED", "POSSIBLE", "UNKNOWN"]},
          "affected_assets": {"type": "array", "items": {"type": "string"}},
          "expected_consequence": {"type": "object"},
          "attack_steps": {"type": "array", "items": {"type": "object", "properties": {
            "order": {"type": "integer"},
            "action": {"type": "string"},
            "status": {"type": "string", "enum": ["PROVEN", "INFERRED", "POSSIBLE", "UNKNOWN"]},
            "fact_ids": {"type": "array", "items": {"type": "string"}},
            "location": {"type": "string"}
          }, "required": ["order", "action", "status"]}},
          "evidence": {"type": "array", "items": {"type": "string"}},
          "fact_ids": {"type": "array", "items": {"type": "string"}},
          "assumptions": {"type": "array", "items": {"type": "string"}},
          "uncertainty": {"type": "array", "items": {"type": "string"}},
          "attack_gates": {"type": "object"},
          "attack_graph": {"type": "object"},
          "validator_plan": {"type": "object", "required": [
            "functions_to_test", "attacker_setup", "confirm_if", "reject_if"
          ]},
          "exploitability_score": {"type": "number", "minimum": 0, "maximum": 10},
          "exploitability_band": {"type": "string", "enum": ["high", "medium", "low"]}
        }
      }
    }
  }
}
