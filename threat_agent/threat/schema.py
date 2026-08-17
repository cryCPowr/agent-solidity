{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Threat Agent Output Schema",
  "version": "1.0",
  "description": "Schema for Threat Agent output artifacts",
  "definitions": {
    "actor": {
      "type": "object",
      "properties": {
        "id": {"type": "string"},
        "type": {"type": "string", "enum": ["user", "caller", "admin", "owner", "operator", "keeper", "guardian", "governance", "relayer", "external_contract", "protocol", "unknown_actor"]},
        "capabilities": {"type": "array", "items": {"type": "string"}},
        "entrypoints": {"type": "array", "items": {"type": "string"}},
        "privileged_operations": {"type": "array", "items": {"type": "string"}},
        "controlled_parameters": {"type": "array", "items": {"type": "string"}},
        "controlled_assets": {"type": "array", "items": {"type": "string"}},
        "reachable_state_transitions": {"type": "array", "items": {"type": "string"}},
        "evidence_fact_ids": {"type": "array", "items": {"type": "string"}}
      },
      "required": ["id", "type", "capabilities", "entrypoints", "evidence_fact_ids"]
    },
    "trust_boundary": {
      "type": "object",
      "properties": {
        "source": {"type": "string"},
        "target": {"type": "string"},
        "relationship": {"type": "string", "enum": ["trusted", "untrusted", "partially_trusted", "unknown"]},
        "evidence_fact_ids": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"}
      },
      "required": ["source", "target", "relationship", "evidence_fact_ids", "rationale"]
    },
    "attack_surface": {
      "type": "object",
      "properties": {
        "id": {"type": "string"},
        "category": {"type": "string"},
        "description": {"type": "string"},
        "functions": {"type": "array", "items": {"type": "string"}},
        "assets": {"type": "array", "items": {"type": "string"}},
        "capabilities": {"type": "array", "items": {"type": "string"}},
        "entrypoints": {"type": "array", "items": {"type": "string"}},
        "evidence_fact_ids": {"type": "array", "items": {"type": "string"}},
        "cross_contract_reach": {"type": "boolean"}
      },
      "required": ["id", "category", "description", "functions", "evidence_fact_ids"]
    },
    "invariant_candidate": {
      "type": "object",
      "properties": {
        "id": {"type": "string"},
        "category": {"type": "string"},
        "statement": {"type": "string"},
        "rationale": {"type": "string"},
        "involved_facts": {"type": "array", "items": {"type": "string"}},
        "involved_functions": {"type": "array", "items": {"type": "string"}},
        "involved_assets": {"type": "array", "items": {"type": "string"}},
        "uncertainty": {"type": "string"},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]}
      },
      "required": ["id", "category", "statement", "rationale", "involved_facts", "involved_functions", "uncertainty"]
    },
    "hypothesis": {
      "type": "object",
      "properties": {
        "hypothesis_id": {"type": "string"},
        "category": {"type": "string"},
        "statement": {"type": "string"},
        "actor": {"type": "string"},
        "preconditions": {"type": "array", "items": {"type": "string"}},
        "observed_facts": {"type": "array", "items": {"type": "string"}},
        "graph_nodes": {"type": "array", "items": {"type": "string"}},
        "graph_edges": {"type": "array", "items": {"type": "string"}},
        "affected_functions": {"type": "array", "items": {"type": "string"}},
        "affected_assets": {"type": "array", "items": {"type": "string"}},
        "invariant_candidate_id": {"type": "string"},
        "uncertainty": {"type": "string"},
        "priority": {"type": "string", "enum": ["very_high_interest", "high_interest", "medium_interest", "low_interest"]},
        "priority_rationale": {"type": "string"},
        "suggested_next_investigation": {"type": "string"},
        "evidence_tier": {"type": "string", "enum": ["CO_OCCURRENCE", "RELATIONSHIP_GROUNDED", "ARGUMENT_DEPENDENCY", "GRAPH_REACHABILITY"]},
        "control_provenance": {"type": "string", "enum": ["", "PROVEN", "INFERRED", "UNKNOWN"]},
        "composition_strength": {"type": "string", "enum": ["", "STRUCTURAL", "SECURITY_RELEVANT", "STRONG_SECURITY_CHAIN"]},
        "chain": {"type": "array", "items": {"type": "object", "properties": {
            "stage": {"type": "string"},
            "description": {"type": "string"},
            "fact_ids": {"type": "array", "items": {"type": "string"}},
            "status": {"type": "string", "enum": ["proven", "inferred", "observed", "uncertain"]},
            "linkage": {"type": "string", "enum": ["asset_flow_linked", "dataflow_linked", "post_call_derived", "adjacent_only", "flow_linked", "authorization_grant", "validation_gap"]},
            "grade": {"type": "string", "enum": ["PROVEN", "STRUCTURALLY_INDICATED", "POSSIBLE"]},
            "weak_signal": {"type": "boolean"}
        }}}
      },
      "required": ["hypothesis_id", "category", "statement", "actor", "observed_facts", "priority", "priority_rationale", "suggested_next_investigation"]
    }
  },
  "type": "object",
  "properties": {
    "threat_model": {
      "type": "object",
      "properties": {
        "actors": {"type": "array", "items": {"$ref": "#/definitions/actor"}},
        "trust_boundaries": {"type": "array", "items": {"$ref": "#/definitions/trust_boundary"}}
      },
      "required": ["actors", "trust_boundaries"]
    },
    "surfaces": {
      "type": "array",
      "items": {"$ref": "#/definitions/attack_surface"}
    },
    "invariants": {
      "type": "array",
      "items": {"$ref": "#/definitions/invariant_candidate"}
    },
    "hypotheses": {
      "type": "array",
      "items": {"$ref": "#/definitions/hypothesis"}
    }
  },
  "required": ["threat_model", "surfaces", "invariants", "hypotheses"]
}