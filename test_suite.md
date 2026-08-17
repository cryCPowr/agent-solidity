=============================================================== test session starts ================================================================
platform linux -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0 -- /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/threat_agent/.venv/bin/python
cachedir: .pytest_cache
rootdir: /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/threat_agent
collected 74 items                                                                                                                                 

tests/test_composition_selectivity.py::test_dynamic_call_plus_unrelated_state_write_not_strong PASSED                                        [  1%]
tests/test_composition_selectivity.py::test_dynamic_call_plus_unrelated_arithmetic_not_strong PASSED                                         [  2%]
tests/test_composition_selectivity.py::test_dynamic_call_plus_unrelated_invariant_not_attached PASSED                                        [  4%]
tests/test_composition_selectivity.py::test_uncertain_callback_alone_stays_moderate PASSED                                                   [  5%]
tests/test_composition_selectivity.py::test_helper_style_entrypoint_not_strong PASSED                                                        [  6%]
tests/test_composition_selectivity.py::test_graph_adjacency_without_semantic_dependency_not_strong PASSED                                    [  8%]
tests/test_composition_selectivity.py::test_full_chain_composes_one_strong_hypothesis PASSED                                                 [  9%]
tests/test_composition_selectivity.py::test_asset_movement_plus_generic_invariant_not_strong PASSED                                          [ 10%]
tests/test_composition_selectivity.py::test_possible_callback_grade_alone_never_strong PASSED                                                [ 12%]
tests/test_composition_selectivity.py::test_structurally_indicated_callback_grades_up PASSED                                                 [ 13%]
tests/test_composition_selectivity.py::test_semantic_same_flow_fixture_is_strong PASSED                                                      [ 14%]
tests/test_composition_selectivity.py::test_influence_inherited_across_internal_call_edge PASSED                                             [ 16%]
tests/test_composition_selectivity.py::test_inbound_attacker_funded_flow_not_strong PASSED                                                   [ 17%]
tests/test_composition_selectivity.py::test_self_ledger_transfer_not_strong PASSED                                                           [ 18%]
tests/test_composition_selectivity.py::test_authorization_dynamic_execution_delta_check_composes_strong PASSED                               [ 20%]
tests/test_composition_selectivity.py::test_validation_gap_requires_execution_inside_probe_window PASSED                                     [ 21%]
tests/test_evidence_hardening.py::test_bug1_relationship_chain_alone_is_not_graph_reachability PASSED                                        [ 22%]
tests/test_evidence_hardening.py::test_bug1_real_graph_path_is_graph_reachability PASSED                                                     [ 24%]
tests/test_evidence_hardening.py::test_bug2_argument_dataflow_is_argument_dependency PASSED                                                  [ 25%]
tests/test_evidence_hardening.py::test_bug2_relationship_without_dataflow_is_relationship_grounded PASSED                                    [ 27%]
tests/test_evidence_hardening.py::test_bug2_pure_co_occurrence_stays_co_occurrence PASSED                                                    [ 28%]
tests/test_evidence_hardening.py::test_bug3_co_occurrence_cannot_stack_to_very_high PASSED                                                   [ 29%]
tests/test_evidence_hardening.py::test_bug3_stronger_evidence_outranks_weaker_equal_impact PASSED                                            [ 31%]
tests/test_evidence_hardening.py::test_bug3_co_occurrence_never_outranks_stronger_equal_impact PASSED                                        [ 32%]
tests/test_evidence_hardening.py::test_bug4_all_consumers_use_canonical_classifier PASSED                                                    [ 33%]
tests/test_evidence_hardening.py::test_bug4_pipeline_emits_only_canonical_tiers PASSED                                                       [ 35%]
tests/test_evidence_hardening.py::test_bug4_deterministic_tier_and_priority PASSED                                                           [ 36%]
tests/test_generic_composition.py::test_isolated_dynamic_call_is_weak PASSED                                                                 [ 37%]
tests/test_generic_composition.py::test_unknown_provenance_weaker_than_proven PASSED                                                         [ 39%]
tests/test_generic_composition.py::test_provenance_ordering_within_equal_impact PASSED                                                       [ 40%]
tests/test_generic_composition.py::test_capability_plus_external_execution_strengthens PASSED                                                [ 41%]
tests/test_generic_composition.py::test_callback_opportunity_is_a_chain_stage_with_uncertainty PASSED                                        [ 43%]
tests/test_generic_composition.py::test_state_value_effect_strengthens_chain PASSED                                                          [ 44%]
tests/test_generic_composition.py::test_invariant_involvement_strengthens PASSED                                                             [ 45%]
tests/test_generic_composition.py::test_unrelated_facts_are_not_composed PASSED                                                              [ 47%]
tests/test_generic_composition.py::test_graph_reachability_alone_is_not_security_relevance PASSED                                            [ 48%]
tests/test_generic_composition.py::test_chain_output_is_deterministic PASSED                                                                 [ 50%]
tests/test_generic_composition.py::test_tier_hardening_intact_with_chain_layer PASSED                                                        [ 51%]
tests/test_generic_composition.py::test_provenance_profiles_are_fact_based PASSED                                                            [ 52%]
tests/test_generic_composition.py::test_no_benchmark_identifiers_in_engine PASSED                                                            [ 54%]
tests/test_hardening.py::test_problem_1_generic_composition_layer PASSED                                                                     [ 55%]
tests/test_hardening.py::test_problem_2_accounting_not_digest_limited PASSED                                                                 [ 56%]
tests/test_hardening.py::test_problem_3_dynamic_trust_decoupled PASSED                                                                       [ 58%]
tests/test_hardening.py::test_problem_3_trust_model_has_resolution_field PASSED                                                              [ 59%]
tests/test_hardening.py::test_problem_4_ids_are_deterministic PASSED                                                                         [ 60%]
tests/test_hardening.py::test_problem_5_rich_dedup_key PASSED                                                                                [ 62%]
tests/test_hardening.py::test_problem_6_cross_contract_traversal PASSED                                                                      [ 63%]
tests/test_hardening.py::test_problem_7_invariant_candidate_vs_explicit PASSED                                                               [ 64%]
tests/test_hardening.py::test_problem_8_actor_authority_evidence PASSED                                                                      [ 66%]
tests/test_hardening.py::test_problem_8_actor_evidence_lookup PASSED                                                                         [ 67%]
tests/test_hardening.py::test_problem_9_priority_is_not_severity PASSED                                                                      [ 68%]
tests/test_hardening.py::test_problem_10_generic_categories_present PASSED                                                                   [ 70%]
tests/test_hardening.py::test_problem_11_auditability PASSED                                                                                 [ 71%]
tests/test_hardening.py::test_problem_12_model_abstraction_noop PASSED                                                                       [ 72%]
tests/test_hardening.py::test_problem_12_filter_drops_ungrounded_claims PASSED                                                               [ 74%]
tests/test_hardening.py::test_dedup_idempotent PASSED                                                                                        [ 75%]
tests/test_hardening.py::test_no_dangling_fact_references PASSED                                                                             [ 77%]
tests/test_threat_agent.py::test_arbitrary_execution_hypothesis PASSED                                                                       [ 78%]
tests/test_threat_agent.py::test_accounting_mismatch_hypothesis PASSED                                                                       [ 79%]
tests/test_threat_agent.py::test_rounding_allocation_hypothesis PASSED                                                                       [ 81%]
tests/test_threat_agent.py::test_benign_external_call_does_not_trigger_bug_claim PASSED                                                      [ 82%]
tests/test_threat_agent.py::test_fixed_treasury_transfer PASSED                                                                              [ 83%]
tests/test_threat_agent.py::test_non_privileged_function_does_not_create_excessive_hypotheses PASSED                                         [ 85%]
tests/test_threat_agent.py::test_no_unrelated_false_connections PASSED                                                                       [ 86%]
tests/test_threat_agent.py::test_unknown_dataflow_not_misclassified PASSED                                                                   [ 87%]
tests/test_threat_agent.py::test_cross_contract_reasoning PASSED                                                                             [ 89%]
tests/test_threat_agent.py::test_no_duplicate_hypotheses PASSED                                                                              [ 90%]
tests/test_threat_agent.py::test_actor_model_has_external_user PASSED                                                                        [ 91%]
tests/test_threat_agent.py::test_trust_boundaries_defined PASSED                                                                             [ 93%]
tests/test_threat_agent.py::test_attack_surfaces_defined PASSED                                                                              [ 94%]
tests/test_threat_agent.py::test_invariants_defined PASSED                                                                                   [ 95%]
tests/test_threat_agent.py::test_priority_logic PASSED                                                                                       [ 97%]
tests/test_threat_agent.py::test_output_writes PASSED                                                                                        [ 98%]
tests/test_threat_agent.py::test_threat_agent_does_not_claim_vulnerabilities PASSED                                                          [100%]

================================================================ 74 passed in 0.65s ================================================================
=============================================================== test session starts ================================================================
platform linux -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0 -- /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/attack_agent/.venv/bin/python
cachedir: .pytest_cache
rootdir: /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/attack_agent
collected 16 items                                                                                                                                 

tests/test_attack_agent.py::test_selects_high_value_hypotheses PASSED                                                                        [  6%]
tests/test_attack_agent.py::test_entry_resolves_to_external_caller PASSED                                                                    [ 12%]
tests/test_attack_agent.py::test_relevance_classification_generic PASSED                                                                     [ 18%]
tests/test_attack_agent.py::test_sink_prefers_protocol_custody_asset_flow PASSED                                                             [ 25%]
tests/test_attack_agent.py::test_controlled_inputs_from_parameter_flows PASSED                                                               [ 31%]
tests/test_attack_agent.py::test_propagation_path_spans_internal_call_edge PASSED                                                            [ 37%]
tests/test_attack_agent.py::test_approval_abuse_and_validation_gap_fire_on_full_chain PASSED                                                 [ 43%]
tests/test_attack_agent.py::test_possible_callback_yields_no_attacker_controlled_target PASSED                                               [ 50%]
tests/test_attack_agent.py::test_consequence_reflects_custody_and_gap PASSED                                                                 [ 56%]
tests/test_attack_agent.py::test_pipeline_dedups_and_scores PASSED                                                                           [ 62%]
tests/test_attack_agent.py::test_attack_steps_concrete_and_ordered PASSED                                                                    [ 68%]
tests/test_attack_agent.py::test_output_artifacts_written PASSED                                                                             [ 75%]
tests/test_attack_agent.py::test_pipeline_deterministic PASSED                                                                               [ 81%]
tests/test_attack_agent.py::test_no_benchmark_identifiers_in_engine PASSED                                                                   [ 87%]
tests/test_attack_agent.py::test_cross_asset_blind_spot_detected PASSED                                                                      [ 93%]
tests/test_attack_agent.py::test_no_cross_asset_claim_without_other_assets PASSED                                                            [100%]

================================================================ 16 passed in 0.12s ================================================================
=============================================================== test session starts ================================================================
platform linux -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0 -- /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/validator_agent/.venv/bin/python
cachedir: .pytest_cache
rootdir: /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/validator_agent
collected 14 items                                                                                                                                 

tests/test_validator_agent.py::test_preflight_blocked_without_harness PASSED                                                                 [  7%]
tests/test_validator_agent.py::test_preflight_ready_with_harness PASSED                                                                      [ 14%]
tests/test_validator_agent.py::test_preflight_blocked_on_incomplete_plan PASSED                                                              [ 21%]
tests/test_validator_agent.py::test_render_test_contains_driver_and_attacker PASSED                                                          [ 28%]
tests/test_validator_agent.py::test_render_test_without_cross_assets PASSED                                                                  [ 35%]
tests/test_validator_agent.py::test_harness_scaffold_is_filled_from_attack_data PASSED                                                       [ 42%]
tests/test_validator_agent.py::test_verdict_confirm PASSED                                                                                   [ 50%]
tests/test_validator_agent.py::test_verdict_reject_when_call_reverts PASSED                                                                  [ 57%]
tests/test_validator_agent.py::test_verdict_reject_when_no_gain PASSED                                                                       [ 64%]
tests/test_validator_agent.py::test_verdict_inconclusive_on_no_results PASSED                                                                [ 71%]
tests/test_validator_agent.py::test_pipeline_confirm_reject_inconclusive PASSED                                                              [ 78%]
tests/test_validator_agent.py::test_pipeline_limit_takes_top_of_queue PASSED                                                                 [ 85%]
tests/test_validator_agent.py::test_workspace_isolation_and_repo_untouched PASSED                                                            [ 92%]
tests/test_validator_agent.py::test_function_scoped_harness_preferred_over_contract PASSED                                                   [100%]

================================================================ 14 passed in 0.06s ================================================================
=============================================================== test session starts ================================================================
platform linux -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0 -- /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/finding_agent/.venv/bin/python
cachedir: .pytest_cache
rootdir: /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/finding_agent
collected 10 items                                                                                                                                 

tests/test_finding_agent.py::test_only_confirm_becomes_finding PASSED                                                                        [ 10%]
tests/test_finding_agent.py::test_severity_theft_proven_is_critical PASSED                                                                   [ 20%]
tests/test_finding_agent.py::test_severity_test_mock_demoted PASSED                                                                          [ 30%]
tests/test_finding_agent.py::test_severity_griefing_low_band PASSED                                                                          [ 40%]
tests/test_finding_agent.py::test_report_structure_and_status_fidelity PASSED                                                                [ 50%]
tests/test_finding_agent.py::test_finding_ids_sequence_and_files PASSED                                                                      [ 60%]
tests/test_finding_agent.py::test_no_benchmark_identifiers_in_engine PASSED                                                                  [ 70%]
tests/test_finding_agent.py::test_uncertainty_preserved_not_hidden PASSED                                                                    [ 80%]
tests/test_finding_agent.py::test_poc_path_recomputed_after_artifacts_moved PASSED                                                           [ 90%]
tests/test_finding_agent.py::test_contract_scope_harness_flagged_in_report PASSED                                                            [100%]

================================================================ 10 passed in 0.04s ================================================================
=============================================================== test session starts ================================================================
platform linux -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0 -- /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/orchestrator/.venv/bin/python
cachedir: .pytest_cache
rootdir: /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/orchestrator
collected 10 items                                                                                                                                 

tests/test_maestro.py::test_stage_specs_chain_artifacts PASSED                                                                               [ 10%]
tests/test_maestro.py::test_all_venv_pythons_exist PASSED                                                                                    [ 20%]
tests/test_maestro.py::test_stats_extractors PASSED                                                                                          [ 30%]
tests/test_maestro.py::test_prepare_run_dir_refuses_dirty_without_clean PASSED                                                               [ 40%]
tests/test_maestro.py::test_assistant_dormant_without_key PASSED                                                                             [ 50%]
tests/test_maestro.py::test_looks_like_solidity PASSED                                                                                       [ 60%]
tests/test_maestro.py::test_run_pipeline_stops_on_first_failure PASSED                                                                       [ 70%]
tests/test_maestro.py::test_no_benchmark_identifiers_in_engine PASSED                                                                        [ 80%]
tests/test_maestro.py::test_assistant_cli_backend_via_stub PASSED                                                                            [ 90%]
tests/test_maestro.py::test_assistant_cli_backend_failure_not_fatal PASSED                                                                   [100%]

================================================================ 10 passed in 0.09s ================================================================
    ~/Do/W/a/agent_solidity/orchestrator    main !18 ?17         
❯ cd /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/orchestrator
❯ .venv/bin/python -m maestro ../benchmarks/code4rena/jackpot \
    --name jackpot-expanded-coverage \
    --clean-run \
    --limit 10
╭─ maestro — orchestrator ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│  AGENT FINDER   recon → threat → attack → validator → finding                                                                                    │
│  target: /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/benchmarks/code4rena/jackpot                                                     │
│  run:    /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/runs/jackpot-expanded-coverage   [  15.6s]                                       │
│  LLM hook: DORMANT (set AGENT_FINDER_LLM_CMD for a session/CLI-based model, or AGENT_FINDER_LLM_API_KEY for an OpenAI-compatible endpoint;       │
│ pipeline runs fully deterministic)                                                                                                               │
│                                                                                                                                                  │
│  ✔   RECON             ok      10373 facts                                                                                                       │
│  ✔   THREAT            ok      548 hypotheses (113 strong)                                                                                       │
│  ✔   ATTACK            ok      26 attacks (top score 10.0)                                                                                       │
│  ✔   VALIDATOR         ok      0 CONFIRM, 10 INCONCLUSIVE, 0 REJECT                                                                              │
│  ✔   FINDING           ok      no findings (nothing confirmed)                                                                                   │
│                                                                                                                                                  │
│ ▶ VALIDATOR running…                                                                                                                             │
│ ✔ VALIDATOR 0 CONFIRM, 10 INCONCLUSIVE, 0 REJECT                                                                                                 │
│ │ Validated: 10                                                                                                                                  │
│ │ CONFIRM: 0                                                                                                                                     │
│ │ REJECT: 0                                                                                                                                      │
│ │ INCONCLUSIVE: 10                                                                                                                               │
│ │ Output written to: /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/runs/jackpot-expanded-coverage/validator                             │
│ ▶ FINDING running…                                                                                                                               │
│ ✔ FINDING no findings (nothing confirmed)                                                                                                        │
│ │ (not reported: INCONCLUSIVE A-429beb5392)                                                                                                      │
│ │ (not reported: INCONCLUSIVE A-6bfcb8af2d)                                                                                                      │
│ │ (not reported: INCONCLUSIVE A-d3cd71b308)                                                                                                      │
│ │ (not reported: INCONCLUSIVE A-f718be3766)                                                                                                      │
│ │ Output written to: /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/runs/jackpot-expanded-coverage/finding                               │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                           Run complete —                                                                                                         │
│ /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/runs/jackpo                                                                               │
│                        t-expanded-coverage                                                                                                       │
│ ┏━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓                                                                               │
│ ┃ stage        ┃  result  ┃ stats                                ┃                                                                               │
│ ┡━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩                                                                               │
│ │ RECON        │    OK    │ 10373 facts                          │                                                                               │
│ │ THREAT       │    OK    │ 548 hypotheses (113 strong)          │                                                                               │
│ │ ATTACK       │    OK    │ 26 attacks (top score 10.0)          │                                                                               │
│ │ VALIDATOR    │    OK    │ 0 CONFIRM, 10 INCONCLUSIVE, 0 REJECT │                                                                               │
│ │ FINDING      │    OK    │ no findings (nothing confirmed)      │                                                                               │
│ └──────────────┴──────────┴──────────────────────────────────────┘                                                                               │
│                                                                                                                                                  │
│ findings summary: /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/runs/jackpot-expanded-coverage/finding/summary.json                     │
│ reports: /home/farhanagil/Dokumen/Workshop/agent/agent_solidity/runs/jackpot-expanded-coverage/finding/finding-*.md   
│ ❯ python3 << 'EOF'
import json
new_types = ['bitshift_operation', 'loop_nesting_depth', 'computational_complexity_indicator',
             'randomness_source_usage', 'state_dependent_constraint', 'mev_exposure_indicator']
with open('../runs/jackpot-expanded-coverage/recon/facts.jsonl', 'r') as f:
    counts = {}
    for line in f:
        fact = json.loads(line)
        ftype = fact.get('type')
        if ftype in new_types:
            counts[ftype] = counts.get(ftype, 0) + 1
for t, c in counts.items():
    print(f"{c:4d} {t}")
EOF
  48 loop_nesting_depth
  41 computational_complexity_indicator
   1 randomness_source_usage
  89 bitshift_operation
   3 state_dependent_constraint
   2 mev_exposure_indicator
❯ python3 << 'EOF'
import json
new_cats = ['gas_dos', 'arithmetic_bound_violation', 'frontrun_vulnerability', 'randomness_manipulation']
with open('../runs/jackpot-expanded-coverage/threat/hypotheses.jsonl', 'r') as f:
    counts = {}
    for line in f:
        hyp = json.loads(line)
        cat = hyp.get('category')
        if cat in new_cats:
            priority = hyp.get('priority', 'unknown')
            key = f"{cat} ({priority})"
            counts[key] = counts.get(key, 0) + 1
for k, c in sorted(counts.items()):
    print(f"{c:4d} {k}")
EOF
   2 frontrun_vulnerability (low_interest)
  13 gas_dos (low_interest)
   1 randomness_manipulation (low_interest)
❯ cd ..
❯ grep -A 5 '"_countSubsetMatches"' runs/jackpot-expanded-coverage/recon/facts.jsonl | grep -E 'loop_nesting_depth|computational_complexity'
❯ grep 'bitshift_operation' runs/jackpot-expanded-coverage/recon/facts.jsonl | head -3
{"confidence": "high", "evidence": ["ev:99e18747acee392a"], "extraction_method": "ast", "id": "fact:06dd112fa97952dd", "properties": {"immediate_consumer": "tuple_component", "note": "Bit-shift operations can cause panic if shift amount exceeds type bounds (255 for uint256)", "operand": "r", "operator": ">>", "result_type": "uint256", "shift_amount": "3", "shift_amount_source": "constant"}, "source": {"ast_node_id": "16247", "end": 31432, "file": "node_modules/@openzeppelin/contracts/utils/math/Math.sol", "line_end": 729, "line_start": 729, "start": 31426}, "status": "observed", "subject": {"function": "node_modules/@openzeppelin/contracts/utils/math/Math.sol#16318::log256#16261"}, "type": "bitshift_operation"}
{"confidence": "high", "evidence": ["ev:fcc75a38df64dd27"], "extraction_method": "ast", "id": "fact:133911b5c1f69e04", "properties": {"immediate_consumer": "tuple_component", "note": "Bit-shift operations can cause panic if shift amount exceeds type bounds (255 for uint256)", "operand": "(a ^ b)", "operator": ">>", "result_type": "int256", "shift_amount": "1", "shift_amount_source": "constant"}, "source": {"ast_node_id": "18177", "end": 1633, "file": "node_modules/@openzeppelin/contracts/utils/math/SignedMath.sol", "line_end": 48, "line_start": 48, "start": 1621}, "status": "observed", "subject": {"function": "node_modules/@openzeppelin/contracts/utils/math/SignedMath.sol#18227::average#18200"}, "type": "bitshift_operation"}
{"confidence": "high", "evidence": ["ev:b672adb8278ed453"], "extraction_method": "ast", "id": "fact:15155caa5f2bf159", "properties": {"immediate_consumer": "tuple_component", "note": "Bit-shift operations can cause panic if shift amount exceeds type bounds (255 for uint256)", "operand": "1", "operator": "<<", "result_type": "int_const 4294967296", "shift_amount": "32", "shift_amount_source": "constant"}, "source": {"ast_node_id": "15701", "end": 21987, "file": "node_modules/@openzeppelin/contracts/utils/math/Math.sol", "line_end": 522, "line_start": 522, "start": 21980}, "status": "observed", "subject": {"function": "node_modules/@openzeppelin/contracts/utils/math/Math.sol#16318::sqrt#15862"}, "type": "bitshift_operation"}
    ~/Do/W/agent/agent_solidity    main !18 ?18    
 ❯ grep -E 'setLPPoolCap|setGovernance' runs/jackpot-expanded-coverage/threat/hypotheses.jsonl
{"hypothesis_id": "H-1bb3bca8c5", "category": "cross_contract_trust", "statement": "Contract MockJackpot calls dynamic target in JackpotLPManager(lpManager). Trust chain: MockJackpot -> dynamic -> JackpotLPManager(lpManager). This is structural graph adjacency: no fact-level influence evidence ties any caller to this specific dynamic call, so it is recorded as a structural observation, not a security-relevant composition.", "actor": "external_user", "preconditions": ["Target is controlled by untrusted party", "Target has code that can interact with protocol"], "observed_facts": ["fact:4d4f9fbc4be43daa"], "graph_nodes": ["node:77c823bcd030bb04", "node:9afaad9e616f3944"], "graph_edges": ["edge:4b0aea3b66898cff"], "affected_functions": ["contracts/mocks/MockJackpot.sol#9504::setLPPoolCap#9378"], "affected_assets": ["cross-contract assets"], "invariant_candidate_id": "", "uncertainty": "Whether the target is user-controlled is unknown; no dataflow or relationship evidence connects caller influence to this call.", "priority": "medium_interest", "priority_rationale": "moderate concern (score=4, tier=GRAPH_REACHABILITY, ceiling=10)", "suggested_next_investigation": "Trace the dataflow to determine who controls the call target.", "evidence_tier": "GRAPH_REACHABILITY", "control_provenance": "INFERRED", "composition_strength": "STRUCTURAL", "chain": []}
{"hypothesis_id": "H-550a88a61d", "category": "cross_contract_trust", "statement": "Contract Jackpot calls dynamic target in JackpotErrors. Trust chain: Jackpot -> dynamic -> JackpotErrors. Recon's relationship evidence over this specific call asserts caller influence at PROVEN certainty, so the dynamic target is an unverified execution path (composition strength SECURITY_RELEVANT).", "actor": "external_user", "preconditions": ["Target is controlled by untrusted party", "Target has code that can interact with protocol"], "observed_facts": ["fact:507d1835e57efe8e"], "graph_nodes": ["node:25e37a9402ddd04c", "node:101b17106778c7ef"], "graph_edges": ["edge:8c7163bf4f0e9285"], "affected_functions": ["contracts/Jackpot.sol#4258::setGovernancePoolCap#2498"], "affected_assets": ["cross-contract assets"], "invariant_candidate_id": "", "uncertainty": "Whether the target is actually user-controlled depends on the dataflow from the function's inputs to the call target expression.", "priority": "medium_interest", "priority_rationale": "significant exposure (score=5, tier=GRAPH_REACHABILITY, ceiling=10) [capped: SECURITY_RELEVANT composition]", "suggested_next_investigation": "Trace the dataflow to determine who controls the call target.", "evidence_tier": "GRAPH_REACHABILITY", "control_provenance": "PROVEN", "composition_strength": "SECURITY_RELEVANT", "chain": []}
{"hypothesis_id": "H-6bc346c3b5", "category": "security_chain", "statement": "Composed security chain in contracts/mocks/MockJackpot.sol#9504::setLPPoolCap#9378 (PROVEN control provenance, composition strength SECURITY_RELEVANT): an external caller can influence the function's inputs; those inputs flow into call arguments; the influence reaches an external interaction with a dynamically resolved target (attacker-influenced execution opportunity). Stages: untrusted_influence -> argument_propagation -> external_execution -> downstream_execution_opportunity. This composition has not been ruled out as security-relevant.", "actor": "external_user", "preconditions": ["The function is reachable by the influencing caller", "The influenced inputs are not constrained by an authorization check before reaching the interaction", "The dynamic recipient executes code that interacts back with this contract"], "observed_facts": ["fact:1eedf37cff26e875", "fact:3f8ba4b62a4b1337", "fact:4d4f9fbc4be43daa", "fact:547155d204f0ba9a", "fact:5b29debc877f0a99", "fact:ef2508c1066fe0f3", "fact:f371bbe06025b48b"], "graph_nodes": [], "graph_edges": [], "affected_functions": ["contracts/mocks/MockJackpot.sol#9504::setLPPoolCap#9378"], "affected_assets": [], "invariant_candidate_id": "", "uncertainty": "The external target is resolved dynamically; caller control over the target/arguments is not established by fact-level dataflow. Whether the dynamic recipient actually executes code at runtime (callback/hook) cannot be proven statically; downstream-execution grade: POSSIBLE.", "priority": "medium_interest", "priority_rationale": "moderate concern (score=4, tier=ARGUMENT_DEPENDENCY, ceiling=6)", "suggested_next_investigation": "Walk the chain stages for contracts/mocks/MockJackpot.sol#9504::setLPPoolCap#9378 in order and verify each step: the control-provenance evidence, the argument propagation into the external interaction, the linkage grade of the downstream effects, and (if present) the flow-linked invariant candidate.", "evidence_tier": "ARGUMENT_DEPENDENCY", "control_provenance": "PROVEN", "composition_strength": "SECURITY_RELEVANT", "chain": [{"stage": "untrusted_influence", "description": "Any external caller can choose the inputs of contracts/mocks/MockJackpot.sol#9504::setLPPoolCap#9378 (externally reachable function; caller-controlled input origins and/or an asserted caller-control relationship).", "fact_ids": ["fact:5b29debc877f0a99"], "status": "proven"}, {"stage": "argument_propagation", "description": "Arguments of calls made in this function trace back to those caller-chosen parameters (parameter-rooted argument origin chains).", "fact_ids": ["fact:1eedf37cff26e875", "fact:547155d204f0ba9a", "fact:ef2508c1066fe0f3", "fact:f371bbe06025b48b"], "status": "proven"}, {"stage": "external_execution", "description": "An external interaction with a dynamically resolved target exists in the same function; whether the caller can control the target or its arguments is not proven.", "fact_ids": ["fact:3f8ba4b62a4b1337", "fact:4d4f9fbc4be43daa"], "status": "inferred"}, {"stage": "downstream_execution_opportunity", "description": "Weak signal (POSSIBLE): the recipient/target of a dynamic external interaction may itself execute code, but nothing ties the recipient to the attacker's data. Runtime dispatch cannot be proven statically; this grade alone can never upgrade the chain to STRONG_SECURITY_CHAIN.", "fact_ids": [], "status": "uncertain", "grade": "POSSIBLE", "weak_signal": true}]}
{"hypothesis_id": "H-95631b9fe0", "category": "security_chain", "statement": "Composed security chain in contracts/Jackpot.sol#4258::setGovernancePoolCap#2498 (PROVEN control provenance, composition strength SECURITY_RELEVANT): an external caller can influence the function's inputs; those inputs flow into call arguments; the influence reaches an external interaction with a dynamically resolved target (attacker-influenced execution opportunity); downstream effects are linkage-graded (post_call_derived). Stages: untrusted_influence -> argument_propagation -> external_execution -> downstream_execution_opportunity -> state_value_effect. This composition has not been ruled out as security-relevant.", "actor": "external_user", "preconditions": ["The function is reachable by the influencing caller", "The influenced inputs are not constrained by an authorization check before reaching the interaction", "The dynamic recipient executes code that interacts back with this contract"], "observed_facts": ["fact:0233a61f46db7ea2", "fact:0eef23392590896b", "fact:491ca9ab15c00314", "fact:4e66627596d876fc", "fact:507d1835e57efe8e", "fact:86998508c0ec0d9f", "fact:ba62b044b25861f6", "fact:bd03062a54b5c7aa", "fact:db7900f695dea501", "fact:eeb5876da97448e3", "fact:f3ee128901cfe4de"], "graph_nodes": [], "graph_edges": [], "affected_functions": ["contracts/Jackpot.sol#4258::setGovernancePoolCap#2498"], "affected_assets": [], "invariant_candidate_id": "", "uncertainty": "The external target is resolved dynamically; caller control over the target/arguments is not established by fact-level dataflow. Whether the dynamic recipient actually executes code at runtime (callback/hook) cannot be proven statically; downstream-execution grade: POSSIBLE. No downstream effect shares the chain's dataflow identity -- the effects are post-call-derived or same-function adjacency only, which never qualifies as a proven consequence.", "priority": "medium_interest", "priority_rationale": "moderate concern (score=4, tier=ARGUMENT_DEPENDENCY, ceiling=6)", "suggested_next_investigation": "Walk the chain stages for contracts/Jackpot.sol#4258::setGovernancePoolCap#2498 in order and verify each step: the control-provenance evidence, the argument propagation into the external interaction, the linkage grade of the downstream effects, and (if present) the flow-linked invariant candidate.", "evidence_tier": "ARGUMENT_DEPENDENCY", "control_provenance": "PROVEN", "composition_strength": "SECURITY_RELEVANT", "chain": [{"stage": "untrusted_influence", "description": "Any external caller can choose the inputs of contracts/Jackpot.sol#4258::setGovernancePoolCap#2498 (externally reachable function; caller-controlled input origins and/or an asserted caller-control relationship).", "fact_ids": ["fact:ba62b044b25861f6", "fact:bd03062a54b5c7aa"], "status": "proven"}, {"stage": "argument_propagation", "description": "Arguments of calls made in this function trace back to those caller-chosen parameters (parameter-rooted argument origin chains).", "fact_ids": ["fact:0eef23392590896b", "fact:86998508c0ec0d9f"], "status": "proven"}, {"stage": "external_execution", "description": "An external interaction with a dynamically resolved target exists in the same function; whether the caller can control the target or its arguments is not proven.", "fact_ids": ["fact:491ca9ab15c00314", "fact:507d1835e57efe8e", "fact:eeb5876da97448e3", "fact:f3ee128901cfe4de"], "status": "inferred"}, {"stage": "downstream_execution_opportunity", "description": "Weak signal (POSSIBLE): the recipient/target of a dynamic external interaction may itself execute code, but nothing ties the recipient to the attacker's data. Runtime dispatch cannot be proven statically; this grade alone can never upgrade the chain to STRONG_SECURITY_CHAIN.", "fact_ids": [], "status": "uncertain", "grade": "POSSIBLE", "weak_signal": true}, {"stage": "state_value_effect", "description": "Downstream state/value effects, graded by linkage to the chain's dataflow identity: strongest=post_call_derived (per fact: adjacent_only, post_call_derived).", "fact_ids": ["fact:0233a61f46db7ea2", "fact:4e66627596d876fc", "fact:db7900f695dea501"], "status": "uncertain", "linkage": "post_call_derived"}]}
{"hypothesis_id": "H-cf92456585", "category": "cross_contract_trust", "statement": "Contract Jackpot calls dynamic target in jackpotLPManager. Trust chain: Jackpot -> dynamic -> jackpotLPManager. Recon's relationship evidence over this specific call asserts caller influence at PROVEN certainty, so the dynamic target is an unverified execution path (composition strength SECURITY_RELEVANT).", "actor": "external_user", "preconditions": ["Target is controlled by untrusted party", "Target has code that can interact with protocol"], "observed_facts": ["fact:eeb5876da97448e3"], "graph_nodes": ["node:25e37a9402ddd04c", "node:ad2561875f1c58ad"], "graph_edges": ["edge:cf43252c39d1ca53"], "affected_functions": ["contracts/Jackpot.sol#4258::setGovernancePoolCap#2498"], "affected_assets": ["cross-contract assets"], "invariant_candidate_id": "", "uncertainty": "Whether the target is actually user-controlled depends on the dataflow from the function's inputs to the call target expression.", "priority": "medium_interest", "priority_rationale": "significant exposure (score=5, tier=GRAPH_REACHABILITY, ceiling=10) [capped: SECURITY_RELEVANT composition]", "suggested_next_investigation": "Trace the dataflow to determine who controls the call target.", "evidence_tier": "GRAPH_REACHABILITY", "control_provenance": "PROVEN", "composition_strength": "SECURITY_RELEVANT", "chain": []}
{"hypothesis_id": "H-519c6dbbdb", "category": "callback_reentrancy", "statement": "Function contracts/Jackpot.sol#4258::setGovernancePoolCap#2498 combines the following signals: external interaction (4 fact(s)), state mutation (1 fact(s)) and is externally reachable. A proven argument/dataflow dependency connects these signals. This combination has not been ruled out as security-relevant, whether or not it matches a previously catalogued hypothesis category.", "actor": "external_user", "preconditions": ["Attacker can reach or influence this function", "The involved signals (external_interaction, state_mutation) can be chained in a way that violates an implicit protocol assumption"], "observed_facts": ["fact:4e66627596d876fc", "fact:507d1835e57efe8e", "fact:ba62b044b25861f6", "fact:bd03062a54b5c7aa", "fact:eeb5876da97448e3"], "graph_nodes": [], "graph_edges": [], "affected_functions": ["contracts/Jackpot.sol#4258::setGovernancePoolCap#2498"], "affected_assets": [], "invariant_candidate_id": "", "uncertainty": "Verified argument/dataflow evidence (e.g. call_argument_dataflow, parameter origin) connects inputs to calls in this function, but whether this leads to actual security impact is not yet confirmed.", "priority": "low_interest", "priority_rationale": "low-impact surface (score=2, tier=ARGUMENT_DEPENDENCY, ceiling=6)", "suggested_next_investigation": "Check if the dependency creates a real security concern and whether the caller-controlled parameter reaches a sensitive sink.", "evidence_tier": "ARGUMENT_DEPENDENCY", "control_provenance": "", "composition_strength": "", "chain": []}
{"hypothesis_id": "H-5d42af8757", "category": "novel_composition", "statement": "Function contracts/JackpotLPManager.sol#5990::setLPPoolCap#5732 combines the following signals: computation (2 fact(s)), control flow (1 fact(s)), state mutation (1 fact(s)) and is externally reachable. This combination has not been ruled out as security-relevant, whether or not it matches a previously catalogued hypothesis category.", "actor": "external_user", "preconditions": ["Attacker can reach or influence this function", "The involved signals (computation, control_flow, state_mutation) can be chained in a way that violates an implicit protocol assumption"], "observed_facts": ["fact:376dfb08b9a93954", "fact:77396523d2394b7b", "fact:bf5a852dbf3faeeb", "fact:e1b27366613827fb"], "graph_nodes": [], "graph_edges": [], "affected_functions": ["contracts/JackpotLPManager.sol#5990::setLPPoolCap#5732"], "affected_assets": [], "invariant_candidate_id": "", "uncertainty": "Signals co-occur in the same function but there is no proven data/argument/control dependency. Whether they cause each other requires deeper analysis or proof.", "priority": "low_interest", "priority_rationale": "low-impact surface (score=2, tier=CO_OCCURRENCE, ceiling=2)", "suggested_next_investigation": "Verify if computation, control_flow, state_mutation are causally connected or merely coincidental. Look for data/argument/control dependency chains.", "evidence_tier": "CO_OCCURRENCE", "control_provenance": "", "composition_strength": "", "chain": []}

❯ grep 'randomness' runs/jackpot-expanded-coverage/threat/hypotheses.jsonl
{"hypothesis_id": "H-4c6e008c90", "category": "cross_contract_trust", "statement": "Contract ScaledEntropyProviderMock calls dynamic target in callback. Trust chain: ScaledEntropyProviderMock -> dynamic -> callback. Recon's relationship evidence over this specific call asserts caller influence at PROVEN certainty, so the dynamic target is an unverified execution path (composition strength SECURITY_RELEVANT).", "actor": "external_user", "preconditions": ["Target is controlled by untrusted party", "Target has code that can interact with protocol"], "observed_facts": ["fact:76e6cc44025e9311"], "graph_nodes": ["node:cd559e859a46bb52", "node:0a6bd0e0a6d2c3ee"], "graph_edges": ["edge:cf9ccc9e58f7c90f"], "affected_functions": ["contracts/mocks/ScaledEntropyProviderMock.sol#9992::randomnessCallback#9960"], "affected_assets": ["cross-contract assets"], "invariant_candidate_id": "", "uncertainty": "Whether the target is actually user-controlled depends on the dataflow from the function's inputs to the call target expression.", "priority": "medium_interest", "priority_rationale": "significant exposure (score=5, tier=GRAPH_REACHABILITY, ceiling=10) [capped: SECURITY_RELEVANT composition]", "suggested_next_investigation": "Trace the dataflow to determine who controls the call target.", "evidence_tier": "GRAPH_REACHABILITY", "control_provenance": "PROVEN", "composition_strength": "SECURITY_RELEVANT", "chain": []}
{"hypothesis_id": "H-6f7cc25769", "category": "security_chain", "statement": "Composed security chain in contracts/mocks/ScaledEntropyProviderMock.sol#9992::randomnessCallback#9960 (PROVEN control provenance, composition strength SECURITY_RELEVANT): an external caller can influence the function's inputs; those inputs flow into call arguments; the influence reaches an external interaction with a dynamically resolved target (attacker-influenced execution opportunity). Stages: untrusted_influence -> argument_propagation -> external_execution -> downstream_execution_opportunity. This composition has not been ruled out as security-relevant.", "actor": "external_user", "preconditions": ["The function is reachable by the influencing caller", "The influenced inputs are not constrained by an authorization check before reaching the interaction", "The dynamic recipient executes code that interacts back with this contract"], "observed_facts": ["fact:156f2e4bf79804fd", "fact:76e6cc44025e9311", "fact:79068fce5f8f384c", "fact:87312b61a4a5a8a3", "fact:899e9f14aebac731"], "graph_nodes": [], "graph_edges": [], "affected_functions": ["contracts/mocks/ScaledEntropyProviderMock.sol#9992::randomnessCallback#9960"], "affected_assets": [], "invariant_candidate_id": "", "uncertainty": "Whether the dynamic recipient actually executes code at runtime (callback/hook) cannot be proven statically; downstream-execution grade: POSSIBLE.", "priority": "medium_interest", "priority_rationale": "moderate concern (score=4, tier=ARGUMENT_DEPENDENCY, ceiling=6)", "suggested_next_investigation": "Walk the chain stages for contracts/mocks/ScaledEntropyProviderMock.sol#9992::randomnessCallback#9960 in order and verify each step: the control-provenance evidence, the argument propagation into the external interaction, the linkage grade of the downstream effects, and (if present) the flow-linked invariant candidate.", "evidence_tier": "ARGUMENT_DEPENDENCY", "control_provenance": "PROVEN", "composition_strength": "SECURITY_RELEVANT", "chain": [{"stage": "untrusted_influence", "description": "Any external caller can choose the inputs of contracts/mocks/ScaledEntropyProviderMock.sol#9992::randomnessCallback#9960 (externally reachable function; caller-controlled input origins and/or an asserted caller-control relationship).", "fact_ids": ["fact:899e9f14aebac731"], "status": "proven"}, {"stage": "argument_propagation", "description": "Arguments of calls made in this function trace back to those caller-chosen parameters (parameter-rooted argument origin chains).", "fact_ids": ["fact:156f2e4bf79804fd", "fact:87312b61a4a5a8a3"], "status": "proven"}, {"stage": "external_execution", "description": "The caller-influenced inputs reach an external interaction with a dynamically resolved target the caller's data identifies, giving the caller influence over externally executed code and/or its arguments.", "fact_ids": ["fact:76e6cc44025e9311", "fact:79068fce5f8f384c"], "status": "proven"}, {"stage": "downstream_execution_opportunity", "description": "Weak signal (POSSIBLE): the recipient/target of a dynamic external interaction may itself execute code, but nothing ties the recipient to the attacker's data. Runtime dispatch cannot be proven statically; this grade alone can never upgrade the chain to STRONG_SECURITY_CHAIN.", "fact_ids": [], "status": "uncertain", "grade": "POSSIBLE", "weak_signal": true}]}
{"hypothesis_id": "H-75f547c723", "category": "DoS_griefing", "statement": "Function contracts/mocks/ScaledEntropyProviderMock.sol#9992::randomnessCallback#9960 combines the following signals: control flow (2 fact(s)), external interaction (4 fact(s)) and is externally reachable. A proven argument/dataflow dependency connects these signals. This combination has not been ruled out as security-relevant, whether or not it matches a previously catalogued hypothesis category.", "actor": "external_user", "preconditions": ["Attacker can reach or influence this function", "The involved signals (control_flow, external_interaction) can be chained in a way that violates an implicit protocol assumption"], "observed_facts": ["fact:13f5d2648c5456e8", "fact:63d00b837599973c", "fact:76e6cc44025e9311", "fact:899e9f14aebac731", "fact:9d317765187d4553", "fact:ccf620473cf7caf1"], "graph_nodes": [], "graph_edges": [], "affected_functions": ["contracts/mocks/ScaledEntropyProviderMock.sol#9992::randomnessCallback#9960"], "affected_assets": [], "invariant_candidate_id": "INV-004", "uncertainty": "Verified argument/dataflow evidence (e.g. call_argument_dataflow, parameter origin) connects inputs to calls in this function, but whether this leads to actual security impact is not yet confirmed.", "priority": "medium_interest", "priority_rationale": "moderate concern (score=4, tier=ARGUMENT_DEPENDENCY, ceiling=6)", "suggested_next_investigation": "Check if the dependency creates a real security concern and whether the caller-controlled parameter reaches a sensitive sink.", "evidence_tier": "ARGUMENT_DEPENDENCY", "control_provenance": "", "composition_strength": "", "chain": []}
{"hypothesis_id": "H-c6a2551c6e", "category": "novel_composition", "statement": "Function contracts/mocks/ScaledEntropyProviderMock.sol#9992::randomnessCallback#9960 combines the following signals: computation (1 fact(s)), external interaction (4 fact(s)) and is externally reachable. A proven argument/dataflow dependency connects these signals. This combination has not been ruled out as security-relevant, whether or not it matches a previously catalogued hypothesis category.", "actor": "external_user", "preconditions": ["Attacker can reach or influence this function", "The involved signals (computation, external_interaction) can be chained in a way that violates an implicit protocol assumption"], "observed_facts": ["fact:067f15aac5570c79", "fact:13f5d2648c5456e8", "fact:63d00b837599973c", "fact:76e6cc44025e9311", "fact:899e9f14aebac731"], "graph_nodes": [], "graph_edges": [], "affected_functions": ["contracts/mocks/ScaledEntropyProviderMock.sol#9992::randomnessCallback#9960"], "affected_assets": [], "invariant_candidate_id": "INV-004", "uncertainty": "Verified argument/dataflow evidence (e.g. call_argument_dataflow, parameter origin) connects inputs to calls in this function, but whether this leads to actual security impact is not yet confirmed.", "priority": "medium_interest", "priority_rationale": "moderate concern (score=4, tier=ARGUMENT_DEPENDENCY, ceiling=6)", "suggested_next_investigation": "Check if the dependency creates a real security concern and whether the caller-controlled parameter reaches a sensitive sink.", "evidence_tier": "ARGUMENT_DEPENDENCY", "control_provenance": "", "composition_strength": "", "chain": []}
{"hypothesis_id": "H-8197c405e1", "category": "arbitrary_execution", "statement": "Low-level call in contracts/mocks/ScaledEntropyProviderMock.sol#9992::randomnessCallback#9960 has dynamic target. External calldata flows into call.", "actor": "caller", "preconditions": [], "observed_facts": ["fact:76e6cc44025e9311", "fact:13f5d2648c5456e8", "fact:afc713370843e779"], "graph_nodes": [], "graph_edges": [], "affected_functions": ["contracts/mocks/ScaledEntropyProviderMock.sol#9992::randomnessCallback#9960"], "affected_assets": [], "invariant_candidate_id": "INV-004", "uncertainty": "Target derivation depends on function dataflow.", "priority": "low_interest", "priority_rationale": "low-impact surface (score=0, tier=CO_OCCURRENCE, ceiling=2)", "suggested_next_investigation": "Trace how the call target expression is constructed: is it a direct parameter, state variable, or derived?", "evidence_tier": "CO_OCCURRENCE", "control_provenance": "", "composition_strength": "", "chain": []}
{"hypothesis_id": "H-9674b3e1ea", "category": "randomness_manipulation", "statement": "Function uses predictable randomness source (block.timestamp). On-chain randomness is manipulable by miners/validators.", "actor": "miner_validator", "preconditions": ["Function relies on on-chain randomness for security-critical decision", "Randomness source is predictable or manipulable"], "observed_facts": ["fact:06db1e3e8d57331b"], "graph_nodes": [], "graph_edges": [], "affected_functions": ["contracts/Jackpot.sol#4258::runJackpot#2034"], "affected_assets": [], "invariant_candidate_id": "", "uncertainty": "", "priority": "low_interest", "priority_rationale": "low-impact surface (score=0, tier=CO_OCCURRENCE, ceiling=2)", "suggested_next_investigation": "", "evidence_tier": "CO_OCCURRENCE", "control_provenance": "", "composition_strength": "", "chain": []}
❯ cat runs/jackpot-run-gue-2/finding/summary.json
{
  "confirmed_attacks": 3,
  "findings": [
    {
      "finding_id": "F-001",
      "attack_id": "A-15e1059d18",
      "severity": "critical",
      "title": "Theft / loss of funds via _bridgeFunds (approval abuse)",
      "report": "finding-F-001.md"
    },
    {
      "finding_id": "F-002",
      "attack_id": "A-f718be3766",
      "severity": "critical",
      "title": "Unauthorized asset movement via buyTickets (approval abuse)",
      "report": "finding-F-002.md"
    },
    {
      "finding_id": "F-003",
      "attack_id": "A-42700b5c2f",
      "severity": "high",
      "title": "Privilege escalation via _updateTicketOwnership (direct unauthorized call)",
      "report": "finding-F-003.md"
    }
  ],
  "not_reported": []
}%    
❯ cat runs/jackpot-expanded-coverage/finding/summary.json
{
  "confirmed_attacks": 0,
  "findings": [],
  "not_reported": [
    {
      "attack_id": "A-030842b871",
      "verdict": "INCONCLUSIVE",
      "reason": "forge output could not be parsed"
    },
    {
      "attack_id": "A-15e1059d18",
      "verdict": "INCONCLUSIVE",
      "reason": "forge output could not be parsed"
    },
    {
      "attack_id": "A-25f98a965c",
      "verdict": "INCONCLUSIVE",
      "reason": "forge output could not be parsed"
    },
    {
      "attack_id": "A-390196c2aa",
      "verdict": "INCONCLUSIVE",
      "reason": "forge output could not be parsed"
    },
    {
      "attack_id": "A-3f2e38ae19",
      "verdict": "INCONCLUSIVE",
      "reason": "forge output could not be parsed"
    },
    {
      "attack_id": "A-42700b5c2f",
      "verdict": "INCONCLUSIVE",
      "reason": "forge output could not be parsed"
    },
    {
      "attack_id": "A-429beb5392",
      "verdict": "INCONCLUSIVE",
      "reason": "forge output could not be parsed"
    },
    {
      "attack_id": "A-6bfcb8af2d",
      "verdict": "INCONCLUSIVE",
      "reason": "forge output could not be parsed"
    },
    {
      "attack_id": "A-d3cd71b308",
      "verdict": "INCONCLUSIVE",
      "reason": "forge output could not be parsed"
    },
    {
      "attack_id": "A-f718be3766",
      "verdict": "INCONCLUSIVE",
      "reason": "forge output could not be parsed"
    }
  ]
}% 
