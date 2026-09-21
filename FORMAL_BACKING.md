# Formal Backing

DARM Guard's checks correspond to conditions proved in the Lean 4 repository
[darm-monitor](https://github.com/Goblohan/darm-monitor). The Python runtime
itself is not formally verified; its exact semantics are formalized separately
(see Runtime correspondence below).

Axiom dependencies are printed with `#print axioms` in each file. CI audits the
whole corpus for sorryAx on every push.

## ODATS conditions: each proved independently necessary

| Condition | Theorem(s) | File | v0.1.x runtime |
|-----------|-----------|------|----------------|
| O Observation | ag_satisfaction_holds, unsafe_causeable_exists | E14AGContractComparison | enforced |
| D Domain | e15_g5b_e15_obligations_do_not_imply_ag_causeable_coverage | E15CausalCoverageContractEquivalence | not enforced |
| A Authority | unsupported_authority_substitution | R4bAuthoritySubstitution | enforced |
| T Temporal | temporal_freshness_independently_necessary | E16TemporalFreshness | at check time |
| S Semantic | exact_lift_missing_A2 ... exact_lift_missing_A5 | E13ExactLiftMissingA2-A5 | not enforced |

Deletion minimality for the four-obligation structure: e15_g5_deletion_minimality.

## Core transfer theory

| Theorem | Statement | File |
|---------|-----------|------|
| transfer_iff_grbs | Transfer iff GRBS, under the stated seams | R1bSufficiency |
| target_assured_of_source_and_delta | Source + discharged delta gives target | R5AssuranceConservation |
| assurance_conservation_failure | Undischarged delta: target fails | R5AssuranceConservation |
| darm_admissibility_preserves_assurance | Admissible transfer preserves assurance | DARMCoreCalculus |
| agent_transfer_integrity | Credential + unauthorized delta: rejected | AgentTransferIntegrity |
| proposal_authority_separation | Generating a proposal is not authority | E17ProposalAuthoritySeparation |
| failure_witness_complete, no_false_admits | Typed ODATS classification | E18AssuranceFailureWitness |

## Executable bridge

| Theorem | Statement | File |
|---------|-----------|------|
| check_true_implies_obligation | Bool check true gives Prop obligation | E21ExecutableObligationBridge |
| obligation_implies_check_true | Prop obligation gives Bool check true | E21ExecutableObligationBridge |
| e22_parameterized_bridge | Same, for any input type | E22ParameterizedExecutablePredicateBridge |

## Runtime correspondence (what is proved about v0.1.x itself)

| Theorem | Statement | File |
|---------|-----------|------|
| checkerAdmissible_iff_runtimeAdmissible | The three v0.1.0 failure tests equal one inclusion condition | IC1RuntimeSemantics |
| runtimeCheck_true_iff_checkerAdmissible | The executable check matches that semantics | IC1RuntimeSemantics |
| no_current_runtime_semantic_authorizer | Tool-name observation cannot separate safe from forbidden calls | R22RuntimeImplementationCorrespondence |
| current_runtime_admission_does_not_imply_semantic_authorization | v0.1.x admission is not semantic authorization | R22RuntimeImplementationCorrespondence |
| refined_classifier_recovers_semantic_authorization | Tool + argument observation recovers it (v0.2 spec) | R22RuntimeImplementationCorrespondence |

## Verified zero-axiom results

behavioral_AG_cannot_recover_latent_coverage, latent_coverage_is_not_behaviorally_visible (R3dBehavioralIsolation);
unsupported_scope_expansion (R4aScopeExpansion); assurance_conservation_failure (R5AssuranceConservation);
physicalAG_implies_transfer (AGCompleteness); refined_classifier_recovers_semantic_authorization,
refined_runtime_request_distinguishes_arguments (R22RuntimeImplementationCorrespondence).

*PerceptraAI Lab*
