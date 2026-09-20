# Formal Backing

Every check in DARM Guard corresponds to a machine-checked Lean 4 theorem
in [darm-monitor](https://github.com/Goblohan/darm-monitor).

## ODATS Conditions

| Condition | Lean Theorem | File | Axioms |
|-----------|-------------|------|--------|
| O Observation | ag_is_satisfied + causal_safety_fails | E14AGContractComparison | Zero |
| D Domain | G5b deletion witness | E15CausalCoverageContractEquivalence | Zero |
| A Authority | unsupported_authority_substitution | R4bAuthoritySubstitution | Zero |
| T Temporal | temporal_freshness_independently_necessary | E16TemporalFreshness | Zero |
| S Semantic | MissingA2-MissingA5 deletion witnesses | E13ExactLiftMissingA2-A5 | Zero |

## Core Theorems

| Theorem | What It Proves | File |
|---------|---------------|------|
| transfer_iff_grbs | Transfer == GRBS biconditional | R1bSufficiency |
| target_assured_of_source_and_delta | Source + Delta -> Target | R5AssuranceConservation |
| assurance_conservation_failure | Undischarged delta -> target fails | R5AssuranceConservation |
| agent_transfer_integrity | Credential + unauthorized delta -> rejected | AgentTransferIntegrity |
| proposal_authority_separation | Generation != authorization | E17ProposalAuthoritySeparation |
| e14_verdict | CausalCoverage: necessary + sufficient + AG-invisible | E14AGContractComparison |

## Executable Bridge

| Theorem | What It Proves | File |
|---------|---------------|------|
| check_true_implies_obligation | Bool check -> Prop obligation | E21ExecutableObligationBridge |
| obligation_implies_check_true | Prop obligation -> Bool check | E21ExecutableObligationBridge |
| e22_parameterized_bridge | Parameterized for any input type | E22ParameterizedExecutablePredicateBridge |

167 modules. 31,553 lines. 1,001 theorems. Zero sorry.

*PerceptraAI Lab*
