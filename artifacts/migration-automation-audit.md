# Legacy automation migration audit

Audit date: 2026-10-17. No production scans or source fixes performed.

## Conclusion

No missing aliases among the 113 legacy rules marked non-manual. However, default primary execution does not preserve their automated observation coverage: 69 legacy rules map exclusively to human-required requirements, and ScanPlanner removes these entire definitions unless include-manual-review is enabled. This is an operational coverage gap even where the human conclusion gate is justified.

## Inventory reconciliation

- Legacy: 371 rules, 113 non-manual and 258 manual.
- Primary: 687 unique requirements, 44 without human evidence and 643 with human evidence.
- All 113 legacy non-manual rules resolve to active primary identities.
- 44 legacy rules have a non-human mapped identity; 69 have only human-required mapped identities. The 44 legacy rows are not 44 distinct primary requirements: mergers/deduplication apply.
- 9 legacy rules have an old check name absent from their mapped primary obligations, including REMOTE variants. These have replacement/scoped predicates and require semantic review, not automatic classification as lost checks.
- 30 legacy rules retain check names with changed argument configurations; this is not proof of equivalent behavior.

## Confirmed runtime planning results

Probe: artifacts/probe-migration-planning.php, empty temporary LOCAL target, no capabilities. This checks actual selection only, not detector outcomes.

| Profile | Default | include-manual-review |
|---|---:|---:|
| basic | 20 | 20 |
| baseline | 41 | 684 |
| asvs-l1 | no plan | 69 |
| asvs-l2 | no plan | 197 |
| asvs-l3 | no plan | 267 |
| pci | no plan | 257 |

No-plan diagnostics: No requirements matched the selection. ASVS capability filtering explains differences between inventory totals and selected totals.

## Findings

1. High: manual-review filter removes automatic observations along with human obligations (src/Engine/ScanPlanner.php, RequirementPolicy.php). Examples: MB-R012 -> MB-0108 SQL checks; MB-R013 -> MB-0105 escaping; MB-R097 -> MB-0097 hardcoded secrets. These do not run in default primary baseline. They remain executable with include-manual-review. Supporting observations do not independently become confirmed requirement failures in RequirementAssessmentEvaluator.
2. High: default ASVS and PCI primary plans are empty. Existing tests passing do not establish usable default execution.
3. Medium: baseline deliberately excludes MB-0728/0729/0730 scoped alternatives to avoid double counting. Its broad human counterparts are filtered by default, leaving a coverage gap for scoped password/debug/working-tree-secret observations that basic does execute.
4. Review needed: changed predicates for MB-R003, R006, R011, R026, R027, R030, R037, R039, R046. Examples: R037 now checks persisted full_page state rather than proving Varnish/cache hits; R039 uses database indexer_state instead of filesystem state; R046 checks installed cron. Some changes strengthen evidence, others narrow scope. REMOTE variants retain mixed-content/static-asset/cache-signal checks and must not be overlooked in comparison.
5. Documentation mismatch: README's 113 automatic legacy rules does not describe default primary requirement execution. Distinguish automated observations from complete requirement conclusions in user-visible counts.

## Validation

Passed in WSL PHP:
- AutomationInventoryContractTest: 716 assertions.
- InternalRequirementCatalogTest.
- PrimaryRequirementPlanningTest.
- RequirementCoverageSafetyTest: 2148 assertions.
- Actual planner probe above.

CSV contains one row for each of the 113 legacy non-manual rules. Name/argument matching is structural; this audit does not certify equivalence for all predicates or false-positive/negative behavior. Legacy-only MB-R selectors use the compatibility planner and cannot demonstrate primary-path completeness.

## Recommended remediation

Preserve automatic observations independently of human conclusion gates. Offer scoped technical results without asserting broad standard compliance. Ensure default profiles execute those observations, retain deliberate deduplication, and add regression tests for legacy detector execution and default ASVS/PCI planning. Review the nine replaced predicates and thirty argument-change rows before declaring behavioral parity.
