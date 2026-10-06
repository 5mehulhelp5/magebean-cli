# ASVS requirement runtime migration

ASVS profiles L1/L2/L3 now compile one assessment definition and one finding per canonical requirement. The 371 MB-R definitions remain reusable evidence sources and legacy compatibility entries. This does not convert PCI DSS, OWASP Top 10 or Magento baseline profiles, or implement the proposed future automation candidates.

| Profile | Default findings | With manual review, before capabilities | Full standard inventory |
|---|---:|---:|---:|
| asvs-l1 | 42 | 70 | 70 |
| asvs-l2 | 90 | 198 | 253 |
| asvs-l3 | 98 | 268 | 345 |

Defaults include 12 native partial implementations for the former unmapped requirements. Missing evidence still produces UNKNOWN; implemented coverage does not establish a passing scan. Capability-dependent definitions account for the difference between non-contextual selection and full inventory. Compilation deduplicates inherited identities and records assessment level separately from introduced level. Registry identities are pinned to ASVS 5.0.0.

## Execution and evidence

RequirementCatalog composes each requirement from its existing coverage mapping. One legacy source can contribute to several requirements; several sources can contribute to one requirement. Evidence groups retain source IDs, operators and individual check outcomes. Mandatory human checks cannot be bypassed by a technical alternative. Unknown sources, incomplete evidence and missing implementation never become a passing requirement.

Partial automated observations do not prove the full normative criterion. Passing signals still need human confirmation; failing partial signals also need confirmation, with UNKNOWN taking precedence when necessary evidence is incomplete. Fully automated findings retain the required-condition evaluation. Legacy MB-R execution remains unchanged. No independently supplied human evidence workflow is introduced by this migration.

## Compatibility

Existing command and option names, underlying legacy catalog loaders, explicit MB-R selectors, non-ASVS profiles and schema 1.0 agent serialization remain supported. Canonical CLI selectors require an ASVS profile. Project canonical policy is applied after compilation; immutable requirement identity/coverage cannot be overridden. Legacy exclusions fan out across mapped requirement definitions in an ASVS profile.

Canonical dashboard manifests require top-level profile context and registered canonical rule_key/assessment_item_id values. The agent emits exactly the requested items, preserves the old envelope/result fields, and continues mapping UNKNOWN/manual findings to error. Backend catalog migration and deployed dashboard acceptance are outside this repository change; an unchanged JSON shape alone does not establish backend acceptance of new IDs.

## Validation

55 test scripts pass, including 709 requirement migration assertions and 159 native evidence assertions, existing QA regression tests, legacy agent tests and architecture boundaries. The compatibility snapshot was reviewed before accepting exactly six migration changes: scan help, rules:list help, two ASVS listing outputs, and scan rules/exclude-rules option descriptions. Other snapshot fields remained unchanged relative to the accepted QA baseline.

A temporary PHAR build passed source/PHAR parity checks for legacy PASS/FAIL, canonical UNKNOWN, unique L1 listing counts and scan help; the repository release artifact is not overwritten. No commit, deployment or dashboard modification is performed.

The native-check follow-up separately reviewed four snapshot changes: two help descriptions and two control-filtered ASVS listings. Legacy findings and the remaining snapshot fields were unchanged. See [native evidence scope](asvs-native-evidence.md).
