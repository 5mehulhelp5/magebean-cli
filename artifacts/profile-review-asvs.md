# Customer-side engineering review: ASVS profiles

Scope: current local catalog and implementation. This is an inventory of every ASVS member plus representative semantic review; not a claim that every binding has been proven or an external compliance opinion. No source behavior changed.

| Profile | Members | With concrete check | No concrete check | Capability-gated | Human required |
|---|---:|---:|---:|---:|---:|
| asvs-l1 |69|41|28|0|69|
| asvs-l2 |252|89|163|55|252|
| asvs-l3 |344|97|247|77|344|

Every L1 member is in L2; every L2 member is in L3. L2 adds 183 members but only 48 additional checked requirements; L3 adds 92 but only 8 additional checked requirements. These are requirement counts, not unique detectors or normative standard clause counts. Member CSV records each ID, scope, capability, binding count, roles and proof labels.

## Highest customer-impact findings

1. CLI profile selection is unusable by default for all three profiles: ScanPlanner::planCli filters requiresHuman before execution; all ASVS members require human. This removes 41/89/97 requirements that already have detectors. RequirementCatalog additionally omits 55 L2 / 77 L3 capability-gated members without context. Missing capability is not proof of non-applicability. Display omitted IDs/reasons and ask scope questions rather than silently shrinking the assessment.
2. 41 L1, 88 L2 and 96 L3 checked requirements have only supporting observations. RequirementAssessmentEvaluator continues immediately for supporting obligations. Their failed observations cannot alone produce a requirement FAIL; this is defensible for broad criteria, but customers need visible technical findings and a separate review task, otherwise useful evidence is hidden behind MANUAL_REVIEW.
3. L2/L3 value is primarily extra review tasks, not dramatically stronger automated execution. Product copy should state the increment and show reusable evidence, workflow tests and capability questionnaires. A customer selecting L3 should not discover only after scan that 247 of 344 members have no concrete check.

## Representative binding review

- MB-0105 (L1+) combines ASVS output contexts and JavaScript escaping. Four obligations invoke only two exact unique bindings: PHTML escaping and JS-context escaping, each twice. Both scope app; vendor, generated assets, live header/CSS/XML contexts are not established. TemplateRequestSourceChecks skips unreadable files and reports success when no offender is found, even on no files. Keep heuristic; require files-scanned/read-failed/coverage evidence and distinguish no observation from successful verification. Deduplicate display/execution without losing alignment references.
- MB-0172 (L2+) asks whether client-side technologies remain supported/secure, but all three bindings read composer.lock via composer audit, marketplace status and release recency. This is partial evidence only: npm/yarn/pnpm/CDN/bundled browser dependencies and actual delivered assets are absent. Add client asset/package inventory and documented support policy; do not suggest PHP package recency establishes browser technology support.
- MB-0399 (L2+) asks for maintained third-party inventory/SBOM but its seven bindings are primarily Composer audit/status plus lock integrity; composer_audit_api repeats identically. A valid lockfile plus CVE lookup does not demonstrate a maintained inventory of all libraries, runtime delivered assets, completeness or provenance. Emit an inventory artifact and compare runtime/source manifests, or explicitly keep this a review-only claim.
- MB-0403 (L1+) asks whether components breach documented remediation timeframes; bindings audit advisories, Adobe patches and fixed latency_days=30. A fixed default is not the customer's documented SLA, and audit status is not remediation history. Require policy input and first-observed/published/remediation timestamps with explicit uncertainty. Keep the current hints useful but separate from compliance conclusion.
- MB-0194 (L1+) file-size/resource safety is checked with generic code_upload_safety. InputSafetySourceChecks::uploadSafety detects code-pattern safeguards, not stress-tested processing cost, decompression/image amplification or runtime proxy/PHP limits. Require controlled boundary tests and effective limits; absence of pattern findings must not certify resource resilience.
- MB-0210 password-change behavior, MB-0256 trusted backend session verification, and MB-0408 returned-field minimization have no checks. Customer evidence should be executable scenario instructions with roles/endpoints/expected behavior, not only restating criteria.
- MB-0379 (L2+) is security_reviewed and has a mandatory verified debug configuration observation plus mandatory human component-wide review. A verified failure can fail the requirement while success still needs human evidence. This is a useful model for narrowly provable counterexamples, but must be reviewed per predicate, not mass-applied to heuristic source patterns.
- MB-0424 (L3) duplicates four exact binding recipes (eight obligations). Sensitive logging observations need redacted locations and counts, not raw secrets/PII. One finding can support multiple criteria without becoming multiple independent security issues.

SourceSecurityObservationsCheck is explicitly discovery-only, bounded to 2,000 files / 10 MiB and records incomplete collection. It returns UNKNOWN without observations and MANUAL_REVIEW when patterns occur. This conservative behavior is appropriate; preserve its limitations in Console and reports. Similar collection metadata is needed for older boolean checks.

## Acceptance from a buyer perspective

- Every profile runs its eligible technical observations by default; human-required affects final conformance, not detector selection.
- Report inventory, applicable, omitted (reason), observed, insufficient evidence, technical findings and review tasks separately.
- L1: include real deployment evidence plus tested auth/session/authorization/output-context scenarios; 28 no-check members each get a concrete follow-up workflow.
- L2: publish the 183-member delta, discover capabilities before selection, and batch reviews by shared evidence. Cover application/browser dependencies beyond Composer.
- L3: publish the 92-member delta with explicit only 8 newly checked requirements, and deliver meaningful high-assurance review/testing workflows before presenting a larger requirement number as better scanning.
- Deduplicate identical recipes and findings; do not inflate coverage by obligation count.
- Add fixture checks for empty/unreadable/bounded source, callback failure, capability missing, shared recipe duplication and default profile execution. Prove bindings with safe and violating examples before promoting mandatory verified conditions.
