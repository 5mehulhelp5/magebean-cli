# Customer-side review: Magento Best Practices / Production Hardening

Reviewed 2026-10-17 against current internal-catalog.json and internal-profiles.json. Read-only review of catalog bindings and evaluator/planner code; no real Magento target was scanned and no runtime source changed. Member-level recommendations: profile-review-deployment-members.csv/json, 102 profile-memberships (20 basic +82 hardening), 85 distinct requirements. These are recommendations, not applied classifications. Counts do not measure detector accuracy.

## Current promise versus execution

| Profile | Inventory | human=false | human=true | REMOTE members |
|---|---:|---:|---:|---:|
| basic |20|20|0|7|
| hardening |82|41|41|16|

All LOCAL members lack capability filters in current definitions. ScanPlanner.php:63-68 excludes complete human requirements from default CLI execution, so hardening defaults to41 LOCAL requirements. Agent manifests follow separate planAgent logic; do not infer identical Console execution behavior solely from CLI filter. Missing runtime URL/DB/API/crontab/Git evidence can still produce UNKNOWN. Catalog inventory is neither executed-check count nor pass-capable requirement count.

## P1: hardening is not a safe upgrade from basic

Set difference is exact: basic minus hardening = MB-0728, MB-0729, MB-0730. Intersection17. Hardening adds65.

- MB-0728 configured admin password minimum >=8 disappears; hardening instead has broad human MB-0209 (admin AND user password policy). Default CLI omits MB-0209 and its supporting detector, reducing password-policy signal compared with basic.
- MB-0729 scoped persisted debug-declaration check disappears; broad human MB-0379 includes runtime/multiple-component policy, omitted by default. Production mode MB-0031 does not replace debug checks.
- MB-0730 deployed-file secret-pattern scan disappears. MB-0072 needs .git and PCRE-compatible Git history; production release directories often lack .git. Human MB-0097 app source heuristic is also omitted by default.

Recommendation: define hardening as inheritance from useful basic technical checks, with deeper requirements layered on top. Run supporting checks regardless of whether full requirement conformance needs human evidence. Preserve exact scopes rather than certify broad compliance from technical signals.

Evidence: internal-profiles.json:696,728; internal-catalog.json:13902 (MB-0209),24988 (MB-0379),3687 (MB-0072),5450 (MB-0097),46952/46999/47042 (three scoped basic requirements); ScanPlanner.php:63-68.

## P1: REMOTE cache check is a different claim

MB-0037 title/criterion say env.php cache_types.full_page is declared enabled. LOCAL cache_type_enabled checks this exact declaration (DeploymentStateCheck.php:32-41). REMOTE execution_variant instead uses http_cache_signals, proof=heuristic. HttpCheck.php:1308-1367 accepts any Age>0, increasing Age, X-Cache containing hit or Via containing varnish. Such observations cannot establish persisted Magento FPC state; cache may be CDN/reverse proxy. RequirementAssessmentEvaluator.php:42,76-78 correctly prevents heuristic-only PASS, so profile presents an automated/non-human requirement that cannot PASS remotely even with positive signals.

Recommendation: split declaration criterion from remote cache observations, or make remote claim explicitly supporting evidence. Explain remote limited scope and do not present7 remote basic members as7 fully automatic verified requirements.

## P1: retention of signal must accompany human boundary

Hardening41 human requirements contain useful vulnerability/security signals: raw SQL MB-0108, output escaping MB-0105, command execution MB-0109, uploads MB-0200/0021, authorization MB-0094/0099, CSP MB-0089, KEV prioritization MB-0054. Keeping human confirmation is appropriate. Omitting all their observations reduces customer value. Supporting status must show exact detector output, location, confidence, missing context and next verification step. An AST/pattern clean result does not establish complete safe behavior.

RequirementAssessmentEvaluator.php:32 ignores supporting observations for normative conclusion, which is appropriate; the UI still needs them visible and actionable. A concrete exposed secret/executable file can warrant an immediate technical finding without pretending all broader normative conditions are established.

## P2: separate security findings from operational/policy advice

26 of82 hardening memberships are recommended readiness/policy, with3 scoped corrections and36 supporting/human;17 retain technical check as-is with explicit scope. Basic has14 keep technical,5 readiness/policy,1 scoped correction. This split is customer-oriented, not a replacement for catalog human flags.

Examples:
- MB-0002 default root owner/group +0640 is a chosen deployment policy, not effective ACL proof.
- MB-0014 blocks every direct $_SERVER/other superglobal reference with high severity, yet criterion explicitly says coding policy, not input-validation proof (catalog:659).
- MB-0034/0035 artifact presence, MB-0037 FPC state, MB-0038 Redis/Varnish, MB-0039 indexer valid snapshot, MB-0046 cron entry, MB-0047 900-second heartbeat and MB-0048 <1000 backlog are deployment/operations readiness. Show time, thresholds, scheduler and architecture exceptions.
- MB-0059 advisory publication age<=30 days is not customer remediation SLA; fresh critical CVE remains urgent via advisory severity/KEV.
- MB-0062 24-month release age, MB-0063 repository activity, MB-0065 wildcard and MB-0066 dev constraints (both include require-dev), MB-0067 prefer-stable and MB-0069 exact latest stable (include_dev=true) can produce upgrade noise. Latest major is not automatically a safe Magento-compatible upgrade (catalog:3575; ComposerVersionChecks.php:432-609).
- MB-0079 insists keys live in env.php. Approved vaults/encrypted external secret management should be valid architectures. Rewrite policy around access/exposure/protection; do not require one storage implementation.
- MB-0102 asks PCI evidence file; keep contextual audit readiness rather than imply vendor default accounts were technically verified just from JSON documentation.

## P2: overlapping and repeated observations need one customer task

Eight hardening requirements contain byte-identical repeated checks across obligations: MB-0105 (2 detector types), MB-0108, MB-0109, MB-0131, MB-0200, MB-0209, MB-0379 (5 detector types), MB-0424 (4 detector types). MB-0200 repeats same code_media_executable_code args twice. These are catalog duplicates, not proof duplicated CPU/network work; runtime caching was not benchmarked. Preserve separate source obligations but share observation identity and avoid duplicate issue/action items.

Across requirements, MB-0049 and MB-0055 share advisory subject matter; MB-0031 appears again within debug assessment MB-0379; upload safety appears in MB-0200 and MB-0021; secret checks cover different scopes. Merge remediation tasks by evidence identity without deleting genuinely different scope.

## Customer acceptance criteria

1. Choosing hardening preserves basic technical observations or clearly documents every justified replacement.
2. Human evidence does not suppress useful technical observations; no full conformance PASS inferred from heuristics.
3. Profile UI states inventory, applicable, executable, executed, missing evidence, verified conclusions and human actions separately, by LOCAL/REMOTE mode.
4. Dependency/operations policies are separately prioritized from confirmed vulnerabilities, with configurable approved exceptions and freshness.
5. Remote admin/cookies/cache/static claims show exact tested URLs and gaps. MB-0030 only probes /, customer login and cart; its criterion explicitly excludes unobserved authenticated sessions, so do not claim tested admin session security.
6. Deduplicate evidence/remediation while retaining requirement alignment and scope.
