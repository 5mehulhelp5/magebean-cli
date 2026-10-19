# Magebean findings-first reporting

Basic, Hardening and Magebean OWASP report observed issues that need attention. Requirement IDs organize observations and remediation; a detector does not need to establish the complete requirement to report an actual issue. This change does not add requirements or reactivate unsafe legacy bindings.

## Behavior

- A check-level negative observation becomes a risk observation requiring attention. This includes useful heuristic observations when the requirement-level outcome remains UNKNOWN, and observations retained alongside unrelated collection gaps.
- No observed issue means no displayed security finding. Clean check results remain available internally for compatibility and lifecycle processing; they are not displayed as findings.
- UNKNOWN results from missing permissions, inputs, unsupported applicability or check errors become actionable findings in the same list. Their observation kind remains `collection_issue`; they do not assert a confirmed security violation. Collection-only findings use informational severity and collection-specific remediation. Technical collection gaps remain in metadata to preserve incomplete-scan semantics, but are not repeated in a second output group when already represented by a finding.
- Applicability/binding bookkeeping without any executed check is not an observation and never creates a finding. Automated Magebean manifest items whose optional capability is not enabled are returned as unsupported/skipped, preserving item correspondence without a security claim. Console also filters historical synthetic `requirement_assessment` findings with applicability/binding reason codes, while retaining actual check observations in mixed payloads. Historical records are retained rather than deleted.
- A verified successful alternative suppresses failed alternatives that do not represent an issue under the declared `any` condition.
- Operational readiness and policy observations retain their lanes and exact scope. An observation requiring attention is not a claim of exploitability.

The CLI pretty output and HTML report prioritize actionable observations, locations, remediation and verification, including UNKNOWN observations in the same finding list. Omitted checks remain visible as coverage metadata. JSON retains the existing `findings` assessment rows for consumers and adds `risk_findings`, `collection_issues`, `summary.needs_attention` and `meta.findings_first` for the new view. `risk_findings` counts affected requirement rows, not individual locations or deduplicated vulnerabilities; correlation across requirements is not added by this change.

The terminal view uses a compact colored summary, severity-sorted numbered findings and width-aware wrapping. Needs attention appears once in the summary, not as a repeated finding badge. Default output shows the first remediation step and up to five source locations; selecting a requirement with `--rules` expands its context, verification and remediation. Plain/no-ANSI output preserves the same layout for logs and CI. Layout regression checks cover 40, 48, 80 and 110 columns.

Source inspection findings now report the actual reason, relative file and known parser/call location, with a reason-specific action. A generic "Source policy could not be evaluated completely" message without specific evidence is not promoted into a finding. Each requirement finding remains independent in CLI, HTML and Console, even when another finding has the same cause. Counts, detail links and ticket/defer/resolve actions retain their individual identities. Generic messages without concrete evidence must be corrected at the detector or excluded from findings; presentation grouping is not used to hide noise.

For the exact optional `app/code` scope, an absent directory or zero eligible PHP/PHTML files produces no source finding when the target has readable regular `bin/magento` and `app/etc/config.php` deployment markers and no other collection gaps. Wrong roots, broken or external symlinks, unreadable paths, traversal limits and explicitly configured alternative missing roots are not suppressed. The result states that this optional custom source scope is empty; it does not claim Composer/vendor code was inspected or all module security was established. Adobe documents both Composer/vendor and app/code component locations: [component file structure](https://developer.adobe.com/commerce/php/development/prepare/component-file-structure/).

## Transport and Console

Each automated Magebean assessment row carries `evidence.risk_observation` with `schema_version:1`, `needs_attention`, actual check observations, separate collection gaps, `collection_complete` and the original `assessment_outcome`. Check reason codes may be null. Existing pass/fail/error wire statuses are retained; additive metadata governs the new Magebean finding behavior.

Console checks the trusted assessment snapshot family (or exact server catalog fallback), validates the envelope and creates/updates a Finding for nonempty observations, including collection-issue observations emitted by the updated CLI. The assessment item becomes Needs attention with no approved requirement conclusion. Existing finding actions remain available. Old metadata with an empty finding list and incomplete collection cannot automatically close an existing Finding. Complete clean wire-PASS results retain existing compatible closure behavior. Malformed new metadata cannot fabricate a Finding or authorize closure. ASVS, PCI and old payloads keep their established paths.

Finding detail shows Needs attention and the observation messages for the new path. UNKNOWN collection observations use the same finding/ticket actions; duplicate collection-gap rows are suppressed. Existing unresolved security evidence is preserved when a later scan only reports missing collection. No human-evidence requirement is added.

Exit codes remain useful for automation: 0 for no observed issues and no collection errors, 1 for observations requiring attention, 2 when such an observation has Critical severity, and 3 for incomplete collection. Exit 0 does not certify full requirement conformance or complete production protection.

## Deployment

Deploy Console code before distributing the updated CLI/agent binary. An older Console can still parse the existing wire schema, but cannot implement the new finding lifecycle from additive metadata. No catalog import is required solely for this behavior change. Existing findings and assessment snapshots are not reset or rewritten. No production deployment or PHAR rebuild is performed by this implementation.

## Validation

Meaningful regressions cover check-level findings under UNKNOWN assessment outcomes, unified informational collection findings, gap-only and clean scans, successful alternatives, agent transport and redaction, CLI/HTML output, trusted-family isolation, malformed metadata, nullable legacy reason codes, dashboard visibility, ticket flow and preservation of existing security findings. See `MagebeanRiskObservationTest.php`, `MagebeanFindingsFirstPipelineTest.php`, `FindingsFirstPresentationTest.php`, and Console `MagebeanRiskObservationTest.php`.

Validated 2026-10-18: all 115 CLI test files passed. The related Console suite passed 36 tests / 205 assertions, including authenticated ingestion of an actual AgentScanner source-observation payload. The complete Console suite was not run; production was not deployed and the PHAR was not rebuilt.
