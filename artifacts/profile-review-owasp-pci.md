# Customer-side review: OWASP Top 10 2025 and PCI DSS v4.0.1

Scope: current persisted catalog and source inspection, 2026-10-17. No behavior changes, live target probes, or external standards validation. Counts are internal requirements, not standard clauses or unique checks. CSV covers every profile member (69+257 rows).

## Inventory and customer value

- OWASP Top 10 2025: 69 requirements, all have checks; 31 have human_evidence.required=false, 38 require human evidence. All 69 declare LOCAL; 15 also declare REMOTE. The human=false count is a catalog attribute, not evidence of run success or full Top 10 assurance.
- PCI DSS v4.0.1: 257 requirements; all require human evidence. 32 contain supporting automatic checks; 225 have no checks. All declare LOCAL and REMOTE; this does not establish that local file predicates can execute usefully on a URL-only target.
- Default planner excludes entire human requirements: ScanPlanner.php:63-69. PCI therefore becomes empty by this path; OWASP hides 38 requirements with useful technical checks. RequirementPolicy.php:7-12 defines the gate. Membership counts must be shown separately from selected/executed/evidence counts.
- Evaluator intentionally preserves supporting observations but skips them for requirement conclusions (RequirementAssessmentEvaluator.php:31-33). Human gate at lines 51-63 prevents promoting those heuristic checks to PCI PASS/FAIL. This is good integrity protection, but the customer still needs actionable technical findings separate from the human task.

## Findings to challenge first

1. P1: PCI MB-0572 criterion explicitly asks 12-character passwords, with 8 only if unsupported; binding unconditionally sets min_password_length=8 (internal-catalog.json:38948). A check can look positive while checking a weaker condition. Human gate avoids normative PASS, but evidence wording should expose the weaker threshold and unsupported-system exception. Fixture: 8, 11, 12 characters and support-capability exception.
2. P1: MB-0625 log modification protection binds only fs_logs_reports_not_in_webroot (catalog:41603). Absence from pub is not evidence of modification controls, ownership/ACL, centralized immutable storage, or administrator behavior. Label supporting web exposure evidence, and collect actual write permissions/integrity controls.
3. P1: MB-0634 12-month retention/3-month immediate availability binds fs_log_rotation_configured with only devops/logrotate.conf (catalog:42082). A rotation file does not prove retained history or retrieval. Need configured duration plus dated artifacts and restore/query evidence.
4. P1: MB-0660 change detection binds code_dirs_readonly (catalog:43302). Read-only policy and active detection/alerting are different functions. Keep the preventative signal, but do not present it as monitoring evidence.
5. P1: MB-0579/0580/0581 all use magento_admin_2fa_enabled. Magento admin configuration covers only a subset of CDE access and remote access. Customer needs account/system inventory and external IAM/VPN evidence, with one observation reused rather than three implied independent verifications.
6. P1: MB-0538 payment scripts and MB-0661 tamper monitoring share code_payment_script_integrity. PaymentSourceChecks.php:364-426 returns positive for no detected custom files/scripts or presence of allowlist/integrity signals. Neither proves the complete browser-loaded inventory, every script authorization/justification, or running detection. Need browser/runtime inventory, drift, alert delivery, scheduling evidence. Monitoring parser starts at PaymentSourceChecks.php:427; local config signals remain heuristic.
7. P2: PCI MB-0687 and MB-0690 use pci_manual_evidence_documented; FilesystemCheck.php:511 onward uses topic regexes in local markdown. Keywords are useful document discovery, not responsibility allocation completeness, current owners, incident readiness, or exercised response. Show topics found/missing and request dated owners/artifacts, never imply validated policy.
8. P2: source heuristics for OWASP SQL, escaping, auth, SSRF, uploads, webhook signatures remain necessary triage rather than business-behavior assurance. TemplateRequestSourceChecks.php:146 onward recognizes signatures in source, not forged/replayed request rejection. Require positive/negative fixtures, dynamic sinks, bypasses, no applicable files, unreadable files and truncated collection. Missing custom-code signals must remain scoped, never a blanket application PASS.

## Duplicate evidence and review burden

OWASP has exact duplicate check+args occurrences within eight requirements: MB-0105(2 extra), MB-0108(1), MB-0109(1), MB-0131(1), MB-0200(1), MB-0209(1), MB-0379(5), MB-0424(4). PCI MB-0533 has one extra. These can represent separate obligations, but should share a single observation/evidence ID; repeating source patterns does not increase independent assurance. CSV counts duplicates only within requirement obligations, not across requirements or execution variants.

PCI MB-0448 and MB-0449 consolidate policies/roles across many domains (catalog:30365,30676). Their scoped instructions explicitly require separate domain conclusions. Customer workflow must retain domain owners, dated evidence and independent conclusions; one uploaded SECURITY.md should not close all alignments. Avoid assigning a consolidated task with a huge paragraph and no per-domain progress.

## Applicability and profile contract

RequirementCatalog.php:13-22 filters target modes and capability context. Evaluator only understands explicit applicability state/capability; PCI entity restrictions/effective dates are metadata at this layer. A separate PciApplicabilityCompiler.php:7-20 interprets role/overlay/context. Verify the primary profile and Console path actually propagate that separate result before showing readiness denominators. Do not infer integration from the presence of the compiler.

Customer-facing profile contract:
- OWASP: Magento-focused technical signals aligned to Top 10, with explicit custom code/runtime scope and remaining verification work. Prioritize restoring hidden automatic signals, source-check fixtures, and requirement-level overlap clarity.
- PCI: readiness evidence workspace with 32 check-supported requirements and 225 human evidence tasks in the current catalog. Start with payment architecture/entity scope, owners, evidence reuse, expiration and gaps. Do not sell 257 entries as 257 automated security checks.

Acceptance: every selected profile shows inventory, applicable/undetermined scope, runnable checks, executed checks, findings, evidence gaps and omitted reasons. Automatic signals run even if the requirement needs human confirmation. Each check has a documented claim and counterexample fixture; broader requirements retain human boundaries.

Limitations: no runtime plan invocation or fixture execution was performed in this subreview. Default selection behavior is established by source inspection; exact reachable counts depend on mode/capabilities/policy. Standards wording was compared internally to the persisted criterion, not certified against external publications.
