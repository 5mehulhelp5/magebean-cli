# Architecture phase 1 of 6: compatibility baseline

This is the first phase (called Phase 0 in the initial zero-based plan). It establishes the behavior to compare during later refactors; it does not change production code or fix known QA defects.

Baseline source revision: `14416eb91c607a91ecc12cbbd7aea653bcf2c93f`.

## Run

From the repository root, with Composer dependencies already available:

```sh
php tests/CompatibilityBaselineTest.php
php tests/run.php
```

Tests run in isolated PHP processes. The runner discovers `tests/*Test.php`, gives each 45 seconds, drains stdout/stderr together and exits nonzero if any test fails. It does not install dependencies, update snapshots, build the PHAR, or invoke live agent jobs.

The compatibility test requires `proc_open` and the ability to bind a loopback port. Missing prerequisites fail explicitly; they must not silently skip coverage. It creates a synthetic Magento directory and a local PHP HTTP server, then removes the directory and stops the server in `finally`. No real Magento bootstrap, production DB, OSV API or dashboard connection is used.

## Contract coverage

| Boundary | Baseline protection |
|---|---|
| CLI command interface | Eight Magebean command names, aliases, command options/defaults/descriptions, help |
| Rule catalog | 371 IDs, control/severity/verification and definition digests |
| Built-in profiles | Ordered IDs with and without manual rules, including baseline aliases |
| Rule listing | Default, control/severity intersection, manual flag and contextual capabilities |
| LOCAL scan | PASS/FAIL/critical/manual/mixed output; exit codes 0/1/2; exclude rules; root autodetection; custom policy/rule file |
| HYBRID scan | Local target plus loopback URL, bundled HTTP rule MB-R032 |
| REMOTE scan | Fingerprint preflight plus MB-R032, and unconfirmed target output/exit behavior |
| Input rejection | Empty explicit path, unknown rule, PCI options outside PCI profile |
| Engine result | All 32 combinations of two PASS/FAIL/UNKNOWN/MANUAL_REVIEW checks under all/any, summary/details/evidence |
| Offline CVE | Advisory match through public ComposerCheck::auditOffline without external API |
| PCI | Profile/policy selection, hidden/included manual rules, context and external evidence import, console plus complete readiness JSON |
| Agent payload | pass/fail, assessment item mapping, unsupported rules, details/evidence/title and schema/hash |

Command definitions are tested at the application layer; inherited Symfony global options are dependency-owned and are not frozen as Magebean-specific interfaces. This is not a complete simulation of every check on a production deployment. In particular, TLS handshake, curl-versus-stream fallback equivalence, DB queries, live pairing, lease renewal/recovery and updater delivery remain separate integration-test requirements.

## Snapshot policy

`tests/fixtures/compatibility/baseline.json` stores semantic structures and normalized console output. It is deliberately readable rather than a single opaque digest. Catalog rule definitions have separate per-rule digests so a definition change is identified by ID without copying all source into the fixture.

Only generated fixture/repository paths, loopback URL/port, PHP display version, the Environment line's scan time, `checked_at`/`generated_at` timestamps, and volatile progress-bar lines are normalized. Outcomes, rule order, messages, evidence, exit codes, report keys and phase labels remain checked. Terminal dimensions are fixed for reproducible formatting. Structured timestamp shape is validated before masking.

Normal tests NEVER regenerate the baseline. An intentional behavior change can be recorded explicitly:

```sh
php tests/CompatibilityBaselineTest.php --record-baseline
git diff -- tests/fixtures/compatibility/baseline.json
php tests/CompatibilityBaselineTest.php
```

Review the changed cases and explain them with the implementation. Do not use regeneration merely to make a refactor green. Source/runtime refactors should leave the baseline unchanged unless an approved behavior correction is being implemented in a separate change. Catalog hashes are intentionally sensitive to definition changes; JSON whitespace alone does not change them.

## Known defects are not desired contracts

The baseline records current behavior for comparison, including existing flaws. It is not an assertion that all recorded outcomes are correct.

Known issues tracked for separate fixes:

1. MB-R014/MB-R017 routing and missing patterns; multiple-regex-match detectors skip findings.
2. SSRF heuristic accepts URL format validation as destination restriction.
3. Failed admin probes can be classified as PASS; redirect headers lose response provenance.
4. OSV last_affected/limit handling and standalone auditor dataset/upgrade-hint behavior.
5. any(false, unknown) yields FAIL; any unknown/manual retains passed=false. These cases are visible in the engine matrix and must change deliberately when fixed.
6. TLS cipher-expression semantics and logrotate evidence shortcuts.
7. PCI scope/boolean/timestamp validation and SARIF status handling.
8. Scan exception aborts, hidden file skips, target PHP execution, divergent agent planning and incomplete delivery lifecycle.

A defect fix should add a focused expected-behavior regression, then update only the corresponding characterized output with a documented reason. Do not promise preservation of a known false PASS/FAIL as a product requirement.

## Gates for subsequent phases

1. Existing tests and the compatibility test pass; any pre-existing failure is separately documented and not hidden.
2. Production interface/output changes are either absent or individually explained with intentional regression coverage.
3. No live API calls or target side effects are introduced into these fixtures.
4. Review file changes: this first phase is limited to tests and documentation. No source/rule/PHAR update is necessary.
5. Later phases still require targeted tests for new result/context adapters, shared planning, collectors and failure recovery. The snapshot complements those tests, not replaces them.
