# Phase 3: scan planning and shared execution

`ScanPlanner` owns the selection of executable rules. Its two entry points make
existing policies explicit rather than silently making the agent follow CLI defaults:

- `planCli`: resolved target catalog, project configuration, capabilities, control
  normalization, profile or explicit IDs, manual filtering, exclusions, validation.
  Diagnostics preserve ordering. Diagnosed selection failures return null; loader
  and option exceptions propagate to the console's existing error handler.
- `planAgent`: bundled catalog and manifest order; duplicate manifest keys retain
  their original position and last entry; unsupported entries stay separate.
  It does not discover project policies, load profiles or perform remote preflight.

`ScanPlan` is an immutable request/pack/metadata envelope. `ScanService` executes
either policy through `ScanRunner`, returning `ScanReport` and forwarding progress
and an optional registry. An empty plan is rejected unless the agent policy allows
it; that case preserves the legacy unsupported-only payload without runner metadata.

The console still resolves filesystem/URL targets, validates the legacy standard
selector, performs remote fingerprint preflight, and handles presentation, exit codes
and PCI enrichment. Preflight stays before configuration loading, so inconclusive
remote scans never start planning or execution. AgentScanner retains redaction,
result mapping, timestamps, title generation and transport schema.

## Compatibility boundaries and follow-up

This phase does not correct check semantics, agent manual-rule detection, duplicate
manifest behavior, HTTP behavior or report interpretation. The agent's historical
`manual_review` check-name predicate remains explicit in its planning policy.
Legacy formatted diagnostic strings are a temporary compatibility boundary; the
planner imports no Symfony classes. Structured presentation diagnostics and the
remaining target/PCI/report helpers can be separated during the final adapter split.
`rules:list` remains a catalog query with its existing policy, not a scan execution.
Collectors/caching, deadlines and outbox reliability belong to later phases.

Do not regenerate the phase 1 baseline for this refactor. Run `php tests/run.php`.
`ScanPlanningTest` additionally checks selection ordering, partial remote catalogs,
manual counts, exclusion failures, unsupported-only agent plans, manifest duplicates,
registry/progress forwarding and plan immutability.

## Final migration state

Phase 6 follow-up: target resolution and report enrichment now have dedicated services. Planner diagnostics are plain ScanDiagnostic objects, rendered only by ScanConsoleRenderer; the transitional formatted-string callback is superseded. See architecture.md.
