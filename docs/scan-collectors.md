# Phase 4: collectors and per-scan observations

The collector layer separates data acquisition from rule interpretation:

- `FileCollector`: suppressed, complete local file reads used by source checks and
  Composer checks. Stream-wrapper and partial reads retain their original paths.
- `CodeInventoryCollector`: existing recursive enumeration, with unchanged order,
  duplicate roots, extension filters, file-root policies and 1 MiB filtered-file limit.
- `ComposerCollector`: safe JSON loading and the existing lock-package projection,
  including packages-dev overwrite behavior.
- `PhpArrayCollector`: file checks and array-result validation. Evaluation stays in
  the calling check's scope and occurs on every call, because PHP config is executable.
- `HttpCollector`: the existing HttpCheck transport and header parsing, always fresh.
  Method, headers, timeout, redirect option, request body, tuple errors and transport
  observations are retained. No HTTP response cache or transport bug fix is introduced.

`CheckRegistry::fromContext()` shares a `CollectorSet` with participating checks.
The optional dependency preserves one-argument check constructors. Standalone calls
perform fresh reads; no global/static cache is used. `ScanRunner` begins a session
for each `runReport()` and ends it in `finally`, including failed scans. CLI and
agent both reach this lifecycle through their shared execution path. Remote preflight
occurs outside the local caching session and still contributes its transport counts.

## Cache semantics and limits

Successful local reads and inventories retain their first observation within the
scan. Inputs should remain stable during an audit; this is not an atomic filesystem
snapshot. Changes after an observation may be visible only on the next scan. PHP
configuration, HTTP probes and metadata checks retain their existing fresh behavior.
There is no metadata/mtime cache key that could silently persist across runs.

Cache keys preserve paths, working directory, ordered roots, ordered extensions and
enumeration policy. Aliases are not merged; different policies are not conflated.
Failures and loader exceptions are not cached. The default retention budget is
8 MiB of accounted payload across at most 256 entries; PHP array/hash overhead is
additional. Inventory arrays above 50,000 items and observations exceeding the
remaining budget are processed without retention. Limits constrain retained data,
not total process memory or the original enumeration/read operation.

`end()` drops cached content immediately. Statistics contain only counts and sizes;
file content and secrets are not emitted into reports or logs. A subsequent scan
using the same registry starts empty. A zero-budget `CollectionSession` can be
injected for comparison or to disable retention without changing check logic.

## Compatibility and remaining scope

The frozen phase 1 output/payload baseline is unchanged. Collector tests verify
reuse, bounds, retry after missing files, inventory policy, fresh executable PHP,
Composer overwrite semantics, cleanup after exceptions and fresh subsequent scans.
HTTP tests use loopback only and cover cURL and PHP stream fallback, repeated
requests, request headers/method/body, duplicate cookies and transport counts/errors.

Checks retain decisions, messages and evidence. Other acquisition paths (Magento's
separate HTTP policy, CVE/OSV APIs, database/process probes, filesystem metadata and
webserver configuration) remain with their existing implementations; combining
their differing semantics is outside this extraction. Deadlines, retries and agent
outbox reliability belong to phase 5. Splitting remaining large adapters/check
families belongs to phase 6. No rules, dependencies, command options or PHAR changed.
