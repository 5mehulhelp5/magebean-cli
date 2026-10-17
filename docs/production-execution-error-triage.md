# Production execution-error triage

Date: 2026-10-11. Input: user-provided dashboard result excerpt. Production runtime/build/database state was not accessed. This is source comparison and triage, not a deployment or assessment mutation.

## Counts

48 entries:40 labelled Execution error and8 other results. Of the40 errors,32 report REQUIREMENT_BINDING_UNVALIDATED-style text and8 report missing collection inputs. Seventeen of the40 IDs require human evidence in the current workspace catalog; this overlaps the prior categories and must not be added to them.

The32 binding errors divide into16 now-reviewed autonomous definitions and16 currently human-required definitions. The17th human item is0043 log rotation. A successful update/selection correction could eliminate these erroneous gates; no exact remaining runtime-error count is guaranteed without rescanning the actual deployment.

## Strong version/snapshot mismatch indicators

- 0039 still demands var/.indexer_status; current catalog uses deployment_indexers_database_ready against indexer_state.
- 0047/0048 still require private heartbeat/backlog files; current catalog uses database_only:true against cron_schedule.
- 0100,0038,0040,0062/0063 and other autonomous items still report unvalidated bindings, while current definitions are accepted_scoped_criterion.
- Human criteria appear as automatically scanned execution errors. Current primary importer classifies human_evidence.required correctly, but agent job selection uses assessment-item verification_method snapshots. Updating the global catalog does not automatically refresh existing assessment snapshots.

These are strong indicators of an older/mismatched execution artifact, imported catalog, assessment snapshot, or a combination. The actual installed PHAR and production database have not been inspected, so the specific deployment cause is not confirmed.

## Per-group actions

Already-reviewed autonomous binding IDs:
0100,0014,0034,0038,0040,0042,0055,0056,0057,0059,0061,0062,0063,0069,0070,0009.

Verify the exact PHAR path used by the agent/scheduler and its build checksum, not just php magebean.phar --version. Source Application::VERSION remains1.0.0, so matching version text alone does not establish matching code. Compare against the tested artifact and imported requirement revision. Do not remove review gates or manufacture PASS results.

Human IDs to exclude from the proposed autonomous Production membership:
0078,0079,0015,0016,0019,0020,0021,0023,0025,0097,0098,0089,0096,0043,0073,0004,0010.

Retain these identities for custom assessments and standard-profile human scope. Do not infer that absence of source patterns proves their broad criteria. Human criteria already scanned from old automated snapshots require a new/correctly revised assessment, not blind rewriting of audit history.

| Collection ID | Input problem | Action |
|---|---|---|
| 0027 | Runtime URL unavailable | Confirm effective Magento secure/base URL discovery from readable configuration/DB and scanner reachability/TLS trust. Use --url only to override missing/incorrect discovery. |
| 0030 | Cookie probes unavailable | Inspect exact per-path transport/status/TLS cause on session-creating same-host HTTPS pages; do not equate site availability with cookie-policy evidence. |
| 0039 | Private indexer status file missing | Use the updated read-only indexer_state recipe and configured table prefix/SELECT permissions. Do not require invented status files. |
| 0043 | Logrotate artifact unavailable | Exclude this human/contextual policy from automatic Production scope; managed logging/journald can be legitimate. |
| 0046 | Scheduler installation cannot be read | Check deployment-owner crontab access or declared managed/container scheduler. Do not run the entire scanner as root just to bypass one input gap. |
| 0047 | Private heartbeat files missing | Use updated cron_schedule execution evidence and explicit expected schedule/window. |
| 0048 | Private backlog files missing | Use updated due-pending cron_schedule aggregation with contextual thresholds. |
| 0072 | Deployed artifact has no.git | Use0730 working-tree secrets in Production. Keep Git-history0072 explicit/custom against the source checkout. |

## Dashboard classification defect

Current source app/Services/ApplyScanObservationToItem.php maps scan Error to VerificationResult::Fail and marks verification_status Approved; ProcessScanUpload has a parallel error-to-fail projection path. That can make collector/tool failures look like verified security failures. Preserve immutable error observations, but project them as unresolved execution state with an action, not a security FAIL or approved conformance verdict. Preserve genuine previous verified observations with explicit freshness/incomplete-run semantics rather than silently turning a partial run into clean PASS. Any fix needs tests for both upload paths and workflow/history compatibility.

## Other results must remain visible

0001/0002 permission observations,0026 redirect observation,0031 developer-mode observation and0049 advisory matches need scoped verification/remediation; reducing error noise does not justify hiding them. For0050, dataset absence for branch2.4.9 alone must not establish critical unsupported lifecycle: validate authoritative lifecycle evidence/data completeness. This review makes no claim about that branch's actual current support status. Composer wildcard/dev constraint observations0065/0066 need policy classification, not automatic equivalence to an exploitable vulnerability.

## Order of remediation

1. Identify installed agent PHAR path/hash, loaded catalog/revisions and assessment snapshot classification.
2. Deploy tested matching scanner/catalog through the normal release workflow; update/import catalog and inspect stale assessment items. A baseline reset alone does not update an old binary or rewrite existing assessments.
3. Apply the revised autonomous Production membership and contextual predicates; the proposed40-item Production profile is still a specification, not implemented behavior.
4. Create a new/correctly versioned assessment after catalog synchronization. The existing security:catalog:sync-human-items command supports dry-run, but intentionally skips items with results/workflow activity, so it is not a blanket repair for this excerpt.
5. Correct dashboard execution-error projection and expose per-check collection guidance/action.
6. Rescan, then resolve only the remaining real prerequisite failures. Report security, operational/policy and execution counts separately.

No production import, reset, deployment, source-code patch or automatic assessment-history migration was performed as part of this triage.
