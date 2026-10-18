# Machine configuration for production checks

Create a regular project-local `.magebean/production-checks.json` with integer `schema_version: 1` and a `checks` object. The [example](production-checks.example.json) is illustrative: replace every PID, approved role ID, vendor configuration path and expected mitigation ID with values applicable to the deployment. Do not copy its sample values into a real assessment.

These are expected policy inputs. They do not assert that a deployment is protected, and they never replace observations from actual processes, files, database tables or runtime responses. The checks execute their real collectors after typed policy validation. Missing or malformed policy returns UNKNOWN rather than PASS or a human-evidence request.

| Check key | Only allowed input | Meaning |
| --- | --- | --- |
| `production_bound_worker_code_readonly` | `worker_pids` | Nonempty list of actual PHP-FPM pool worker PIDs to bind to the scanner identity and namespace. Refresh after pool restart. Run the scanner as the matching unprivileged runtime user; another user/root cannot substitute its write permissions. |
| `production_direct_global_roles_approved` | `approved_role_ids` | Explicit group-role ID allow-list for direct global Admin grants. `[]` explicitly means no direct global group grant is permitted. The scanner checks real database rows. |
| `production_integration_debug_defaults_disabled` | `paths` | Nonempty list of known debug/verbose Magento setting paths for the installed vendor integration versions. The example path is illustrative and not an asserted vendor schema. Values are resolved in default scope; custom/store/runtime behavior remains outside the predicate. |
| `dependency_mitigation_records` | `expected_ids` | Nonempty explicit list of mitigation IDs expected by the dependency record check. This is inventory configuration, not a claim that mitigations work. |

Omit check entries that are not applicable; a check requiring an omitted entry remains UNKNOWN. No passwords, tokens, database connections, observed results, approval attestations or arbitrary check arguments are accepted. Only the four keys and one input listed per key are supported. Unknown keys, duplicate JSON property names/values, malformed types, overlarge inputs, symbolic links and files over 32 KiB are rejected without echoing their contents.

The corresponding capability names are `runtime_worker_access`, `admin_role_policy`, `integration_debug_policy` and `dependency_mitigation_policy`. Dependency source comparison additionally uses `dependency_source_policy` with its separate `.magebean/dependency-source-policy.json` file. Linux Xdebug process-map observation uses `runtime_worker_inventory` with `.magebean/php-fpm-workers.json`, containing schema version 1 and explicit `{pool, pid, start_ticks}` worker identities. These capabilities only select checks; supplying expected policy never substitutes for the checks' actual observations.

Worker PIDs are ephemeral runtime targeting inputs; keep a versioned policy template and generate the applicable current PID list through deployment tooling. The policy file cannot select arbitrary filesystem paths, URLs, commands or PHP code. No production configuration or policy file is created automatically by the scanner.

Registry wrapper API:

```php
$policy = new ProductionCheckPolicy($context);
$policy->run('production_direct_global_roles_approved', $args,
    fn(array $resolved): array => $runtime->directGlobalRolesApproved($resolved));
```

The wrapper preserves static check arguments such as fixed inventory budgets and supplies only the whitelisted expected-policy argument for the selected check.
