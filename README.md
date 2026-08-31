# Magebean CLI — Magento 2 Security & Compliance Auditing

Magebean CLI audits Magento 2 installations and public storefronts against versioned security profiles. Run it locally, remotely, or in hybrid mode to turn filesystem, configuration, dependency, and HTTP evidence into actionable findings.

Use the fast production-readiness profile for routine checks, map an assessment to OWASP ASVS, OWASP Top 10, or PCI DSS, or run the complete Magebean baseline. The CLI supports both automated checks and structured human verification, works in CI, and can connect a Magento host to Magebean Security Dashboard for managed assessments.

> **Goal**: “Audit in minutes. Know exactly what to fix and why.”

---

## ✨ Features

- **Target-aware scanning**: audit a Magento filesystem in LOCAL mode, a public storefront in REMOTE mode, or combine both evidence sources in HYBRID mode.
- **Security profiles**: choose `basic`, ASVS Level 1–3, OWASP Top 10 2025, PCI DSS v4.0.1, `hardening`, the full `baseline`, or a custom profile.
- **Automated and human checks**: run 113 automated rules by default in the full baseline and opt into 258 structured `HUMAN VERIFICATION REQUIRED` rules when an assessment needs human evidence.
- **Actionable results**: distinguish PASS, confirmed findings, and INCONCLUSIVE checks; inspect evidence, remediation guidance, and re-run commands for individual rules.
- **PCI DSS workflow**: compile applicability context, import structured external evidence, and generate an evidence-readiness JSON report.
- **Project policy**: customize capabilities, controls, exclusions, rule overrides, project-specific rules, and additional rule packs with `.magebean.json` or YAML.
- **CI-friendly behavior**: use deterministic exit codes based on confirmed finding severity while keeping inconclusive checks separate.
- **Security Dashboard agent**: pair a Magento host, validate prerequisites, install bounded polling, and run managed assessment work with the `agent:*` commands.
- **Local-first data handling**: filesystem checks stay on the host; API-backed checks disclose only endpoint-specific data described in [API data disclosure](docs/api-reference.md#data-disclosure).

---

## 📦 Requirements

- PHP **8.1+**
- For LOCAL or HYBRID scans: a readable Magento **2.4+** installation
- For REMOTE scans: an accessible HTTP/HTTPS Magento storefront; source access is not required
- For Security Dashboard agent commands: PHP cURL extension
- Optional: PHP YAML extension when using `.magebean.yml` or `.yaml` policy files
- Optional for scheduled agent polling: cron and `flock`

---

## 🚀 Install

### Option 1: Use the packaged PHAR
```bash
# Download magebean.phar (example path)
curl -L -o magebean.phar https://magebean.com/files/magebean.phar
chmod +x magebean.phar
```

### Option 2: Local development (composer)
```bash
composer install
php bin/magebean rules:list
```

---

## 🧪 Quick Start

```bash
./magebean.phar scan \
  --path=/var/www/magento
```

The current rule library contains **19 controls and 371 rules**: **113 automated** and **258 marked `HUMAN VERIFICATION REQUIRED`**.

`scan` and `rules:list` use the 21-rule `basic` profile by default. Select `asvs-l1`, `asvs-l2`, `asvs-l3`, `owasp`, `pci`, or `hardening` with `--profile`, or use `--profile=baseline` for the full catalog. The `asvs-l1`, `asvs-l2`, and `asvs-l3` profiles exclude manual-review rules by default; add `--include-manual-review` when human evidence collection is desired. The PCI profile runs 67 rules by default and 68 with human verification enabled; use `--pci-context`, `--pci-evidence`, and `--pci-report` for applicability compilation and evidence-readiness reporting.

See [CLI Reference](docs/cli-reference.md) for all commands, options, profiles, target modes, and examples.

---

## Commands

| Command | Purpose |
|---|---|
| `scan` | Audit a local Magento installation, a public storefront, or both. |
| `rules:list` | List rules after applying profile, control, severity, capability, and manual-review filters. |
| `agent:connect` | Pair this host with Magebean Security Dashboard. |
| `agent:status` | Show local and remote agent status. |
| `agent:doctor` | Validate PHP, Magento, agent storage, credentials, and disk prerequisites. |
| `agent:tick` | Run one bounded Dashboard polling cycle. |
| `agent:cron` | Print or install the current-user polling cron entry. |
| `agent:disconnect` | Disconnect the host and remove its local token. |
| `completion` | Generate shell completion. |
| `list` / `help` | Discover commands and command-specific help. |

Use command help as the authoritative option summary for the installed build:

```bash
php magebean.phar list
php magebean.phar scan --help
php magebean.phar rules:list --help
php magebean.phar agent:connect --help
```

---

## 🖥️ CLI Output Template

```
Magebean CLI v1.0.0 — Security Audit (Baseline v1.0)        Target: /var/www/magento
Profile ID: BASIC
Profile: Magebean Baseline
Time: 2026-07-13 05:39   PHP: 8.4   Env: PRODUCTION

AUDIT COMPLETE · ATTENTION REQUIRED

76 / 81 checks passed · 4 findings · 1 inconclusive
1 Critical | 2 High | 1 Medium | 0 Low

Findings (4)
  [CRITICAL] MB-R091 Executable handlers detected in media/upload paths
  [HIGH] MB-R006 Admin path is default, weak, or missing
  [HIGH] MB-R007 Admin 2FA is disabled
  [MEDIUM] MB-R038 Cache backend is using file-based storage

Inconclusive checks (1)
  [INCONCLUSIVE] [MEDIUM] MB-R039 Indexer status file not found

Next steps
  Inspect a finding with its evidence and remediation:
    php magebean.phar scan --rules=MB-R091

  Resolve an inconclusive check:
    php magebean.phar scan --rules=MB-R039

Contact: support@magebean.com
```

---

## 📄 Command-Line Results

- The summary reports passed checks, confirmed findings, inconclusive checks, and confirmed-finding severity counts separately.
- The default output lists every finding with its existing description, without verbose evidence or package/path lists.
- Use `--rules=MB-R0xx` to inspect one rule with every selected result (including PASS), per-check status and full messages, plus remediation for FAIL or INCONCLUSIVE.
- Inconclusive rule details include contextual `How to resolve` steps and a re-run command.
- Multiple rules can be inspected with a comma-separated filter such as `--rules=MB-R091,MB-R006`.

---

## 🔢 Exit Codes

- `0` – no confirmed findings
- `1` – has confirmed `High`/`Medium`/`Low` findings
- `2` – has confirmed `Critical` findings

Inconclusive checks do not change the exit code because they are not confirmed findings.

> Adjust policy in `ScanCommand` if your team prefers a different threshold.

---

## ⚙️ Scan Options

Target mode is selected from the explicitly provided options:

- `--url` without `--path`: **REMOTE**; confirm Magento 2 first, then run 10 externally observable rules.
- `--path` without `--url`: **LOCAL**.
- `--path` with `--url`: **HYBRID**, combining local and HTTP evidence.
- No target options: auto-detect a Magento root and run **LOCAL**.

| Option | Description | Default |
|---|---|---|
| `--profile` | Built-in profile or custom JSON profile path | `basic` |
| `--standard` | Legacy report selector: `magebean`, `owasp`, `pci`, or `cwe`; prefer `--profile` | `magebean` |
| `--path` | Magento root to audit | auto-detect in LOCAL mode |
| `--url` | Absolute HTTP/HTTPS store base URL | none |
| `--rules` | Run only selected rule IDs | all |
| `--controls` | Restrict the loaded pack to selected control IDs | none |
| `--exclude-rules` | Exclude selected rule IDs | none |
| `--config` | Project policy file (`.magebean.json` auto-detected in Magento root) | auto |
| `--include-manual-review` | Include human-review rules | off |
| `--capabilities` | Enable contextual profile rules, such as `graphql` or `oauth_oidc` | none |
| `--pci-context` | PCI DSS applicability context JSON | none |
| `--pci-evidence` | PCI DSS structured external evidence JSON | none |
| `--pci-report` | Write a PCI evidence-readiness report as JSON | none |

Selection order is: target pack → project policy → (`--rules` or profile) → `--exclude-rules`. An explicit `--rules` list bypasses profile selection and chooses IDs from the available catalog.

### Profiles

| Profile | Rules selected by default |
|---|---:|
| `basic` | 21 |
| `asvs-l1` | 32 (60 with manual review) |
| `asvs-l2` | 73 (183 with manual review) |
| `asvs-l3` | 80 (259 with manual review) |
| `owasp` | 77 |
| `pci` | 67 (68 with manual review) |
| `hardening` | 91 (92 with manual review) |
| `baseline` | 113 automated (371 with manual review) |

`all` and `magebean` are aliases for `baseline`. Custom profile files can be passed to `--profile`, including profiles stored under `.magebean/profiles`.

### List and filter rules

```bash
php magebean.phar rules:list
php magebean.phar rules:list --profile=asvs-l2 --include-manual-review
php magebean.phar rules:list --profile=baseline --control=MB-C03
php magebean.phar rules:list --profile=owasp --severity=critical
```

`rules:list` supports `--profile`, `--include-manual-review`, `--capabilities`, `--control`, and `--severity`. Its filters are intersected.

### Project-specific policy

Create `.magebean.json` in the Magento root to tune the baseline per project without changing the CLI:

```json
{
  "capabilities": {
    "graphql": true,
    "oauth_oidc": false,
    "webrtc": false
  },
  "include_controls": ["MB-C01", "MB-C02", "MB-C03"],
  "exclude_rules": ["MB-R005"],
  "override_rules": {
    "MB-R002": {
      "severity": "critical",
      "checks": [
        {
          "name": "file_mode_max",
          "args": {
            "file": "app/etc/env.php",
            "max_octal": "0600"
          }
        },
        {
          "name": "file_owner_group_matches",
          "args": {
            "file": "app/etc/env.php",
            "owner_reference": ".",
            "group_reference": "."
          }
        }
      ]
    }
  },
  "rules": [
    {
      "id": "PROJECT-R001",
      "title": "No project debug module references",
      "control": "PROJECT",
      "severity": "high",
      "op": "all",
      "checks": [
        {
          "name": "code_grep",
          "args": {
            "paths": ["app/code"],
            "must_not_match": ["DebugToolbar"]
          }
        }
      ],
      "messages": {
        "pass": "No debug module references detected.",
        "fail": "Debug module reference detected in project code."
      }
    }
  ]
}
```

For MB-R101, explicitly document approved global Admin ACL exceptions by overriding its check arguments. Both the role and every active user inheriting that role must be approved:

```json
{
  "override_rules": {
    "MB-R101": {
      "checks": [
        {
          "name": "magento_admin_global_acl_restricted",
          "args": {
            "env_file": "app/etc/env.php",
            "approved_global_role_names": ["Emergency Administrators"],
            "approved_global_usernames": ["breakglass.admin"]
          }
        }
      ]
    }
  }
}
```

You can also attach external JSON rule packs:

```json
{
  "rule_packs": ["security-rules"]
}
```

YAML configs are accepted when the PHP `yaml` extension is installed; JSON is the portable PHAR-safe format.

---

## Security Dashboard Agent

Pair the host using a one-time code from Magebean Security Dashboard, check it, and install the polling schedule:

```bash
php magebean.phar agent:connect \
  --code=MB-N77V-XKNF \
  --magento-path=/var/www/magento

php magebean.phar agent:doctor
php magebean.phar agent:status
php magebean.phar agent:cron --install
```

The agent stores its configuration, private token, state, queue, cache, and logs in `$MAGEBEAN_HOME`, or `~/.magebean` when the variable is unset. The token is stored locally and is never printed.

Run one polling cycle manually with `agent:tick`. To print the recommended cron line without modifying the crontab, run `agent:cron` without `--install`. Cron installation requires interactive confirmation and avoids duplicate agent entries.

```bash
php magebean.phar agent:tick
php magebean.phar agent:cron
php magebean.phar agent:disconnect
```

`agent:status`, `agent:doctor`, `agent:tick`, `agent:cron`, and `agent:disconnect` accept `--config-dir`. For the initial connection, use `MAGEBEAN_HOME` to select a non-default data directory. `agent:connect --dev` targets the local development Dashboard API and disables TLS verification; do not use it in production.

See [Security Dashboard agent](docs/cli-reference.md#security-dashboard-agent) for storage layout, command behavior, and troubleshooting.

---

## 🧩 Development

```bash
# run locally
php bin/magebean scan --path=/path/to/magento

# scan a public store without filesystem access
php bin/magebean scan --url=https://magento-store.com

# inspect available rules
php bin/magebean rules:list

# inspect every registered command
php bin/magebean list
```

- Findings Overview counts **failures only**

---

## 🔐 Security

Responsible disclosure: please email **support@magebean.com**.

---

## 🗺️ Roadmap

- Live CVE updates via Magebean Cloud API
- Additional controls & rule packs
- PDF export
- GitHub Action wrapper

---

## 📬 Contact

- Email: **support@magebean.com**
- Website: **https://magebean.com**

---

## License

MageBean CLI is open-sourced software licensed under the [MIT license](./LICENSE).

- **Core CLI** → MIT licensed, free to use and extend.
- **CVE Data Bundle** → Proprietary, licensed separately.
- **Audit-as-a-Service** → Commercial offering.

This dual model ensures that the community benefits from a free baseline audit tool, while advanced vulnerability data and professional audit services remain sustainable.
