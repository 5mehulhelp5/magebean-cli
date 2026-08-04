# Magebean CLI — Magento 2 Security Audit

Audit Magento 2 security, configuration, performance, and extensions from the command line. Generate actionable command-line results and integrate with CI.

> **Goal**: “Audit in minutes. Know exactly what to fix and why.”

---

## ✨ Features

- **Security Audit**: file permissions, PHP hardening, admin exposure, SQLi/XSS/SSRF surfaces.
- **Config Audit**: production mode, cache, Elasticsearch/OpenSearch, cron, logging/monitoring.
- **Performance Signals**: cache effectiveness, DB indexes, static assets, storefront anti‑patterns.
- **Extension Audit**: parse `composer.lock` to flag vulnerable/abandoned modules (CVE bundle optional).
- **Local-first**: most checks run locally. API-backed checks send endpoint-specific package or Magento version metadata documented in [API data disclosure](docs/api-reference.md#data-disclosure).
- **CI‑friendly**: non‑zero exit codes on findings for pipelines.

---

## 📦 Requirements

- PHP **8.1+**
- Magento **2.4+** codebase to scan
- (Optional) CVE Bundle for vulnerability lookups

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

`scan` and `rules:list` use the 21-rule `basic` profile by default. Select `asvs-l1`, `asvs-l2`, `owasp`, `pci`, or `hardening` with `--profile`, or use `--profile=baseline` for the full catalog. The `asvs-l1` and `asvs-l2` profiles exclude manual-review rules by default; add `--include-manual-review` when human evidence collection is desired.

See [CLI Reference](docs/cli-reference.md) for all commands, options, profiles, target modes, and examples.

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

## ⚙️ Command Options

Target mode is selected from the explicitly provided options:

- `--url` without `--path`: **REMOTE**; confirm Magento 2 first, then run 10 externally observable rules.
- `--path` without `--url`: **LOCAL**.
- `--path` with `--url`: **HYBRID**, combining local and HTTP evidence.
- No target options: auto-detect a Magento root and run **LOCAL**.

| Option | Description | Default |
|---|---|---|
| `--path` | Magento root to audit | auto-detect in LOCAL mode |
| `--url` | Absolute HTTP/HTTPS store base URL | none |
| `--cve-data` | Path to CVE bundle (optional) | none |
| `--rules` | Run only selected rule IDs | all |
| `--exclude-rules` | Exclude selected rule IDs | none |
| `--config` | Project policy file (`.magebean.json` auto-detected in Magento root) | auto |
| `--include-manual-review` | Include human-review rules | off |
| `--capabilities` | Enable contextual profile rules, such as `graphql` or `oauth_oidc` | none |

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

## 🧩 Development

```bash
# run locally
php bin/magebean scan --path=/path/to/magento

# scan a public store without filesystem access
php bin/magebean scan --url=https://magento-store.com

# inspect available rules
php bin/magebean rules:list
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
