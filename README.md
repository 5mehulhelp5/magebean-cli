# Magebean CLI — Magento 2 Security Audit

Audit Magento 2 security, configuration, performance, and extensions from the command line. Generate actionable **HTML/JSON** reports and integrate with CI.

> **Goal**: “Audit in minutes. Know exactly what to fix and why.”

---

## ✨ Features

- **Security Audit**: file permissions, PHP hardening, admin exposure, SQLi/XSS/SSRF surfaces.
- **Config Audit**: production mode, cache, Elasticsearch/OpenSearch, cron, logging/monitoring.
- **Performance Signals**: cache effectiveness, DB indexes, static assets, storefront anti‑patterns.
- **Extension Audit**: parse `composer.lock` to flag vulnerable/abandoned modules (CVE bundle optional).
- **Offline‑first**: runs locally; privacy by design.
- **CI‑friendly**: non‑zero exit codes on findings; JSON/SARIF outputs for pipelines.

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
# HTML report
./magebean.phar scan \
  --path=/var/www/magento \
  --format=html --output=report.html
```

**Supported formats**: `html` (default) | `json` | `sarif`

---

## 🖥️ CLI Output Template

```
Magebean Security Audit v1.0    Target: /var/www/magento
Time: 2025-08-28 11:32    PHP: 8.2    Env: prod

⚠ CVE check skipped
  → Requires CVE Bundle (--cve-data=magebean-cve-bundle-YYYYMM.zip)
  → Visit https://magebean.com/downloads

Findings (5)
[CRITICAL] Magento core outdated — detected 2.4.3, latest 2.4.7-p1
[HIGH]     Admin route is default (/admin)
[HIGH]     Admin 2FA disabled
[MEDIUM]   Folder permission /pub/media is 777
[MEDIUM]   Full Page Cache disabled/misconfigured

Summary
Passed Rules: 76 / 81
Issues: 1 Critical, 2 High, 2 Medium

→ Report saved to report.html
Contact: support@magebean.com
```

---

## 📄 HTML Report

- **Summary** includes:
  - Completed time, audited path
  - **Rules Checked**: Total, Passed, Failed, **Score %**
  - **Findings Overview** *(counts **failed rules only**)* by severity: **Critical/High/Medium/Low**
- Table lists **both PASS and FAIL**, with colors:
  - ✅ PASS: green background
  - ❌ FAIL: red background

---

## 🔢 Exit Codes

- `0` – no failed findings
- `1` – has `High`/`Medium`/`Low` failed findings
- `2` – has `Critical` failed findings

> Adjust policy in `ScanCommand` if your team prefers a different threshold.

---

## ⚙️ Command Options

| Option | Description | Default |
|---|---|---|
| `--path` | Magento root to audit | current dir |
| `--url` | Optional base URL override for HTTP checks | auto-detect |
| `--format` | `html` \| `json` \| `sarif` | `html` |
| `--output` | Output file path | auto by format |
| `--cve-data` | Path to CVE bundle (optional) | none |
| `--rules` | Run only selected rule IDs | all |
| `--exclude-rules` | Exclude selected rule IDs | none |
| `--config` | Project policy file (`.magebean.json` auto-detected in Magento root) | auto |

### Project-specific policy

Create `.magebean.json` in the Magento root to tune the baseline per project without changing the CLI:

```json
{
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
php bin/magebean scan --path=/path/to/magento --format=html --output=report.html

# run with JSON for CI
php bin/magebean scan --path=/path --format=json > report.json

# inspect available rules
php bin/magebean rules:list
```

- Reporter templates: `resources/report-template.html`
- HTML reporter colors: `.status-pass` (green), `.status-fail` (red)
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
