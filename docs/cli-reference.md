# Magebean CLI Reference

Magebean CLI audits Magento 2 production readiness using a catalog of 19 controls and 370 rules: 113 automated and 257 requiring human verification.

Current CLI version:

```text
Magebean CLI — Magento 2 Security Audit 1.0.0
```

## Invocation

Run the source checkout:

```bash
php bin/magebean <command> [options]
```

Run the packaged executable:

```bash
php magebean.phar <command> [options]
```

Show the version or command list:

```bash
php magebean.phar --version
php magebean.phar list
```

## Commands

| Command | Purpose |
|---|---|
| `scan` | Audit a Magento installation or storefront. |
| `rules:list` | List rules after applying profile and filters. |
| `completion` | Generate Bash, Fish, or Zsh completion. |
| `help` | Display help for a command. |
| `list` | List available commands. |

## `scan`

### Synopsis

```bash
php magebean.phar scan [--path=PATH] [--url=URL] [options]
```

### Target modes

| Mode | Options | Coverage |
|---|---|---|
| Local | `--path=PATH`, or omit both target options | Reads the Magento filesystem and local configuration. |
| Remote | `--url=URL` | Runs externally observable checks after confirming the target is Magento. |
| Hybrid | `--path=PATH --url=URL` | Combines local and HTTP evidence. |

When neither `--path` nor `--url` is supplied, Magebean searches for a Magento root from the current directory. A local Magento root must contain at least:

- `composer.json`
- `bin/magento`
- `app/etc/config.php` or `app/etc/env.php`

### Profiles

| Profile | Rules | Purpose |
|---|---:|---|
| `basic` | 21 | Default fast, low-noise production security and operations check. |
| `asvs-l1` | 32 default / 60 with manual | Level 1 mapping; manual-review rules require `--include-manual-review`. |
| `asvs-l2` | 73 default / 183 with manual | Cumulative Level 2 mapping; manual and contextual reviews are opt-in. |
| `asvs-l3` | 80 default / 259 with manual | Cumulative Level 3 mapping; substantial independent human assurance is mandatory. |
| `owasp` | 77 | Application-security checks mapped to OWASP Top 10 2025. |
| `pci` | 69 | PCI DSS v4.0.1 payment-readiness checks; not a certification. |
| `hardening` | 89 | Deep production, code, dependency, integration, and operations checks. |
| `baseline` | 113 default / 370 with manual | Full local catalog. Aliases: `all`, `magebean`. |
| `FILE` | Custom | JSON profile path or a profile in `.magebean/profiles`. |

The `asvs-l1` mapping covers all 70 Level 1 requirements: 15 automated, 15 partially automated, 28 manual-review, and 12 currently without a mapped rule. This is an evidence-oriented scan profile, not an ASVS certification.

The cumulative `asvs-l3` mapping covers all 345 ASVS 5.0 requirements: 70 Level 1, 183 Level 2, and 92 Level 3 additions. It selects 80 non-manual rules by default and 259 non-contextual rules with `--include-manual-review`. Level 3 human-assessment results use the `HUMAN VERIFICATION REQUIRED` status and provide the specific assessment scope for each requirement.

The cumulative `asvs-l2` mapping covers 253 requirements. By default it selects 73 automated or partially automated rules. Add `--include-manual-review` to select 183 non-contextual rules. Set capabilities explicitly to activate relevant conditional reviews:

```json
{
  "capabilities": {
    "graphql": true,
    "oauth_oidc": false,
    "webrtc": false
  }
}
```

Manual reviews can be enabled with `--include-manual-review`. The same capabilities can be supplied for one scan with `--capabilities=graphql,oauth_oidc`. Unspecified or false capabilities do not activate contextual rules.

If `--profile` is omitted, Magebean uses `basic`.

The former `standard` profile name is no longer supported:

```bash
php magebean.phar scan --profile=basic
```

### Command options

| Option | Description |
|---|---|
| `--path=PATH` | Magento root. Omit to auto-detect it from the current directory. |
| `--url=URL` | Absolute storefront URL. Selects Remote or Hybrid mode. |
| `--profile=PROFILE\|FILE` | Built-in or custom profile. Default: `basic`. |
| `--include-manual-review` | Include human manual-review rules; excluded by default. |
| `--capabilities=NAME,...` | Enable capability-dependent profile rules for this scan. |
| `--controls=MB-Cxx,...` | Restrict the loaded rule pack to control IDs. |
| `--rules=MB-Rxxx,...` | Run listed rule IDs directly from the available catalog and bypass profile selection. |
| `--exclude-rules=MB-Rxxx,...` | Remove listed rules after profile and project configuration. |
| `--config=FILE` | Project policy file. Local scans auto-detect `.magebean.json` or `.magebean.yml`. |
| `--standard=NAME` | Legacy report selector: `magebean`, `owasp`, `pci`, or `cwe`. Prefer `--profile`. |

An explicit `--profile` takes precedence over the legacy `--standard` selector.

### Global options

| Option | Description |
|---|---|
| `-h`, `--help` | Display command help. |
| `-V`, `--version` | Display the Magebean version. |
| `-q`, `--quiet` | Display errors only. |
| `--silent` | Suppress all output. |
| `--ansi`, `--no-ansi` | Force or disable ANSI formatting. |
| `-n`, `--no-interaction` | Disable interactive questions. |
| `-v`, `-vv`, `-vvv` | Increase verbosity. |

### Selection order

Magebean applies selection in this order:

```text
Target rule pack
→ project policy
→ explicit `--rules` selection or profile selection
→ --exclude-rules
```

When `--rules` is provided, Magebean bypasses profile selection and resolves the requested IDs directly from the available catalog. A separate `--profile` value is ignored for that scan:

With `--rules`, the summary renders every selected rule, including PASS, FAIL, and INCONCLUSIVE. Each rule includes a `Detail` block with the underlying check name, status, and full multiline message. Without `--rules`, the summary remains compact.

```bash
php magebean.phar scan \
  --path=/var/www/magento \
  --rules=MB-R100,MB-R101
```

### Examples

Default Basic scan:

```bash
cd /var/www/magento
php /var/www/magebean-cli/magebean.phar scan
```

Explicit local scan:

```bash
php magebean.phar scan --path=/var/www/magento
```

Remote and Hybrid scans:

```bash
php magebean.phar scan --url=https://store.example.com
php magebean.phar scan \
  --path=/var/www/magento \
  --url=https://store.example.com
```

Select a profile:

```bash
php magebean.phar scan --path=/var/www/magento --profile=basic
php magebean.phar scan --path=/var/www/magento --profile=owasp
php magebean.phar scan --path=/var/www/magento --profile=pci
php magebean.phar scan --path=/var/www/magento --profile=hardening
php magebean.phar scan --path=/var/www/magento --profile=baseline
```

Filter controls or rules:

```bash
php magebean.phar scan \
  --path=/var/www/magento \
  --profile=hardening \
  --controls=MB-C01,MB-C05

php magebean.phar scan \
  --path=/var/www/magento \
  --profile=baseline \
  --rules=MB-R049,MB-R050

php magebean.phar scan \
  --path=/var/www/magento \
  --exclude-rules=MB-R032
```

Use a project policy:

```bash
php magebean.phar scan \
  --path=/var/www/magento \
  --config=.magebean.yml
```

### Exit behavior

- Exit `0`: scan completed without confirmed findings. `UNKNOWN` results are reported as inconclusive.
- Exit `1`: invalid input, target/configuration error, or one or more confirmed findings.

## `rules:list`

### Synopsis

```bash
php magebean.phar rules:list [options]
```

### Options

| Option | Description |
|---|---|
| `--profile=PROFILE\|FILE` | Select a built-in or custom profile. Default: `basic`. |
| `--control=MB-Cxx,...` | Keep only listed controls. |
| `--severity=LEVEL` | Keep `low`, `medium`, `high`, or `critical` rules. |

`--control` and `--severity` are intersected with the selected profile; they do not add rules.

### Examples

```bash
php magebean.phar rules:list
php magebean.phar rules:list --profile=hardening
php magebean.phar rules:list --profile=baseline --control=MB-C03
php magebean.phar rules:list --profile=owasp --severity=critical
php magebean.phar rules:list --profile=.magebean/profiles/acme.json
```

## Custom profiles

A custom profile is a JSON file containing an ID and a list of rule IDs:

```json
{
  "id": "acme",
  "title": "ACME Magento Policy",
  "description": "Rules required by ACME production policy.",
  "rules": [
    "MB-R001",
    "MB-R031",
    "MB-R049",
    "MB-R050"
  ]
}
```

Load it by path:

```bash
php magebean.phar scan \
  --path=/var/www/magento \
  --profile=.magebean/profiles/acme.json
```

Unknown rule IDs fail validation.

## Shell completion

Generate completion for Bash, Fish, or Zsh:

```bash
php magebean.phar completion bash
php magebean.phar completion fish
php magebean.phar completion zsh
```

Example Bash installation:

```bash
php magebean.phar completion bash > completion.sh
source completion.sh
```

## Troubleshooting

Show detailed help:

```bash
php magebean.phar scan --help
php magebean.phar rules:list --help
```

Disable colors for logs and CI:

```bash
php magebean.phar scan \
  --path=/var/www/magento \
  --no-ansi \
  --no-interaction
```

Increase diagnostic output:

```bash
php magebean.phar scan --path=/var/www/magento -vvv
```

If Magento root detection fails, pass the installation root explicitly:

```bash
php magebean.phar scan --path=/var/www/magento
```
