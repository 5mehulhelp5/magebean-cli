# Magebean Security Baseline v1.0 - Current Rule Catalog

**Author:** Son Cao
**Original date:** 2025-08-20
**Catalog revision:** 2026-08-03
**Baseline version:** 1.0
**Catalog size:** 19 controls, 370 rules

---

## Introduction

The **Magebean Security Baseline v1** is the canonical security rule catalog used by Magebean CLI for Magento 2 assessment. The current catalog contains **19 controls and 370 rules**:

- **113 `AUTOMATED` rules** execute technical checks and produce machine-generated evidence.
- **257 `HUMAN VERIFICATION REQUIRED` rules** identify requirements that Magebean CLI cannot conclusively attest without independent human assessment and supporting evidence.

Profiles select subsets of this catalog for a particular assessment objective. A profile result is evidence for review; it is not, by itself, an OWASP ASVS or PCI DSS certification.

---

## Chapter 1. Key Terminology

### 1.1 Control

A **Control** is a high-level security category that groups related rules, such as file permissions, authentication hardening, secure coding, transport security, dependency governance, or human assurance.

### 1.2 Rule

A **Rule** is the canonical unit of assessment identified by an `MB-Rxxx` ID. Every rule has a severity, a verification type, and a concrete assessment criterion.

### 1.3 Verification tags

- **`AUTOMATED`** - Magebean CLI executes one or more checks. A result is limited to the target, evidence sources, and check coverage available during that scan.
- **`HUMAN VERIFICATION REQUIRED`** - independent human assessment is mandatory. The description states exactly what must be verified. Magebean CLI does not determine, certify, or attest that the requirement is satisfied.
- Human-verification rules are excluded by default and are included with `--include-manual-review`.
- Capability-dependent rules are selected only when their capability is explicitly enabled.

### 1.4 Baseline

The **Baseline** is the complete current catalog of **19 controls and 370 rules**. The `baseline` profile selects all **113 automated rules** by default and all **370 rules** when `--include-manual-review` is supplied, subject to target applicability and capability filters.

### 1.5 Profile

A **Profile** is a curated selection and standards mapping over canonical rules. Profiles select the evidence appropriate to a specific assessment objective without duplicating rule definitions.

### 1.6 Scan and audit

A **scan** executes selected automated checks and emits required human-verification items. An **audit** combines those results with reviewed evidence and accountable human conclusions.

---

## Chapter 2. Scope & Objectives

### 2.1 Scope

The baseline covers Magento application code, configuration, dependencies, deployment state, public endpoints, integrations, logging, payment-related exposure, and security requirements that require design, process, or runtime evidence.

### 2.2 Intended audience

The baseline is intended for developers, agencies, merchants, security reviewers, auditors, and CI/CD owners responsible for Magento 2 security assurance.

### 2.3 Objectives

- Provide a repeatable Magento 2 security assessment framework.
- Keep automated evidence separate from mandatory human verification.
- Map canonical Magebean rules to OWASP ASVS, OWASP Top 10, PCI DSS readiness, and related security objectives.
- Produce actionable findings and explicit assessment scopes without claiming certification.

---

## Chapter 3. Controls & Rules Catalog

### Catalog summary

| Control | Title | Total | Automated | Human required |
|---|---|---:|---:|---:|
| MB-C01 | File & Folder Permissions | 7 | 7 | 0 |
| MB-C02 | Admin & Auth Hardening | 8 | 8 | 0 |
| MB-C03 | Secure Coding Practices | 20 | 20 | 0 |
| MB-C04 | HTTPS & TLS Enforcement | 7 | 7 | 0 |
| MB-C05 | Production Mode & Deployment Hygiene | 6 | 6 | 0 |
| MB-C06 | Cache & Indexing Health | 5 | 5 | 0 |
| MB-C07 | Logging & Monitoring | 7 | 7 | 0 |
| MB-C08 | Cron Job Reliability | 3 | 3 | 0 |
| MB-C09 | Extension Vulnerability Management | 12 | 12 | 0 |
| MB-C10 | Abandoned Extensions Removal | 4 | 4 | 0 |
| MB-C11 | Composer Dependency Hygiene | 7 | 7 | 0 |
| MB-C12 | Third-party Config Security | 15 | 15 | 0 |
| MB-C13 | Application Behavior & Human Assurance | 28 | 0 | 28 |
| MB-C14 | ASVS Web, Transport & Cryptography Verification | 6 | 6 | 0 |
| MB-C15 | ASVS Level 2 Human Assurance | 82 | 0 | 82 |
| MB-C16 | ASVS Level 2 Contextual Human Assurance | 55 | 0 | 55 |
| MB-C17 | ASVS Level 2 Automated Verification | 3 | 3 | 0 |
| MB-C18 | ASVS Level 3 Human Assurance | 92 | 0 | 92 |
| MB-C19 | ASVS Level 3 Automated Verification | 3 | 3 | 0 |

## Complete Rule Catalog (370 Rules)

### MB-C01 - File & Folder Permissions (7 rules)

#### MB-R001 - No world-writable files or directories

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No world-writable files or directories detected.

#### MB-R002 - env.php restricted to owner/group access

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** app/etc/env.php is restricted to owner/group access and is not accessible by others.

#### MB-R003 - Webroot hygiene (no .git/.env/backups in pub/)

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Webroot is clean: no sensitive or backup artifacts exposed under pub/.

#### MB-R004 - Code directories are read-only

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Code directories (app, vendor, lib) are read-only.

#### MB-R005 - Directory listing disabled

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Directory listing is disabled for public paths.

#### MB-R083 - No cardholder data in files, exports, or backups

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** No cardholder data patterns detected in common file, export, or backup paths.

#### MB-R091 - No executable code in media or upload paths

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** No executable code or script-enabling handlers detected in media or upload paths.

### MB-C02 - Admin & Auth Hardening (8 rules)

#### MB-R006 - Non-default admin path (not /admin)

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Admin path is non-default and not trivially guessable.

#### MB-R007 - Admin 2FA module enabled

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** Two-Factor Authentication core and at least one provider module are enabled for admin.

#### MB-R008 - Admin passwords require at least 8 characters

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Admin password policy requires at least 8 characters.

#### MB-R009 - Admin session timeout <= 900s

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Admin session lifetime is at or below 900 seconds.

#### MB-R010 - Admin URL exposure restricted

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Admin URL is either non-default or network-restricted (deny/allow rules present).

#### MB-R011 - Login rate-limiting / CAPTCHA enabled

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** CAPTCHA, reCAPTCHA, or login lockout protection is enabled for admin authentication.

#### MB-R100 - Admin role assignments are valid

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Active Magento Admin users have valid role and ACL assignments.

#### MB-R101 - Global Admin ACL limited to approved roles

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Global Magento Admin ACL access is limited to approved roles and users.

### MB-C03 - Secure Coding Practices (20 rules)

#### MB-R012 - No raw SQL without abstraction

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No unsafe raw SQL statements detected; database queries use abstraction layers.

#### MB-R013 - Template output is escaped

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Template output uses proper escaping functions.

#### MB-R014 - Avoid PHP superglobals directly

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No direct access to PHP superglobals detected.

#### MB-R015 - Forms include CSRF tokens (form_key)

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Forms include CSRF protection via form\_key.

#### MB-R016 - SSRF protections present

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Outbound HTTP requests include SSRF protections (allowlists and timeouts).

#### MB-R017 - No unsafe deserialization

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No unsafe unserialize() usage detected; safe serialization methods in use.

#### MB-R018 - Command execution is guarded

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** Command execution sinks are absent or guarded by escaping/allow-lists.

#### MB-R019 - No eval/assert/dynamic execution

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** No unsafe dynamic execution patterns detected.

#### MB-R020 - Path traversal protections

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** File path sinks are absent or guarded against traversal.

#### MB-R021 - Secure file upload handling

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Upload flows are absent or include validation and storage safeguards.

#### MB-R022 - Escaping for JS context

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** JavaScript-context PHP output is escaped or encoded.

#### MB-R023 - Use CSPRNG; avoid weak PRNG

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No weak PRNG detected in security-sensitive randomness.

#### MB-R024 - Sensitive data not logged

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No raw sensitive data logging detected.

#### MB-R025 - No unsafe raw crypto or session APIs in custom code

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** No unsafe raw crypto or session API usage was detected in the scanned custom code.

#### MB-R086 - No raw card collection in Magento checkout

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** No raw card collection patterns detected in custom checkout code.

#### MB-R094 - Custom controllers and APIs include function-level authorization

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No missing function-level authorization evidence was detected in sensitive custom controllers or APIs. Object-level authorization requires separate verification.

#### MB-R095 - GraphQL and API exposure minimized

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** No high-risk anonymous REST API or unauthenticated GraphQL resolver exposure detected.

#### MB-R097 - Secrets are not hardcoded in custom code

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No hardcoded secrets detected in custom code paths.

#### MB-R098 - Unsafe XML parsing disabled

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No unsafe XML entity expansion patterns detected.

#### MB-R099 - File download and export endpoints require authorization

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No unprotected download or export endpoint patterns detected.

### MB-C04 - HTTPS & TLS Enforcement (7 rules)

#### MB-R026 - Force HTTPS in admin and storefront

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** HTTPS is enforced for both admin and storefront areas.

#### MB-R027 - HSTS max-age is at least one year

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** HSTS is configured with max-age of at least 31536000 seconds.

#### MB-R028 - TLS protocols >= 1.2

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** TLS is configured to use version 1.2 or higher.

#### MB-R029 - No mixed content (http://) in templates/assets

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** No insecure http:// references detected in templates or assets.

#### MB-R030 - Sensitive cookies use Secure, HttpOnly, and SameSite

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Observed sensitive cookies and Magento cookie configuration use Secure, HttpOnly, and an allowed SameSite policy.

#### MB-R089 - Checkout Content Security Policy enforced

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Checkout CSP includes payment-page script, connection, frame, form-action, object, base-URI, and reporting controls.

#### MB-R096 - Security headers baseline enforced

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Baseline browser security headers are configured in application or web server config.

### MB-C05 - Production Mode & Deployment Hygiene (6 rules)

#### MB-R031 - Magento runs in PRODUCTION mode

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Magento is running in PRODUCTION mode.

#### MB-R032 - Xdebug disabled in production

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Xdebug is not enabled in the production PHP configuration.

#### MB-R033 - display_errors is Off

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** PHP display\_errors is Off. No error traces visible.

#### MB-R034 - Compiled DI generated (metadata & code)

- **Verification:** `AUTOMATED`
- **Severity:** `LOW`
- **Description:** Generated DI metadata and code are present.

#### MB-R035 - Static content deployed

- **Verification:** `AUTOMATED`
- **Severity:** `LOW`
- **Description:** Static view files are deployed (pub/static and var/view\_preprocessed exist).

#### MB-R036 - No dev debug configs on production (template hints off)

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Developer template hints are disabled in production.

### MB-C06 - Cache & Indexing Health (5 rules)

#### MB-R037 - Full Page Cache (FPC) enabled

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Full Page Cache (FPC) is enabled and configured.

#### MB-R038 - Cache backend is Redis/Varnish (not file)

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Cache backend is configured to use Redis or Varnish.

#### MB-R039 - Indexers are READY (no backlog)

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** All indexers are in READY state with no backlog.

#### MB-R040 - Session storage hardened (Redis with auth)

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Sessions are stored in Redis with authentication configured.

#### MB-R041 - No dev cache backends (avoid file backend)

- **Verification:** `AUTOMATED`
- **Severity:** `LOW`
- **Description:** No file-based cache backend detected.

### MB-C07 - Logging & Monitoring (7 rules)

#### MB-R042 - Logs and reports not exposed under pub/

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Log and report directories are not exposed under pub/.

#### MB-R043 - Log rotation configured

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Log rotation is configured (rotate and compress directives present).

#### MB-R044 - Debug template hints disabled in production

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Debug template hints are disabled in production.

#### MB-R045 - PII not logged in application logs

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No PII such as passwords, tokens, or card data is logged.

#### MB-R084 - No cardholder data in application logs

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** No cardholder data patterns detected in application logs.

#### MB-R090 - Payment page tamper monitoring readiness

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Payment page tamper monitoring includes payment-page scope, alerting, and CSP reporting or scheduled integrity detection.

#### MB-R093 - PCI manual evidence checklist present

- **Verification:** `AUTOMATED`
- **Severity:** `LOW`
- **Description:** PCI evidence documentation covers payment scope, SAQ notes, access review, incident response, and vendor responsibilities.

### MB-C08 - Cron Job Reliability (3 rules)

#### MB-R046 - Crontab entries present (Magento cron)

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Found Magento cron run command in crontab or deployment scheduler configuration.

#### MB-R047 - Cron heartbeat is recent (<= 900s)

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Cron heartbeat is recent (<= 15 minutes).

#### MB-R048 - Cron backlog below threshold

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Cron queue size is within acceptable limits.

### MB-C09 - Extension Vulnerability Management (12 rules)

#### MB-R049 - No vulnerable packages (CVE via OSV)

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** No vulnerable packages detected by the Magebean OSV API.

#### MB-R050 - Adobe security patches applied

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** Checks the installed Adobe Commerce or Magento version and patch evidence against the Magebean Adobe security-patch service to identify missing applicable security patches.

#### MB-R051 - Suggest fixed versions for vulnerable packages

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** No vulnerable packages require a fixed-version recommendation.

#### MB-R052 - Enabled high-risk modules are maintained

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Enabled high-risk modules are current, or detected high-risk modules are disabled.

#### MB-R053 - Temporary mitigations documented

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Temporary mitigations and their rollback/remediation lifecycle are documented.

#### MB-R054 - Known-exploited packages prioritized (CISA KEV)

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** No installed package versions match the CISA Known Exploited Vulnerabilities catalog.

#### MB-R055 - Transitive dependencies checked for CVEs

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** Transitive dependencies are free from known vulnerabilities.

#### MB-R056 - No constraints blocking security updates

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Composer constraints allow all required security update ranges.

#### MB-R057 - No yanked/withdrawn packages

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No yanked or withdrawn package versions are installed.

#### MB-R058 - Marketplace extensions are current and maintained

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Marketplace and third-party Magento extensions are current and actively maintained.

#### MB-R059 - Unresolved advisories are within remediation SLA

- **Verification:** `AUTOMATED`
- **Severity:** `LOW`
- **Description:** Installed packages have no overdue unresolved advisories.

#### MB-R060 - Marketplace extensions have vendor support evidence

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Installed Marketplace extensions have active vendor support evidence.

### MB-C10 - Abandoned Extensions Removal (4 rules)

#### MB-R061 - No packages marked 'abandoned' on Packagist

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No installed packages are marked as abandoned in the Packagist snapshot.

#### MB-R062 - No packages without release in > 24 months

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Packagist-tracked packages have had a release within the last 24 months.

#### MB-R063 - No packages from archived or disabled repositories

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** No installed packages come from archived or disabled repositories.

#### MB-R064 - No risky forks replacing upstream libs

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** No risky forks detected replacing upstream libraries.

### MB-C11 - Composer Dependency Hygiene (7 rules)

#### MB-R065 - No wildcard constraints in composer.json

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No wildcard constraints found in composer.json.

#### MB-R066 - No dev branches in composer.json

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No development branch or dev-stability constraints are used.

#### MB-R067 - prefer-stable=true in composer.json

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** composer.json sets top-level prefer-stable=true.

#### MB-R068 - Composer audit clean (no known vulns)

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** No known vulnerabilities found in composer.lock by the Magebean OSV API.

#### MB-R069 - Direct dependencies up-to-date

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** All assessable direct dependencies use the latest stable release.

#### MB-R070 - composer.lock integrity with composer.json

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** composer.lock content-hash and direct dependency graph match composer.json.

#### MB-R071 - No abandoned libraries allowed

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** No installed PHP libraries are marked as abandoned on Packagist.

### MB-C12 - Third-party Config Security (15 rules)

#### MB-R072 - No secrets in VCS (working tree or git history)

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** No secrets detected in the working tree or Git history.

#### MB-R073 - HTTPS-only endpoints configured

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** All detected configured endpoints use HTTPS.

#### MB-R074 - Debug/verbose off for third-party integrations

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Third-party debug/verbose logging is disabled.

#### MB-R075 - Webhook signature validation present

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Webhook handlers validate provider signatures, or no webhook endpoints are present.

#### MB-R076 - Outbound connections restricted by allow-list

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Outbound connections are enforced by network policy or each app-level outbound sink has allowlist and timeout controls.

#### MB-R077 - PII minimization for third-party flows

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Third-party flows avoid raw sensitive PII or use tokenized/minimized payloads.

#### MB-R078 - Strong TLS ciphers on upstream gateways

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Web server enforces strong TLS protocols and cipher suites.

#### MB-R079 - API keys stored in env.php (not in DB/plain code)

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** API credentials are not embedded in code or written to database config paths.

#### MB-R080 - Third-party logging sanitized (mask/redact)

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Description:** Third-party logs apply masking/redaction for sensitive fields.

#### MB-R081 - SaaS integrations scoped by ACL (least privilege/IP allowlist)

- **Verification:** `AUTOMATED`
- **Severity:** `LOW`
- **Description:** SaaS integration entry points use least-privilege ACL resources or IP allowlists.

#### MB-R082 - No PAN, CVV, or track data stored in database

- **Verification:** `AUTOMATED`
- **Severity:** `CRITICAL`
- **Description:** No database schema or code patterns indicating stored raw cardholder data were detected.

#### MB-R085 - Payment method scope detection

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** No obvious direct raw-card payment scope patterns detected.

#### MB-R087 - Payment page script inventory maintained

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Payment page script inventory is present, or no custom payment-page script sources were detected.

#### MB-R088 - Payment page script allowlist and integrity controls

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Payment page script allowlist or integrity controls are present, or no custom payment-page scripts were detected.

#### MB-R092 - Payment webhook endpoint authentication hardening

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Description:** Payment webhook endpoints include signature validation, timestamp/replay protection, and idempotency evidence.

### MB-C13 - Application Behavior & Human Assurance (28 rules)

Human verification rules for ASVS requirements that cannot be concluded reliably from unattended CLI evidence.

#### MB-R102 - ASVS 2.1.1 Input validation rules are documented

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 2.1.1 (L1)
- **Description:** The application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format.

#### MB-R103 - ASVS 2.3.1 Business workflows enforce the required sequence

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 2.3.1 (L1)
- **Description:** The application will only process business logic flows for the same user in the expected sequential step order and without skipping steps.

#### MB-R104 - ASVS 6.1.1 Anti-automation policy is documented

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.1.1 (L1)
- **Description:** Application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout.

#### MB-R105 - ASVS 6.2.2 Users can change their password

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.2.2 (L1)
- **Description:** Users can change their password.

#### MB-R106 - ASVS 6.2.3 Password changes require the current password

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.2.3 (L1)
- **Description:** Password change functionality requires the user's current and new password.

#### MB-R107 - ASVS 6.2.5 Password policy does not impose composition rules

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.2.5 (L1)
- **Description:** Passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters.

#### MB-R108 - ASVS 6.2.6 Password entry is masked

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.2.6 (L1)
- **Description:** Password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password.

#### MB-R109 - ASVS 6.2.7 Password managers and paste are allowed

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.2.7 (L1)
- **Description:** "paste"functionality, browser password helpers, and external password managers are permitted.

#### MB-R110 - ASVS 6.2.8 Password verification preserves the exact input

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.2.8 (L1)
- **Description:** The application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation.

#### MB-R111 - ASVS 6.4.1 Initial credentials are random, short-lived, and replaced

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.4.1 (L1)
- **Description:** System generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password.

#### MB-R112 - ASVS 6.4.2 Password hints and secret questions are not used

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.4.2 (L1)
- **Description:** Password hints or knowledge-based authentication (so-called "secret questions") are not present.

#### MB-R113 - ASVS 7.2.1 Sessions are validated by a trusted backend

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.2.1 (L1)
- **Description:** The application performs all session token verification using a trusted, backend service.

#### MB-R114 - ASVS 7.2.2 Session tokens are dynamically generated

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.2.2 (L1)
- **Description:** The application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys.

#### MB-R115 - ASVS 7.2.3 Reference session tokens have at least 128 bits of entropy

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.2.3 (L1)
- **Description:** If reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy.

#### MB-R116 - ASVS 7.2.4 Session tokens rotate after authentication

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.2.4 (L1)
- **Description:** The application generates a new session token on user authentication, including re-authentication, and terminates the current session token.

#### MB-R117 - ASVS 7.4.1 Logout and expiry terminate sessions

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.4.1 (L1)
- **Description:** When session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key.

#### MB-R118 - ASVS 7.4.2 Disabled accounts lose all active sessions

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.4.2 (L1)
- **Description:** The application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company).

#### MB-R119 - ASVS 8.1.1 Authorization rules are documented

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 8.1.1 (L1)
- **Description:** Authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes.

#### MB-R120 - ASVS 8.2.2 Object-level authorization prevents IDOR and BOLA

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 8.2.2 (L1)
- **Description:** The application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA).

#### MB-R121 - ASVS 8.3.1 Authorization is enforced by a trusted service layer

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 8.3.1 (L1)
- **Description:** The application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript.

#### MB-R122 - ASVS 10.4.1 OAuth redirect URIs are exactly matched

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.1 (L1)
- **Description:** The authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison.

#### MB-R123 - ASVS 10.4.2 OAuth authorization codes are single-use

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.2 (L1)
- **Description:** If the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code.

#### MB-R124 - ASVS 10.4.3 OAuth authorization codes expire within ten minutes

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.3 (L1)
- **Description:** The authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications.

#### MB-R125 - ASVS 10.4.4 OAuth grants are restricted per client

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.4 (L1)
- **Description:** For a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token'(Implicit flow) and 'password'(Resource Owner Password Credentials flow) must no longer be used.

#### MB-R126 - ASVS 10.4.5 Public clients have refresh-token replay protection

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.5 (L1)
- **Description:** The authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided.

#### MB-R127 - ASVS 14.3.1 Authenticated client-side data is cleared on session end

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 14.3.1 (L1)
- **Description:** Authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated.

#### MB-R128 - ASVS 15.1.1 Dependency remediation deadlines are documented

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.1.1 (L1)
- **Description:** Application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components.

#### MB-R129 - ASVS 15.3.1 Responses return only required fields

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.3.1 (L1)
- **Description:** The application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users.

### MB-C14 - ASVS Web, Transport & Cryptography Verification (6 rules)

Automated verification rules added for OWASP ASVS 5.0 coverage gaps.

#### MB-R130 - CORS origins and preflight behavior are safe

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.4.2 (L1); OWASP-ASVS 5.0.0 section 3.5.2 (L1)
- **Description:** CORS does not combine wildcard origins with credentials and preflight behavior is constrained.

#### MB-R131 - WebSocket endpoints use WSS

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 4.4.1 (L1)
- **Description:** No insecure non-local WebSocket endpoint was detected.

#### MB-R132 - Known insecure cryptographic modes and padding are not used

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.3.1 (L1); OWASP-ASVS 5.0.0 section 11.3.2 (L1); OWASP-ASVS 5.0.0 section 11.4.1 (L1)
- **Description:** No explicitly insecure ECB, PKCS#1 v1.5 encryption, or legacy mcrypt pattern was detected.

#### MB-R133 - Sensitive values are not embedded in URL query strings

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 14.2.1 (L1)
- **Description:** No sensitive credential or session value was detected in literal URL query strings.

#### MB-R134 - Production does not expose source-control metadata

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.4.1 (L1)
- **Description:** No public source-control metadata or sensitive deployment artifact was detected.

#### MB-R135 - Public TLS certificate is valid and not expired

- **Verification:** `AUTOMATED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 12.2.2 (L1)
- **Description:** The public TLS certificate is trusted by the scan environment and remains valid.

### MB-C15 - ASVS Level 2 Human Assurance (82 rules)

Human verification rules for OWASP ASVS 5.0 Level 2 requirements that cannot yet be concluded reliably from unattended Magebean evidence.

#### MB-R136 - ASVS 1.1.1 Canonical decoding

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.1.1 (L2)
- **Description:** Input is decoded or unescaped into a canonical form only once, it is only decoded when encoded data in that form is expected, and that this is done before processing the input further, for example it is not performed after input validation or sanitization.

#### MB-R137 - ASVS 1.1.2 Late output encoding

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.1.2 (L2)
- **Description:** The application performs output encoding and escaping either as a final step before being used by the interpreter for which it is intended or by the interpreter itself.

#### MB-R138 - ASVS 1.2.9 Regular-expression injection

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.2.9 (L2)
- **Description:** The application escapes special characters in regular expressions (typically using a backslash) to prevent them from being misinterpreted as metacharacters.

#### MB-R139 - ASVS 1.3.3 Dangerous-context sanitization

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.3.3 (L2)
- **Description:** Data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long.

#### MB-R140 - ASVS 1.3.7 Template injection

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.3.7 (L2)
- **Description:** The application protects against template injection attacks by not allowing templates to be built based on untrusted input. Where there is no alternative, any untrusted input being included dynamically during template creation must be sanitized or strictly validated.

#### MB-R141 - ASVS 1.3.10 Format-string injection

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.3.10 (L2)
- **Description:** Format strings which might resolve in an unexpected or malicious way when used are sanitized before being processed.

#### MB-R142 - ASVS 1.3.11 Mail injection

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.3.11 (L2)
- **Description:** The application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection.

#### MB-R143 - ASVS 2.1.2 Contextual data consistency

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 2.1.2 (L2)
- **Description:** The application's documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match.

#### MB-R144 - ASVS 2.1.3 Business limits documentation

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 2.1.3 (L2)
- **Description:** Expectations for business logic limits and validations are documented, including both per-user and globally across the application.

#### MB-R145 - ASVS 2.2.3 Related-data validation

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 2.2.3 (L2)
- **Description:** The application ensures that combinations of related data items are reasonable according to the pre-defined rules.

#### MB-R146 - ASVS 2.3.2 Enforce business limits

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 2.3.2 (L2)
- **Description:** Business logic limits are implemented per the application's documentation to avoid business logic flaws being exploited.

#### MB-R147 - ASVS 2.3.3 Transactional integrity

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 2.3.3 (L2)
- **Description:** Transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state.

#### MB-R148 - ASVS 2.3.4 Business locking

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 2.3.4 (L2)
- **Description:** Business logic level locking mechanisms are used to ensure that limited quantity resources (such as theater seats or delivery slots) cannot be double-booked by manipulating the application's logic.

#### MB-R149 - ASVS 3.3.3 Host-bound cookies

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.3.3 (L2)
- **Description:** Cookies have the '\_\_Host-'prefix for the cookie name unless they are explicitly designed to be shared with other hosts.

#### MB-R150 - ASVS 3.4.5 Referrer policy

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.4.5 (L2)
- **Description:** The application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the 'Referer'HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname.

#### MB-R151 - ASVS 3.5.4 Separate application origins

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.5.4 (L2)
- **Description:** Separate applications are hosted on different hostnames to leverage the restrictions provided by same-origin policy, including how documents or scripts loaded by one origin can interact with resources from another origin and hostname-based restrictions on cookies.

#### MB-R152 - ASVS 3.5.5 postMessage validation

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.5.5 (L2)
- **Description:** Messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid.

#### MB-R153 - ASVS 3.7.2 External redirect allowlist

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.7.2 (L2)
- **Description:** The application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist.

#### MB-R154 - ASVS 4.1.3 Trusted intermediary headers

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 4.1.3 (L2)
- **Description:** Any HTTP header field used by the application and set by an intermediary layer, such as a load balancer, a web proxy, or a backend-for-frontend service, cannot be overridden by the end-user. Example headers might include X-Real-IP, X-Forwarded-\*, or X-User-ID.

#### MB-R155 - ASVS 4.2.1 HTTP request-smuggling defense

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 4.2.1 (L2)
- **Description:** All application components (including load balancers, firewalls, and application servers) determine boundaries of incoming HTTP messages using the appropriate mechanism for the HTTP version to prevent HTTP request smuggling. In HTTP/1.x, if a Transfer-Encoding header field is present, the Content-Length header must be ignored per RFC 2616. When using HTTP/2 or HTTP/3, if a Content-Length header field is present, the receiver must ensure that it is consistent with the length of the DATA frames.

#### MB-R156 - ASVS 6.1.2 Context-specific password denylist

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.1.2 (L2)
- **Description:** A list of context-specific words is documented in order to prevent their use in passwords. The list could include permutations of organization names, product names, system identifiers, project codenames, department or role names, and similar.

#### MB-R157 - ASVS 6.1.3 Authentication-path inventory

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.1.3 (L2)
- **Description:** If the application includes multiple authentication pathways, these are all documented together with the security controls and authentication strength which must be consistently enforced across them.

#### MB-R158 - ASVS 6.2.9 Long passwords

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.2.9 (L2)
- **Description:** Passwords of at least 64 characters are permitted.

#### MB-R159 - ASVS 6.2.10 No forced periodic rotation

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.2.10 (L2)
- **Description:** A user's password stays valid until it is discovered to be compromised or the user rotates it. The application must not require periodic credential rotation.

#### MB-R160 - ASVS 6.2.11 Context-specific word checks

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.2.11 (L2)
- **Description:** The documented list of context specific words is used to prevent easy to guess passwords being created.

#### MB-R161 - ASVS 6.2.12 Breached-password checks

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.2.12 (L2)
- **Description:** Passwords submitted during account registration or password changes are checked against a set of breached passwords.

#### MB-R162 - ASVS 6.3.4 Consistent authentication pathways

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.3.4 (L2)
- **Description:** If the application includes multiple authentication pathways, there are no undocumented pathways and that security controls and authentication strength are enforced consistently.

#### MB-R163 - ASVS 6.4.3 Secure password reset

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.4.3 (L2)
- **Description:** A secure process for resetting a forgotten password is implemented, that does not bypass any enabled multi-factor authentication mechanisms.

#### MB-R164 - ASVS 6.4.4 MFA-factor recovery

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.4.4 (L2)
- **Description:** If a multi-factor authentication factor is lost, evidence of identity proofing is performed at the same level as during enrollment.

#### MB-R165 - ASVS 6.5.1 One-time use

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.5.1 (L2)
- **Description:** Lookup secrets, out-of-band authentication requests or codes, and time-based one-time passwords (TOTPs) are only successfully usable once.

#### MB-R166 - ASVS 6.5.2 Stored lookup secrets

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.5.2 (L2)
- **Description:** When being stored in the application's backend, lookup secrets with less than 112 bits of entropy (19 random alphanumeric characters or 34 random digits) are hashed with an approved password storage hashing algorithm that incorporates a 32-bit random salt. A standard hash function can be used if the secret has 112 bits of entropy or more.

#### MB-R167 - ASVS 6.5.3 Secure generation

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.5.3 (L2)
- **Description:** Lookup secrets, out-of-band authentication code, and time-based one-time password seeds, are generated using a Cryptographically Secure Pseudorandom Number Generator (CSPRNG) to avoid predictable values.

#### MB-R168 - ASVS 6.5.4 Minimum entropy

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.5.4 (L2)
- **Description:** Lookup secrets and out-of-band authentication codes have a minimum of 20 bits of entropy (typically 4 random alphanumeric characters or 6 random digits is sufficient).

#### MB-R169 - ASVS 6.5.5 Short lifetime

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.5.5 (L2)
- **Description:** Out-of-band authentication requests, codes, or tokens, as well as time-based one-time passwords (TOTPs) have a defined lifetime. Out of band requests must have a maximum lifetime of 10 minutes and for TOTP a maximum lifetime of 30 seconds.

#### MB-R170 - ASVS 6.6.1 Phone/SMS OTP limitations

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.6.1 (L2)
- **Description:** Authentication mechanisms using the Public Switched Telephone Network (PSTN) to deliver One-time Passwords (OTPs) via phone or SMS are offered only when the phone number has previously been validated, alternate stronger methods (such as Time based One-time Passwords) are also offered, and the service provides information on their security risks to users. For L3 applications, phone and SMS must not be available as options.

#### MB-R171 - ASVS 6.6.2 Bind OOB challenge

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.6.2 (L2)
- **Description:** Out-of-band authentication requests, codes, or tokens are bound to the original authentication request for which they were generated and are not usable for a previous or subsequent one.

#### MB-R172 - ASVS 7.1.1 Session-lifetime policy

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.1.1 (L2)
- **Description:** The user's session inactivity timeout and absolute maximum session lifetime are documented, are appropriate in combination with other controls, and that the documentation includes justification for any deviations from NIST SP 800-63B re-authentication requirements.

#### MB-R173 - ASVS 7.1.2 Concurrent-session policy

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.1.2 (L2)
- **Description:** The documentation defines how many concurrent (parallel) sessions are allowed for one account as well as the intended behaviors and actions to be taken when the maximum number of active sessions is reached.

#### MB-R174 - ASVS 7.3.2 Absolute lifetime

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.3.2 (L2)
- **Description:** There is an absolute maximum session lifetime such that re-authentication is enforced according to risk analysis and documented security decisions.

#### MB-R175 - ASVS 7.4.3 Terminate other sessions after factor changes

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.4.3 (L2)
- **Description:** The application gives the option to terminate all other active sessions after a successful change or removal of any authentication factor (including password change via reset or recovery and, if present, an MFA settings update).

#### MB-R176 - ASVS 7.4.4 Visible logout

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.4.4 (L2)
- **Description:** All pages that require authentication have easy and visible access to logout functionality.

#### MB-R177 - ASVS 7.4.5 Administrative session termination

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.4.5 (L2)
- **Description:** Application administrators are able to terminate active sessions for an individual user or for all users.

#### MB-R178 - ASVS 7.5.1 Re-authenticate sensitive account changes

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.5.1 (L2)
- **Description:** The application requires full re-authentication before allowing modifications to sensitive account attributes which may affect authentication such as email address, phone number, MFA configuration, or other information used in account recovery.

#### MB-R179 - ASVS 7.5.2 User session management

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.5.2 (L2)
- **Description:** Users are able to view and (having authenticated again with at least one factor) terminate any or all currently active sessions.

#### MB-R180 - ASVS 7.6.2 User-initiated sessions

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.6.2 (L2)
- **Description:** Creation of a session requires either the user's consent or an explicit action, preventing the creation of new application sessions without user interaction.

#### MB-R181 - ASVS 8.1.2 Field-level authorization rules

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 8.1.2 (L2)
- **Description:** Authorization documentation defines rules for field-level access restrictions (both read and write) based on consumer permissions and resource attributes. Note that these rules might depend on other attribute values of the relevant data object, such as state or status.

#### MB-R182 - ASVS 11.1.1 Key-management policy

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.1.1 (L2)
- **Description:** There is a documented policy for management of cryptographic keys and a cryptographic key lifecycle that follows a key management standard such as NIST SP 800-57. This should include ensuring that keys are not overshared (for example, with more than two entities for shared secrets and more than one entity for private keys).

#### MB-R183 - ASVS 11.1.2 Cryptographic inventory

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.1.2 (L2)
- **Description:** A cryptographic inventory is performed, maintained, regularly updated, and includes all cryptographic keys, algorithms, and certificates used by the application. It must also document where keys can and cannot be used in the system, and the types of data that can and cannot be protected using the keys.

#### MB-R184 - ASVS 11.2.2 Crypto agility

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.2.2 (L2)
- **Description:** The application is designed with crypto agility such that random number, authenticated encryption, MAC, or hashing algorithms, key lengths, rounds, ciphers and modes can be reconfigured, upgraded, or swapped at any time, to protect against cryptographic breaks. Similarly, it must also be possible to replace keys and passwords and re-encrypt data. This will allow for seamless upgrades to post-quantum cryptography (PQC), once high-assurance implementations of approved PQC schemes or standards are widely available.

#### MB-R185 - ASVS 11.4.3 Hash strength

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.4.3 (L2)
- **Description:** Hash functions used in digital signatures, as part of data authentication or data integrity are collision resistant and have appropriate bit-lengths. If collision resistance is required, the output length must be at least 256 bits. If only resistance to second pre-image attacks is required, the output length must be at least 128 bits.

#### MB-R186 - ASVS 11.4.4 Password-derived keys

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.4.4 (L2)
- **Description:** The application uses approved key derivation functions with key stretching parameters when deriving secret keys from passwords. The parameters in use must balance security and performance to prevent brute-force attacks from compromising the resulting cryptographic key.

#### MB-R187 - ASVS 12.1.3 mTLS certificate trust

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 12.1.3 (L2)
- **Description:** The application validates that mTLS client certificates are trusted before using the certificate identity for authentication or authorization.

#### MB-R188 - ASVS 12.3.4 Internal certificate trust

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 12.3.4 (L2)
- **Description:** TLS connections between internal services use trusted certificates. Where internally generated or self-signed certificates are used, the consuming service must be configured to only trust specific internal CAs and specific self-signed certificates.

#### MB-R189 - ASVS 13.1.1 Communication inventory

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.1.1 (L2)
- **Description:** All communication needs for the application are documented. This must include external services which the application relies upon and cases where an end user might be able to provide an external location to which the application will then connect.

#### MB-R190 - ASVS 13.2.1 Backend authentication

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.2.1 (L2)
- **Description:** Communications between backend application components that don't support the application's standard user session mechanism, including APIs, middleware, and data layers, are authenticated. Authentication must use individual service accounts, short-term tokens, or certificate-based authentication and not unchanging credentials such as passwords, API keys, or shared accounts with privileged access.

#### MB-R191 - ASVS 13.4.4 Disable HTTP TRACE

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.4.4 (L2)
- **Description:** Using the HTTP TRACE method is not supported in production environments, to avoid potential information leakage.

#### MB-R192 - ASVS 14.1.1 Sensitive-data inventory

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 14.1.1 (L2)
- **Description:** All sensitive data created and processed by the application has been identified and classified into protection levels. This includes data that is only encoded and therefore easily decoded, such as Base64 strings or the plaintext payload inside a JWT. Protection levels need to take into account any data protection and privacy regulations and standards which the application is required to comply with.

#### MB-R193 - ASVS 14.1.2 Protection requirements

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 14.1.2 (L2)
- **Description:** All sensitive data protection levels have a documented set of protection requirements. This must include (but not be limited to) requirements related to general encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies to be used, and other confidentiality requirements.

#### MB-R194 - ASVS 14.2.2 Server-side cache protection

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 14.2.2 (L2)
- **Description:** The application prevents sensitive data from being cached in server components, such as load balancers and application caches, or ensures that the data is securely purged after use.

#### MB-R195 - ASVS 14.3.2 Browser anti-caching

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 14.3.2 (L2)
- **Description:** The application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers.

#### MB-R196 - ASVS 14.3.3 Browser-storage minimization

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 14.3.3 (L2)
- **Description:** Data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data, with the exception of session tokens.

#### MB-R197 - ASVS 15.1.3 Resource-intensive functionality

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.1.3 (L2)
- **Description:** The application documentation identifies functionality which is time-consuming or resource-demanding. This must include how to prevent a loss of availability due to overusing this functionality and how to avoid a situation where building a response takes longer than the consumer's timeout. Potential defenses may include asynchronous processing, using queues, and limiting parallel processes per user and per application.

#### MB-R198 - ASVS 15.2.2 Availability defenses

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.2.2 (L2)
- **Description:** The application has implemented defenses against loss of availability due to functionality which is time-consuming or resource-demanding, based on the documented security decisions and strategies for this.

#### MB-R199 - ASVS 15.3.2 External redirect handling

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.3.2 (L2)
- **Description:** Where the application backend makes calls to external URLs, it is configured to not follow redirects unless it is intended functionality.

#### MB-R200 - ASVS 15.3.3 Mass-assignment protection

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.3.3 (L2)
- **Description:** The application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g., it is not possible to insert or update a field value when it was not intended to be part of that action.

#### MB-R201 - ASVS 15.3.4 Trusted client IP propagation

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.3.4 (L2)
- **Description:** All proxying and middleware components transfer the user's original IP address correctly using trusted data fields that cannot be manipulated by the end user, and the application and web server use this correct value for logging and security decisions such as rate limiting, taking into account that even the original IP address may not be reliable due to dynamic IPs, VPNs, or corporate firewalls.

#### MB-R202 - ASVS 15.3.5 Strict typing and comparison

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.3.5 (L2)
- **Description:** The application explicitly ensures that variables are of the correct type and performs strict equality and comparator operations. This is to avoid type juggling or type confusion vulnerabilities caused by the application code making an assumption about a variable type.

#### MB-R203 - ASVS 15.3.6 Prototype-pollution defense

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.3.6 (L2)
- **Description:** JavaScript code is written in a way that prevents prototype pollution, for example, by using Set() or Map() instead of object literals.

#### MB-R204 - ASVS 15.3.7 HTTP parameter pollution

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.3.7 (L2)
- **Description:** The application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or header fields).

#### MB-R205 - ASVS 16.1.1 Logging inventory

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.1.1 (L2)
- **Description:** An inventory exists documenting the logging performed at each layer of the application's technology stack, what events are being logged, log formats, where that logging is stored, how it is used, how access to it is controlled, and for how long logs are kept.

#### MB-R206 - ASVS 16.2.1 Investigation metadata

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.2.1 (L2)
- **Description:** Each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens.

#### MB-R207 - ASVS 16.2.2 Time synchronization

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.2.2 (L2)
- **Description:** Time sources for all logging components are synchronized, and that timestamps in security event metadata use UTC or include an explicit time zone offset. UTC is recommended to ensure consistency across distributed systems and to prevent confusion during daylight saving time transitions.

#### MB-R208 - ASVS 16.2.3 Approved log destinations

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.2.3 (L2)
- **Description:** The application only stores or broadcasts logs to the files and services that are documented in the log inventory.

#### MB-R209 - ASVS 16.2.4 Correlatable format

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.2.4 (L2)
- **Description:** Logs can be read and correlated by the log processor that is in use, preferably by using a common logging format.

#### MB-R210 - ASVS 16.3.1 Authentication logging

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.3.1 (L2)
- **Description:** All authentication operations are logged, including successful and unsuccessful attempts. Additional metadata, such as the type of authentication or factors used, should also be collected.

#### MB-R211 - ASVS 16.3.2 Authorization logging

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.3.2 (L2)
- **Description:** Failed authorization attempts are logged. For L3, this must include logging all authorization decisions, including logging when sensitive data is accessed (without logging the sensitive data itself).

#### MB-R212 - ASVS 16.3.3 Security-control events

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.3.3 (L2)
- **Description:** The application logs the security events that are defined in the documentation and also logs attempts to bypass the security controls, such as input validation, business logic, and anti-automation.

#### MB-R213 - ASVS 16.3.4 Error and control-failure logging

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.3.4 (L2)
- **Description:** The application logs unexpected errors and security control failures such as backend TLS failures.

#### MB-R214 - ASVS 16.4.1 Log-injection prevention

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.4.1 (L2)
- **Description:** All logging components appropriately encode data to prevent log injection.

#### MB-R215 - ASVS 16.4.3 Separate log system

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.4.3 (L2)
- **Description:** Logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation. The aim is to ensure that if the application is breached, the logs are not compromised.

#### MB-R216 - ASVS 16.5.2 Secure external-service failure

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.5.2 (L2)
- **Description:** The application continues to operate securely when external resource access fails, for example, by using patterns such as circuit breakers or graceful degradation.

#### MB-R217 - ASVS 16.5.3 Fail securely

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.5.3 (L2)
- **Description:** The application fails gracefully and securely, including when an exception occurs, preventing fail-open conditions such as processing a transaction despite errors resulting from validation logic.

### MB-C16 - ASVS Level 2 Contextual Human Assurance (55 rules)

Conditional human-verification rules activated only for capabilities explicitly enabled in Magebean project configuration.

#### MB-R218 - ASVS 1.2.6 LDAP injection (when ldap is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `ldap`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.2.6 (L2)
- **Description:** The application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented.

#### MB-R219 - ASVS 1.2.7 XPath injection (when xpath is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `xpath`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.2.7 (L2)
- **Description:** The application is protected against XPath injection attacks by using query parameterization or precompiled queries.

#### MB-R220 - ASVS 1.2.8 LaTeX injection (when latex_processing is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `latex_processing`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.2.8 (L2)
- **Description:** LaTeX processors are configured securely (such as not using the "- shell-escape"flag) and an allowlist of commands is used to prevent LaTeX injection attacks.

#### MB-R221 - ASVS 1.3.4 SVG sanitization (when user_supplied_svg is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `user_supplied_svg`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.3.4 (L2)
- **Description:** User-supplied Scalable Vector Graphics (SVG) scriptable content is validated or sanitized to contain only tags and attributes (such as draw graphics) that are safe for the application, e.g., do not contain scripts and foreignObject.

#### MB-R222 - ASVS 1.3.5 Scriptable content (when scriptable_user_content is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `scriptable_user_content`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.3.5 (L2)
- **Description:** The application sanitizes or disables user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar.

#### MB-R223 - ASVS 1.3.8 JNDI injection (when jndi is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `jndi`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.3.8 (L2)
- **Description:** The application appropriately sanitizes untrusted input before use in Java Naming and Directory Interface (JNDI) queries and that JNDI is configured securely to prevent JNDI injection attacks.

#### MB-R224 - ASVS 1.3.9 Memcache injection (when memcache is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `memcache`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.3.9 (L2)
- **Description:** The application sanitizes content before it is sent to memcache to prevent injection attacks.

#### MB-R225 - ASVS 1.4.1 Memory-safe operations (when native_code is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `native_code`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.4.1 (L2)
- **Description:** The application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows.

#### MB-R226 - ASVS 1.4.2 Integer overflow (when native_code is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `native_code`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.4.2 (L2)
- **Description:** Sign, range, and input validation techniques are used to prevent integer overflows.

#### MB-R227 - ASVS 1.4.3 Resource lifecycle (when native_code is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `native_code`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.4.3 (L2)
- **Description:** Dynamically allocated memory and resources are released, and that references or pointers to freed memory are removed or set to null to prevent dangling pointers and use-after-free vulnerabilities.

#### MB-R228 - ASVS 4.4.3 WebSocket session tokens (when websocket is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `websocket`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 4.4.3 (L2)
- **Description:** If the application's standard session management cannot be used, dedicated tokens are being used for this, which comply with the relevant Session Management security requirements.

#### MB-R229 - ASVS 4.4.4 Authenticated WebSocket upgrade (when websocket is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `websocket`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 4.4.4 (L2)
- **Description:** Dedicated WebSocket session management tokens are initially obtained or validated through the previously authenticated HTTPS session when transitioning an existing HTTPS session to a WebSocket channel.

#### MB-R230 - ASVS 5.1.1 Upload policy documentation (when file_handling is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `file_handling`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 5.1.1 (L2)
- **Description:** The documentation defines the permitted file types, expected file extensions, and maximum size (including unpacked size) for each upload feature. Additionally, ensure that the documentation specifies how files are made safe for end-users to download and process, such as how the application behaves when a malicious file is detected.

#### MB-R231 - ASVS 5.4.3 Malware scanning (when file_handling is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `file_handling`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 5.4.3 (L2)
- **Description:** Files obtained from untrusted sources are scanned by antivirus scanners to prevent serving of known malicious content.

#### MB-R232 - ASVS 6.8.1 IdP namespace isolation (when federated_identity is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `federated_identity`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.8.1 (L2)
- **Description:** If the application supports multiple identity providers (IdPs), the user's identity cannot be spoofed via another supported identity provider (eg. by using the same user identifier). The standard mitigation would be for the application to register and identify the user using a combination of the IdP ID (serving as a namespace) and the user's ID in the IdP.

#### MB-R233 - ASVS 6.8.2 Signed assertions (when federated_identity is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `federated_identity`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.8.2 (L2)
- **Description:** The presence and integrity of digital signatures on authentication assertions (for example on JWTs or SAML assertions) are always validated, rejecting any assertions that are unsigned or have invalid signatures.

#### MB-R234 - ASVS 6.8.3 SAML replay prevention (when federated_identity is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `federated_identity`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.8.3 (L2)
- **Description:** SAML assertions are uniquely processed and used only once within the validity period to prevent replay attacks.

#### MB-R235 - ASVS 6.8.4 Authentication-context validation (when federated_identity is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `federated_identity`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.8.4 (L2)
- **Description:** If an application uses a separate Identity Provider (IdP) and expects specific authentication strength, methods, or recentness for specific functions, the application verifies this using the information returned by the IdP. For example, if OIDC is used, this might be achieved by validating ID Token claims such as 'acr', 'amr', and 'auth\_time'(if present). If the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used (for example, single-factor authentication using username and password).

#### MB-R236 - ASVS 7.1.3 Federated-session inventory (when federated_identity is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `federated_identity`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.1.3 (L2)
- **Description:** All systems that create and manage user sessions as part of a federated identity management ecosystem (such as SSO systems) are documented along with controls to coordinate session lifetimes, termination, and any other conditions that require re-authentication.

#### MB-R237 - ASVS 7.6.1 Federated lifetime enforcement (when federated_identity is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `federated_identity`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.6.1 (L2)
- **Description:** Session lifetime and termination between Relying Parties (RPs) and Identity Providers (IdPs) behave as documented, requiring re-authentication as necessary such as when the maximum time between IdP authentication events is reached.

#### MB-R238 - ASVS 8.4.1 Tenant isolation (when multi_tenant is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `multi_tenant`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 8.4.1 (L2)
- **Description:** Multi-tenant applications use cross-tenant controls to ensure consumer operations will never affect tenants with which they do not have permissions to interact.

#### MB-R239 - ASVS 9.2.2 Token type and purpose (when self_contained_tokens is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `self_contained_tokens`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 9.2.2 (L2)
- **Description:** The service receiving a token validates the token to be the correct type and is meant for the intended purpose before accepting the token's contents. For example, only access tokens can be accepted for authorization decisions and only ID Tokens can be used for proving user authentication.

#### MB-R240 - ASVS 9.2.3 Audience validation (when self_contained_tokens is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `self_contained_tokens`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 9.2.3 (L2)
- **Description:** The service only accepts tokens which are intended for use with that service (audience). For JWTs, this can be achieved by validating the 'aud' claim against an allowlist defined in the service.

#### MB-R241 - ASVS 9.2.4 Audience restriction across services (when self_contained_tokens is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `self_contained_tokens`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 9.2.4 (L2)
- **Description:** If a token issuer uses the same private key for issuing tokens to different audiences, the issued tokens contain an audience restriction that uniquely identifies the intended audiences. This will prevent a token from being reused with an unintended audience. If the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation.

#### MB-R242 - ASVS 10.1.1 Token minimization (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.1.1 (L2)
- **Description:** Tokens are only sent to components that strictly need them. For example, when using a backend-for-frontend pattern for browser-based JavaScript applications, access and refresh tokens shall only be accessible for the backend.

#### MB-R243 - ASVS 10.1.2 Bind authorization transaction (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.1.2 (L2)
- **Description:** The client only accepts values from the authorization server (such as the authorization code or ID Token) if these values result from an authorization flow that was initiated by the same user agent session and transaction. This requires that client-generated secrets, such as the proof key for code exchange (PKCE) 'code\_verifier', 'state'or OIDC 'nonce', are not guessable, are specific to the transaction, and are securely bound to both the client and the user agent session in which the transaction was started.

#### MB-R244 - ASVS 10.2.1 Code-flow CSRF defense (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.2.1 (L2)
- **Description:** If the code flow is used, the OAuth client has protection against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF), which trigger token requests, either by using proof key for code exchange (PKCE) functionality or checking the 'state'parameter that was sent in the authorization request.

#### MB-R245 - ASVS 10.2.2 Mix-up attack defense (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.2.2 (L2)
- **Description:** If the OAuth client can interact with more than one authorization server, it has a defense against mix-up attacks. For example, it could require that the authorization server return the 'iss'parameter value and validate it in the authorization response and the token response.

#### MB-R246 - ASVS 10.3.1 Access-token audience (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.3.1 (L2)
- **Description:** The resource server only accepts access tokens that are intended for use with that service (audience). The audience may be included in a structured access token (such as the 'aud'claim in JWT), or it can be checked using the token introspection endpoint.

#### MB-R247 - ASVS 10.3.2 Delegated authorization claims (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.3.2 (L2)
- **Description:** The resource server enforces authorization decisions based on claims from the access token that define delegated authorization. If claims such as 'sub', 'scope', and 'authorization\_details'are present, they must be part of the decision.

#### MB-R248 - ASVS 10.3.3 Stable user identity (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.3.3 (L2)
- **Description:** If an access control decision requires identifying a unique user from an access token (JWT or related token introspection response), the resource server identifies the user from claims that cannot be reassigned to other users. Typically, it means using a combination of 'iss'and 'sub'claims.

#### MB-R249 - ASVS 10.3.4 Authentication strength and freshness (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.3.4 (L2)
- **Description:** If the resource server requires specific authentication strength, methods, or recentness, it verifies that the presented access token satisfies these constraints. For example, if present, using the OIDC 'acr', 'amr'and 'auth\_time'claims respectively.

#### MB-R250 - ASVS 10.4.6 PKCE enforcement (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.6 (L2)
- **Description:** If the code grant is used, the authorization server mitigates authorization code interception attacks by requiring proof key for code exchange (PKCE). For authorization requests, the authorization server must require a valid 'code\_challenge'value and must not accept a 'code\_challenge\_method'value of 'plain'. For a token request, it must require validation of the 'code\_verifier'parameter.

#### MB-R251 - ASVS 10.4.7 Dynamic-client registration safety (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.7 (L2)
- **Description:** If the authorization server supports unauthenticated dynamic client registration, it mitigates the risk of malicious client applications. It must validate client metadata such as any registered URIs, ensure the user's consent, and warn the user before processing an authorization request with an untrusted client application.

#### MB-R252 - ASVS 10.4.8 Refresh-token expiration (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.8 (L2)
- **Description:** Refresh tokens have an absolute expiration, including if sliding refresh token expiration is applied.

#### MB-R253 - ASVS 10.4.9 Token revocation (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.9 (L2)
- **Description:** Refresh tokens and reference access tokens can be revoked by an authorized user using the authorization server user interface, to mitigate the risk of malicious clients or stolen tokens.

#### MB-R254 - ASVS 10.4.10 Confidential-client authentication (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.10 (L2)
- **Description:** Confidential client is authenticated for client-to-authorized server backchannel requests such as token requests, pushed authorization requests (PAR), and token revocation requests.

#### MB-R255 - ASVS 10.4.11 Least OAuth scopes (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.11 (L2)
- **Description:** The authorization server configuration only assigns the required scopes to the OAuth client.

#### MB-R256 - ASVS 10.5.1 ID Token replay defense (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.5.1 (L2)
- **Description:** The client (as the relying party) mitigates ID Token replay attacks. For example, by ensuring that the 'nonce'claim in the ID Token matches the 'nonce'value sent in the authentication request to the OpenID Provider (in OAuth2 refereed to as the authorization request sent to the authorization server).

#### MB-R257 - ASVS 10.5.2 Stable OIDC identity (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.5.2 (L2)
- **Description:** The client uniquely identifies the user from ID Token claims, usually the 'sub'claim, which cannot be reassigned to other users (for the scope of an identity provider).

#### MB-R258 - ASVS 10.5.3 Issuer metadata validation (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.5.3 (L2)
- **Description:** The client rejects attempts by a malicious authorization server to impersonate another authorization server through authorization server metadata. The client must reject authorization server metadata if the issuer URL in the authorization server metadata does not exactly match the pre-configured issuer URL expected by the client.

#### MB-R259 - ASVS 10.5.4 ID Token audience (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.5.4 (L2)
- **Description:** The client validates that the ID Token is intended to be used for that client (audience) by checking that the 'aud'claim from the token is equal to the 'client\_id'value for the client.

#### MB-R260 - ASVS 10.5.5 Back-channel logout validation (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.5.5 (L2)
- **Description:** When using OIDC back-channel logout, the relying party mitigates denial of service through forced logout and cross-JWT confusion in the logout flow. The client must verify that the logout token is correctly typed with a value of 'logout+jwt', contains the 'event'claim with the correct member name, and does not contain a 'nonce'claim. Note that it is also recommended to have a short expiration (e.g., 2 minutes).

#### MB-R261 - ASVS 10.6.1 Safe response types (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.6.1 (L2)
- **Description:** The OpenID Provider only allows values 'code', 'ciba', 'id\_token', or 'id\_token code'for response mode. Note that 'code'is preferred over 'id\_token code'(the OIDC Hybrid flow), and 'token'(any Implicit flow) must not be used.

#### MB-R262 - ASVS 10.6.2 Logout DoS protection (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.6.2 (L2)
- **Description:** The OpenID Provider mitigates denial of service through forced logout. By obtaining explicit confirmation from the end-user or, if present, validating parameters in the logout request (initiated by the relying party), such as the 'id\_token\_hint'.

#### MB-R263 - ASVS 10.7.1 Consent per authorization (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.7.1 (L2)
- **Description:** The authorization server ensures that the user consents to each authorization request. If the identity of the client cannot be assured, the authorization server must always explicitly prompt the user for consent.

#### MB-R264 - ASVS 10.7.2 Informed consent (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.7.2 (L2)
- **Description:** When the authorization server prompts for user consent, it presents sufficient and clear information about what is being consented to. When applicable, this should include the nature of the requested authorizations (typically based on scope, resource server, Rich Authorization Requests (RAR) authorization details), the identity of the authorized application, and the lifetime of these authorizations.

#### MB-R265 - ASVS 10.7.3 Consent management (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.7.3 (L2)
- **Description:** The user can review, modify, and revoke consents which the user has granted through the authorization server.

#### MB-R266 - ASVS 17.1.1 TURN destination restrictions (when webrtc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `webrtc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 17.1.1 (L2)
- **Description:** The Traversal Using Relays around NAT (TURN) service only allows access to IP addresses that are not reserved for special purposes (e.g., internal networks, broadcast, loopback). Note that this applies to both IPv4 and IPv6 addresses.

#### MB-R267 - ASVS 17.2.1 DTLS key management (when webrtc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `webrtc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 17.2.1 (L2)
- **Description:** The key for the Datagram Transport Layer Security (DTLS) certificate is managed and protected based on the documented policy for management of cryptographic keys.

#### MB-R268 - ASVS 17.2.2 Secure DTLS-SRTP configuration (when webrtc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `webrtc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 17.2.2 (L2)
- **Description:** The media server is configured to use and support approved Datagram Transport Layer Security (DTLS) cipher suites and a secure protection profile for the DTLS Extension for establishing keys for the Secure Real-time Transport Protocol (DTLS-SRTP).

#### MB-R269 - ASVS 17.2.3 SRTP authentication (when webrtc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `webrtc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 17.2.3 (L2)
- **Description:** Secure Real-time Transport Protocol (SRTP) authentication is checked at the media server to prevent Real-time Transport Protocol (RTP) injection attacks from leading to either a Denial of Service condition or audio or video media insertion into media streams.

#### MB-R270 - ASVS 17.2.4 Malformed media resilience (when webrtc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `webrtc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 17.2.4 (L2)
- **Description:** The media server is able to continue processing incoming media traffic when encountering malformed Secure Real-time Transport Protocol (SRTP) packets.

#### MB-R271 - ASVS 17.3.1 Signaling flood protection (when webrtc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `webrtc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 17.3.1 (L2)
- **Description:** The signaling server is able to continue processing legitimate incoming signaling messages during a flood attack. This should be achieved by implementing rate limiting at the signaling level.

#### MB-R272 - ASVS 17.3.2 Malformed signaling resilience (when webrtc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `webrtc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 17.3.2 (L2)
- **Description:** The signaling server is able to continue processing legitimate signaling messages when encountering malformed signaling message that could cause a denial of service condition. This could include implementing input validation, safely handling integer overflows, preventing buffer overflows, and employing other robust error-handling techniques.

### MB-C17 - ASVS Level 2 Automated Verification (3 rules)

Focused automated checks that provide direct or partial evidence for OWASP ASVS 5.0 Level 2 requirements.

#### MB-R273 - Referrer-Policy limits cross-origin information leakage

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.4.5 (L2)
- **Description:** Referrer-Policy uses an approved restrictive value.

#### MB-R274 - Production endpoint rejects HTTP TRACE

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.4.4 (L2)
- **Description:** HTTP TRACE is rejected by the production endpoint.

#### MB-R275 - GraphQL introspection is disabled when GraphQL is private

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `graphql`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 4.3.2 (L2)
- **Description:** GraphQL schema introspection is not exposed.

### MB-C18 - ASVS Level 3 Human Assurance (92 rules)

Mandatory independent human-assessment rules for OWASP ASVS 5.0 Level 3 requirements that Magebean CLI cannot fully verify or attest.

#### MB-R276 - ASVS 1.2.10 CSV and formula injection

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.2.10 (L3)
- **Description:** The application is protected against CSV and Formula Injection. The application must follow the escaping rules defined in RFC 4180 sections 2.6 and 2.7 when exporting CSV content. Additionally, when exporting to CSV or other spreadsheet formats (such as XLS, XLSX, or ODF), special characters (including '=', '+', '-', '@', '\\t'(tab), and '\\0'(null character)) must be escaped with a single quote if they appear as the first character in a field value.

#### MB-R277 - ASVS 1.3.12 ReDoS prevention

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.3.12 (L3)
- **Description:** Regular expressions are free from elements causing exponential backtracking, and ensure untrusted input is sanitized to mitigate ReDoS or Runaway Regex attacks.

#### MB-R278 - ASVS 1.5.3 Consistent parser behavior

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 1.5.3 (L3)
- **Description:** Different parsers used in the application for the same data type (e.g., JSON parsers, XML parsers, URL parsers), perform parsing in a consistent way and use the same character encoding mechanism to avoid issues such as JSON Interoperability vulnerabilities or different URI or file parsing behavior being exploited in Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks.

#### MB-R279 - ASVS 2.3.5 Multi-user approval (when high_value_operations is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `high_value_operations`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 2.3.5 (L3)
- **Description:** High-value business logic flows require multi-user approval to prevent unauthorized or accidental actions. This could include but is not limited to large monetary transfers, contract approvals, access to classified information, or safety overrides in manufacturing.

#### MB-R280 - ASVS 2.4.2 Human transaction timing (when high_value_operations is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `high_value_operations`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 2.4.2 (L3)
- **Description:** Business logic flows require realistic human timing, preventing excessively rapid transaction submissions.

#### MB-R281 - ASVS 3.1.1 Browser-security requirements

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.1.1 (L3)
- **Description:** Application documentation states the expected security features that browsers using the application must support (such as HTTPS, HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), and other relevant HTTP security mechanisms). It must also define how the application must behave when some of these features are not available (such as warning the user or blocking access).

#### MB-R282 - ASVS 3.2.3 DOM-clobbering defense

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.2.3 (L3)
- **Description:** The application avoids DOM clobbering when using client-side JavaScript by employing explicit variable declarations, performing strict type checking, avoiding storing global variables on the document object, and implementing namespace isolation.

#### MB-R283 - ASVS 3.3.5 Cookie-size limit

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.3.5 (L3)
- **Description:** When the application writes a cookie, the cookie name and value length combined are not over 4096 bytes. Overly large cookies will not be stored by the browser and therefore not sent with requests, preventing the user from using application functionality which relies on that cookie.

#### MB-R284 - ASVS 3.4.7 CSP violation reporting

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.4.7 (L3)
- **Description:** The Content-Security-Policy header field specifies a location to report violations.

#### MB-R285 - ASVS 3.4.8 Cross-Origin-Opener-Policy

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.4.8 (L3)
- **Description:** All HTTP responses that initiate a document rendering (such as responses with Content-Type text/html), include the Cross-Origin-Opener-Policy header field with the same-origin directive or the same-origin-allow-popups directive as required. This prevents attacks that abuse shared access to Window objects, such as tabnabbing and frame counting.

#### MB-R286 - ASVS 3.5.6 Disable JSONP

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.5.6 (L3)
- **Description:** JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion (XSSI) attacks.

#### MB-R287 - ASVS 3.5.7 No authorized data in scripts

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.5.7 (L3)
- **Description:** Data requiring authorization is not included in script resource responses, like JavaScript files, to prevent Cross-Site Script Inclusion (XSSI) attacks.

#### MB-R288 - ASVS 3.5.8 Authorized-resource embedding

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.5.8 (L3)
- **Description:** Authenticated resources (such as images, videos, scripts, and other documents) can be loaded or embedded on behalf of the user only when intended. This can be accomplished by strict validation of the Sec-Fetch-\* HTTP request header fields to ensure that the request did not originate from an inappropriate cross-origin call, or by setting a restrictive Cross-Origin-Resource-Policy HTTP response header field to instruct the browser to block returned content.

#### MB-R289 - ASVS 3.6.1 External asset integrity (when external_assets is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `external_assets`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.6.1 (L3)
- **Description:** Client-side assets, such as JavaScript libraries, CSS, or web fonts, are only hosted externally (e.g., on a Content Delivery Network) if the resource is static and versioned and Subresource Integrity (SRI) is used to validate the integrity of the asset. If this is not possible, there should be a documented security decision to justify this for each resource.

#### MB-R290 - ASVS 3.7.3 External-redirect warning

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.7.3 (L3)
- **Description:** The application shows a notification when the user is being redirected to a URL outside of the application's control, with an option to cancel the navigation.

#### MB-R291 - ASVS 3.7.4 HSTS preload

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.7.4 (L3)
- **Description:** The application's top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict Transport Security (HSTS). This ensures that the use of TLS for the application is built directly into the main browsers, rather than relying only on the Strict-Transport-Security response header field.

#### MB-R292 - ASVS 3.7.5 Unsupported-browser handling

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.7.5 (L3)
- **Description:** The application behaves as documented (such as warning the user or blocking access) if the browser used to access the application does not support the expected security features.

#### MB-R293 - ASVS 4.1.4 HTTP-method allowlist

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 4.1.4 (L3)
- **Description:** Only HTTP methods that are explicitly supported by the application or its API (including OPTIONS during preflight requests) can be used and that unused methods are blocked.

#### MB-R294 - ASVS 4.1.5 Message-level signatures

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 4.1.5 (L3)
- **Description:** Per-message digital signatures are used to provide additional assurance on top of transport protections for requests or transactions which are highly sensitive or which traverse a number of systems.

#### MB-R295 - ASVS 4.2.2 Correct Content-Length generation

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 4.2.2 (L3)
- **Description:** When generating HTTP messages, the Content-Length header field does not conflict with the length of the content as determined by the framing of the HTTP protocol, in order to prevent request smuggling attacks.

#### MB-R296 - ASVS 4.2.3 HTTP/2 and HTTP/3 header restrictions

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 4.2.3 (L3)
- **Description:** The application does not send nor accept HTTP/2 or HTTP/3 messages with connection-specific header fields such as Transfer-Encoding to prevent response splitting and header injection attacks.

#### MB-R297 - ASVS 4.2.4 Reject CR/LF in modern HTTP headers

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 4.2.4 (L3)
- **Description:** The application only accepts HTTP/2 and HTTP/3 requests where the header fields and values do not contain any CR (\\r), LF (\\n), or CRLF (\\r\\n) sequences, to prevent header injection attacks.

#### MB-R298 - ASVS 4.2.5 Outbound message-size validation

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 4.2.5 (L3)
- **Description:** If the application (backend or frontend) builds and sends requests, it uses validation, sanitization, or other mechanisms to avoid creating URIs (such as for API calls) or HTTP request header fields (such as Authorization or Cookie), which are too long to be accepted by the receiving component. This could cause a denial of service, such as when sending an overly long request (e.g., a long cookie header field), which results in the server always responding with an error status.

#### MB-R299 - ASVS 5.2.4 Per-user storage quotas (when file_handling is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `file_handling`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 5.2.4 (L3)
- **Description:** A file size quota and maximum number of files per user are enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files.

#### MB-R300 - ASVS 5.2.5 Archive symlink restrictions (when file_handling is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `file_handling`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 5.2.5 (L3)
- **Description:** The application does not allow uploading compressed files containing symlinks unless this is specifically required (in which case it will be necessary to enforce an allowlist of the files that can be symlinked to).

#### MB-R301 - ASVS 5.2.6 Image pixel limits (when file_handling is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `file_handling`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 5.2.6 (L3)
- **Description:** The application rejects uploaded images with a pixel size larger than the maximum allowed, to prevent pixel flood attacks.

#### MB-R302 - ASVS 5.3.3 Ignore archive paths (when file_handling is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Applicability:** capability `file_handling`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 5.3.3 (L3)
- **Description:** Server-side file processing, such as file decompression, ignores user-provided path information to prevent vulnerabilities such as zip slip.

#### MB-R303 - ASVS 6.3.5 Suspicious-attempt notifications

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.3.5 (L3)
- **Description:** Users are notified of suspicious authentication attempts (successful or unsuccessful). This may include authentication attempts from an unusual location or client, partially successful authentication (only one of multiple factors), an authentication attempt after a long period of inactivity or a successful authentication after several unsuccessful attempts.

#### MB-R304 - ASVS 6.3.6 No email authentication factor

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.3.6 (L3)
- **Description:** Email is not used as either a single-factor or multi-factor authentication mechanism.

#### MB-R305 - ASVS 6.3.7 Authentication-change notifications

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.3.7 (L3)
- **Description:** Users are notified after updates to authentication details, such as credential resets or modification of the username or email address.

#### MB-R306 - ASVS 6.3.8 Account-enumeration resistance

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.3.8 (L3)
- **Description:** Valid users cannot be deduced from failed authentication challenges, such as by basing on error messages, HTTP response codes, or different response times. Registration and forgot password functionality must also have this protection.

#### MB-R307 - ASVS 6.4.5 Expiring-factor renewal

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.4.5 (L3)
- **Description:** Renewal instructions for authentication mechanisms which expire are sent with enough time to be carried out before the old authentication mechanism expires, configuring automated reminders if necessary.

#### MB-R308 - ASVS 6.4.6 Admin-assisted reset without password knowledge

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.4.6 (L3)
- **Description:** Administrative users can initiate the password reset process for the user, but that this does not allow them to change or choose the user's password. This prevents a situation where they know the user's password.

#### MB-R309 - ASVS 6.5.6 Factor revocation

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.5.6 (L3)
- **Description:** Any authentication factor (including physical devices) can be revoked in case of theft or other loss.

#### MB-R310 - ASVS 6.5.7 Biometrics as secondary factor (when biometric_authentication is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `biometric_authentication`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.5.7 (L3)
- **Description:** Biometric authentication mechanisms are only used as secondary factors together with either something you have or something you know.

#### MB-R311 - ASVS 6.5.8 Trusted TOTP clock

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.5.8 (L3)
- **Description:** Time-based one-time passwords (TOTPs) are checked based on a time source from a trusted service and not from an untrusted or client provided time.

#### MB-R312 - ASVS 6.6.4 Push-bombing defense

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.6.4 (L3)
- **Description:** Where push notifications are used for multi-factor authentication, rate limiting is used to prevent push bombing attacks. Number matching may also mitigate this risk.

#### MB-R313 - ASVS 6.7.1 Protect authentication certificates (when cryptographic_authentication is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `cryptographic_authentication`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.7.1 (L3)
- **Description:** The certificates used to verify cryptographic authentication assertions are stored in a way protects them from modification.

#### MB-R314 - ASVS 6.7.2 Strong challenge nonce (when cryptographic_authentication is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `cryptographic_authentication`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 6.7.2 (L3)
- **Description:** The challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device.

#### MB-R315 - ASVS 7.5.3 Step-up for highly sensitive operations (when high_value_operations is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `high_value_operations`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 7.5.3 (L3)
- **Description:** The application requires further authentication with at least one factor or secondary verification before performing highly sensitive transactions or operations.

#### MB-R316 - ASVS 8.1.3 Contextual-attribute inventory

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 8.1.3 (L3)
- **Description:** The application's documentation defines the environmental and contextual attributes (including but not limited to, time of day, user location, IP address, or device) that are used in the application to make security decisions, including those pertaining to authentication and authorization.

#### MB-R317 - ASVS 8.1.4 Adaptive decision policy

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 8.1.4 (L3)
- **Description:** Authentication and authorization documentation defines how environmental and contextual factors are used in decision-making, in addition to function-level, data-specific, and field-level authorization. This should include the attributes evaluated, thresholds for risk, and actions taken (e.g., allow, challenge, deny, step-up authentication).

#### MB-R318 - ASVS 8.2.4 Continuous adaptive controls

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 8.2.4 (L3)
- **Description:** Adaptive security controls based on a consumer's environmental and contextual attributes (such as time of day, location, IP address, or device) are implemented for authentication and authorization decisions, as defined in the application's documentation. These controls must be applied when the consumer tries to start a new session and also during an existing session.

#### MB-R319 - ASVS 8.3.2 Immediate authorization changes

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 8.3.2 (L3)
- **Description:** Changes to values on which authorization decisions are made are applied immediately. Where changes cannot be applied immediately, (such as when relying on data in self-contained tokens), there must be mitigating controls to alert when a consumer performs an action when they are no longer authorized to do so and revert the change. Note that this alternative would not mitigate information leakage.

#### MB-R320 - ASVS 8.3.3 End-user permission propagation

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 8.3.3 (L3)
- **Description:** Access to an object is based on the originating subject's (e.g. consumer's) permissions, not on the permissions of any intermediary or service acting on their behalf. For example, if a consumer calls a web service using a self-contained token for authentication, and the service then requests data from a different service, the second service will use the consumer's token, rather than a machine-to-machine token from the first service, to make permission decisions.

#### MB-R321 - ASVS 8.4.2 Layered administrative access

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 8.4.2 (L3)
- **Description:** Access to administrative interfaces incorporates multiple layers of security, including continuous consumer identity verification, device security posture assessment, and contextual risk analysis, ensuring that network location or trusted endpoints are not the sole factors for authorization even though they may reduce the likelihood of unauthorized access.

#### MB-R322 - ASVS 10.2.3 Client scope minimization (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.2.3 (L3)
- **Description:** The OAuth client only requests the required scopes (or other authorization parameters) in requests to the authorization server.

#### MB-R323 - ASVS 10.3.5 Sender-constrained access tokens (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.3.5 (L3)
- **Description:** The resource server prevents the use of stolen access tokens or replay of access tokens (from unauthorized parties) by requiring sender-constrained access tokens, either Mutual TLS for OAuth 2 or OAuth 2 Demonstration of Proof of Possession (DPoP).

#### MB-R324 - ASVS 10.4.12 Restrict response mode (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.12 (L3)
- **Description:** For a given client, the authorization server only allows the 'response\_mode'value that this client needs to use. For example, by having the authorization server validate this value against the expected values or by using pushed authorization request (PAR) or JWT-secured Authorization Request (JAR).

#### MB-R325 - ASVS 10.4.13 PAR for code grant (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.13 (L3)
- **Description:** Grant type 'code'is always used together with pushed authorization requests (PAR).

#### MB-R326 - ASVS 10.4.14 Proof-of-possession tokens (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.14 (L3)
- **Description:** The authorization server issues only sender-constrained (Proof-of-Possession) access tokens, either with certificate-bound access tokens using mutual TLS (mTLS) or DPoP-bound access tokens (Demonstration of Proof of Possession).

#### MB-R327 - ASVS 10.4.15 Protect authorization details (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.15 (L3)
- **Description:** For a server-side client (which is not executed on the end-user device), the authorization server ensures that the 'authorization\_details' parameter value is from the client backend and that the user has not tampered with it. For example, by requiring the usage of pushed authorization request (PAR) or JWT-secured Authorization Request (JAR).

#### MB-R328 - ASVS 10.4.16 Strong confidential-client authentication (when oauth_oidc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `oauth_oidc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 10.4.16 (L3)
- **Description:** The client is confidential and the authorization server requires the use of strong client authentication methods (based on public-key cryptography and resistant to replay attacks), such as mutual TLS ( 'tls\_client\_auth', 'self\_signed\_tls\_client\_auth') or private key JWT ( 'private\_key\_jwt').

#### MB-R329 - ASVS 11.1.3 Cryptographic discovery

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.1.3 (L3)
- **Description:** Cryptographic discovery mechanisms are employed to identify all instances of cryptography in the system, including encryption, hashing, and signing operations.

#### MB-R330 - ASVS 11.1.4 Cryptographic migration plan

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.1.4 (L3)
- **Description:** A cryptographic inventory is maintained. This must include a documented plan that outlines the migration path to new cryptographic standards, such as post-quantum cryptography, in order to react to future threats.

#### MB-R331 - ASVS 11.2.4 Constant-time operations

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.2.4 (L3)
- **Description:** All cryptographic operations are constant-time, with no 'short-circuit'operations in comparisons, calculations, or returns, to avoid leaking information.

#### MB-R332 - ASVS 11.2.5 Secure cryptographic failure

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.2.5 (L3)
- **Description:** All cryptographic modules fail securely, and errors are handled in a way that does not enable vulnerabilities, such as Padding Oracle attacks.

#### MB-R333 - ASVS 11.3.4 Unique nonce and IV

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.3.4 (L3)
- **Description:** Nonces, initialization vectors, and other single-use numbers are not used for more than one encryption key and data-element pair. The method of generation must be appropriate for the algorithm being used.

#### MB-R334 - ASVS 11.3.5 Encrypt-then-MAC

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.3.5 (L3)
- **Description:** Any combination of an encryption algorithm and a MAC algorithm is operating in encrypt-then-MAC mode.

#### MB-R335 - ASVS 11.5.2 Randomness under load

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.5.2 (L3)
- **Description:** The random number generation mechanism in use is designed to work securely, even under heavy demand.

#### MB-R336 - ASVS 11.6.2 Secure key exchange

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.6.2 (L3)
- **Description:** Approved cryptographic algorithms are used for key exchange (such as Diffie-Hellman) with a focus on ensuring that key exchange mechanisms use secure parameters. This will prevent attacks on the key establishment process which could lead to adversary-in-the-middle attacks or cryptographic breaks.

#### MB-R337 - ASVS 11.7.1 Memory encryption

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.7.1 (L3)
- **Description:** Full memory encryption is in use that protects sensitive data while it is in use, preventing access by unauthorized users or processes.

#### MB-R338 - ASVS 11.7.2 Processing minimization

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 11.7.2 (L3)
- **Description:** Data minimization ensures the minimal amount of data is exposed during processing, and ensure that data is encrypted immediately after use or as soon as feasible.

#### MB-R339 - ASVS 12.1.4 Certificate revocation

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 12.1.4 (L3)
- **Description:** Proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured.

#### MB-R340 - ASVS 12.1.5 Encrypted Client Hello

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 12.1.5 (L3)
- **Description:** Encrypted Client Hello (ECH) is enabled in the application's TLS settings to prevent exposure of sensitive metadata, such as the Server Name Indication (SNI), during TLS handshake processes.

#### MB-R341 - ASVS 12.3.5 Strong internal service identity

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 12.3.5 (L3)
- **Description:** Services communicating internally within a system (intra-service communications) use strong authentication to ensure that each endpoint is verified. Strong authentication methods, such as TLS client authentication, must be employed to ensure identity, using public-key infrastructure and mechanisms that are resistant to replay attacks. For microservice architectures, consider using a service mesh to simplify certificate management and enhance security.

#### MB-R342 - ASVS 13.1.2 Connection-limit policy

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.1.2 (L3)
- **Description:** For each service the application uses, the documentation defines the maximum number of concurrent connections (e.g., connection pool limits) and how the application behaves when that limit is reached, including any fallback or recovery mechanisms, to prevent denial of service conditions.

#### MB-R343 - ASVS 13.1.3 External-resource strategy

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.1.3 (L3)
- **Description:** The application documentation defines resource-management strategies for every external system or service it uses (e.g., databases, file handles, threads, HTTP connections). This should include resource-release procedures, timeout settings, failure handling, and where retry logic is implemented, specifying retry limits, delays, and back-off algorithms. For synchronous HTTP request-response operations it should mandate short timeouts and either disable retries or strictly limit retries to prevent cascading delays and resource exhaustion.

#### MB-R344 - ASVS 13.1.4 Critical-secret rotation policy

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.1.4 (L3)
- **Description:** The application's documentation defines the secrets that are critical for the security of the application and a schedule for rotating them, based on the organization's threat model and business requirements.

#### MB-R345 - ASVS 13.2.6 Enforce connection configuration

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.2.6 (L3)
- **Description:** Where the application connects to separate services, it follows the documented configuration for each connection, such as maximum parallel connections, behavior when maximum allowed connections is reached, connection timeouts, and retry strategies.

#### MB-R346 - ASVS 13.3.3 Isolated cryptographic module

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.3.3 (L3)
- **Description:** All cryptographic operations are performed using an isolated security module (such as a vault or hardware security module) to securely manage and protect key material from exposure outside of the security module.

#### MB-R347 - ASVS 13.3.4 Secret expiration and rotation

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.3.4 (L3)
- **Description:** Secrets are configured to expire and be rotated based on the application's documentation.

#### MB-R348 - ASVS 13.4.6 Hide backend versions

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.4.6 (L3)
- **Description:** The application does not expose detailed version information of backend components.

#### MB-R349 - ASVS 13.4.7 Served-file extension allowlist

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.4.7 (L3)
- **Description:** The web tier is configured to only serve files with specific file extensions to prevent unintentional information, configuration, and source code leakage.

#### MB-R350 - ASVS 14.2.5 Web-cache-deception defense

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 14.2.5 (L3)
- **Description:** Caching mechanisms are configured to only cache responses which have the expected content type for that resource and do not contain sensitive, dynamic content. The web server should return a 404 or 302 response when a non-existent file is accessed rather than returning a different, valid file. This should prevent Web Cache Deception attacks.

#### MB-R351 - ASVS 14.2.6 Sensitive-data minimization

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 14.2.6 (L3)
- **Description:** The application only returns the minimum required sensitive data for the application's functionality. For example, only returning some of the digits of a credit card number and not the full number. If the complete data is required, it should be masked in the user interface unless the user specifically views it.

#### MB-R352 - ASVS 14.2.7 Retention enforcement

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 14.2.7 (L3)
- **Description:** Sensitive information is subject to data retention classification, ensuring that outdated or unnecessary data is deleted automatically, on a defined schedule, or as the situation requires.

#### MB-R353 - ASVS 14.2.8 File metadata removal

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 14.2.8 (L3)
- **Description:** Sensitive information is removed from the metadata of user-submitted files unless storage is consented to by the user.

#### MB-R354 - ASVS 15.1.4 Risky-component inventory

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.1.4 (L3)
- **Description:** Application documentation highlights third-party libraries which are considered to be "risky components".

#### MB-R355 - ASVS 15.1.5 Dangerous-functionality inventory

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.1.5 (L3)
- **Description:** Application documentation highlights parts of the application where "dangerous functionality"is being used.

#### MB-R356 - ASVS 15.2.4 Dependency-confusion defense

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.2.4 (L3)
- **Description:** Third-party components and all of their transitive dependencies are included from the expected repository, whether internally owned or an external source, and that there is no risk of a dependency confusion attack.

#### MB-R357 - ASVS 15.2.5 Isolation around high-risk code

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.2.5 (L3)
- **Description:** The application implements additional protections around parts of the application which are documented as containing "dangerous functionality"or using third-party libraries considered to be "risky components". This could include techniques such as sandboxing, encapsulation, containerization or network level isolation to delay and deter attackers who compromise one part of an application from pivoting elsewhere in the application.

#### MB-R358 - ASVS 15.4.1 Thread-safe shared objects

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.4.1 (L3)
- **Description:** Shared objects in multi-threaded code (such as caches, files, or in-memory objects accessed by multiple threads) are accessed safely by using thread-safe types and synchronization mechanisms like locks or semaphores to avoid race conditions and data corruption.

#### MB-R359 - ASVS 15.4.2 Atomic state checks

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.4.2 (L3)
- **Description:** Checks on a resource's state, such as its existence or permissions, and the actions that depend on them are performed as a single atomic operation to prevent time-of-check to time-of-use (TOCTOU) race conditions. For example, checking if a file exists before opening it, or verifying a user's access before granting it.

#### MB-R360 - ASVS 15.4.3 Consistent locking

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.4.3 (L3)
- **Description:** Locks are used consistently to avoid threads getting stuck, whether by waiting on each other or retrying endlessly, and that locking logic stays within the code responsible for managing the resource to ensure locks cannot be inadvertently or maliciously modified by external classes or code.

#### MB-R361 - ASVS 15.4.4 Prevent thread starvation

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 15.4.4 (L3)
- **Description:** Resource allocation policies prevent thread starvation by ensuring fair access to resources, such as by leveraging thread pools, allowing lower-priority threads to proceed within a reasonable timeframe.

#### MB-R362 - ASVS 16.5.4 Last-resort exception handler

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 16.5.4 (L3)
- **Description:** A "last resort"error handler is defined which will catch all unhandled exceptions. This is both to avoid losing error details that must go to log files and to ensure that an error does not take down the entire application process, leading to a loss of availability.

#### MB-R363 - ASVS 17.1.2 TURN resource-exhaustion defense (when webrtc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `webrtc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 17.1.2 (L3)
- **Description:** The Traversal Using Relays around NAT (TURN) service is not susceptible to resource exhaustion when legitimate users attempt to open a large number of ports on the TURN server.

#### MB-R364 - ASVS 17.2.5 SRTP flood resilience (when webrtc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `webrtc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 17.2.5 (L3)
- **Description:** The media server is able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users.

#### MB-R365 - ASVS 17.2.6 DTLS ClientHello race defense (when webrtc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `webrtc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 17.2.6 (L3)
- **Description:** The media server is not susceptible to the "ClientHello"Race Condition vulnerability in Datagram Transport Layer Security (DTLS) by checking if the media server is publicly known to be vulnerable or by performing the race condition test.

#### MB-R366 - ASVS 17.2.7 Recording resilience (when webrtc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `webrtc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 17.2.7 (L3)
- **Description:** Any audio or video recording mechanisms associated with the media server are able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users.

#### MB-R367 - ASVS 17.2.8 DTLS fingerprint validation (when webrtc is used)

- **Verification:** `HUMAN VERIFICATION REQUIRED`
- **Severity:** `HIGH`
- **Applicability:** capability `webrtc`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 17.2.8 (L3)
- **Description:** The Datagram Transport Layer Security (DTLS) certificate is checked against the Session Description Protocol (SDP) fingerprint attribute, terminating the media stream if the check fails, to ensure the authenticity of the media stream.

### MB-C19 - ASVS Level 3 Automated Verification (3 rules)

Focused HTTP checks that provide partial evidence for OWASP ASVS 5.0 Level 3 requirements.

#### MB-R368 - HSTS policy is preload-ready

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 3.7.4 (L3)
- **Description:** HSTS policy is configured with preload-ready directives.

#### MB-R369 - Public endpoint does not advertise unsafe HTTP methods

- **Verification:** `AUTOMATED`
- **Severity:** `MEDIUM`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 4.1.4 (L3)
- **Description:** Public endpoint does not advertise unsafe HTTP methods.

#### MB-R370 - Backend server banner does not expose a detailed version

- **Verification:** `AUTOMATED`
- **Severity:** `LOW`
- **Mapped requirements:** OWASP-ASVS 5.0.0 section 13.4.6 (L3)
- **Description:** Backend server banner does not expose a detailed version.

---

## Chapter 4. Implementation Guidance

The **Magebean CLI** (`magebean-cli`) is the primary tool to operationalize this baseline.
It allows automated scanning of Magento 2 projects, validation of Controls and Rules, and generation of actionable reports.

### 4.1 Installation
Magebean CLI is distributed as a self-contained `.phar` package.
It requires **PHP 8.1+** and can be downloaded from the official Magebean distribution site.

```bash
wget https://files.magebean.com/magebean-cli.phar -O magebean.phar
chmod +x magebean.phar
```

### 4.2 Basic Usage
Run a scan against a Magento 2 installation:

```bash
./magebean.phar scan --path=/var/www/magento
```

- `--path` specifies the root directory of the Magento 2 project.
- Without a profile, the tool applies the 21-rule `basic` profile for a fast, low-noise production check. Use `--profile=baseline` to run the full catalog.

### 4.3 Profile-based Scans
Profiles select a curated subset of baseline rules for a specific assessment lens. Rules remain canonical `MB-Rxxx` entries in the baseline catalog, while each profile provides selection, mapping, and report metadata.

```bash
./magebean.phar scan --path=/var/www/magento --profile=owasp
./magebean.phar scan --path=/var/www/magento --profile=pci
./magebean.phar scan --path=/var/www/magento --profile=.magebean/profiles/acme.json
./magebean.phar scan --path=/var/www/magento --profile=hardening
./magebean.phar scan --path=/var/www/magento --profile=baseline
```

- **Basic profile (default):** Runs 21 fast, low-noise Magento production readiness checks.
- **OWASP profile:** Selects application security rules mapped to OWASP Top 10 categories.
- **PCI profile:** Selects PCI DSS readiness rules focused on payment scope, cardholder data leakage, payment-page script integrity, admin hardening, transport security, logging, and dependency risk.
- **Hardening profile:** Runs deep production checks while excluding payment-specific compliance evidence.
- **Baseline profile:** Runs all 113 automated rules by default, or all 370 rules with `--include-manual-review`.
- **Custom profile:** Allows projects, agencies, or open-source contributors to define their own rule selection and mappings without changing the core rule catalog.

### 4.4 Command-Line Output
Magebean CLI prints results directly to the command line:

- **CLI:** Human-readable summary directly in the console.

```bash
./magebean scan --path=/var/www/magento
```

### 4.5 CI/CD Integration
Magebean CLI is designed to run inside CI/CD pipelines.
Exit codes are mapped to severity levels, allowing builds to fail when critical issues are found.

Example GitHub Actions workflow:

```yaml
jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Magebean Audit
        run: /path-to-file/magebean.phar scan --path=.
```

### 4.6 Operational Recommendations
- **Audit Frequency:** Run baseline audits before every release and weekly on production environments.
- **Remediation Workflow:** Prioritize fixes for *Critical* and *High* severity findings.
- **Version Control:** Store reports in CI artifacts for traceability and compliance.
- **Local and API-backed operation:** Most checks run locally. Rules backed by Magebean APIs send endpoint-specific package or Magento version metadata when selected; Adobe package and patch alternatives are evaluated locally. See the [API data disclosure](api-reference.md#data-disclosure). Blocking those requests can cause the affected rules to return `UNKNOWN`.

---

## Chapter 5. Severity & Risk Rating

Each Rule in this baseline is assigned a **severity level** based on potential impact and likelihood of exploitation.
This chapter explains the rating system to help prioritize remediation.

### 5.1 Severity Levels
- **Critical**
  Exploitation can lead to full system compromise, data breach, or payment fraud. Must be remediated immediately.
- **High**
  Exploitation can cause significant security or operational risk, such as privilege escalation or data leakage. Should be prioritized for remediation.
- **Medium**
  Exploitation has limited impact or requires additional conditions. Important to fix but may be scheduled.
- **Low**
  Minor security hygiene issues or best practices. Fix as part of normal maintenance.

### 5.2 Risk Mapping
- **OWASP Top 10:** Each Rule is mapped to relevant OWASP category (e.g., A01: Broken Access Control, A06: Vulnerable Components).
- **PCI DSS Readiness:** Payment-related Rules may be mapped to PCI DSS requirements for readiness reporting. Magebean does not certify PCI DSS compliance; it provides automated technical checks and evidence signals that support PCI scoping and review.
- **CVSS Alignment:** Critical/High ratings generally align with CVSS base scores ≥ 7.0, while Medium/Low correspond to lower CVSS ranges.

### 5.3 Usage in Reporting
- Magebean CLI can generate reports grouped by severity.
- Exit codes may be configured for CI/CD pipelines (e.g., fail build if Critical issues are detected).
- Severity levels guide triage and remediation priorities for development and operations teams.

---

## References
- OWASP Top 10 — https://owasp.org/Top10/
- OWASP ASVS 5.0 — https://owasp.org/www-project-application-security-verification-standard/
- PCI Security Standards Council PCI DSS — https://www.pcisecuritystandards.org/standards/pci-dss/
- Magento 2 Documentation — https://developer.adobe.com/commerce/docs/
- OSV.dev Vulnerability Database — https://osv.dev/

## Appendix C. Glossary of Terms

**Audit**
A structured review process to evaluate a Magento system against Controls and Rules. In Magebean CLI, an audit is executed via automated scans.

**Baseline**
The complete current Magebean rule catalog consisting of 19 controls and 370 rules. It provides a reference point for measuring Magento 2 security posture and readiness signals.

**Control**
A high-level category of checks that represents a key security or compliance area (e.g., Admin Hardening, HTTPS Enforcement).

**Rule**
A specific, measurable requirement that enforces a Control. Rules are tagged as either automated or requiring mandatory human verification and serve as the unit of assessment.

**Profile**
A curated selection of baseline rules for a specific assessment lens, such as OWASP Top 10, PCI DSS readiness, or a custom organization-specific standard.

**Scan**
The technical execution of selected automated checks and human-verification requirements, producing evidence-oriented results and reports.

**OWASP Top 10**
A globally recognized standard for the top ten most critical web application security risks. Magebean profiles can map rules to OWASP categories for application security reporting.

**PCI DSS (Payment Card Industry Data Security Standard)**
A payment security standard for protecting cardholder data. Magebean provides PCI DSS readiness checks and evidence signals but does not certify PCI compliance.

**CVE (Common Vulnerabilities and Exposures)**
A standardized identifier for publicly known security vulnerabilities. Used in Magebean to flag risky Magento extensions or dependencies.

**Composer / composer.lock**
PHP’s dependency manager. The `composer.lock` file ensures deterministic dependency versions. Weak constraints or outdated lockfiles can lead to insecure builds.

**Extension (Magento Module)**
A third-party or custom Magento add-on. Extensions increase functionality but may also introduce vulnerabilities if unmaintained or insecure.

**Dependency / Transitive Dependency**
A software package required by Magento or its extensions. Transitive dependencies are nested libraries pulled indirectly, often overlooked but exploitable.

**Misconfiguration**
An insecure or unintended system setting (e.g., `display_errors=On`, HTTP enabled instead of HTTPS). A common source of compromise.

**Hardening**
Strengthening security by reducing attack surface and enforcing best practices. Examples include Admin Hardening and TLS Hardening.

**2FA (Two-Factor Authentication)**
An additional authentication step beyond passwords, required to secure Magento admin logins.

**CSRF (Cross-Site Request Forgery)**
An attack where a user’s authenticated session is abused to perform unwanted actions. Magento mitigates CSRF with form keys.

**XSS (Cross-Site Scripting)**
An injection attack where malicious scripts execute in the browser. Prevented by proper output escaping in templates and JavaScript contexts.

**SQL Injection (SQLi)**
An injection flaw where unsanitized input alters database queries. Prevented by Magento’s query abstraction and bound parameters.

**SSRF (Server-Side Request Forgery)**
An attack where the server is tricked into making unintended HTTP requests. Prevented by allow-listing outbound destinations.

**CSPRNG (Cryptographically Secure Random Number Generator)**
A random generator suitable for security-sensitive tokens (e.g., `random_bytes`). Prevents predictability in sessions or nonces.

**PII (Personally Identifiable Information)**
Any data that can identify an individual (e.g., name, email, address). Must be protected and never logged in plaintext.

**HSTS (HTTP Strict Transport Security)**
A security header forcing browsers to use HTTPS, preventing downgrade or SSL-stripping attacks.

**TLS (Transport Layer Security)**
The cryptographic protocol that secures data in transit. Magebean requires TLS 1.2 or higher with strong ciphers.

**FPC (Full Page Cache)**
Magento’s built-in caching mechanism. Ensures better performance and reduces backend exposure.

**Indexers**
Magento background processes that pre-compute data (e.g., search, catalog, pricing). Must remain healthy to avoid performance degradation.

---

**Note:** Magebean Security Baseline is an original framework authored by Son Cao.
It is aligned with OWASP standards but tailored specifically for Magento 2.
