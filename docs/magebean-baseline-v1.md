# Magebean Security Baseline v1.0

**Author:** Son Cao  
**Date:** 2025-08-20  
**Version:** 1.0

---

## Introduction

The **Magebean Security Baseline** defines 12 Controls and 81 Logic Rules to evaluate the
security, configuration, and dependency hygiene of Magento 2 stores.  
It is 100% aligned with the **OWASP Top 10 (2021)**.

This baseline is designed to be implemented with the `magebean-cli` tool, which provides
automated validation, reporting, and CI/CD integration.

---

## Magebean 12 Controls

- **MB-C01** File & Folder Permissions  
- **MB-C02** Admin Hardening  
- **MB-C03** Secure Coding Practices  
- **MB-C04** HTTPS & TLS Enforcement  
- **MB-C05** Production Mode & Deployment Hygiene  
- **MB-C06** Cache & Indexing Health  
- **MB-C07** Logging & Monitoring  
- **MB-C08** Cron Job Reliability  
- **MB-C09** Extension Vulnerability Management  
- **MB-C10** Abandoned Extensions Removal  
- **MB-C11** Composer Dependency Hygiene  
- **MB-C12** Third-party Config Security  

---

## Rule Catalog (81 Rules)

### MB-C01 File & Folder Permissions
- MB-R001 — No chmod 777 (High, A05)
- MB-R002 — Restrict code dirs not writable (High, A05)
- MB-R003 — Secure env.php perms (High, A05)
- MB-R004 — No .git/.env/backups in pub (High, A05)
- MB-R005 — Error pages privacy (Medium, A05)
- MB-R006 — Directory listing disabled (Medium, A05)

### MB-C02 Admin Hardening
- MB-R010 — Non-default admin path (High, A07)
- MB-R011 — Admin 2FA enabled (Critical, A07)
- MB-R012 — Session timeout ≤ 900s (Medium, A07)
- MB-R013 — Strong password policy (High, A07)
- MB-R014 — Limit admin exposure (Medium, A07)
- MB-R015 — Login throttling/rate-limit (Medium, A07)

### MB-C03 Secure Coding Practices
- MB-R020 — No raw SQL queries (Critical, A03)
- MB-R021 — Output escaping in templates (High, A03)
- MB-R022 — No direct superglobals (High, A05)
- MB-R023 — CSRF protection on POST (High, A01/A05)
- MB-R024 — SSRF safeguards (High, A10)
- MB-R025 — Deserialization safety (High, A08)
- MB-R026 — Command injection guards (Critical, A03)
- MB-R027 — No unsafe eval/dynamic code (Critical, A03/A08)
- MB-R028 — Path traversal protections (High, A01/A05)
- MB-R029 — Secure file uploads (High, A08)
- MB-R030 — JavaScript-context escaping (High, A03)
- MB-R031 — Cryptographically secure RNG (High, A02)

### MB-C04 HTTPS & TLS Enforcement
- MB-R030 — Force HTTPS base URLs (High, A02)
- MB-R031 — HSTS header present (Medium, A02)
- MB-R032 — TLS ≥ 1.2 required (High, A02)
- MB-R033 — No mixed content (Medium, A02)
- MB-R034 — Secure cookies flags (High, A02/A07)
- MB-R035 — Restrictive CORS policy (Medium, A05)

### MB-C05 Production Mode & Deployment Hygiene
- MB-R040 — Magento in production mode (High, A05)
- MB-R041 — No Xdebug in prod (Medium, A05)
- MB-R042 — Display errors off (High, A05)
- MB-R043 — Compiled DI enabled (Medium, A05)
- MB-R044 — Static content deployed (Medium, A05)
- MB-R045 — No dev configs on prod (High, A05/A08)

### MB-C06 Cache & Indexing Health
- MB-R050 — FPC enabled (High, A05)
- MB-R051 — Redis/Varnish configured (Medium, A05)
- MB-R052 — Indexers READY (Medium, A05)
- MB-R053 — Cache dirs correctly writable (Medium, A05)
- MB-R054 — No dev cache backend in prod (Medium, A05)
- MB-R055 — Secure session storage (High, A05)

### MB-C07 Logging & Monitoring
- MB-R060 — var/log protected (High, A09)
- MB-R061 — Log rotation enabled (Medium, A09)
- MB-R062 — No verbose traces exposed (High, A09/A05)
- MB-R063 — Admin login/logout logged (Medium, A09)
- MB-R064 — Centralized log forwarding (Low, A09)
- MB-R065 — PII sanitized in logs (High, A09/A02)

### MB-C08 Cron Job Reliability
- MB-R070 — System crontab entries (High, A05)
- MB-R071 — Cron heartbeat healthy (Medium, A05)
- MB-R072 — Cron backlog <100 jobs (Medium, A05)
- MB-R073 — No cron fatal errors (Medium, A05)
- MB-R074 — Consumers supervised (Medium, A05)
- MB-R075 — Time sync via NTP (Low, A05)

### MB-C09 Extension Vulnerability Management
- MB-R080 — CVE match via OSV (Critical, A06)
- MB-R081 — Vulnerable core modules flagged (Critical, A06)
- MB-R082 — Safe fixed version suggested (High, A06)
- MB-R083 — High-risk modules flagged (High, A06)
- MB-R084 — Temporary mitigations noted (Medium, A06/A08)
- MB-R085 — CVE exploit status annotated (High, A06)
- MB-R086 — Transitive dependencies checked (Critical, A06)
- MB-R087 — Constraints blocking fixes flagged (High, A06)
- MB-R088 — Yanked/withdrawn versions flagged (High, A06)

### MB-C10 Abandoned Extensions Removal
- MB-R090 — Abandoned flag detected (High, A06)
- MB-R091 — No release in >24 months (Medium, A06)
- MB-R092 — Archived repo detected (Medium, A06)
- MB-R093 — Single inactive maintainer (Low, A06)
- MB-R094 — Risky forks replacing originals (Medium, A06/A08)
- MB-R095 — No advisories enabled (Low, A06)

### MB-C11 Composer Dependency Hygiene
- MB-R100 — No wildcards in constraints (High, A06)
- MB-R101 — No dev-master/main deps (High, A06)
- MB-R102 — Stability not set to dev (High, A06)
- MB-R103 — composer audit clean (High, A06)
- MB-R104 — No critical outdated deps (Medium, A06)
- MB-R105 — composer.lock in VCS (Medium, A08)

### MB-C12 Third-party Config Security
- MB-R110 — Secrets not in VCS (Critical, A08/A02)
- MB-R111 — Only HTTPS endpoints (High, A02)
- MB-R112 — Debug mode disabled (Medium, A05)
- MB-R113 — Webhook validation enabled (High, A08/A07)
- MB-R114 — Outbound host allow-list (High, A10/A05)
- MB-R115 — PII minimization in configs (Medium, A02/A08)

---

## References

- OWASP Top 10 (2021) — https://owasp.org/Top10/  
- OWASP ASVS 4.0 — https://owasp.org/ASVS/  
- Magento 2 Documentation — https://developer.adobe.com/commerce/docs/  
- OSV.dev Vulnerability Database — https://osv.dev/

---

**Note:** Magebean Security Baseline is an original framework authored by Son Cao.  
It is aligned with OWASP standards but tailored specifically for Magento 2.

