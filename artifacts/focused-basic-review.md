# Basic: requirement/check review

Review tĩnh 20 requirements và implementation. Đây là specification đề xuất; chưa sửa runtime, chưa chạy Magento target hay fixture mới.

## MB-0001 — KEEP

No world-writable files or directories

Check/args: {"name":"fs_no_world_writable","args":{"path":".","max_results":50,"strict_observation":true}}

Source: src/Engine/Checks/FilesystemCheck.php:847

Thực tế: Unix world-write trong cây deployment; symlink là gap UNKNOWN.

Đề xuất: Giữ lỗi world-write; báo số entry và gap; traversal cần deadline/budget.

- Safe fixture: Cây đọc đủ mode 0755/0640 PASS
- Unsafe fixture: File hoặc thư mục 0777 FAIL
- Missing fixture: Unreadable hoặc symlink UNKNOWN

## MB-0002 — REVISE

env.php satisfies configured mode and ownership policy

Check/args: [{"name":"file_mode_max","args":{"file":"app/etc/env.php","max_octal":"0640","strict_observation":true}},{"name":"file_owner_group_matches","args":{"file":"app/etc/env.php","owner_reference":".","group_reference":".","strict_observation":true}}]

Source: src/Engine/Checks/FilesystemCheck.php:62; src/Engine/Checks/FilesystemCheck.php:95

Thực tế: Mode phải là subset 0640 và owner/group bằng project root; chưa kiểm ACL.

Đề xuất: Giữ kiểm env.php other-read/write là core security; tách owner-reference và execute-bit thành policy có cấu hình; không suy ra effective access.

- Safe fixture: 0600/0640 với approved owner PASS
- Unsafe fixture: 0644 lộ world-read;0666 world-write FAIL
- Missing fixture: stat/file thiếu UNKNOWN; ACL chưa quan sát ghi gap

## MB-0003 — KEEP

Webroot hygiene (no .git/.env/backups in pub/)

Check/args: {"name":"fs_webroot_artifact_policy","args":{"webroot":"pub","forbidden":[".git",".env",".env.local",".env.*","*.bak","*.old","*~"]}}

Source: src/Engine/Checks/DeploymentStateCheck.php:11

Thực tế: Tìm forbidden basenames trong pub; duyệt internal symlink; external/unreadable UNKNOWN.

Đề xuất: Giữ local precursor; bổ sung quan sát HTTP file nhạy cảm riêng; path hiện diện không đồng nghĩa public exposure.

- Safe fixture: Pub đầy đủ không forbidden PASS
- Unsafe fixture: pub/.git hoặc backup qua symlink nội bộ FAIL
- Missing fixture: external symlink/unreadable/budget UNKNOWN

## MB-0005 — KEEP

Directory listing absent on probed Magento paths

Check/args: {"name":"http_no_directory_listing","args":{"paths":["/media/","/static/","/errors/","/var/"],"timeout_ms":8000,"strict_scope":true}}

Source: src/Engine/Checks/HttpCheck.php:507

Thực tế: Nhận diện markup listing trong 8KB đầu của bốn đường dẫn, không kiểm mọi URL.

Đề xuất: Giữ bounded listing; evidence URL/status/redirect; không tuyên bố server tắt autoindex toàn cục.

- Safe fixture: 403/404 hoặc normal 200 PASS trong scope
- Unsafe fixture: 200 title Index of FAIL
- Missing fixture: 429/timeout/off-host redirect UNKNOWN

## MB-0006 — OPTIONAL

Declared backend route differs from admin

Check/args: {"name":"magento_admin_frontname_declared","args":{}}

Source: src/Engine/Checks/MagentoCheck.php:22

Thực tế: frontName hợp lệ khác admin; không chứng minh auth, entropy hay exposure.

Đề xuất: Giữ defense-in-depth advisory; giảm vai trò security gate và ưu tiên MFA/lockout.

- Safe fixture: Declared custom route PASS
- Unsafe fixture: admin FAIL policy
- Missing fixture: Missing/malformed config UNKNOWN

## MB-0007 — REVISE

Admin 2FA core and provider modules declared enabled

Check/args: {"name":"magento_admin_2fa_enabled","args":{"file":"app/etc/config.php","core_module":"Magento_TwoFactorAuth","provider_modules":["Magento_GoogleAuthenticator","Magento_DuoSecurity","Magento_U2fKey","Magento_AdminAdobeImsTwoFactorAuth"],"declared_scope_only":true}}

Source: src/Engine/Checks/MagentoCheck.php:374

Thực tế: Core module và ít nhất một fixed provider MODULE được bật; chưa chứng minh provider/service/enrollment.

Đề xuất: Đối chiếu fixture config thật của từng Magento hỗ trợ; resolve provider config thực và IMS/custom MFA alternative; không coi provider thiếu tên module là tắt MFA.

- Safe fixture: Authentic supported Magento MFA config + provider active được nhận
- Unsafe fixture: Core MFA disabled và không approved alternative FAIL
- Missing fixture: Provider/service mapping chưa hiểu UNKNOWN, không false FAIL

## MB-0728 — REVISE

Configured admin password minimum is at least eight

Check/args: {"name":"magento_admin_password_minimum_configured","args":{"min_length":8}}

Source: src/Engine/Checks/MagentoCheck.php:113

Thực tế: Minimum >=8 từ locked/default DB/module validator source regex, không kiểm password thực.

Đề xuất: Giữ observed minimum như policy có threshold; validate đúng Magento versions/custom validator; không gọi >=8 là strong password.

- Safe fixture: Resolved >= configured threshold PASS
- Unsafe fixture: Resolved below threshold FAIL
- Missing fixture: Custom validator không resolve/DB lỗi UNKNOWN

## MB-0011 — REVISE

Configured admin login CAPTCHA or bounded lockout

Check/args: {"name":"magento_admin_login_protection_configured","args":{"max_lockout_failures":10}}

Source: src/Engine/Checks/MagentoCheck.php:173

Thực tế: CAPTCHA backend_login hoặc lockout failures 1..10 và threshold>0 hoặc recognized reCAPTCHA type.

Đề xuất: Giữ configured signal; verify supported providers và key/config completeness; CAPTCHA-only không chứng minh throttling; separate runtime test opt-in.

- Safe fixture: Valid bounded lockout hoặc authentic CAPTCHA config PASS scoped
- Unsafe fixture: Known all mechanisms off FAIL
- Missing fixture: Partial/malformed config UNKNOWN

## MB-0026 — REVISE

Force HTTPS in admin and storefront

Check/args: {"name":"http_force_https_redirect","args":{"strict_scope":true,"include_admin":true}}

Source: src/Engine/Checks/HttpCheck.php:169

Thực tế: HTTP root và backend.frontName phải redirect trực tiếp same-host HTTPS; remote-only không có env.php nên UNKNOWN.

Đề xuất: Tách root HTTPS và admin HTTPS obligations; nhận explicit admin URL/context; 403/HTTP-port-blocked là policy/exposure context không tự suy ra plaintext login.

- Safe fixture: Root/admin direct HTTPS redirect PASS
- Unsafe fixture: HTTP login 200 hoặc downgrade FAIL
- Missing fixture: Remote không admin context: root có kết quả, admin UNKNOWN

## MB-0028 — KEEP

Runtime endpoint rejects legacy TLS

Check/args: {"name":"http_tls_min_version","args":{"timeout_ms":8000,"strict_scope":true}}

Source: src/Engine/Checks/HttpCheck.php:1052; src/Engine/Checks/HttpCheck.php:1554

Thực tế: Host/port chấp nhận modern TLS và từ chối 1.0/1.1 bằng evidence có ý nghĩa.

Đề xuất: Giữ protocol evidence; client không hỗ trợ TLS cũ không được coi server reject.

- Safe fixture: Modern success + legacy peer rejection PASS
- Unsafe fixture: TLS1.0/1.1 accepted FAIL
- Missing fixture: Client protocol disabled/network outage UNKNOWN

## MB-0029 — KEEP

Literal HTTP asset references absent in assessed markup/CSS

Check/args: {"name":"code_no_mixed_content","args":{"paths":["app"],"include_ext":["phtml","html","xml","css","less"],"max_results":50,"strict_scope":true}}

Source: src/Engine/Checks/CodeSearchCheck.php:209; src/Engine/Checks/HttpCheck.php:254

Thực tế: Literal HTTP subresource/form trong app markup/CSS; remote homepage thôi.

Đề xuất: Giữ bounded mixed-content signal; evidence file/line hoặc URL; JS generated/authenticated paths gap.

- Safe fixture: HTTPS resource/form references PASS
- Unsafe fixture: Literal HTTP script/form FAIL
- Missing fixture: Unreadable local roots hoặc remote failed UNKNOWN

## MB-0030 — REVISE

Sensitive cookies use Secure, HttpOnly, and SameSite

Check/args: {"name":"http_cookie_flags","args":{"strict_scope":true,"paths":["/","/customer/account/login","/checkout/cart"]}}

Source: src/Engine/Checks/HttpCheck.php:351; src/Engine/Checks/HttpCheck.php:401

Thực tế: Flags chỉ cho sensitive cookie names phát ra tại ba anonymous URLs; không chứng minh admin session.

Đề xuất: Giữ anonymous cookie checks; thêm observed configured/custom session names; explicit authenticated/admin workflow; SameSite=None+Secure hợp lệ cross-site cần exception theo integration.

- Safe fixture: Observed sensitive Secure/HttpOnly/Lax PASS
- Unsafe fixture: Sensitive thiếu Secure hoặc HttpOnly FAIL
- Missing fixture: Không Set-Cookie hoặc auth chưa quan sát UNKNOWN

## MB-0031 — KEEP

Declared Magento deployment mode is production

Check/args: {"name":"magento_production_mode","args":{"file":"app/etc/env.php","path":"MAGE_MODE","equals":"production"}}

Source: src/Engine/Checks/MagentoCheck.php:536

Thực tế: env.php MAGE_MODE production; không quan sát web-worker override.

Đề xuất: Giữ declared production security posture; evidence source; thêm runtime declaration riêng khi có.

- Safe fixture: MAGE_MODE production PASS
- Unsafe fixture: developer/default FAIL policy
- Missing fixture: Missing/malformed config UNKNOWN

## MB-0729 — REVISE

Declared project debug settings are disabled

Check/args: {"name":"magento_deployment_debug_flags_disabled","args":{}}

Source: src/Engine/Checks/MagentoCheck.php:137

Thực tế: Default-scope debug declarations và bốn project ini files; absence là không explicitly enabled.

Đề xuất: Giữ declared-scope claim; thêm website/store overrides và web-worker evidence riêng; không gọi live debug disabled.

- Safe fixture: Explicit flags off PASS scoped
- Unsafe fixture: Enabled template hint/display_errors/Xdebug FAIL
- Missing fixture: Malformed/DB inaccessible UNKNOWN; site-scope chưa quan sát là gap

## MB-0035 — OPTIONAL

Published static artifacts present in assessed deployment

Check/args: {"name":"fs_static_content_deployed","args":{"static_path":"pub/static","preprocessed_path":"var/view_preprocessed","min_static_files":1,"min_preprocessed_files":1,"strict_scope":true}}

Source: src/Engine/Checks/FilesystemCheck.php:710; src/Engine/Checks/HttpCheck.php:1270

Thực tế: Có ít nhất một published static artifact hoặc homepage assets hoạt động.

Đề xuất: Chuyển readiness optional; không tính vào security coverage; không ép deployment đầy đủ mọi theme/locale.

- Safe fixture: One nonempty real artifact PASS readiness
- Unsafe fixture: No published artifact FAIL readiness
- Missing fixture: Unreadable/static request failed UNKNOWN

## MB-0037 — OPTIONAL

Declared Full Page Cache type enabled

Check/args: {"name":"cache_type_enabled","args":{"file":"app/etc/env.php","type":"full_page"}}

Source: src/Engine/Checks/DeploymentStateCheck.php:32; src/Engine/Checks/HttpCheck.php:1308

Thực tế: Local full_page declaration; remote Age/X-Cache/Via cache heuristic khác claim.

Đề xuất: Chuyển readiness optional; bỏ remote variant khỏi declaration requirement hoặc tạo signal cache riêng supporting.

- Safe fixture: Local full_page=1 PASS declaration
- Unsafe fixture: Local full_page=0 FAIL readiness
- Missing fixture: Absent state UNKNOWN; CDN hit không PASS Magento FPC

## MB-0046 — OPTIONAL

Installed Magento cron entry present

Check/args: {"name":"installed_magento_cron","args":{"users":["www-data","nginx","apache","http","www","magento","deploy"],"timeout_ms":2500}}

Source: src/Engine/Checks/InstalledCronCheck.php:10

Thực tế: Có installed syntactically-valid cron:run cho đúng project; không chứng minh job chạy.

Đề xuất: Readiness advisory với accepted external scheduler; security relevance patch/task delivery giải thích riêng.

- Safe fixture: Installed correct-project cron PASS
- Unsafe fixture: Complete sources không entry FAIL readiness
- Missing fixture: Unreadable sources UNKNOWN; approved orchestrator N/A

## MB-0049 — KEEP

Composer dependency OSV advisory matches

Check/args: {"name":"composer_audit_api","args":{"lock_file":"composer.lock","endpoint":"https://api.magebean.com/v1/osv/advisories","timeout_ms":10000,"batch_size":500,"allow_private_http_fallback":true,"strict_scope":true}}

Source: src/Engine/Checks/Families/ComposerAdvisoryChecks.php:40

Thực tế: OSV matches locked versions và local advisory-specific hotfix evidence, không proof runtime dependency set.

Đề xuất: Giữ core security; show freshness/packages queried/hotfix validation; thiếu advisory coverage UNKNOWN, secret API token không log.

- Safe fixture: Patched version với complete dataset PASS
- Unsafe fixture: Applicable unfixed advisory FAIL
- Missing fixture: API failure/malformed lock/partial dataset UNKNOWN

## MB-0050 — KEEP

Adobe security release patch assessment

Check/args: {"name":"composer_adobe_security_patches_api","args":{"lock_file":"composer.lock","endpoint":"https://api.magebean.com/v1/adobe/security-patches","timeout_ms":10000,"allow_private_http_fallback":true,"strict_scope":true}}

Source: src/Engine/Checks/Families/ComposerAdvisoryChecks.php:255

Thực tế: Magento security-release branch current hoặc verified alternative patch; không runtime attestation.

Đề xuất: Giữ core patch assessment; fixture edition/version/security branch, unsupported branch, patch integrity; không latest-major policy.

- Safe fixture: Supported patched branch/verified patch PASS
- Unsafe fixture: Required patch missing/unsupported branch FAIL
- Missing fixture: Unknown version/dataset unavailable/unverified patch UNKNOWN

## MB-0730 — REVISE

No configured secret patterns in deployed application files

Check/args: {"name":"working_tree_secret_scan","args":{"paths":["."],"exclude_dirs":[".git","vendor","var","generated","node_modules","pub/media","pub/static","pub/cache","setup","dev/tests","dev/tools","app/etc/env.php"],"patterns":["AKIA[0-9A-Z]{16}","ASIA[0-9A-Z]{16}","AIza[0-9A-Za-z\\-_]{35}","-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----","xox[baprs]-[0-9A-Za-z\\-]{10,48}","sk_live_[0-9a-zA-Z]{24,}","gh[pousr]_[0-9A-Za-z]{36,255}","(api[_-]?key|client[_-]?secret|access[_-]?token|password)[[:space:]]*[\"']?[[:space:]]*(=>|=|:)[[:space:]]*[\"'][A-Za-z0-9_./+=-]{16,}[\"']"],"max_results":200,"max_file_bytes":16777216}}

Source: src/Engine/Checks/GitHistoryCheck.php:23; src/Engine/Checks/GitHistoryCheck.php:28

Thực tế: Regex secret scan deployed nonbinary files; excludes env.php, vendor,var,pub/media/static; redacts matches.

Đề xuất: Giữ suspected secret triage; inventory exclusions rõ; thêm scoped public/static exposure scan vì current excludes; không dump matched values.

- Safe fixture: Eligible clean files PASS scoped
- Unsafe fixture: Known secret match FAIL suspected finding, redacted
- Missing fixture: Oversize/unreadable/invalid pattern UNKNOWN

## Bổ sung cần ưu tiên

- MB-0027 HSTS: quan sát header HTTPS thật; không ép preload/subdomain. Safe valid year; unsafe missing/duplicate/zero; thiếu transport UNKNOWN. Source HttpCheck.php:199.
- MB-0009 admin session lifetime: default config 1..900s; không chứng minh runtime termination. Safe900; unsafe0/excessive; missing DB UNKNOWN. Source MagentoCheck.php:567.
- Scoped media executable: không promote broad human requirement. Detector AuthorizationSourceChecks.php:195 hiện skips unreadable/large rồi có thể PASS; phải sửa completeness trước. Fixtures PHP-in-JPG, phtml, handler htaccess, image clean, inaccessible/oversize tree.
- Public artifact HTTP: candidate HttpCheck.php:591 cần review sâu trước enable; verify content signature tránh SPA/error HTML200 false positive. Scope chỉ tested paths; không expose secret body.

Tổng 20: 8 KEEP, 8 REVISE, 4 OPTIONAL (đếm bằng JSON để xác minh). Giữ owner/group là deployment policy, nhưng env.php world-read/world-write vẫn là core security finding.
