# Rà requirements và checks: Hardening

82/82 membership đã có quyết định cụ thể. Đây là đề xuất, không phải source change hay chứng nhận detector accuracy.

Hardening phải giữ toàn bộ protection Basic: thêm MB-0728 (admin password scoped), MB-0729 (debug persisted), MB-0730 (deployed secrets). Hiện thiếu cả ba.

Phân loại OPTIONAL cho policy/readiness không có nghĩa xóa requirement; đưa vào section advisory có applicability và customer policy. env.php permissions vẫn là core security, chỉnh ownership defaults thay vì bỏ.

| ID | Quyết định | Nhận định, thay đổi và fixture cần chứng minh |
|---|---|---|
| MB-0001 | KEEP | Giữ lỗi world-writable; fixture mount/symlink/unreadable, code writable và vùng runtime hợp lệ. |
| MB-0002 | REVISE | Giữ bảo vệ env.php là security; cấu hình owner/mode theo deployment, không cố định root. Fixture ACL mở rộng và group web-process đọc/ghi. |
| MB-0003 | KEEP | Giữ artifact leakage; fixture backup đổi đuôi, dotfiles, docroot tùy chỉnh và alias HTTP. |
| MB-0004 | REVISE | Xác minh code không writable bởi web process; Unix bits không đủ ACL. Fixture deploy owner khác PHP user và immutable container. |
| MB-0005 | KEEP | Probe directory index theo URL rõ ràng; fixture 403/404/timeout/custom index và reverse proxy. |
| MB-0200 | REVISE | Tách file PHP trong media khỏi khả năng thực thi; dedup media detector; fixture nginx deny và nguy hiểm được allow, không upload thật vào production. |
| MB-0006 | OPTIONAL | Route khác admin là defense-in-depth, không chứng minh access control; fixture route tùy biến vẫn public và WAF bảo vệ. |
| MB-0007 | REVISE | Module declaration cần bổ sung enrollment/bypass/provider; fixture Magento 2FA enabled nhưng user chưa enroll, SSO hợp lệ. |
| MB-0209 | REVISE | Check admin lặp lại không chứng minh customer password; giữ MB-0728, tách admin/customer scope và inherited defaults. Fixture hai policy khác nhau. |
| MB-0009 | KEEP | Giữ threshold session đã khai báo; fixture override DB/config và missing values; chưa chứng minh session thực sự hết hạn. |
| MB-0010 | SUPPORT | Allowlist hint không chứng minh effective Admin restriction; fixture CDN/WAF, location sai và alternative route; cần runtime trusted vantage. |
| MB-0011 | KEEP | Giữ lockout/CAPTCHA cấu hình; fixture scope inheritance, disabled CAPTCHA và threshold vô hiệu; kiểm thử login riêng có kiểm soát. |
| MB-0100 | KEEP | Kiểm quan hệ admin_user/role/rule là bounded integrity; fixture orphan/cycle/disabled user/incomplete DB; không gọi đây là least privilege. |
| MB-0101 | REVISE | Danh sách role global phải do khách duyệt; fixture quyền thừa kế/custom ACL/wildcard và role rỗng; không chỉ đếm số superadmin. |
| MB-0102 | OPTIONAL | Chuyển evidence vendor defaults vào audit readiness; JSON tài liệu không chứng minh account bị vô hiệu. Fixture stale evidence và scope thiếu. |
| MB-0108 | SUPPORT | Raw SQL marker chỉ triage; fixture bind params an toàn so với concat untrusted, wrapper Magento; cần dataflow trước kết luận injection. |
| MB-0105 | SUPPORT | Escaping phụ thuộc HTML/JS/URL context; dedup obligations; fixture escapeHtml trong JS và safe framework renderer. |
| MB-0014 | REPLACE | Không cấm mọi superglobal ở severity cao; thay bằng untrusted input đến sensitive sink. Fixture $_SERVER dùng hợp lệ và tainted request sink. |
| MB-0015 | SUPPORT | Form_key presence không chứng minh server CSRF validation; fixture GET mutation, JSON API, framework CSRF interface và token không validate. |
| MB-0016 | SUPPORT | SSRF phải xét redirect/DNS/private IP/protocol; fixture allowlist substring bypass và URL encode; static presence chưa đủ. |
| MB-0131 | SUPPORT | Unserialize phải xét nguồn dữ liệu/allowed_classes; fixture safe serialization, user-controlled object và wrapper Magento; dedup. |
| MB-0109 | SUPPORT | Command APIs không tự là injection; fixture escaped arg, executable path taint và shell concatenation; dedup. |
| MB-0019 | SUPPORT | Phân biệt eval động với literal và assert phiên bản PHP; fixture user-controlled code, comments và generated code. |
| MB-0020 | SUPPORT | Traversal cần canonical containment; fixture ../, symlink escape, double encoding và safe file API. |
| MB-0021 | SUPPORT | Upload cần extension/MIME/content/storage/execution policy; fixture double extension và image polyglot; dùng chung evidence MB-0200. |
| MB-0023 | SUPPORT | Weak PRNG chỉ security khi dùng token/secret; fixture rand cho UI so với reset token, random_bytes wrapper. |
| MB-0424 | SUPPORT | Redaction phải theo data và sink; fixture PAN/token/PII đã mask và logger wrapper; không lộ secret trong finding; dedup. |
| MB-0025 | SUPPORT | Raw crypto/session API là review signal; fixture authenticated encryption và native session legitimate; không gọi mọi usage là vulnerability. |
| MB-0094 | SUPPORT | Authorization cần runtime role/resource/object ownership; fixture inherited _isAllowed, anonymous webapi và cross-customer access. |
| MB-0095 | SUPPORT | Anonymous GraphQL/API có trường hợp đúng; fixture public catalog so với customer PII, schema exposure có auth; không cấm mặc định. |
| MB-0097 | SUPPORT | Secret heuristics có false positive; fixture dummy key, multiline key, indirect vault và deployed secret; giữ thêm MB-0730. |
| MB-0098 | SUPPORT | XXE phụ thuộc parser options/runtime; fixture LIBXML_NONET chưa đủ, external entity enabled và harmless XML. |
| MB-0099 | SUPPORT | Export/download cần ownership và path containment; fixture logged-in cross-customer export và protected inherited middleware. |
| MB-0026 | REVISE | Test storefront/admin endpoints và trusted proxy redirects; fixture TLS terminator, redirect loop và HTTP credential post. |
| MB-0027 | KEEP | Giữ HSTS max-age predicate đúng response đã test; fixture repeated headers/subdomains/CDN; không tự áp preload. |
| MB-0028 | REVISE | Probe endpoint TLS với timeout và unavailable cipher support; fixture TLS1.0/1.1 enabled, tool thiếu protocol và CDN termination. |
| MB-0029 | SUPPORT | Literal HTTP scan không bắt DOM dynamic resource; fixture CSS url, protocol-relative và JS-generated mixed content. |
| MB-0030 | REVISE | Cookie probe anonymous không chứng minh admin/auth sessions; fixture cookie deletion, login cookies, SameSite=None thiếu Secure và path/domain. |
| MB-0089 | SUPPORT | CSP phải enforced trên checkout thực, không chỉ config marker; fixture report-only, unsafe-inline nonce và Magento version-dependent behavior. |
| MB-0096 | SUPPORT | Security headers theo endpoint/architecture; fixture duplicated permissive headers, API content type và proxy overrides. |
| MB-0031 | KEEP | Production declaration useful; fixture deployment env override; production mode không thay debug checks MB-0729/0379. |
| MB-0379 | REVISE | Tách persisted flags, HTTP disclosure, PHP-FPM effective config; CLI ini không đại diện FPM; dedup và giữ MB-0729. Fixture prod mode+xdebug/error display. |
| MB-0034 | OPTIONAL | DI artifact presence là readiness; fixture generated/code symlink/read-only build và irrelevant empty artifacts. |
| MB-0035 | OPTIONAL | Static artifacts là readiness; fixture CDN assets/deployment strategy và stale files. |
| MB-0037 | REVISE | Giữ readiness declaration riêng; remote Age/X-Cache không chứng minh env.php FPC. Fixture CDN cache trong khi Magento FPC tắt. |
| MB-0038 | OPTIONAL | Redis/Varnish là kiến trúc/performance, không bắt buộc security. Fixture safe file cache và managed cache; không fail vì khác vendor. |
| MB-0039 | OPTIONAL | Indexer valid snapshot là vận hành; fixture legitimate processing/reindex và stale DB; không security high. |
| MB-0040 | REVISE | Không ép Redis: auth/TLS/isolation theo backend; hiện non-Redis FAIL. Fixture Unix socket Redis, external vault ACL, secure files sessions và public Redis. |
| MB-0042 | KEEP | Log/report ngoài docroot useful leakage predicate; fixture symlink alias, custom docroot và HTTP deny; absence local không chứng minh không public. |
| MB-0043 | OPTIONAL | Rotation cần hiệu lực/freshness/central logging; fixture journald/container stdout và file config stale. |
| MB-0046 | OPTIONAL | Cron có thể do orchestrator thay crontab; fixture Kubernetes scheduler/systemd và duplicate entries. |
| MB-0047 | OPTIONAL | 900s tùy schedule; fixture timezone/clock skew/quiet cron và DB thiếu; report timestamp rõ. |
| MB-0048 | OPTIONAL | 1000 backlog tùy workload; fixture long-running legitimate jobs, retry storm và per-group thresholds. |
| MB-0049 | KEEP | Known advisory matching cần version/range/source freshness; fixture alias/dev version, timeout và partial API không PASS. |
| MB-0050 | KEEP | Adobe patch applicability cần edition/product/hotfix; fixture supported security patch/backport và unsupported product không gán false FAIL. |
| MB-0051 | SUPPORT | Fixed version không chứng minh upgrade deployable; fixture conflict Magento/PHP, no fix và backport. Đưa remediation action theo advisory. |
| MB-0052 | SUPPORT | Risk tags+maintenance metadata không chứng minh enabled module an toàn; fixture disabled extension, app/code module ngoài Composer và source unavailable. |
| MB-0053 | OPTIONAL | Mitigation documentation là evidence workflow; fixture expired WAF exception và scope advisory mismatch; không thay finding CVE. |
| MB-0054 | SUPPORT | KEV match tăng ưu tiên, không chứng minh exploitation; fixture CVE mapping package ambiguous và partial metadata. |
| MB-0055 | KEEP | Giữ transitive advisories, dùng chung observation MB-0049; fixture dev-only prod relevance và transitive package missing version. |
| MB-0056 | SUPPORT | Constraint cho phép fix không nghĩa resolver cài được; fixture transitive conflicts và platform constraints; dùng dry-run controlled environment. |
| MB-0057 | REVISE | Withdrawn package không đồng nghĩa vulnerable; trả lifecycle warning kèm lý do; fixture yanked vì packaging so với security và unknown status. |
| MB-0058 | OPTIONAL | Marketplace current/maintained phải xét entitlement và compatible release; fixture private extension/latest incompatible/metadata missing. |
| MB-0059 | REPLACE | Ngày advisory xuất bản không phải thời gian khách bị exposed hay SLA; thay patch deadline theo severity/KEV và installed affected version. Fixture old fixed/new critical. |
| MB-0060 | OPTIONAL | Vendor support là procurement evidence; fixture valid paid support dù package public ít update, expired contract. |
| MB-0061 | REVISE | Abandoned lifecycle risk cần replacement/reachability; dedup check; fixture official replacement/private fork và unsupported API metadata. |
| MB-0062 | OPTIONAL | 24 tháng release age không chứng minh unmaintained; fixture mature stable library và vendor-supported long-term release. |
| MB-0063 | OPTIONAL | Repo activity/archive là tín hiệu maintenance; fixture mirrored/private repo, archived upstream với supported fork và rate limit. |
| MB-0064 | SUPPORT | Fork provenance cần reason/patch evidence; fixture approved security backport fork, unknown fork và malicious replacement; không coi mọi fork lỗi. |
| MB-0065 | OPTIONAL | Wildcard là reproducibility policy khi có lock; fixture locked wildcard, unlocked prod và require-dev scope. |
| MB-0066 | OPTIONAL | Dev branch cần pin commit/provenance; fixture pinned supported fork, dev-only tooling và floating production branch. |
| MB-0067 | OPTIONAL | prefer-stable không phải vulnerability; fixture minimum-stability stable không khai báo prefer-stable và deliberate prerelease. |
| MB-0069 | OPTIONAL | Latest stable không nhất thiết Magento compatible; fixture latest major breaks PHP và supported patched older line; dev deps riêng. |
| MB-0070 | KEEP | Lock identity/hash consistency là supply-chain integrity bounded; fixture edited json/hash mismatch, aliases/path repo và installed vendor differs lock. |
| MB-0072 | REVISE | Production thường không có .git; UNKNOWN phải có deployed scan MB-0730 bù; fixture no git, old revoked secret, PCRE tool unavailable và redact output. |
| MB-0073 | SUPPORT | Literal endpoints bỏ sót dynamic URL, HTTP internal hợp lệ; fixture secret-bearing HTTP gateway so với private healthcheck và proxy TLS. |
| MB-0075 | SUPPORT | HMAC marker không chứng minh signed raw body, constant-time và replay; fixture reused nonce/old timestamp/signature wrong secret. |
| MB-0076 | REVISE | Host OUTPUT default deny không chứng minh effective cloud/container/network allowlist; iptables fallback bỏ qua ACCEPT rules. Fixture DROP+ACCEPT, IPv6/nftables/cloud ACL. |
| MB-0077 | SUPPORT | PII minimization phụ thuộc nghiệp vụ và consent; fixture hashed identifier re-identifiable, approved required payload và unknown schema. |
| MB-0078 | REPLACE | Tên upstream gateways nhưng đọc local nginx/apache. Một file strong trả PASS dù endpoint khác weak; config không tìm thấy FAIL sai managed TLS. Probe actual upstream/TLS evidence theo scope. |
| MB-0079 | REPLACE | Thay bắt key nằm env.php bằng bảo vệ secret backend; cho vault/env injection/encrypted external storage. Fixture secure vault và env.php public-readable. |
| MB-0081 | SUPPORT | ACL/IP markers không chứng minh least privilege token; fixture scoped token nhưng endpoint thiếu ACL, unrestricted OAuth và revoked integration. |

## Đọc implementation

- AdminAclCheck.php:22 đọc ba bảng, kiểm integrity; least privilege cần approved role context.
- PhpConfigCheck.php:541 session storage chỉ chấp nhận Redis/password; cần applicability cho backend khác.
- SystemCheck.php:80 fallback OUTPUT policy và WebServerConfigCheck.php:93 first strong local config là priority review findings, chưa exploit validation.
- ComposerVersionChecks.php:432 latest release check include dev; tách maintenance khỏi vulnerability.
- Source checks qua CodeSearchCheck facade tới các Families: không có pattern chưa chứng minh request flow an toàn; root scope probe chỉ xác minh động tám methods.

Tham chiếu catalog/registry theo từng ID nằm trong focused-hardening-review.json; fixtures ở bảng là acceptance gaps đề xuất, chưa tuyên bố mọi fixture đang thiếu trong test suite.
