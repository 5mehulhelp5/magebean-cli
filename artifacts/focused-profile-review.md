# Rà lại Basic, Hardening và OWASP theo mục tiêu khách hàng

2026-10-17. Review requirements, check bindings, implementation và hành vi trên fixture tạm. Chưa sửa source/catalog/Console hoặc scan production.

## Đã hoàn thành

- Rà20 Basic,82 Hardening,69 OWASP memberships:171 dòng,85 requirement IDs duy nhất.
- Xuất263 check-binding occurrences gồm overlaps và execution variants, đầy đủ args/role/proof, trong `focused-check-bindings.json`. Đây không phải263 detectors độc lập.
- Mỗi membership có quyết định, thay đổi đề xuất, giới hạn bằng chứng và fixture nghiệm thu; dữ liệu hợp nhất trong `focused-profile-decisions.csv`.
- Đã chạy32 observations thật trên source fixtures qua8 checks: missing scope, empty scope, oversized source và readable risky source. Không thực thi nội dung payload và không gọi network.

## Quyết định đề xuất

| Profile | KEEP | REVISE | REPLACE | SUPPORT | OPTIONAL |
|---|---:|---:|---:|---:|---:|
| Basic |8|8|0|0|4|
| Hardening |13|16|4|30|19|
| OWASP |23|22|3|14|7|

KEEP giữ mục đích/membership, không đóng băng implementation hoặc chứng nhận check đã đúng. Shared collector/check fixes phải áp dụng cho mọi profile dùng chúng, kể cả dòng ghi KEEP. SUPPORT phải chạy và hiển thị observation phù hợp, nhưng giữ human boundary; không mass-promote heuristic thành confirmed violation. OPTIONAL giữ identity/check trong catalog và chuyển thành readiness/policy/advisory, không xóa lịch sử. Counts là review proposals, chưa phải target membership cuối cùng sau additions/consolidations.

## Phát hiện cần xử lý trước

### 1. Collection completeness: đã tái hiện

8 checks `code_raw_sql`, `code_phtml_escaped_output`, `code_csrf_form_key`, `code_ssrf_safeguards`, `code_unserialize_safety`, `code_command_execution_safety`, `code_upload_safety`, `code_js_context_escaping` đều trả PASS khi source root thiếu/trống hoặc chỉ có file quá1MiB. Cùng snippet nguy hiểm khi đọc được cho8 FAIL.

`CodeInventoryCollector.php` bỏ root thiếu/file quá giới hạn; một số source family bỏ read=false rồi dùng absence-of-offenders làm success. Human gate hiện ngăn broad requirement PASS, nhưng các observation vẫn có wording gây hiểu nhầm. Cần inventory/completeness evidence, giữ findings đã đọc và phân biệt no-applicable-sink với missing/truncated/unreadable scope.

Probe: `probe-source-scope-review.php`; kết quả: `focused-source-scope-observations.json`. Không mở rộng kết luận động này sang mọi source check.

### 2. Basic: scoped security trước readiness

- Giữ core env.php world-read/world-write protection; exact owner/group reference cần deployment policy cấu hình được.
- MB-0026 REMOTE include_admin đọc backend.frontName từ env.php; URL-only không có dữ liệu này. Tách storefront/admin observations hoặc yêu cầu explicit admin context, không giữ requirement không thể thu đủ evidence từ target mode.
- MB-0007 provider-module mapping cần authentic Magento version/config fixtures. Nguồn Adobe mô tả providers/IMS làm rõ rằng native module declaration không chứng minh toàn login enforcement. Đây là compatibility review, chưa xác nhận ảnh hưởng trên mọi Magento release.
- MB-0030 anonymous probes không chứng minh authenticated Admin cookie behavior; MB-0729 persisted/default scope không chứng minh runtime worker/website/store overrides.
- Static/FPC/cron và tùy biến route là candidates advisory/readiness; không đồng nhất failure với vulnerability.
- Add candidates: MB-0027 HSTS, MB-0009 scoped session lifetime, scoped executable-media observation sau sửa collection gaps, HTTP public-artifact observation sau review sâu. Không auto-promote broad upload/human requirement.

### 3. Hardening: giữ protection Basic và bổ sung đúng security

- Thêm MB-0728/0729/0730 hoặc replacements có fixture chứng minh equivalent scope; broad human/Git-history checks không tự thay được deployed/configured observations.
- MB-0040 check session storage ép Redis/password khi criterion chỉ nói declared Redis; non-Redis cần applicability/approved architecture, không tự FAIL.
- Local TLS config thành công ở một file không chứng minh mọi vhost/upstream; managed TLS không có file local không tự là weak TLS.
- Firewall default DROP không chứng minh effective egress allowlist nếu chưa đánh giá ACCEPT exceptions; cần effective rules/context.
- Thay direct-superglobal prohibition, advisory-age-as-SLA, env.php-only-secret-storage và latest-stable policy bằng scoped security observation/policy phù hợp. Không hướng dẫn upgrade major chỉ để làm check xanh.

### 4. OWASP: phát hiện nguồn có ngữ cảnh và evidence có thể hành động

- Chạy technical observations trong human requirements, tách technical finding khỏi conformance conclusion.
- Source inspection thấy any PHP webhook signature signal có thể suppress XML endpoint findings khác; cần binding route/service/class tương ứng. Chưa reproduction riêng.
- Auth keywords `isLoggedIn/getCustomerId` không chứng minh ownership; cần cross-customer IDOR fixtures và inherited middleware/ACL cases.
- Upload MIME/size/path keywords không chứng minh validation; raw SQL direct APIs/PDO có thể là prepared/bound an toàn. Không biến pattern candidate thành exploit đã xác nhận.
- Lưu coverage, locations/kinds/confidence, missing context và action xác minh; dedup shared observation/remediation, giữ obligations riêng.

## Backlog triển khai đề xuất

1. **P0 collection contract**: missing/truncated/read-failed không ra misleading clean check; fixtures safe/violating/missing/malformed/oversized.
2. **P0 execution/conclusion contract**: CLI+Console chạy eligible observations dù requirement cần người; human/unknown không bị đổi thành PASS, suspected findings không tự thành confirmed vulnerabilities.
3. **P0 Basic scope fixes**: 2FA compatibility fixtures, HTTPS admin context, env protection policy, cookies/debug scope, media completeness.
4. **P1 membership**: chốt Basic security core/advisory; Hardening bảo toàn Basic; OWASP ưu tiên application-risk observations.
5. **P1 source predicate fixes**: auth/SSRF/SQL/upload/webhook có positive/negative counterexamples theo endpoint/control flow.
6. **P1 rollout parity**: version profile membership, giữ aliases/assessment snapshots, test agent payload/report semantics, import Console catalog cùng release. Chưa thực hiện rollout trong lượt review này.

Không chốt số lượng requirement mới trước khi fixture chứng minh scope và equivalent replacements. Chọn OPTIONAL không đồng nghĩa xóa check/requirement.

## Hồ sơ review từng dòng

- `focused-basic-review.md/json`: checks+args, source refs, actual claim, proposed scope, safe/unsafe/missing fixtures và additions.
- `focused-hardening-review.md/json`:82 decisions, fixture gaps, references và Basic protection inheritance.
- `focused-owasp-review.md/json`:69 decisions, bindings/roles/proof, collection acceptance và human boundaries.
- `focused-profile-contract.md`: customer goals và acceptance contract chung.
- `focused-profile-decisions.csv/json`: consolidated decisions và coverage validation.
- `focused-check-bindings.json`: current recipes/args/variants. Test-name mentions chỉ là navigation hints, không phải test coverage.

Nguồn bên ngoài cho review2FA: [Adobe2FA](https://experienceleague.adobe.com/en/docs/commerce-admin/systems/security/tfa/security-two-factor-authentication), [Magento TwoFactorAuth module](https://github.com/magento/security-package/blob/develop/TwoFactorAuth/etc/module.xml), [provider DI](https://github.com/magento/security-package/blob/develop/TwoFactorAuth/etc/di.xml). Các nguồn này không thay authentic version fixtures. Những nhận định implementation còn lại dựa source nội bộ và probes đã nêu, không phải compliance certification hoặc exhaustive detector validation.
