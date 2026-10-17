# Hợp đồng mục tiêu cho Basic, Hardening và OWASP

Đề xuất để review implementation, 2026-10-17. Không tự thay đổi catalog, severity, execution hay profile key.

## Basic

Người dùng: chủ shop/kỹ sư chạy scan đầu tiên hoặc trước deploy Magento.
Kết quả: phát hiện các cấu hình/exposure/version/secret rõ ràng, tác động cao trong phạm vi đã quan sát. Không yêu cầu tài liệu compliance để bắt đầu scan.

- Core: world-writable và secret-file exposure, public sensitive artifacts, Admin configuration, HTTPS/TLS/cookies, debug, deployed secret/executable evidence, dependency/Adobe advisories.
- Bổ sung có scope: HSTS, Admin session policy, executable uploads. Không tự promote toàn requirement rộng thành automated; dùng predicate đủ chứng minh điều kiện hẹp và giữ evidence thiếu.
- Env.php world-readable/world-writable là rủi ro cần giữ; exact owner/group reference0640 là policy configurable, không làm biến mất core protection.
- FPC/static artifact/cron presence có ích cho readiness; tách khỏi vulnerability mặc định hoặc hiển thị advisory lane có lý do/exception.
- Mỗi check cần rẻ, bounded, read-only và evidence đủ để khách hàng tìm/sửa/chạy lại. HTTP-only không giả định đọc được env.php/admin route.

## Hardening

Người dùng: người vận hành production muốn phòng vệ sâu hơn.
Kết quả: giữ tất cả protection Basic, thêm effective access/config/runtime protections và các observations sâu hơn. Có thể cần context/quyền đọc cao hơn, nhưng không biến missing privilege thành PASS.

- Basic subset theo protection và scope, không chỉ theo ID. Replacement phải có fixture chứng minh tương đương.
- Thêm Admin access/ACL/session, upload execution restrictions, logs exposure, storage authentication, advanced source/config observations và supply-chain security.
- Latest version, wildcard/dev constraints, Redis architecture, release recency, indexers/cron thresholds không tự động là vulnerability. Cho phép policy/architecture ngoại lệ có căn cứ; không bắt upgrade major mù quáng.
- Vault hoặc external secret management hợp lệ phải được chấp nhận theo protection/access criteria, không ép env.php là kiến trúc duy nhất.

## OWASP

Người dùng: developer/security engineer triage ứng dụng và customizations Magento.
Kết quả: phát hiện dấu hiệu SQLi/XSS/CSRF/SSRF/command/deserialization/auth/upload/secret risks và nêu bước xác minh. Không tuyên bố broad category an toàn từ absence-of-pattern.

- Check nguồn phải thể hiện files considered/read/skipped/unreadable, cutoff/truncation, actual paths/extensions; vendor/custom themes/generated/browser assets chưa quét phải nói rõ.
- Pattern match là observation có độ tin cậy, không mặc định confirmed exploit. Sinks/guards ở một endpoint không chứng minh mọi endpoint an toàn.
- Dynamic cases cần controlled scenarios và tài khoản/quyền cụ thể. Hướng dẫn manual phải là hành động và expected outcome, không chỉ chép criterion.
- Shared detector có một observation/evidence identity; giữ nhiều obligation/alignment nhưng không tạo nhiều remediation tasks cho cùng bug.

## Hợp đồng chung cho từng requirement/check

Mỗi dòng review phải có: lỗi khách hàng cần tìm, criterion hẹp, checks+args+scope hiện tại, claim implementation thực sự chứng minh, quyết định membership, bằng chứng bắt buộc, giới hạn/human boundary, fixtures và priority.

Các quyết định: KEEP, REVISE, OPTIONAL, REPLACE, SUPPORT. OPTIONAL giữ identity/check khả dụng cho custom/explicit selection; không đồng nghĩa xóa khỏi catalog. SUPPORT phải vẫn chạy khi áp dụng được nhưng không nâng thành broad requirement PASS. REPLACE bảo toàn migration aliases và lịch sử assessment.

Các trạng thái cần phân biệt: verified technical violation, suspicious observation, checked-with-no-match, no applicable sink, insufficient evidence, collection error và human requirement conclusion. Không có scope hoặc bị giới hạn scan không được trình bày như đã xác minh an toàn.

Nghiệm thu mỗi check: fixture safe, violating, missing, malformed, permission-denied, truncated/oversized, alternate legitimate architecture; remote/local variants cần chứng minh cùng criterion hoặc tách claim. Automated positive phải có evidence về phạm vi đầy đủ, không chỉ `offenders=[]`.

CLI và Console cần cùng execution/evidence policy. Đổi profile phải version membership, import catalog, giữ existing assessment snapshots và test selection/agent/report contracts. Lượt review này chưa thực hiện rollout.
