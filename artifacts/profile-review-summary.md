# Phản biện checks và requirements theo profile

Ngày: 2026-10-17. Phạm vi: bảy profiles hiện còn trong source CLI và đường đi catalog/agent của Console. Không sửa behavior hoặc scan website/production trong lượt này.

## Kết luận

Profile cần được đánh giá theo công việc khách hàng thực hiện, không theo số requirement. Human evidence có thể cần thiết để tránh kết luận tuân thủ sai, nhưng không phải lý do bỏ các quan sát kỹ thuật hữu ích. Cần tách kết quả check, finding kỹ thuật và kết luận requirement.

## Số liệu kiểm tra trực tiếp

Các cột có check/không cần người là trên toàn inventory của profile. Default LOCAL là lựa chọn của planner với context trống, chưa scan target. Một requirement có thể gọi nhiều check, và một check có thể dùng ở nhiều requirements/profiles.

| Profile | Inventory | Có check trong obligations | Không có check | Không cần human | Default LOCAL |
|---|---:|---:|---:|---:|---:|
| basic | 20 | 20 | 0 | 20 | 20 |
| hardening | 82 | 82 | 0 | 41 | 41 |
| OWASP Top 10 | 69 | 69 | 0 | 31 | 31 |
| ASVS L1 | 69 | 41 | 28 | 0 | Không tạo được plan |
| ASVS L2 | 252 | 89 | 163 | 0 | Không tạo được plan |
| ASVS L3 | 344 | 97 | 247 | 0 | Không tạo được plan |
| PCI DSS | 257 | 32 | 225 | 0 | Không tạo được plan |

Bật human review: LOCAL ASVS L1 chọn69; L2 chọn197; L3 chọn267; PCI chọn257. Bật thêm mọi capability trong catalog: L2 chọn252 và L3 chọn344. Counts ASVS theo level bao gồm inheritance, không cộng thành tổng requirement độc lập.

Script audit: `artifacts/audit-profile-coverage.php`. Ma trận per-profile/per-requirement: `profile-review-inventory.csv`; số liệu planner, omissions, overlap và synthetic evaluator: `profile-review-inventory.json`.

## Phản biện theo nhu cầu

### basic: default trước deploy và kiểm tra định kỳ

Giá trị: gọn,20 requirements có checks; phù hợp làm điểm bắt đầu. Cần chứng minh phạm vi của từng điều kiện, không quảng bá như bảo đảm an toàn toàn Magento.

- HSTS MB-0027 và bounded admin session MB-0009 không được chọn, trong khi các policy readiness FPC/static/cron lại nằm trong profile. Đây là lựa chọn ưu tiên cần giải thích với khách hàng, không tự động coi là lỗi catalog.
- MB-0037 REMOTE dùng heuristic HTTP cache signals cho criterion khai báo `env.php cache_types.full_page`. Synthetic tất cả checks PASS vẫn ra UNKNOWN cho requirement này: không thể sửa bằng chỉ làm network thành công.
- FPC/static deployment/cron presence có giá trị vận hành, nhưng thất bại không luôn là vulnerability. Cần phân biệt security finding với readiness/policy.
- Điều kiện nghiệm thu: mỗi check có fixture tốt/xấu/thiếu evidence; kết luận đúng scope; REMOTE không dùng recipe không đủ chứng minh criterion LOCAL.

### hardening: kiểm tra sâu hơn basic

- Không phải superset của basic: thiếu MB-0728/0729/0730 (password minimum, debug flags, deployed working-tree secrets). Broad human counterparts không bù được coverage mặc định vì bị lọc.
- 41 human-required definitions còn chứa technical checks; default không thu các observations này. Tăng độ sâu phải thể hiện bằng detector/evidence thực sự chạy, không chỉ thêm checklist.
- Cần phân biệt dependency advisory với upgrade/architecture preference; deduplicate theo package/advisory/scope và giữ relationship evidence.
- Điều kiện nghiệm thu: mọi protection của basic được giữ hoặc có replacement chứng minh tương đương; không đếm lại cùng finding để tạo cảm giác sâu hơn.

### OWASP: phát hiện dấu hiệu rủi ro ứng dụng

- 69 requirements đều có checks, nhưng38 cần human và bị default loại. Các source observations hữu ích phải có lối hiển thị riêng.
- Cấu hình/source pattern không chứng minh authorization, SSRF hoặc flow nghiệp vụ đầy đủ. Negative pattern match không phải PASS ứng dụng.
- Có lặp exact check+args trong một số definitions; tái dùng evidence và giữ provenance, không coi số lần gọi là độ rộng bảo vệ.
- Điều kiện nghiệm thu: technical observations có vị trí/phạm vi/remediation; category coverage không bị trình bày như xác nhận toàn bộ category an toàn.

### ASVS L1/L2/L3: đánh giá bằng chứng theo mức

- Tất cả profiles bị human filter làm rỗng mặc định. Human gate giữ kết luận đúng, nhưng UX cần chạy phần evidence collection khả thi.
- L2/L3 thêm nhiều obligation thủ công. Inventory344 của L3 chỉ có97 definitions chứa checks, không thể trình bày thành344 checks tự động.
- Capability thiếu làm omission, không có nghĩa không áp dụng. Phải ghi lý do và cho người dùng bổ sung context.
- Supporting observations không quyết định requirement verdict; synthetic all-PASS chỉ ra MANUAL_REVIEW. Điều này đúng cho kết luận broad, nhưng khách hàng vẫn cần technical findings riêng khi observations có vấn đề.
- Bindings cần sửa/thu hẹp: MB-0172 nói client-side technologies nhưng chỉ kiểm Composer; MB-0399 nói inventory/SBOM nhưng chưa tạo/kiểm inventory đầy đủ; MB-0403 nói thời hạn remediation theo chính sách nhưng dùng latency_days=30 cố định; MB-0194 resource safety chỉ dùng upload source patterns. Đây là partial evidence, không phải đã chứng minh criterion.
- L2 thêm183 members so với L1 nhưng chỉ48 members có check; L3 thêm92 nhưng chỉ8 members có check. Các phần thêm phải đem lại workflow đánh giá sâu hơn, không quảng bá như mức tăng tương đương về automated detection.
- Điều kiện nghiệm thu: mỗi obligation có evidence cần thiết, scope, người phụ trách và cách kiểm; inheritance không lặp công việc; các bindings được review theo từng domain.

### PCI: chuẩn bị đánh giá môi trường thanh toán

- 225/257 requirements không có checks trong definitions; đây chủ yếu là evidence workflow, chưa phải257 automated tests.
- Một số binding không khớp criterion nội bộ: MB-0572 dùng password minimum8 cho criterion nêu12 và điều kiện exception; MB-0625 dùng logs-not-webroot cho protection-from-modification; MB-0634 dùng logrotate-file-present cho retention12months/3months availability. Đây là evidence yếu, không phải bằng chứng đã có false normative PASS vì chúng là supporting heuristics.
- Evidence cần applicability, scope, source, thời điểm và điều kiện đủ. Chỉ có một file/chứng từ không chứng minh vận hành thực tế.
- Điều kiện nghiệm thu: tự động thu phần kỹ thuật có thể thu, nhóm evidence dùng chung, không biến absence-of-pattern thành tuân thủ.

## Khoảng hụt xuyên CLI và Console

1. `src/Engine/ScanPlanner.php:65` loại toàn definition cần human, thay vì chỉ giữ human gate ở kết luận.
2. `src/Engine/RequirementAssessmentEvaluator.php:32` vẫn thu supporting checks nhưng bỏ chúng khỏi verdict. Cần technical observation/finding lane, không biến heuristic FAIL thành confirmed requirement FAIL.
3. Console `app/Services/ImportSecurityCatalog.php:180` thay checks của human definitions thành manual dispatcher trong metadata import. Đây chưa phải cơ chế lưu đầy đủ technical support.
4. Console `app/Actions/AgentJobs/QueueAssessmentScan.php:41` và eligibility chỉ queue automated items. Với assessment mới theo catalog hiện tại, ASVS/PCI không có item đủ điều kiện tự động qua luồng này; không chỉ CLI bị lọc.
5. Console manifest đang gửi rules/parameters, không mang capability context của profile. Cần đồng bộ applicability trước khi mở rộng chạy support checks.
6. `src/Console/ScanCommand.php:205` trả success khi không xác nhận được Magento ở REMOTE. Không nên dùng exit0 để suy ra đã kiểm xong/không có lỗi nếu requirement chưa chạy.

## Thứ tự khuyến nghị

- P0: thống nhất execution/evidence/conclusion trên CLI và Console; chạy observations áp dụng được nhưng giữ human gate; ASVS/PCI không còn rỗng mặc định.
- P0: sửa recipe/criterion mismatch (đặc biệt REMOTE FPC/HSTS) và giữ missing evidence ở trạng thái incomplete.
- P1: rà basic/hardening theo giá trị security so với readiness, bảo đảm hardening không bỏ protection của basic; deduplicate findings.
- P1: sửa bindings PCI và kiểm proof sufficiency của các domain ASVS; hướng dẫn evidence phải cụ thể.
- P2: bổ sung active test workflows/context/connectors khi khách hàng cần, sau khi coverage hiện có được chạy và trình bày đúng.

## Báo cáo chuyên sâu

- `profile-review-deployment.md` và bảng decisions basic/hardening.
- `profile-review-asvs.md`, `profile-review-asvs-members.csv`.
- `profile-review-owasp-pci.md`, `profile-review-owasp-pci-members.csv`.

## Giới hạn

Đã inventory toàn membership, gọi planner thực và evaluator với observations giả để kiểm logic. Đây không phải kết quả scan Magento, không chứng minh độ chính xác của mọi collector/predicate, không chứng nhận ASVS/PCI và chưa phải exhaustive semantic review từng binding. Các báo cáo chuyên sâu chỉ rõ phần đã inspect sâu và đề xuất còn cần fixture. Không dùng synthetic all-PASS để kết luận profile an toàn.
