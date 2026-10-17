$c=Get-Content src/Rules/requirements/internal-catalog.json -Raw|ConvertFrom-Json
$p=Get-Content src/Rules/requirements/internal-profiles.json -Raw|ConvertFrom-Json
$ids=$p.profiles.'owasp-top-10-2025'.requirement_ids
$special=@{}
@'
MB-0014|REPLACE|Direct superglobal references là input-handling review signal, không tự động là vulnerability.|Validated harmless input vs raw input vào sink; comment/string không finding.
MB-0015|REVISE|Form/CSRF validation signals không chứng minh server từ chối missing/invalid token.|Token trong HTML nhưng thiếu server validation; JSON/AJAX routes; cross-user token.
MB-0016|REVISE|Outbound URL sinks thiếu SSRF safeguards signals; không khẳng định an toàn bằng keyword.|Unrelated allowlist gần sink, redirect metadata, DNS rebinding, helper ngoài window.
MB-0019|REVISE|Dynamic execution sinks và input context cần triage.|Comment/string eval; request-derived arg vs safe literal; wrapper/variable function.
MB-0020|REVISE|Filesystem sinks thiếu dấu hiệu path confinement.|realpath không boundary check; /safe2 prefix bypass; symlink escape; safe helper.
MB-0021|REVISE|Upload sinks thiếu MIME/extension/size/storage validation signals.|Client-provided MIME không trusted; double extension; unrelated size/allowed keyword.
MB-0023|REVISE|Weak PRNG trong security-sensitive contexts được nhận diện.|rand UI không vulnerability; reset token dùng rand; helper/alias bypass.
MB-0025|REVISE|Native crypto/session API usage cần review; Magento wrapper không bảo đảm safe.|Safe vetted library; wrong algorithm/key in wrapper; native code unreachable.
MB-0034|OPTIONAL|Generated DI artifacts là production readiness signal.|Runtime/build layout hợp lệ thiếu generated không security vulnerability.
MB-0035|OPTIONAL|Static artifacts là deployment readiness signal.|CDN/remote assets/build pipeline; chuyển readiness lane.
MB-0043|OPTIONAL|Local rotation config tồn tại; không chứng minh retention/central logging.|External log service hợp lệ; stale local config; Hardening readiness.
MB-0059|OPTIONAL|Advisory age so SLA cấu hình, tách policy khỏi actual vulnerability.|29/30/31 ngày, severity SLA, exception hợp lệ.
MB-0065|OPTIONAL|Wildcard dependency constraints là hygiene signal.|Locked supported patched version; dev-only wildcard; không coi là CVE.
MB-0066|OPTIONAL|Dev-branch constraint là reproducibility signal.|Pinned commit/private maintained branch; informational.
MB-0067|OPTIONAL|prefer-stable là dependency policy.|Explicit stable constraints không prefer-stable vẫn hợp lệ.
MB-0069|REPLACE|Outdated dependency là update signal; security finding dựa applicable advisories.|Latest major breaking vs current supported+patched; latest không security requirement.
MB-0073|REVISE|Literal HTTP integration endpoint candidates trong bounded source scope.|Local loopback hợp lệ; dynamic URLs missed; comments không finding.
MB-0075|REVISE|Signature verification evidence phải bind từng route/handler.|Unsigned route B vẫn finding khi route A có HMAC; replay/wrong secret/raw-body test.
MB-0076|SUPPORT|App allowlist/timeout và system egress evidence tách riêng.|App config không firewall proof; proxy/DNS/redirect bypass; controlled traffic test.
MB-0077|SUPPORT|Raw PII candidates trong third-party outbound flows.|Unrelated mask keyword; hashed data vẫn identifiable; review purpose/schema.
MB-0078|SUPPORT|Configured upstream cipher policy; runtime negotiation riêng.|Inactive config, CDN/load balancer overrides; route-specific handshake.
MB-0079|REPLACE|Secret không hardcode, dùng approved protected storage; không bắt env.php.|Vault/env injection/encrypted DB hợp lệ; plain source secret finding và redact.
MB-0081|SUPPORT|SaaS entry-point ACL/IP scope signals chưa proof least privilege.|Broad admin ACL; isLoggedIn không ownership; external OAuth scope.
MB-0089|SUPPORT|Checkout CSP declarations/runtime headers theo route.|Report-only != enforced; nonce misuse; actual third-party inventory.
MB-0094|REVISE|Custom controller/API thiếu authorization signals; không proof IDOR prevention.|getCustomerId có mặt nhưng không compare owner; two-user cross-object test; helper guard.
MB-0095|REVISE|Anonymous webapi/GraphQL exposure inventory và sensitivity triage.|Public catalog hợp lệ; private order resolver; indirect resolver/helper.
MB-0096|SUPPORT|Security-header evidence theo route/origin/status đã probe.|Config chưa active; redirect/error/checkout differences.
MB-0097|REVISE|Hardcoded credential candidates ngoài approved storage, redacted evidence.|Real secret vs example/test; env injection; JSON/HTML/log không plaintext secret.
MB-0098|REVISE|Unsafe XML parsing/entity expansion signals.|NONET với file entity; version/defaults; safe local XML; empty UNKNOWN.
MB-0099|REVISE|Download/export thiếu authorization/ownership signals.|Logged-in user tải invoice người khác; signed link expiry; safe public export.
MB-0105|REVISE|Output expressions thiếu context-appropriate escaping signals.|escapeHtml trong JS không safe; closing-script JSON; trusted literal; dedupe obligations.
MB-0108|REVISE|Raw/direct DB APIs và unsafe construction candidates, không proof SQLi.|Prepared PDO/bound query không SQLi; query variable/wrapper missed; comments.
MB-0109|REVISE|Command execution sinks và guard signals để triage.|escapeshellcmd full untrusted command không đủ; unrelated guard keyword; Process argv safe.
MB-0131|REVISE|Native deserialization sinks cần review trust boundary.|allowed_classes=false không toàn bộ workflow; safe JSON; trusted local serialized data.
MB-0200|REVISE|Executable signatures/handlers trong upload paths, chưa proof execution policy.|phtml/phar/double extension/handler overrides; benign SVG; controlled execution test riêng.
MB-0209|REVISE|Declared Admin password policy riêng, chưa customer-account policy.|Admin mạnh/customer yếu; config override; reuse Basic evidence.
MB-0379|REVISE|Debug/error config và runtime leak observations từng scope.|CLI PHP khác FPM; proxy stacktrace; benign debug text; dedupe.
MB-0424|REVISE|Sensitive logging/sanitization signals, chưa proof toàn bộ logs sạch.|Redaction helper vs unrelated sanitizer; PAN/token structured log; redact findings.
MB-0730|KEEP|Configured secret patterns absent trong deployed files đã đọc, không proof không secret.|Known secret/benign token/unreadable/oversized/missing root; completeness và redaction.
'@ -split "`n" | ForEach-Object {$v=$_.Trim()-split '\|',4;if($v.Count -eq 4){$special[$v[0]]=$v}}
$items=@($c.requirements|Where-Object {$_.id -in $ids}|ForEach-Object {
$r=$_;$s=$special[$r.id];$d=if($s){$s[1]}elseif($r.human_evidence.required){'SUPPORT'}else{'KEEP'}
$source=if(($r.checks.name -join ',') -match 'code_(raw_sql|ssrf|unserialize|command|dynamic|path_traversal|upload|csprng|outbound)'){'InputSafetySourceChecks.php'}elseif(($r.checks.name -join ',') -match 'code_(custom_authorization|api_exposure|download_export|media_executable)'){'AuthorizationSourceChecks.php'}elseif(($r.checks.name -join ',') -match 'code_(webhook|csrf|phtml|js_context|no_mixed)'){'TemplateRequestSourceChecks.php'}elseif(($r.checks.name -join ',') -match 'code_(pii|api_key|saas|hardcoded|unsafe_xml|sensitive|magento_api|third_party_logging)'){'DataProtectionSourceChecks.php'}else{'CheckRegistry.php (deployment/dependency shared Basic/Hardening)'}
[ordered]@{id=$r.id;title=$r.title;decision=$d;proposed_claim=if($s){$s[2]}else{$r.criterion};checks=@($r.checks);obligations=@($r.obligations);target_modes=$r.target_modes;human_required_now=$r.human_evidence.required;execution_proposal='Chạy technical observations mặc định; human requirement giữ MANUAL_REVIEW; independent finding lane không nâng heuristic thành normative conclusion.';human_boundary=if($r.human_evidence.required){$r.human_evidence.instructions}else{'Chỉ kết luận scoped criterion đã khai báo, không suy ra toàn ứng dụng an toàn.'};fixture_acceptance=if($s){$s[3]}else{'Đạt/vi phạm scoped criterion, absent/unreadable evidence UNKNOWN; shared deployment/dependency fixture Basic/Hardening. '+$r.title};collection_acceptance='Missing/unreadable/oversized/truncated scope báo explicit UNKNOWN/incomplete; giữ finding đã đọc; no-sink hợp lệ chỉ scoped observation, không application-wide PASS.';source_refs=@('src/Rules/requirements/internal-catalog.json#'+$r.id,$source,'src/Engine/Collectors/CodeInventoryCollector.php:16','src/Engine/RequirementAssessmentEvaluator.php:31');priority=if($d -in @('REVISE','REPLACE')){'P1'}else{'P2'}}
})
[ordered]@{profile='owasp-top-10-2025';date='2026-10-17';scope='69 persisted members, source inspection and synthetic scope probes; not target scan, not external standards certification.';items=$items}|ConvertTo-Json -Depth 25|Set-Content artifacts/focused-owasp-review.json -Encoding utf8
$lines=@('# OWASP: rà requirements và checks theo nhu cầu khách hàng','','Review đủ 69 thành viên; deployment/dependency dùng chung evidence với Basic/Hardening. KEEP là giữ scoped claim, chưa là chứng nhận detector. Không sửa source behavior.','','## Các lỗi thiết kế cần ưu tiên','','- Chạy observations mặc định dù requirement cần human evidence; giữ human gate và tạo finding lane riêng.','- Root synthetic probe: 8 detectors trả PASS cho missing/empty/over-1MiB scope: 24 misleading PASS. Same readable risky snippet cho 8 FAIL. Xem focused-source-scope-observations.json. Human gate vẫn bảo vệ requirement.','- CodeInventoryCollector.php:16 bỏ root thiếu và >1MiB không manifest; source families skip read=false. Cần explicit completeness, phân biệt no-sink với không quan sát được.','- TemplateRequestSourceChecks.php:189-202: any PHP signature signal loại XML failures ở endpoint khác. Source-inspected, chưa reproduction riêng. Bind route/service/class/guard.','- AuthorizationSourceChecks.php:472-489: getCustomerId/isLoggedIn/keyword toàn file không chứng minh ownership. Need two-user IDOR fixture.','- InputSafetySourceChecks.php:871-888: client MIME/size/destination keywords chưa chứng minh upload validation; unrelated nearby guard gây false negative.','- InputSafetySourceChecks.php:366-396: PDO construction/direct API flag dù parameterized safe; cần candidate claim và triage.','- DI/static/logrotate/dependency selection/latest stable phải readiness/policy lane, không ngang CVE.','','## Từng thành viên','','| ID | Quyết định | Claim | Fixture chính |','|---|---|---|---|')
$lines += $items|ForEach-Object {'| '+$_.id+' | '+$_.decision+' | '+($_.proposed_claim -replace '\|','/')+' | '+($_.fixture_acceptance -replace '\|','/')+' |'}
$lines += @('','JSON chứa current checks/args/obligations/modes, human boundary, source refs, collection acceptance. Những đề xuất là backlog review, chưa thay membership/runtime.','No actual target/network/payload execution. External OWASP wording chưa đối chiếu, không claims chứng nhận Top 10 coverage.')
$lines|Set-Content artifacts/focused-owasp-review.md -Encoding utf8
$items|Group-Object decision|Select-Object Name,Count|Format-Table
