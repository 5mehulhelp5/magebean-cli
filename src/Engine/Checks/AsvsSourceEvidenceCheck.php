<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;

use Magebean\Engine\{Context, CheckResult, CheckOutcome};
use Magebean\Engine\Collectors\CollectorSet;

/** Discovery only: source patterns do not establish data flow or complete conformance. */
final class AsvsSourceEvidenceCheck
{
    public function __construct(private readonly Context $ctx, private readonly CollectorSet $collectors) {}

    private const PATTERNS = [
        '1.3.1' => [
            ['html_sanitizer_call', '~\b(?:DOMPurify\s*\.\s*sanitize|HTMLPurifier|HtmlSanitizer|sanitizeHtml)\b~i', 'candidate_control'],
            ['html_rendering_sink', '~\b(?:innerHTML|outerHTML|insertAdjacentHTML)\b|\$\([^\r\n]*\)\s*\.\s*html\s*\(~i', 'review_sink'],
        ],
        '2.2.1' => [
            ['server_validation_call', '~\b(?:validate|isValid|filter_var|assertValid|validateValue)\s*\(~i', 'candidate_control'],
            ['decision_input', '~\b(?:getParam|getPostValue|getRequest|INPUT_POST|INPUT_GET)\b|\$_(?:GET|POST|REQUEST)\b~', 'review_input'],
        ],
        '3.2.2' => [
            ['text_rendering', '~\b(?:textContent|innerText|createTextNode)\b|\.\s*text\s*\(~', 'candidate_control'],
            ['html_rendering', '~\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\s*\.\s*write)\b|\.\s*html\s*\(~', 'review_sink'],
        ],
        '3.5.3' => [
            ['unsafe_method_interface', '~\b(?:HttpGetActionInterface|HttpHeadActionInterface|HttpOptionsActionInterface)\b~', 'review_safe_method'],
            ['state_changing_call', '~(?:->|::)\s*(?:save|delete|placeOrder|cancel|update|setPassword)\s*\(~i', 'review_sensitive_operation'],
            ['method_or_fetch_guard', '~\b(?:HttpPostActionInterface|HttpPutActionInterface|HttpPatchActionInterface|HttpDeleteActionInterface|isPost|Sec-Fetch-Site|Sec-Fetch-Mode|Sec-Fetch-Dest)\b~i', 'candidate_control'],
        ],
        '6.2.4' => [
            ['password_denylist_control', '~\b(?:NotCompromisedPassword|PasswordBlacklist|PasswordDenylist|isCommonPassword|isBreachedPassword|checkPasswordBreach)\b~i', 'candidate_control'],
            ['password_validation_flow', '~\b(?:validatePassword|changePassword|createAccount|setPassword)\s*\(~i', 'review_password_flow'],
        ],
        '9.1.1' => [
            ['token_verification', '~\b(?:JWT\s*::\s*decode|JWSVerifier|verifySignature|openssl_verify|hash_equals|SignedWith)\b~i', 'candidate_control'],
            ['token_decode_or_parse', '~\b(?:JWT|JsonWebToken|base64_decode|parseToken|parseJwt)\b~i', 'review_token_flow'],
        ],
        '9.1.2' => [
            ['algorithm_policy', '~\b(?:allowedAlgorithms|algorithmAllowlist|supported_algs|new\s+Key|SignedWith)\b~i', 'candidate_control'],
            ['none_algorithm', '~[\x22\x27]alg[\x22\x27]\s*(?:=>|:)\s*[\x22\x27]none[\x22\x27]~i', 'review_insecure_algorithm'],
            ['token_algorithm_selection', '~\b(?:JWT|JWS|JsonWebToken|allowedAlgorithms|algorithmAllowlist)\b~i', 'review_token_flow'],
        ],
        '9.1.3' => [
            ['configured_key_source', '~\b(?:JWKSet|keySet|publicKey|verificationKey|trustedIssuers|trustedJwks|keyAllowlist)\b~i', 'candidate_control'],
            ['token_header_key_source', '~[\x22\x27](?:jku|x5u|jwk)[\x22\x27]~i', 'review_untrusted_key_source'],
        ],
        '9.2.1' => [
            ['time_claim_validation', '~\b(?:ValidAt|StrictValidAt|LooseValidAt|validateExpiration|validateNotBefore)\b~i', 'candidate_control'],
            ['time_claim_reference', '~[\x22\x27](?:nbf|exp)[\x22\x27]|\b(?:expiration|notBefore|JWT)\b~', 'review_time_flow'],
        ],
        '11.4.1' => [
            ['weak_hash_call', '~\b(?:md5|sha1)\s*\(|\b(?:hash|hash_hmac)\s*\(\s*[\x22\x27](?:md5|sha1)[\x22\x27]~i', 'review_hash_purpose'],
            ['modern_hash_call', '~\b(?:hash|hash_hmac)\s*\(\s*[\x22\x27](?:sha256|sha384|sha512|sha3-256|sha3-384|sha3-512)[\x22\x27]~i', 'candidate_control'],
        ],
    ];

    public function run(array $args): CheckResult
    {
        $requirement = (string)($args['requirement'] ?? '');
        if (!isset(self::PATTERNS[$requirement])) throw new \InvalidArgumentException('Unsupported ASVS source evidence criterion.');
        $paths = ['app', 'lib/web'];
        $evidence = ['requirement' => $requirement, 'scope' => $paths, 'required_follow_up' => (string)($args['review'] ?? ''), 'files_read' => 0, 'observations' => [],
            'limitations' => ['Static discovery does not prove data flow, reachability, control effectiveness or complete input/path coverage.', 'Dependencies, generated assets and runtime/account state are outside this source scope; files larger than 1 MiB are excluded.']];
        if (($this->ctx->get('meta', [])['target_mode'] ?? '') === 'REMOTE') return $this->unknown('Local source evidence is unavailable in remote mode.', $evidence);
        if ($this->ctx->path === '' || !is_dir($this->ctx->path)) return $this->unknown('Local source is unavailable.', $evidence);
        $files = $this->collectors->code->files(array_map(fn(string $p): string => $this->ctx->abs($p), $paths), ['php','phtml','js','ts']);
        sort($files); $bytes = 0; $incomplete = false; $count = 0;
        foreach ($files as $file) {
            $this->collectors->session->checkpoint();
            if (++$count > 2000) { $incomplete = true; break; }
            $real = realpath($file); $root = realpath($this->ctx->path);
            if ($real !== false) $real = str_replace('\\', '/', $real);
            if ($root !== false) $root = str_replace('\\', '/', $root);
            if ($real === false || $root === false || !str_starts_with($real, rtrim($root, '/') . '/')) { $incomplete = true; continue; }
            $text = $this->collectors->files->read($file);
            if ($text === false) { $incomplete = true; continue; }
            $bytes += strlen($text);
            if ($bytes > 10485760) { $incomplete = true; break; }
            if (in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), ['php','phtml'], true) && !function_exists('token_get_all')) { $incomplete = true; $evidence['tokenizer_unavailable'] = true; continue; }
            $evidence['files_read']++;
            $clean = $this->collectors->session->remember('asvs:comments:' . $file, fn(): string => self::withoutComments($text, pathinfo($file, PATHINFO_EXTENSION)));
            $stringRanges = in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), ['php','phtml'], true) ? self::phpStringRanges($text) : self::jsStringRanges($clean);
            if (str_starts_with($requirement, '9.') && !preg_match('~\b(?:JWT|JWS|JsonWebToken|parseToken|parseJwt|SignedWith|JWKSet|StrictValidAt|LooseValidAt|ValidAt|jku|x5u|jwk)\b~i', $clean)) continue;
            foreach (self::PATTERNS[$requirement] as [$signal,$regex,$kind]) {
                if (preg_match_all($regex, $clean, $matches, PREG_OFFSET_CAPTURE) === false) throw new \LogicException('Invalid built-in ASVS evidence pattern.');
                foreach ($matches[0] as [, $offset]) {
                    $quoted = false;
                    foreach ($stringRanges as [$start,$end]) {
                        if ($offset >= $start && $offset < $end) {
                            $quoted = !in_array($signal, ['none_algorithm','token_header_key_source','time_claim_reference'], true) || $offset !== $start;
                            break;
                        }
                    }
                    if ($quoted) continue;
                    if (count($evidence['observations']) >= 50) { $evidence['observations_truncated'] = true; break; }
                    $evidence['observations'][] = ['file' => substr($real, strlen(rtrim($root, '/')) + 1),
                        'line' => substr_count(substr($text,0,$offset), "\n") + 1, 'signal' => $signal, 'kind' => $kind];
                }
            }
        }
        $evidence['collection_incomplete'] = $incomplete;
        if ($incomplete) return $this->unknown('Source collection was incomplete; observations require review.', $evidence);
        if ($evidence['observations'] === []) return $this->unknown('No relevant implementation evidence was observed in the bounded source scope; applicability remains unverified.', $evidence);
        return CheckResult::of(CheckOutcome::ManualReview, 'Static implementation observations collected; independently verify the requirement against the actual workflow and scope.', $evidence, 'ASVS_SOURCE_CONFIRMATION');
    }

    private function unknown(string $message, array $evidence): CheckResult
    {
        return CheckResult::of(CheckOutcome::Unknown, '[UNKNOWN] ' . $message, $evidence, 'ASVS_SOURCE_EVIDENCE_MISSING');
    }

    private static function jsStringRanges(string $text): array
    {
        $ranges=[]; $length=strlen($text);
        for ($i=0;$i<$length;$i++) {
            if (!in_array($text[$i],["'",'"','`'],true)) continue;
            $start=$i; $quote=$text[$i];
            while (++$i<$length) { if($text[$i]==='\\'){$i++;continue;} if($text[$i]===$quote)break; }
            $ranges[]=[$start,min($length,$i+1)];
        }
        return $ranges;
    }

    private static function phpStringRanges(string $text): array
    {
        $ranges=[]; $offset=0;
        foreach (token_get_all($text) as $token) {
            $value=is_array($token)?$token[1]:$token;
            if (is_array($token) && in_array($token[0],[T_CONSTANT_ENCAPSED_STRING,T_ENCAPSED_AND_WHITESPACE],true)) $ranges[]=[$offset,$offset+strlen($value)];
            $offset+=strlen($value);
        }
        return $ranges;
    }

    /** Preserve offsets and newlines; PHP tokenizer distinguishes comments from strings. */
    private static function withoutComments(string $text, string $ext): string
    {
        $mask = static fn(string $s): string => preg_replace('/[^\r\n]/', ' ', $s);
        if (in_array(strtolower($ext), ['php','phtml'], true)) {
            $out = '';
            foreach (token_get_all($text) as $token) $out .= is_array($token) ? (in_array($token[0], [T_COMMENT,T_DOC_COMMENT], true) ? $mask($token[1]) : $token[1]) : $token;
            return preg_replace_callback('~<!--.*?-->~s', static fn(array $m): string => $mask($m[0]), $out);
        }
        // JS strings/templates are retained; comments are masked without treating URL literals as comments.
        $out = $text; $length = strlen($text);
        for ($i=0; $i<$length; $i++) {
            if (in_array($text[$i], ["'", '"', '`'], true)) {
                $quote=$text[$i];
                while (++$i<$length) { if ($text[$i]==='\\') {$i++;continue;} if($text[$i]===$quote)break; }
            } elseif ($text[$i]==='/' && ($text[$i+1]??'')==='/') {
                $end=strpos($text,"\n",$i);$end=$end===false?$length:$end;
                $out=substr_replace($out,$mask(substr($text,$i,$end-$i)),$i,$end-$i);$i=$end-1;
            } elseif ($text[$i]==='/' && ($text[$i+1]??'')==='*') {
                $end=strpos($text,'*/',$i+2);$end=$end===false?$length:$end+2;
                $out=substr_replace($out,$mask(substr($text,$i,$end-$i)),$i,$end-$i);$i=$end-1;
            }
        }
        return $out;
    }
}
