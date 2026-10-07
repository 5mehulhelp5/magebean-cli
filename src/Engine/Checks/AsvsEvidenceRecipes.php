<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;

/** Deprecated ASVS recipe lookup, used only by compatibility adapters. */
final class AsvsEvidenceRecipes
{
    public const PATTERNS = [
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

    public static function forRequirement(string $id): array
    {
        if (!isset(self::PATTERNS[$id])) throw new \InvalidArgumentException("Unsupported ASVS source evidence criterion.");
        $args = ["patterns"=>self::PATTERNS[$id], "literal_signals"=>["none_algorithm","token_header_key_source","time_claim_reference"]];
        if (str_starts_with($id, "9.")) $args["prefilter"] = "~\\b(?:JWT|JWS|JsonWebToken|parseToken|parseJwt|SignedWith|JWKSet|StrictValidAt|LooseValidAt|ValidAt|jku|x5u|jwk)\\b~i";
        return $args;
    }
}
