<?php
declare(strict_types=1);

namespace Magebean\Agent\Http;

final class ConsoleClient
{
    public const DEFAULT_BASE_URL = 'https://console.magebean.com/api';
    public const DEV_BASE_URL = 'https://console.magebean.local/api';

    public function __construct(private readonly string $baseUrl, private readonly ?string $token = null, private readonly int $timeout = 30, private readonly bool $verifyTls = true) {}

    public function get(string $path, array $headers = []): array { return $this->request('GET', $path, null, $headers); }
    public function post(string $path, array $body = [], array $headers = []): array { return $this->request('POST', $path, $body, $headers); }
    public function postApi(string $path, array $body = [], array $headers = []): array { return $this->request('POST', '/v1/' . ltrim($path, '/'), $body, $headers); }

    private function request(string $method, string $path, ?array $body, array $headers): array
    {
        if (!extension_loaded('curl')) throw new \RuntimeException('The curl PHP extension is required for agent commands.');
        $url = rtrim($this->baseUrl, '/') . (str_starts_with($path, '/v1/') ? $path : '/v1/agent/' . ltrim($path, '/'));
        $ch = curl_init($url);
        $requestHeaders = ['Accept: application/json', 'Content-Type: application/json', 'User-Agent: Magebean-Agent/1'];
        if ($this->token !== null && $this->token !== '') $requestHeaders[] = 'Authorization: Bearer ' . $this->token;
        foreach ($headers as $name => $value) $requestHeaders[] = $name . ': ' . $value;
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CUSTOMREQUEST => $method, CURLOPT_HTTPHEADER => $requestHeaders, CURLOPT_TIMEOUT => $this->timeout]);
        if (! $this->verifyTls) curl_setopt_array($ch, [CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0]);
        if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_THROW_ON_ERROR));
        $raw = curl_exec($ch);
        if ($raw === false) { $message = curl_error($ch); curl_close($ch); throw new \RuntimeException('Security Dashboard request failed: ' . $message); }
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        $decoded = $raw === '' ? [] : json_decode($raw, true);
        if (!is_array($decoded)) throw new \RuntimeException("Console returned invalid JSON (HTTP {$status}).");
        if ($status < 200 || $status >= 300) {
            throw new \RuntimeException($this->errorMessage($decoded, $status));
        }
        return $decoded;
    }

    private function errorMessage(array $response, int $status): string
    {
        $error = $response['error'] ?? null;
        $code = is_array($error) && is_scalar($error['code'] ?? null) ? trim((string) $error['code']) : '';
        $message = is_array($error) && is_scalar($error['message'] ?? null)
            ? trim((string) $error['message'])
            : (is_scalar($response['message'] ?? null)
                ? trim((string) $response['message'])
                : (is_scalar($error) ? trim((string) $error) : 'Security Dashboard request rejected'));

        if ($message === '') $message = 'Security Dashboard request rejected';
        if ($code !== '' && strcasecmp($code, $message) !== 0) $message .= " ({$code})";

        return "{$message} (HTTP {$status})";
    }
}
