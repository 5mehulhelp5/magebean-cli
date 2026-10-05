<?php
declare(strict_types=1);
namespace Magebean\Agent\Http;

interface ConsoleTransport
{
    public function get(string $path, array $headers = []): array;
    public function post(string $path, array $body = [], array $headers = []): array;
    public function postApi(string $path, array $body = [], array $headers = []): array;
}
