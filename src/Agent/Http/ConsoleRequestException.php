<?php
declare(strict_types=1);
namespace Magebean\Agent\Http;

/** Transport classification without changing existing RuntimeException messages. */
final class ConsoleRequestException extends \RuntimeException
{
    public function __construct(string $message, public readonly ?int $httpStatus = null, public readonly bool $retryable = true)
    {
        parent::__construct($message);
    }
}
