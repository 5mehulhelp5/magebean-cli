<?php

declare(strict_types=1);

namespace Magebean\Engine;

/** Immutable normalized observation with an explicit legacy tuple adapter. */
final class CheckResult
{
    private function __construct(
        public readonly CheckOutcome $outcome,
        public readonly string $message,
        public readonly array $evidence,
        public readonly ?string $reasonCode,
        public readonly string $checkName,
        private readonly array $legacyTuple
    ) {
    }

    public static function of(
        CheckOutcome $outcome,
        string $message,
        array $evidence = [],
        ?string $reasonCode = null,
        string $checkName = ''
    ): self {
        foreach (['[MANUAL_REVIEW]' => CheckOutcome::ManualReview, '[UNKNOWN]' => CheckOutcome::Unknown] as $prefix => $expected) {
            if (str_starts_with($message, $prefix) && $outcome !== $expected) {
                throw new \InvalidArgumentException('Typed result outcome conflicts with a reserved legacy message prefix.');
            }
        }
        $passed = match ($outcome) {
            CheckOutcome::Pass => true,
            CheckOutcome::Fail => false,
            CheckOutcome::Unknown, CheckOutcome::ManualReview => null,
        };
        $legacyMessage = $message;
        if ($outcome === CheckOutcome::ManualReview && !str_starts_with($message, '[MANUAL_REVIEW]')) {
            $legacyMessage = '[MANUAL_REVIEW] ' . $message;
        }
        return new self($outcome, $message, $evidence, $reasonCode, $checkName, [$passed, $legacyMessage, $evidence]);
    }

    /** Match ScanRunner's historical normalization, including non-boolean values. */
    public static function fromLegacy(array $tuple, string $checkName = ''): self
    {
        $passed = $tuple[0] ?? null;
        $message = (string)($tuple[1] ?? '');
        $evidence = $tuple[2] ?? [];
        if (!is_array($evidence)) $evidence = $evidence !== null ? [$evidence] : [];
        $outcome = match (true) {
            $passed === true => CheckOutcome::Pass,
            $passed === false => CheckOutcome::Fail,
            str_starts_with($message, '[MANUAL_REVIEW]') => CheckOutcome::ManualReview,
            default => CheckOutcome::Unknown,
        };
        return new self($outcome, $message, $evidence, null, $checkName, [$passed, $message, $evidence]);
    }

    /** @return array{0:mixed, 1:string, 2:array} */
    public function toLegacy(): array
    {
        return $this->legacyTuple;
    }

    public function forCheck(string $name): self
    {
        return new self($this->outcome, $this->message, $this->evidence, $this->reasonCode, $name, $this->legacyTuple);
    }
}
