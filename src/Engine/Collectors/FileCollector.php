<?php
declare(strict_types=1);
namespace Magebean\Engine\Collectors;

final class FileCollector
{
    public function __construct(private CollectionSession $session) {}

    /** Full, suppressed local reads only; stream/context/partial reads stay with callers. */
    public function read(string $path): string|false
    {
        // Do not coalesce stream wrappers or their potentially stateful reads.
        $this->session->checkpoint();
        if (str_contains($path, '://')) return @file_get_contents($path);
        // Retain the supplied path: aliases/symlinks can have different observations.
        return $this->session->remember('file:' . getcwd() . ':' . $path, static fn(): string|false => @file_get_contents($path));
    }
}
