<?php
declare(strict_types=1);
namespace Magebean\Engine\Cve;

/** OSV fixed/limit are exclusive; last_affected is inclusive and is not a fix. */
final class OsvRange
{
    public static function intervals(array $events, ?string &$minFixed = null): array
    {
        $result = []; $start = null; $minFixed = null;
        foreach ($events as $event) {
            if (isset($event['introduced'])) { $start = ltrim((string)$event['introduced'], 'vV'); continue; }
            foreach (['fixed', 'last_affected', 'limit'] as $kind) {
                if (!isset($event[$kind])) continue;
                $end = ltrim((string)$event[$kind], 'vV');
                $result[] = [$start, $end, $kind === 'last_affected', $kind];
                if ($kind === 'fixed' && ($minFixed === null || version_compare($end, $minFixed, '<'))) $minFixed = $end;
                $start = null;
                break;
            }
        }
        if ($start !== null) $result[] = [$start, null, false, null];
        return $result;
    }

    public static function contains(string $version, ?string $start, ?string $end, bool $inclusive = false): bool
    {
        $version = ltrim($version, 'vV');
        if ($start !== null && $start !== '0' && version_compare($version, $start, '<')) return false;
        return $end === null || version_compare($version, $end, $inclusive ? '<=' : '<');
    }

    public static function affects(array $affected, string $version): bool
    {
        foreach ($affected['versions'] ?? [] as $explicit) if (version_compare(ltrim($version, 'vV'), ltrim((string)$explicit, 'vV'), '==')) return true;
        foreach ($affected['ranges'] ?? [] as $range) {
            foreach (self::intervals($range['events'] ?? []) as [$start, $end, $inclusive]) if (self::contains($version, $start, $end, $inclusive)) return true;
        }
        return false;
    }
}
