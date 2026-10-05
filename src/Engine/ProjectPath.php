<?php
declare(strict_types=1);
namespace Magebean\Engine;
final class ProjectPath
{
    public static function resolve(string $config, string $projectPath): string
    {
        if ($config === '') {
            return $config;
        }
        if ($config[0] === '/' || (bool)preg_match('/^[A-Za-z]:[\\\\\\/]/', $config)) {
            return $config;
        }

        $cwdCandidate = getcwd() . DIRECTORY_SEPARATOR . $config;
        if (is_file($cwdCandidate)) {
            return $cwdCandidate;
        }

        return rtrim($projectPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $config;
    }
    public static function normalize(string $p): string
    {
        $rp = realpath($p);
        return $rp !== false ? rtrim($rp, DIRECTORY_SEPARATOR) : rtrim($p, DIRECTORY_SEPARATOR);
    }
}
