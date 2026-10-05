<?php
declare(strict_types=1);
namespace Magebean\Engine\Collectors;

final class PhpArrayCollector
{
    /** PHP configuration may be executable/dynamic: evaluate every time as before. */
    public function load(string $file, string $label, callable $evaluate): array
    {
        if (!is_file($file)) return ['__ERROR__' => "$label not found"];
        $data = $evaluate();
        return is_array($data) ? $data : ['__ERROR__' => "$label did not return array"];
    }
}
