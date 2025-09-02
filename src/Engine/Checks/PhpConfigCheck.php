<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class PhpConfigCheck
{
    private Context $ctx;

    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }

    // Router
    public function dispatch(string $name, array $args): array
    {
        return match ($name) {
            'php_array_exists'          => $this->arrayExists($args),
            'php_array_eq'              => $this->arrayEquals($args),
            'php_array_neq'             => $this->arrayNotEquals($args),
            'php_array_numeric_compare' => $this->arrayNumericCompare($args),
            default => [false, 'Unknown PhpConfigCheck: ' . $name],
        };
    }

    private function loadArray(string $relativeFile): array
    {
        $file = $this->ctx->abs($relativeFile);
        if (!is_file($file)) {
            return ['__ERROR__' => "$relativeFile not found"];
        }
        // include trả về array
        $data = @include $file;
        if (!is_array($data)) {
            return ['__ERROR__' => "$relativeFile did not return array"];
        }
        return $data;
    }

    private function getByDotPath(array $arr, string $path, mixed $default = null): mixed
    {
        if ($path === '' || $path === '.') return $arr;
        $keys = explode('.', $path);
        $cur = $arr;
        foreach ($keys as $k) {
            if (!is_array($cur) || !array_key_exists($k, $cur)) {
                return $default;
            }
            $cur = $cur[$k];
        }
        return $cur;
    }

    private function arrayExists(array $args): array
    {
        $file = (string)($args['file'] ?? '');
        $path = (string)($args['path'] ?? '');
        if ($file === '' || $path === '') return [false, 'php_array_exists requires file & path'];

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) return [false, $arr['__ERROR__']];

        $val = $this->getByDotPath($arr, $path, '__NOT_FOUND__');
        if ($val === '__NOT_FOUND__') return [false, "Path '$path' not found in $file"];
        return [true, "Found '$path' in $file"];
    }

    private function arrayEquals(array $args): array
    {
        $file = (string)($args['file'] ?? '');
        $path = (string)($args['path'] ?? '');
        $expect = $args['equals'] ?? null;
        if ($file === '' || $path === '') return [false, 'php_array_eq requires file & path'];

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) return [false, $arr['__ERROR__']];

        $val = $this->getByDotPath($arr, $path, '__NOT_FOUND__');
        if ($val === '__NOT_FOUND__') return [false, "Path '$path' not found in $file"];

        $ok = ($val == $expect); // lỏng hơn === để tiện số/chuỗi
        return [$ok, "Value at '$path' == " . var_export($expect, true) . " (actual: " . var_export($val, true) . ")"];
    }

    private function arrayNotEquals(array $args): array
    {
        $file = (string)($args['file'] ?? '');
        $path = (string)($args['path'] ?? '');
        $not = $args['not_equals'] ?? null;
        if ($file === '' || $path === '') return [false, 'php_array_neq requires file & path'];

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) return [false, $arr['__ERROR__']];

        $val = $this->getByDotPath($arr, $path, '__NOT_FOUND__');
        if ($val === '__NOT_FOUND__') return [false, "Path '$path' not found in $file"];

        $ok = ($val != $not);
        return [$ok, "Value at '$path' != " . var_export($not, true) . " (actual: " . var_export($val, true) . ")"];
    }

    private function arrayNumericCompare(array $args): array
    {
        $file = (string)($args['file'] ?? '');
        $path = (string)($args['path'] ?? '');
        $op   = (string)($args['op'] ?? '');
        $rhs  = $args['value'] ?? null;

        if ($file === '' || $path === '' || $op === '' || $rhs === null) {
            return [false, 'php_array_numeric_compare requires file, path, op, value'];
        }

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) return [false, $arr['__ERROR__']];

        $val = $this->getByDotPath($arr, $path, '__NOT_FOUND__');
        if ($val === '__NOT_FOUND__') return [false, "Path '$path' not found in $file"];
        if (!is_numeric($val)) return [false, "Value at '$path' is not numeric (actual: " . var_export($val, true) . ")"];

        $lv = (float)$val;
        $rv = (float)$rhs;
        $ok = match ($op) {
            '<=' => $lv <= $rv,
            '<'  => $lv <  $rv,
            '>=' => $lv >= $rv,
            '>'  => $lv >  $rv,
            '==' => $lv == $rv,
            '!=' => $lv != $rv,
            default => false
        };
        return [$ok, "Numeric compare: $lv $op $rv at '$path'"];
    }

    public function keySearch(array $args): array
    {
        $file = (string)($args['file'] ?? '');
        $keyRe = (string)($args['key_regex'] ?? '');
        $minFound = (int)($args['min_found'] ?? 1);

        if ($file === '' || $keyRe === '') {
            return [false, 'php_array_key_search requires file & key_regex'];
        }
        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) return [false, $arr['__ERROR__']];

        // duyệt đệ qui và đếm số key khớp regex
        $count = $this->countKeysByRegex($arr, $keyRe);
        $ok = ($count >= $minFound);
        return [$ok, "php_array_key_search '$keyRe' matches=$count (min $minFound) in $file"];
    }

    private function countKeysByRegex(array $arr, string $keyRe): int
    {
        $cnt = 0;
        foreach ($arr as $k => $v) {
            if (@preg_match('/' . $keyRe . '/i', (string)$k)) {
                $cnt++;
            }
            if (is_array($v)) {
                $cnt += $this->countKeysByRegex($v, $keyRe);
            }
        }
        return $cnt;
    }
}
