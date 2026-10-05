<?php
declare(strict_types=1);
namespace Magebean\Engine\Collectors;
final class CodeInventoryCollector
{
    public function __construct(private CollectionSession $session) {}
    public function files(array $roots, array $extensions): array
    {
        $key = 'inventory:filtered:' . serialize([getcwd(), $roots, $extensions]);
        return $this->session->remember($key, fn(): array => $this->enumerateFiltered($roots, $extensions));
    }
    public function anyExtension(array $roots): array
    {
        return $this->session->remember('inventory:any:' . serialize([getcwd(), $roots]), fn(): array => $this->enumerateAny($roots));
    }
    private function enumerateFiltered(array $roots, array $inc): array
    {
        $ret = [];
        $incLower = array_map('strtolower', $inc);
        foreach ($roots as $root) {
            $this->session->checkpoint();
            if (!is_dir($root)) continue;
            $rii = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(
                $root, \FilesystemIterator::SKIP_DOTS
            ));
            foreach ($rii as $f) {
                $this->session->checkpoint();
                if (!$f->isFile()) continue;
                $ext = strtolower(pathinfo($f->getFilename(), PATHINFO_EXTENSION));
                if ($ext === '' || !in_array($ext, $incLower, true)) continue;
                // mặc định bỏ qua file > 1MB để tránh tốn bộ nhớ
                if ($f->getSize() > 1024*1024) continue;
                $ret[] = $f->getPathname();
            }
        }
        return $ret;
    }
    private function enumerateAny(array $roots): array
    {
        $ret = [];
        foreach ($roots as $root) {
            $this->session->checkpoint();
            if (is_file($root)) {
                $ret[] = $root;
                continue;
            }
            if (!is_dir($root)) {
                continue;
            }

            $rii = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(
                $root,
                \FilesystemIterator::SKIP_DOTS
            ));
            foreach ($rii as $f) {
                $this->session->checkpoint();
                if (!$f->isFile()) {
                    continue;
                }
                $ret[] = $f->getPathname();
            }
        }

        return $ret;
    }
}
