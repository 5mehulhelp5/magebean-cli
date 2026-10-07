<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;

use Magebean\Engine\{Context, CheckResult, CheckOutcome};
use Magebean\Engine\Collectors\CollectorSet;

/** Discovery only: source patterns do not establish data flow or complete conformance. */
final class SourceSecurityObservationsCheck
{
    public function __construct(private readonly Context $ctx, private readonly CollectorSet $collectors) {}


    public function run(array $args): CheckResult
    {
        $patterns = $args['patterns'] ?? [];
        if (!is_array($patterns) || !array_is_list($patterns) || $patterns === [] || count($patterns)>100) throw new \InvalidArgumentException('A bounded nonempty pattern recipe is required.');
        foreach ($patterns as $pattern) if (!is_array($pattern) || !array_is_list($pattern) || count($pattern)!==3 || !is_string($pattern[0]) || !is_string($pattern[1]) || !is_string($pattern[2]) || @preg_match($pattern[1], '')===false) throw new \InvalidArgumentException('Invalid source observation pattern.');
        $paths = $args['scope'] ?? ['app', 'lib/web'];
        if (!is_array($paths) || !array_is_list($paths) || $paths===[]) throw new \InvalidArgumentException('Source scope must be a nonempty relative path list.');
        foreach ($paths as $path) if (!is_string($path) || $path==='' || preg_match('~(?:^/|^[A-Za-z]:|(?:^|/)\.\.(?:/|$))~', str_replace('\\', '/', $path))) throw new \InvalidArgumentException('Source scope must stay within the project.');
        $prefilter = $args['prefilter'] ?? null;
        if ($prefilter!==null && (!is_string($prefilter) || @preg_match($prefilter,'')===false)) throw new \InvalidArgumentException('Invalid source prefilter.');
        $literalSignals = $args['literal_signals'] ?? [];
        if (!is_array($literalSignals) || !array_is_list($literalSignals) || array_filter($literalSignals,static fn($signal):bool=>!is_string($signal))!==[]) throw new \InvalidArgumentException('Literal signals must be a list.');
        $evidence = ['scope' => $paths, 'required_follow_up' => (string)($args['review'] ?? ''), 'files_read' => 0, 'observations' => [],
            'limitations' => ['Static discovery does not prove data flow, reachability, control effectiveness or complete input/path coverage.', 'Dependencies, generated assets and runtime/account state are outside this source scope; files larger than 1 MiB are excluded.']];
        if (($this->ctx->get('meta', [])['target_mode'] ?? '') === 'REMOTE') return $this->unknown('Local source evidence is unavailable in remote mode.', $evidence);
        if ($this->ctx->path === '' || !is_dir($this->ctx->path)) return $this->unknown('Local source is unavailable.', $evidence);
        $files = $this->collectors->code->files(array_map(fn(string $p): string => $this->ctx->abs($p), $paths), ['php','phtml','js','ts']);
        sort($files); $bytes = 0; $incomplete = false; $count = 0;
        foreach ($files as $file) {
            $this->collectors->session->checkpoint();
            if (++$count > 2000) { $incomplete = true; break; }
            $real = realpath($file); $root = realpath($this->ctx->path);
            if ($real !== false) $real = str_replace('\\', '/', $real);
            if ($root !== false) $root = str_replace('\\', '/', $root);
            if ($real === false || $root === false || !str_starts_with($real, rtrim($root, '/') . '/')) { $incomplete = true; continue; }
            $text = $this->collectors->files->read($file);
            if ($text === false) { $incomplete = true; continue; }
            $bytes += strlen($text);
            if ($bytes > 10485760) { $incomplete = true; break; }
            if (in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), ['php','phtml'], true) && !function_exists('token_get_all')) { $incomplete = true; $evidence['tokenizer_unavailable'] = true; continue; }
            $evidence['files_read']++;
            $clean = $this->collectors->session->remember('source:comments:' . $file, fn(): string => self::withoutComments($text, pathinfo($file, PATHINFO_EXTENSION)));
            $stringRanges = in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), ['php','phtml'], true) ? self::phpStringRanges($text) : self::jsStringRanges($clean);
            if ($prefilter !== null && preg_match($prefilter, $clean)!==1) continue;
            foreach ($patterns as [$signal,$regex,$kind]) {
                if (preg_match_all($regex, $clean, $matches, PREG_OFFSET_CAPTURE) === false) throw new \LogicException('Invalid source observation pattern.');
                foreach ($matches[0] as [, $offset]) {
                    $quoted = false;
                    foreach ($stringRanges as [$start,$end]) {
                        if ($offset >= $start && $offset < $end) {
                            $quoted = !in_array($signal, $literalSignals, true) || $offset !== $start;
                            break;
                        }
                    }
                    if ($quoted) continue;
                    if (count($evidence['observations']) >= 50) { $evidence['observations_truncated'] = true; break; }
                    $evidence['observations'][] = ['file' => substr($real, strlen(rtrim($root, '/')) + 1),
                        'line' => substr_count(substr($text,0,$offset), "\n") + 1, 'signal' => $signal, 'kind' => $kind];
                }
            }
        }
        $evidence['collection_incomplete'] = $incomplete;
        if ($incomplete) return $this->unknown('Source collection was incomplete; observations require review.', $evidence);
        if ($evidence['observations'] === []) return $this->unknown('No relevant implementation evidence was observed in the bounded source scope; applicability remains unverified.', $evidence);
        return CheckResult::of(CheckOutcome::ManualReview, 'Static implementation observations collected; independently verify the requirement against the actual workflow and scope.', $evidence, 'SOURCE_OBSERVATION_CONFIRMATION');
    }

    private function unknown(string $message, array $evidence): CheckResult
    {
        return CheckResult::of(CheckOutcome::Unknown, '[UNKNOWN] ' . $message, $evidence, 'SOURCE_OBSERVATION_MISSING');
    }

    private static function jsStringRanges(string $text): array
    {
        $ranges=[]; $length=strlen($text);
        for ($i=0;$i<$length;$i++) {
            if (!in_array($text[$i],["'",'"','`'],true)) continue;
            $start=$i; $quote=$text[$i];
            while (++$i<$length) { if($text[$i]==='\\'){$i++;continue;} if($text[$i]===$quote)break; }
            $ranges[]=[$start,min($length,$i+1)];
        }
        return $ranges;
    }

    private static function phpStringRanges(string $text): array
    {
        $ranges=[]; $offset=0;
        foreach (token_get_all($text) as $token) {
            $value=is_array($token)?$token[1]:$token;
            if (is_array($token) && in_array($token[0],[T_CONSTANT_ENCAPSED_STRING,T_ENCAPSED_AND_WHITESPACE],true)) $ranges[]=[$offset,$offset+strlen($value)];
            $offset+=strlen($value);
        }
        return $ranges;
    }

    /** Preserve offsets and newlines; PHP tokenizer distinguishes comments from strings. */
    private static function withoutComments(string $text, string $ext): string
    {
        $mask = static fn(string $s): string => preg_replace('/[^\r\n]/', ' ', $s);
        if (in_array(strtolower($ext), ['php','phtml'], true)) {
            $out = '';
            foreach (token_get_all($text) as $token) $out .= is_array($token) ? (in_array($token[0], [T_COMMENT,T_DOC_COMMENT], true) ? $mask($token[1]) : $token[1]) : $token;
            return preg_replace_callback('~<!--.*?-->~s', static fn(array $m): string => $mask($m[0]), $out);
        }
        // JS strings/templates are retained; comments are masked without treating URL literals as comments.
        $out = $text; $length = strlen($text);
        for ($i=0; $i<$length; $i++) {
            if (in_array($text[$i], ["'", '"', '`'], true)) {
                $quote=$text[$i];
                while (++$i<$length) { if ($text[$i]==='\\') {$i++;continue;} if($text[$i]===$quote)break; }
            } elseif ($text[$i]==='/' && ($text[$i+1]??'')==='/') {
                $end=strpos($text,"\n",$i);$end=$end===false?$length:$end;
                $out=substr_replace($out,$mask(substr($text,$i,$end-$i)),$i,$end-$i);$i=$end-1;
            } elseif ($text[$i]==='/' && ($text[$i+1]??'')==='*') {
                $end=strpos($text,'*/',$i+2);$end=$end===false?$length:$end+2;
                $out=substr_replace($out,$mask(substr($text,$i,$end-$i)),$i,$end-$i);$i=$end-1;
            }
        }
        return $out;
    }
}
