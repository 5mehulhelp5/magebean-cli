<?php
declare(strict_types=1);
namespace Magebean\Update;
final class SelfUpdater
{
    /** @param null|callable(string,string):void $downloader @param null|callable(string):bool $validator */
    public function __construct(private $downloader=null,private $validator=null){}
    /** @param array<string,mixed> $release */
    public function update(array $release,string $current):void
    {
        $version=trim((string)($release['version']??''));$url=trim((string)($release['url']??''));$sha256=strtolower(trim((string)($release['sha256']??'')));
        if($version===''||!preg_match('/^[0-9A-Za-z][0-9A-Za-z._-]{0,39}$/',$version))throw new \RuntimeException('Release version is invalid.');
        if(!filter_var($url,FILTER_VALIDATE_URL)||parse_url($url,PHP_URL_SCHEME)!=='https')throw new \RuntimeException('Release URL must use HTTPS.');
        if(!preg_match('/^[a-f0-9]{64}$/',$sha256))throw new \RuntimeException('Release SHA-256 is invalid.');
        if(!is_file($current)||!is_writable($current)||!is_writable(dirname($current)))throw new \RuntimeException('Current PHAR or its directory is not writable.');
        $update=$current.'.update';@unlink($update);
        try{($this->downloader??$this->download(...))($url,$update);if(!is_file($update)||!hash_equals($sha256,hash_file('sha256',$update)))throw new \RuntimeException('Downloaded PHAR checksum verification failed.');$this->verifySignature($update,$release);if(!(($this->validator??$this->validatePhar(...))($update)))throw new \RuntimeException('Downloaded PHAR failed its executable validation check.');$mode=fileperms($current);if($mode===false||!chmod($update,$mode&0777))throw new \RuntimeException('Unable to preserve PHAR permissions.');if(!rename($update,$current))throw new \RuntimeException('Unable to atomically replace the current PHAR.');}
        catch(\Throwable $exception){if(is_file($update))@unlink($update);throw $exception;}
    }
    private function download(string $url,string $destination):void
    {
        if(!extension_loaded('curl'))throw new \RuntimeException('The curl PHP extension is required for self-update.');$handle=fopen($destination,'xb');if($handle===false)throw new \RuntimeException('Unable to create the update file.');$curl=curl_init($url);curl_setopt_array($curl,[CURLOPT_FILE=>$handle,CURLOPT_FOLLOWLOCATION=>false,CURLOPT_CONNECTTIMEOUT=>10,CURLOPT_TIMEOUT=>120,CURLOPT_PROTOCOLS=>CURLPROTO_HTTPS,CURLOPT_FAILONERROR=>true]);$ok=curl_exec($curl);$error=curl_error($curl);curl_close($curl);fclose($handle);if($ok!==true)throw new \RuntimeException('PHAR download failed: '.($error?:'unknown transport error'));
    }
    /** @param array<string,mixed> $release */
    private function verifySignature(string $file,array $release):void
    {
        $signature=trim((string)($release['signature']??''));$publicKey=trim((string)($release['public_key']??''));if($signature===''&&$publicKey==='')return;if($signature===''||$publicKey===''||!function_exists('sodium_crypto_sign_verify_detached'))throw new \RuntimeException('Release signature cannot be verified on this system.');$decodedSignature=base64_decode($signature,true);$decodedKey=base64_decode($publicKey,true);$contents=file_get_contents($file);if($decodedSignature===false||$decodedKey===false||$contents===false||!sodium_crypto_sign_verify_detached($decodedSignature,$contents,$decodedKey))throw new \RuntimeException('Downloaded PHAR signature verification failed.');
    }
    private function validatePhar(string $file):bool
    {
        try{new \Phar($file);}catch(\Throwable){return false;}
        if(!function_exists('proc_open'))return false;$pipes=[];$process=proc_open([PHP_BINARY,$file,'--version'],[['pipe','r'],['pipe','w'],['pipe','w']],$pipes);if(!is_resource($process))return false;fclose($pipes[0]);stream_get_contents($pipes[1]);fclose($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[2]);return proc_close($process)===0;
    }
}
