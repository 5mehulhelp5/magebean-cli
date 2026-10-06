<?php
$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);
if($path==='/redirect'){http_response_code(302);header('Location: /good');echo 'redirect';return;}
if($path==='/empty'){http_response_code(204);return;}
if($path==='/opaque'){header('Content-Type: application/octet-stream');echo "\x01\x02";return;}
header('Content-Type: '.($path==='/bad'?'application/json':'text/html; charset=UTF-8'));
echo '<!doctype html><html>fixture</html>';
