<?php
declare(strict_types=1);
if (isset($_GET['delay'])) usleep(750000);
if (isset($_GET['status'])) {
    http_response_code((int)$_GET['status']);
    header('Content-Type: application/json');
    echo isset($_GET['invalid']) ? '{bad' : json_encode(['error' => ['message' => 'fixture rejected']]);
    return;
}
$state = getcwd() . '/requests.txt';
$count = is_file($state) ? (int)file_get_contents($state) + 1 : 1;
file_put_contents($state, (string)$count);
header('Set-Cookie: first=1; Secure; HttpOnly', false);
header('Set-Cookie: second=2; Secure; HttpOnly', false);
header('X-Cache: HIT');
header('Age: ' . $count);
header('Content-Type: application/json');
echo json_encode(['count' => $count, 'method' => $_SERVER['REQUEST_METHOD'], 'body' => file_get_contents('php://input'), 'probe' => $_SERVER['HTTP_X_PROBE'] ?? '']);
