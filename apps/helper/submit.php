<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { exit(0); }

$data = json_decode(file_get_contents('php://input'), true);
if (!$data || !isset($data['month'], $data['year'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing month/year']);
    exit;
}

$job_file = __DIR__ . '/job.json';
$existing = file_exists($job_file) ? json_decode(file_get_contents($job_file), true) : [];

// Kein doppeltes Einreihen wenn bereits pending/running
if (in_array($existing['status'] ?? '', ['pending', 'running'])) {
    echo json_encode(['ok' => false, 'error' => 'Job already in queue', 'status' => $existing['status']]);
    exit;
}

$job = [
    'status' => 'pending',
    'month'  => preg_replace('/[^0-9]/', '', $data['month']),
    'year'   => preg_replace('/[^0-9]/', '', $data['year']),
    'model'  => preg_replace('/[^a-zA-Z0-9:._-]/', '', $data['model'] ?? 'auto'),
    'ts'     => time(),
];
file_put_contents($job_file, json_encode($job));
echo json_encode(['ok' => true]);
