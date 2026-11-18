<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/billing_helpers.php';
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

$domain = strtolower(trim((string) ($_GET['domain'] ?? '')));
if ($domain === '') {
    echo json_encode(['error' => 'domain parameter missing']);
    exit;
}

$statusData = is_file(STATUS_FILE) ? json_decode((string) file_get_contents(STATUS_FILE), true) : [];
$statusData = is_array($statusData) ? $statusData : [];
$data = $statusData[$domain] ?? null;

if (!is_array($data)) {
    echo json_encode(['status' => 'isolir', 'reason' => 'domain not found']);
    exit;
}

// Auto check jatuh tempo
$today = new DateTimeImmutable('today');
$dueDate = parse_billing_date($data['due_date'] ?? null);
if ($dueDate && $today > $dueDate) {
    $data['status'] = 'isolir';
}

echo json_encode([
    'domain' => $domain,
    'status' => $data['status'] ?? 'isolir',
    'due_date' => $data['due_date'] ?? null,
]);
