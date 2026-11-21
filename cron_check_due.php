<?php
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/billing_helpers.php';

// Hanya izinkan eksekusi dari CLI (cron server), tolak akses langsung dari browser
if (PHP_SAPI !== 'cli') {
    $cronToken = defined('CRON_SECRET_TOKEN') ? (string) CRON_SECRET_TOKEN : '';
    $providedToken = (string) ($_GET['token'] ?? '');
    if ($cronToken === '' || !hash_equals($cronToken, $providedToken)) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo "403 Forbidden (CLI only)\n";
        exit(1);
    }
    header('Content-Type: text/plain; charset=utf-8');
}

$statusFile = STATUS_FILE;
if (!is_file($statusFile)) {
    echo '[' . date('Y-m-d H:i:s') . "] ERROR: status.json tidak ditemukan di {$statusFile}\n";
    exit(1);
}

$statusData = json_decode((string) file_get_contents($statusFile), true);
if (!is_array($statusData)) {
    echo '[' . date('Y-m-d H:i:s') . "] ERROR: format status.json tidak valid\n";
    exit(1);
}

$today = new DateTimeImmutable('today');
$changed = false;
$newlyIsolated = [];
$dueSoon = [];
$activeCount = 0;
$isolatedCount = 0;

foreach ($statusData as $domain => $info) {
    if (!is_array($info)) {
        $statusData[$domain] = [
            'status' => 'isolir',
            'activated_at' => null,
            'due_date' => null,
        ];
        $changed = true;
        $isolatedCount++;
        continue;
    }

    $status = $info['status'] ?? 'isolir';
    $dueStr = $info['due_date'] ?? null;
    $dueDate = parse_billing_date($dueStr);

    if ($status === 'aktif' && $dueDate) {
        $daysLeft = (int) $today->diff($dueDate)->format('%r%a');

        if ($daysLeft < 0) {
            $statusData[$domain]['status'] = 'isolir';
            $changed = true;
            $newlyIsolated[$domain] = $dueDate->format('Y-m-d');
            $isolatedCount++;
            write_audit_log('cron_auto_isolir', (string) $domain, ['due_date' => $dueDate->format('Y-m-d')]);
            continue;
        }

        if ($daysLeft <= 3) {
            $dueSoon[$domain] = [
                'due_date' => $dueDate->format('Y-m-d'),
                'days_left' => $daysLeft,
            ];
        }
    }

    if (($statusData[$domain]['status'] ?? 'isolir') === 'aktif') {
        $activeCount++;
    } else {
        $isolatedCount++;
    }
}

if ($changed) {
    save_status_data($statusFile, $statusData);
}

$timestamp = date('Y-m-d H:i:s');
echo "[{$timestamp}] Cek jatuh tempo selesai. Total: " . count($statusData)
    . " | Aktif: {$activeCount} | Isolir: {$isolatedCount}"
    . " | Baru diisolir: " . count($newlyIsolated)
    . " | H-3 jatuh tempo: " . count($dueSoon) . "\n";

foreach ($newlyIsolated as $domain => $due) {
    echo "  -> AUTO-ISOLIR: {$domain} (jatuh tempo {$due})\n";
}
foreach ($dueSoon as $domain => $meta) {
    echo "  -> SEGERA JATUH TEMPO: {$domain} ({$meta['days_left']} hari lagi, {$meta['due_date']})\n";
}

// Kirim notifikasi ke Telegram jika TELEGRAM_BOT_TOKEN & TELEGRAM_CHAT_ID diatur di config.php
$tgToken = defined('TELEGRAM_BOT_TOKEN') ? trim((string) TELEGRAM_BOT_TOKEN) : '';
$tgChatId = defined('TELEGRAM_CHAT_ID') ? trim((string) TELEGRAM_CHAT_ID) : '';

if ($tgToken !== '' && $tgChatId !== '' && (!empty($newlyIsolated) || !empty($dueSoon))) {
    $lines = ["🔔 *Laporan Billing Madignet* (" . $today->format('d M Y') . ")"];

    if (!empty($newlyIsolated)) {
        $lines[] = "\n⛔ *Otomatis Diisolir Hari Ini:*";
        foreach ($newlyIsolated as $domain => $due) {
            $lines[] = "• `{$domain}` (Exp: {$due})";
        }
    }

    if (!empty($dueSoon)) {
        $lines[] = "\n⚠️ *Segera Jatuh Tempo (≤ 3 Hari):*";
        foreach ($dueSoon as $domain => $meta) {
            $label = $meta['days_left'] === 0 ? 'HARI INI' : "H-{$meta['days_left']}";
            $lines[] = "• `{$domain}` ({$label} - {$meta['due_date']})";
        }
    }

    $lines[] = "\n📊 Total Aktif: {$activeCount} | Isolir: {$isolatedCount}";
    $text = implode("\n", $lines);

    $tgUrl = "https://api.telegram.org/bot{$tgToken}/sendMessage";
    $payload = http_build_query([
        'chat_id' => $tgChatId,
        'text' => $text,
        'parse_mode' => 'Markdown',
    ]);

    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => $payload,
            'timeout' => 10,
            'ignore_errors' => true,
        ],
    ]);

    $res = @file_get_contents($tgUrl, false, $ctx);
    if ($res === false && function_exists('curl_init')) {
        $ch = curl_init($tgUrl);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
        ]);
        $res = curl_exec($ch);
        curl_close($ch);
    }

    echo "  -> Notifikasi Telegram dikirim.\n";
}
