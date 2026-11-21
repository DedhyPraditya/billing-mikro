<?php
// Salin file ini menjadi config.php lalu sesuaikan nilainya.
// ADMIN_PASS mendukung plain text maupun bcrypt hash (hasil password_hash()).
define('ADMIN_USER', 'admin');
define('ADMIN_PASS', 'ganti-password-anda');

define('STATUS_FILE', __DIR__ . '/status.json');

// Opsional: batasi domain yang boleh didaftarkan hanya ke akhiran tertentu (misal '.madignet.site')
// Kosongkan '' jika mengizinkan semua domain valid.
define('ALLOWED_DOMAIN_SUFFIX', '');

// Opsional: isi jika ingin cron_check_due.php mengirim laporan jatuh tempo ke Telegram Anda
define('TELEGRAM_BOT_TOKEN', '');
define('TELEGRAM_CHAT_ID', '');
?>
