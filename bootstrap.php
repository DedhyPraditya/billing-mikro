<?php

$storageBasePath = __DIR__ . DIRECTORY_SEPARATOR . 'storage';
$projectHash = substr(hash('sha256', __DIR__), 0, 12);
$projectSessionPath = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'billing_sessions_' . $projectHash;

if (!is_dir($storageBasePath)) {
    mkdir($storageBasePath, 0700, true);
}
if (!is_dir($projectSessionPath)) {
    mkdir($projectSessionPath, 0700, true);
}

// Lindungi folder storage dari akses publik langsung
$storageHtaccess = $storageBasePath . DIRECTORY_SEPARATOR . '.htaccess';
if (!is_file($storageHtaccess)) {
    @file_put_contents($storageHtaccess, "Order deny,allow\nDeny from all\n");
}
$storageIndex = $storageBasePath . DIRECTORY_SEPARATOR . 'index.php';
if (!is_file($storageIndex)) {
    @file_put_contents($storageIndex, "<?php http_response_code(403); exit;\n");
}

if (!headers_sent()) {
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
}

if (session_status() !== PHP_SESSION_ACTIVE) {
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') === '443')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_save_path($projectSessionPath);
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') . '">';
}

function verify_csrf(): bool
{
    $token = $_POST['csrf_token'] ?? '';
    $sessionToken = $_SESSION['csrf_token'] ?? '';
    return is_string($token) && $sessionToken !== '' && hash_equals($sessionToken, $token);
}

function get_client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function get_rate_limit_file(): string
{
    $projectHash = substr(hash('sha256', __DIR__), 0, 12);
    return rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'billing_sessions_' . $projectHash . DIRECTORY_SEPARATOR . 'rate_limit.json';
}

function check_login_rate_limit(int $maxAttempts = 5, int $lockoutSeconds = 300): ?int
{
    $file = get_rate_limit_file();
    $ip = get_client_ip();
    $now = time();

    $records = is_file($file) ? json_decode((string) @file_get_contents($file), true) : [];
    $records = is_array($records) ? $records : [];

    if (!isset($records[$ip])) {
        return null;
    }

    $attempts = array_values(array_filter(
        $records[$ip]['attempts'] ?? [],
        fn($ts) => is_int($ts) && ($now - $ts) < $lockoutSeconds
    ));

    if (count($attempts) >= $maxAttempts) {
        $oldest = min($attempts);
        return max(1, $lockoutSeconds - ($now - $oldest));
    }

    return null;
}

function record_login_failure(int $lockoutSeconds = 300): void
{
    $file = get_rate_limit_file();
    $ip = get_client_ip();
    $now = time();

    $records = is_file($file) ? json_decode((string) @file_get_contents($file), true) : [];
    $records = is_array($records) ? $records : [];

    $attempts = array_values(array_filter(
        $records[$ip]['attempts'] ?? [],
        fn($ts) => is_int($ts) && ($now - $ts) < $lockoutSeconds
    ));
    $attempts[] = $now;
    $records[$ip] = ['attempts' => $attempts];

    @file_put_contents($file, json_encode($records), LOCK_EX);
}

function clear_login_failures(): void
{
    $file = get_rate_limit_file();
    $ip = get_client_ip();
    if (!is_file($file)) {
        return;
    }
    $records = json_decode((string) @file_get_contents($file), true);
    if (is_array($records) && isset($records[$ip])) {
        unset($records[$ip]);
        @file_put_contents($file, json_encode($records), LOCK_EX);
    }
}

function write_audit_log(string $action, string $domain, array $extra = []): void
{
    $logFile = __DIR__ . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'audit.log.php';
    if (!is_file($logFile)) {
        @file_put_contents($logFile, "<?php http_response_code(403); exit; ?>\n", LOCK_EX);
    }
    $entry = [
        'time' => date('Y-m-d H:i:s'),
        'ip' => get_client_ip(),
        'user' => $_SESSION['admin_user'] ?? 'anonymous',
        'action' => $action,
        'domain' => $domain,
        'script' => $_SERVER['SCRIPT_NAME'] ?? php_sapi_name(),
        'ua' => substr($_SERVER['HTTP_USER_AGENT'] ?? '-', 0, 120),
    ] + $extra;

    @file_put_contents($logFile, json_encode($entry, JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);
}
