<?php
require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../config.php';

if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $waitSeconds = check_login_rate_limit(5, 300);

    if ($waitSeconds !== null) {
        $error = 'Terlalu banyak percobaan gagal. Coba lagi dalam ' . $waitSeconds . ' detik.';
        write_audit_log('login_rate_limited', '-');
    } elseif (!verify_csrf()) {
        $error = 'Sesi form tidak valid. Silakan muat ulang halaman.';
    } else {
        $username = (string) ($_POST['username'] ?? '');
        $password = (string) ($_POST['password'] ?? '');

        $userMatch = hash_equals((string) ADMIN_USER, $username);
        $configuredPass = (string) ADMIN_PASS;
        if (str_starts_with($configuredPass, '$2y$') || str_starts_with($configuredPass, '$argon2')) {
            $passMatch = password_verify($password, $configuredPass);
        } else {
            $passMatch = hash_equals($configuredPass, $password);
        }

        if ($userMatch && $passMatch) {
            clear_login_failures();
            session_regenerate_id(true);
            $_SESSION['logged_in'] = true;
            $_SESSION['admin_user'] = $username;
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            write_audit_log('login_success', '-');
            header('Location: dashboard.php');
            exit;
        } else {
            record_login_failure(300);
            write_audit_log('login_failed', '-', ['attempted_user' => substr($username, 0, 64)]);
            $error = 'Username atau password salah.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In | WarungCloud Billing</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<link rel="stylesheet" href="assets/css/app.css">
</head>
<body>
<main class="auth-shell">
    <div class="auth-box">
        <div class="d-flex align-items-center gap-2 mb-4 pb-3 border-bottom">
            <img src="assets/img/logo-warung-cloud.png" alt="WarungCloud" class="auth-logo-sm" onerror="this.style.display='none'">
            <div>
                <div class="fw-bold" style="font-size:1.05rem;letter-spacing:-0.01em;">WarungCloud Billing</div>
                <div class="text-muted" style="font-size:0.78rem;">Panel Kontrol Isolir &amp; Subdomain</div>
            </div>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-danger py-2 px-3 mb-3" style="font-size:0.82rem;border-radius:6px;">
                <i class="bi bi-exclamation-circle me-1"></i><?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <form method="post">
            <?= csrf_field() ?>
            <div class="mb-3">
                <label class="form-label">Username</label>
                <input type="text" name="username" class="form-control" placeholder="admin" required autofocus>
            </div>
            <div class="mb-4">
                <label class="form-label">Password</label>
                <input type="password" name="password" class="form-control" placeholder="••••••••" required>
            </div>
            <button type="submit" class="btn btn-ops-primary w-100 py-2">
                Masuk ke Panel
            </button>
        </form>
    </div>
</main>
</body>
</html>
