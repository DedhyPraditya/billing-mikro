<?php
require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../config.php';

// Jika sudah login, langsung ke dashboard
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    header('Location: dashboard.php');
    exit;
}

// Cek login
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
<title>Login Admin | WarungCloud</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<link rel="stylesheet" href="assets/css/app.css">
</head>
<body>
<main class="auth-shell">
    <div class="auth-card">
        <div class="row g-0">
            <div class="col-lg-6">
                <section class="auth-panel auth-aside auth-logo-panel d-flex align-items-center justify-content-center">
                    <img src="assets/img/logo-warung-cloud.png" alt="Logo WarungCloud" class="auth-logo img-fluid">
                </section>
            </div>

            <div class="col-lg-6">
                <section class="auth-panel h-100 d-flex flex-column justify-content-center">
                    <div class="mb-4">
                        <span class="soft-badge">
                            <i class="bi bi-stars"></i>
                            WarungCloud
                        </span>
                        <h2 class="mt-3 mb-2 fw-bold">Selamat datang kembali</h2>
                        <p class="text-soft mb-0">Silakan login untuk masuk ke area administrasi billing.</p>
                    </div>

                    <?php if ($error): ?>
                        <div class="alert alert-danger border-0 rounded-4 py-3">
                            <i class="bi bi-exclamation-triangle me-2"></i><?= htmlspecialchars($error) ?>
                        </div>
                    <?php endif; ?>

                    <form method="post" class="mt-2">
                        <?= csrf_field() ?>
                        <div class="mb-3">
                            <label class="form-label">Username</label>
                            <div class="position-relative">
                                <input type="text" name="username" class="form-control ps-5" placeholder="Masukkan username admin" required autofocus>
                                <i class="bi bi-person position-absolute top-50 start-0 translate-middle-y ms-3 text-secondary"></i>
                            </div>
                        </div>
                        <div class="mb-4">
                            <label class="form-label">Password</label>
                            <div class="position-relative">
                                <input type="password" name="password" class="form-control ps-5" placeholder="Masukkan password" required>
                                <i class="bi bi-key position-absolute top-50 start-0 translate-middle-y ms-3 text-secondary"></i>
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary btn-lg w-100">
                            <i class="bi bi-box-arrow-in-right me-2"></i>Masuk ke Dashboard
                        </button>
                    </form>
                </section>
            </div>
        </div>
    </div>
</main>
</body>
</html>
