<?php
require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../billing_helpers.php';

if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

$statusFile = STATUS_FILE;
$data = is_file($statusFile) ? json_decode((string) file_get_contents($statusFile), true) : [];
$data = is_array($data) ? $data : [];

$message = '';
$messageType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf()) {
        $message = 'Token keamanan (CSRF) tidak valid. Silakan muat ulang halaman.';
        $messageType = 'danger';
        write_audit_log('csrf_failed', $_POST['domain'] ?? '-');
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'add') {
            $rawDomain = $_POST['domain'] ?? '';
            $domain = normalize_and_validate_domain($rawDomain);
            $status = $_POST['status'] ?? 'isolir';
            $activated_at = $_POST['activated_at'] ?? '';
            $due_date = calculate_due_date_from_activation($activated_at);

            if ($domain === null) {
                $message = defined('ALLOWED_DOMAIN_SUFFIX') && ALLOWED_DOMAIN_SUFFIX !== ''
                    ? 'Format domain tidak valid! Wajib berakhiran ' . ALLOWED_DOMAIN_SUFFIX
                    : 'Format domain tidak valid!';
                $messageType = 'danger';
                write_audit_log('invalid_domain_rejected', (string) $rawDomain);
            } elseif (!in_array($status, ['aktif', 'isolir'], true)) {
                $message = 'Status tidak valid!';
                $messageType = 'danger';
            } elseif (!$due_date) {
                $message = 'Tanggal aktivasi tidak valid!';
                $messageType = 'danger';
            } elseif (isset($data[$domain])) {
                $message = 'Domain sudah terdaftar!';
                $messageType = 'danger';
            } else {
                $data[$domain] = [
                    'status' => $status,
                    'activated_at' => $activated_at,
                    'due_date' => $due_date,
                ];
                save_status_data($statusFile, $data);
                write_audit_log('domain_add', $domain, ['status' => $status, 'due_date' => $due_date]);
                $message = 'Data berhasil ditambahkan!';
                $messageType = 'success';
            }
        } elseif ($action === 'edit') {
            $old_domain = strtolower(trim((string) ($_POST['old_domain'] ?? '')));
            $rawDomain = $_POST['domain'] ?? '';
            $domain = normalize_and_validate_domain($rawDomain);
            $status = $_POST['status'] ?? 'isolir';
            $activated_at = $_POST['activated_at'] ?? '';
            $due_date = calculate_due_date_from_activation($activated_at);

            if ($domain === null) {
                $message = defined('ALLOWED_DOMAIN_SUFFIX') && ALLOWED_DOMAIN_SUFFIX !== ''
                    ? 'Format domain tidak valid! Wajib berakhiran ' . ALLOWED_DOMAIN_SUFFIX
                    : 'Format domain tidak valid!';
                $messageType = 'danger';
                write_audit_log('invalid_domain_rejected', (string) $rawDomain);
            } elseif (!in_array($status, ['aktif', 'isolir'], true)) {
                $message = 'Status tidak valid!';
                $messageType = 'danger';
            } elseif (!$due_date) {
                $message = 'Tanggal aktivasi tidak valid!';
                $messageType = 'danger';
            } elseif ($domain !== $old_domain && isset($data[$domain])) {
                $message = 'Domain sudah terdaftar!';
                $messageType = 'danger';
            } else {
                if ($domain !== $old_domain && isset($data[$old_domain])) {
                    unset($data[$old_domain]);
                }

                $data[$domain] = [
                    'status' => $status,
                    'activated_at' => $activated_at,
                    'due_date' => $due_date,
                ];
                save_status_data($statusFile, $data);
                write_audit_log('domain_edit', $domain, ['old_domain' => $old_domain, 'status' => $status, 'due_date' => $due_date]);
                $message = 'Data berhasil diupdate!';
                $messageType = 'success';
            }
        } elseif ($action === 'delete') {
            $domain = strtolower(trim((string) ($_POST['domain'] ?? '')));
            if (isset($data[$domain])) {
                unset($data[$domain]);
                save_status_data($statusFile, $data);
                write_audit_log('domain_delete', $domain);
                $message = 'Data berhasil dihapus!';
                $messageType = 'success';
            }
        }
    }
}

$data = is_file($statusFile) ? json_decode((string) file_get_contents($statusFile), true) : [];
$data = is_array($data) ? $data : [];

$stats = [
    'total' => count($data),
    'aktif' => 0,
    'isolir' => 0,
];

foreach ($data as $item) {
    if (($item['status'] ?? 'isolir') === 'aktif') {
        $stats['aktif']++;
    } else {
        $stats['isolir']++;
    }
}

$adminUser = $_SESSION['admin_user'] ?? ADMIN_USER;
?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manajemen Data | WarungCloud</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <link rel="stylesheet" href="assets/css/app.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg topbar navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="dashboard.php">
                <span class="brand-mark"><i class="bi bi-router-fill"></i></span>
                <span>WarungCloud</span>
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto align-items-lg-center gap-lg-2">
                    <li class="nav-item">
                        <a class="nav-link" href="dashboard.php">Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="management.php">Manajemen Data</a>
                    </li>
                    <li class="nav-item my-2 my-lg-0">
                        <span class="user-chip">
                            <i class="bi bi-person-circle"></i>
                            <?= htmlspecialchars($adminUser) ?>
                        </span>
                    </li>
                    <li class="nav-item">
                        <a class="btn btn-outline-light btn-sm px-3" href="logout.php">
                            <i class="bi bi-box-arrow-right me-1"></i>Logout
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <main class="app-shell">
        <div class="container">
            <section class="app-card page-intro mb-4">
                <div class="d-flex flex-column flex-lg-row justify-content-between align-items-lg-start gap-3">
                    <div>
                        <span class="eyebrow">
                            <i class="bi bi-database-gear"></i>
                            Manajemen Data
                        </span>
                        <h1 class="page-intro-title">Kelola data pelanggan dengan lebih ringkas</h1>
                        <p class="page-intro-copy">
                            Tambahkan domain baru, edit data lama, atau hapus entri yang sudah tidak dipakai tanpa memenuhi layar dengan informasi yang tidak perlu.
                        </p>
                    </div>
                    <div class="d-flex flex-wrap gap-2">
                        <span class="soft-badge"><i class="bi bi-hdd-stack"></i> <?= $stats['total'] ?> data</span>
                        <span class="soft-badge"><i class="bi bi-check2-circle"></i> <?= $stats['aktif'] ?> aktif</span>
                        <span class="soft-badge"><i class="bi bi-slash-circle"></i> <?= $stats['isolir'] ?> isolir</span>
                    </div>
                </div>
            </section>

            <?php if ($message): ?>
                <div class="alert alert-<?= $messageType ?> alert-dismissible border-0 rounded-4 shadow-sm fade show mb-4" role="alert">
                    <i class="bi <?= $messageType === 'success' ? 'bi-check-circle-fill' : 'bi-exclamation-triangle-fill' ?> me-2"></i>
                    <?= htmlspecialchars($message) ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>

            <div class="row g-4">
                <div class="col-xl-4">
                    <div class="app-card p-4 h-100">
                        <div class="card-title-row">
                            <div>
                                <h2 class="section-title">Form data pelanggan</h2>
                                <p class="section-subtitle">Tambahkan domain baru dengan tanggal aktivasi, lalu jatuh tempo dihitung otomatis 1 bulan ke depan.</p>
                            </div>
                            <span class="soft-badge"><i class="bi bi-plus-circle"></i> Entry Baru</span>
                        </div>

                        <form method="POST">
                            <?= csrf_field() ?>
                            <input type="hidden" name="action" value="add" id="action-field">
                            <input type="hidden" name="old_domain" id="old-domain">

                            <div class="mb-3">
                                <label class="form-label">Domain</label>
                                <input type="text" class="form-control" name="domain" id="domain" placeholder="contoh.madignet.cloud" required>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">Status</label>
                                <select class="form-select" name="status" id="status" required>
                                    <option value="">-- Pilih Status --</option>
                                    <option value="aktif">Aktif</option>
                                    <option value="isolir">Isolir</option>
                                </select>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">Tanggal Aktivasi</label>
                                <input type="date" class="form-control" name="activated_at" id="activated_at" required>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">Jatuh Tempo Otomatis</label>
                                <input type="date" class="form-control" name="due_date" id="due_date" readonly>
                            </div>

                            <div class="d-grid gap-2 pt-2">
                                <button type="submit" class="btn btn-primary btn-lg" id="submit-btn">
                                    <i class="bi bi-plus-lg me-2"></i>Tambah Data
                                </button>
                                <button type="reset" class="btn btn-light border" id="reset-btn">
                                    <i class="bi bi-arrow-counterclockwise me-2"></i>Reset Form
                                </button>
                            </div>
                        </form>

                        <div class="surface-muted rounded-4 p-3 mt-4">
                            <div class="d-flex align-items-start gap-3">
                                <span class="metric-icon icon-primary flex-shrink-0" style="width:42px;height:42px;font-size:1rem;">
                                    <i class="bi bi-lightbulb"></i>
                                </span>
                                <div>
                                    <h3 class="h6 mb-1">Tips pengisian</h3>
                                    <p class="text-soft mb-0">Tanggal jatuh tempo sekarang otomatis mengikuti 1 bulan kalender dari tanggal aktivasi yang dipilih.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xl-8">
                    <div class="app-card p-4">
                        <div class="card-title-row flex-wrap">
                            <div>
                                <h2 class="section-title">Daftar domain</h2>
                                <p class="section-subtitle">Edit data lewat modal atau hapus entri yang sudah tidak digunakan.</p>
                            </div>
                            <div class="search-box" style="min-width: min(100%, 320px);">
                                <i class="bi bi-search"></i>
                                <input type="search" id="managementSearch" class="form-control" placeholder="Cari domain, status, atau tanggal...">
                            </div>
                        </div>

                        <div class="table-wrap">
                            <div class="table-responsive">
                                <table class="table table-modern mb-0" id="managementTable">
                                    <thead>
                                        <tr>
                                            <th>Domain</th>
                                            <th>Status</th>
                                            <th>Aktivasi</th>
                                            <th>Jatuh Tempo</th>
                                            <th>Aksi</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($data as $domain => $info): ?>
                                        <tr data-search="<?= htmlspecialchars(strtolower($domain . ' ' . ($info['status'] ?? '') . ' ' . ($info['activated_at'] ?? '') . ' ' . ($info['due_date'] ?? ''))) ?>">
                                            <td>
                                                <span class="domain-title"><?= htmlspecialchars($domain) ?></span>
                                                <span class="domain-meta">Data pelanggan billing</span>
                                            </td>
                                            <td>
                                                <?php if (($info['status'] ?? 'isolir') === 'aktif'): ?>
                                                    <span class="status-pill status-aktif"><i class="bi bi-check-circle-fill"></i> Aktif</span>
                                                <?php else: ?>
                                                    <span class="status-pill status-isolir"><i class="bi bi-slash-circle-fill"></i> Isolir</span>
                                                <?php endif; ?>
                                            </td>
                                            <td><?= htmlspecialchars($info['activated_at'] ?? '-') ?></td>
                                            <td><?= htmlspecialchars($info['due_date'] ?? '-') ?></td>
                                            <td>
                                                <div class="d-flex flex-wrap gap-2">
                                                    <button type="button" class="btn btn-sm btn-soft-warning" data-bs-toggle="modal"
                                                            data-bs-target="#editModal"
                                                            data-domain="<?= htmlspecialchars($domain, ENT_QUOTES, 'UTF-8') ?>"
                                                            data-status="<?= htmlspecialchars($info['status'] ?? 'isolir', ENT_QUOTES, 'UTF-8') ?>"
                                                            data-activated="<?= htmlspecialchars($info['activated_at'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                                                            data-due="<?= htmlspecialchars($info['due_date'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                                                            onclick="loadEditFormFromBtn(this)">
                                                        <i class="bi bi-pencil me-1"></i>Edit
                                                    </button>
                                                    <form method="POST" class="m-0" onsubmit="return confirm('Yakin ingin menghapus data ini?');">
                                                        <?= csrf_field() ?>
                                                        <input type="hidden" name="action" value="delete">
                                                        <input type="hidden" name="domain" value="<?= htmlspecialchars($domain) ?>">
                                                        <button type="submit" class="btn btn-sm btn-soft-danger">
                                                            <i class="bi bi-trash me-1"></i>Hapus
                                                        </button>
                                                    </form>
                                                </div>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                        <?php if (empty($data)): ?>
                                        <tr>
                                            <td colspan="5">
                                                <div class="empty-state">
                                                    <i class="bi bi-folder2-open"></i>
                                                    <h3 class="h5 mb-2">Belum ada data pelanggan</h3>
                                                    <p class="mb-0">Silakan tambahkan data baru dari form di sebelah kiri.</p>
                                                </div>
                                            </td>
                                        </tr>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <div class="modal fade" id="editModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-pencil-square me-2"></i>Edit Data</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <?= csrf_field() ?>
                    <div class="modal-body">
                        <input type="hidden" name="action" value="edit">
                        <input type="hidden" name="old_domain" id="edit-old-domain">

                        <div class="mb-3">
                            <label class="form-label">Domain</label>
                            <input type="text" class="form-control" name="domain" id="edit-domain" required>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Status</label>
                            <select class="form-select" name="status" id="edit-status" required>
                                <option value="aktif">Aktif</option>
                                <option value="isolir">Isolir</option>
                            </select>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Tanggal Aktivasi</label>
                            <input type="date" class="form-control" name="activated_at" id="edit-activated_at" required>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Jatuh Tempo Otomatis</label>
                            <input type="date" class="form-control" name="due_date" id="edit-due_date" readonly>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-light border" data-bs-dismiss="modal">Batal</button>
                        <button type="submit" class="btn btn-primary"><i class="bi bi-check-lg me-1"></i>Simpan Perubahan</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function calculateDueDate(activationDate) {
            if (!activationDate) {
                return '';
            }

            const [year, month, day] = activationDate.split('-').map(Number);
            if (!year || !month || !day) {
                return '';
            }

            const targetYear = month === 12 ? year + 1 : year;
            const targetMonth = month === 12 ? 1 : month + 1;
            const lastDay = new Date(targetYear, targetMonth, 0).getDate();
            const safeDay = Math.min(day, lastDay);

            return [
                targetYear,
                String(targetMonth).padStart(2, '0'),
                String(safeDay).padStart(2, '0')
            ].join('-');
        }

        function syncDueDate(sourceId, targetId) {
            const activationInput = document.getElementById(sourceId);
            const dueInput = document.getElementById(targetId);

            if (!activationInput || !dueInput) {
                return;
            }

            const applyValue = function() {
                dueInput.value = calculateDueDate(activationInput.value);
            };

            activationInput.addEventListener('input', applyValue);
            activationInput.addEventListener('change', applyValue);
            applyValue();
        }

        function loadEditFormFromBtn(btn) {
            const domain = btn.dataset.domain || '';
            const status = btn.dataset.status || 'isolir';
            const activated_at = btn.dataset.activated || '';
            const due_date = btn.dataset.due || '';

            document.getElementById('edit-old-domain').value = domain;
            document.getElementById('edit-domain').value = domain;
            document.getElementById('edit-status').value = status;
            document.getElementById('edit-activated_at').value = activated_at;
            document.getElementById('edit-due_date').value = calculateDueDate(activated_at) || due_date;
        }

        document.addEventListener('DOMContentLoaded', function() {
            const today = new Date().toISOString().split('T')[0];
            document.getElementById('activated_at').value = today;
            syncDueDate('activated_at', 'due_date');
            syncDueDate('edit-activated_at', 'edit-due_date');
            document.getElementById('due_date').value = calculateDueDate(today);

            const searchInput = document.getElementById('managementSearch');
            const rows = document.querySelectorAll('#managementTable tbody tr[data-search]');

            if (searchInput && rows.length) {
                searchInput.addEventListener('input', function() {
                    const keyword = this.value.trim().toLowerCase();
                    rows.forEach(function(row) {
                        row.style.display = row.dataset.search.includes(keyword) ? '' : 'none';
                    });
                });
            }
        });
    </script>
</body>
</html>
