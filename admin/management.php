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
                $message = "Domain {$domain} berhasil ditambahkan.";
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
                $message = "Data {$domain} berhasil diperbarui.";
                $messageType = 'success';
            }
        } elseif ($action === 'delete') {
            $domain = strtolower(trim((string) ($_POST['domain'] ?? '')));
            if (isset($data[$domain])) {
                unset($data[$domain]);
                save_status_data($statusFile, $data);
                write_audit_log('domain_delete', $domain);
                $message = "Domain {$domain} berhasil dihapus.";
                $messageType = 'success';
            }
        }
    }
}

$data = is_file($statusFile) ? json_decode((string) file_get_contents($statusFile), true) : [];
$data = is_array($data) ? $data : [];

$adminUser = $_SESSION['admin_user'] ?? ADMIN_USER;
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manajemen Data | WarungCloud Billing</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <link rel="stylesheet" href="assets/css/app.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg topbar navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="dashboard.php">
                <span class="brand-mark"><i class="bi bi-hdd-network"></i></span>
                <span>WarungCloud Billing</span>
            </a>
            <button class="navbar-toggler border-0" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto align-items-lg-center gap-1">
                    <li class="nav-item">
                        <a class="nav-link" href="dashboard.php"><i class="bi bi-grid-1x2 me-1"></i>Overview</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="management.php"><i class="bi bi-sliders me-1"></i>Manajemen</a>
                    </li>
                    <li class="nav-item ms-lg-2 my-2 my-lg-0">
                        <span class="user-chip">
                            <i class="bi bi-person-fill"></i>
                            <?= htmlspecialchars($adminUser) ?>
                        </span>
                    </li>
                    <li class="nav-item ms-lg-1">
                        <a class="btn btn-sm btn-outline-secondary text-light border-secondary px-2 py-1" style="font-size:0.78rem;" href="logout.php">
                            <i class="bi bi-box-arrow-right me-1"></i>Keluar
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <main class="app-shell">
        <div class="container">
            <header class="page-header">
                <div>
                    <h1 class="page-title">Manajemen Data Subdomain</h1>
                    <p class="page-meta">Tambah, ubah tanggal aktivasi, atau hapus entri dari <span class="font-mono">status.json</span></p>
                </div>
            </header>

            <?php if ($message): ?>
                <div class="alert alert-<?= $messageType ?> alert-dismissible fade show py-2 px-3 mb-3 d-flex align-items-center justify-content-between" role="alert" style="font-size:0.84rem;border-radius:8px;">
                    <div>
                        <i class="bi <?= $messageType === 'success' ? 'bi-check-circle-fill' : 'bi-exclamation-triangle-fill' ?> me-2"></i>
                        <?= htmlspecialchars($message) ?>
                    </div>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" style="padding:0.65rem;"></button>
                </div>
            <?php endif; ?>

            <div class="row g-3">
                <div class="col-lg-4">
                    <div class="panel-card p-3">
                        <h2 class="h6 fw-bold mb-3 pb-2 border-bottom">Tambah Subdomain Baru</h2>

                        <form method="POST">
                            <?= csrf_field() ?>
                            <input type="hidden" name="action" value="add">

                            <div class="mb-3">
                                <label class="form-label">Subdomain</label>
                                <input type="text" class="form-control font-mono" name="domain" id="domain" placeholder="pelanggan.madignet.site" required>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">Status</label>
                                <select class="form-select" name="status" id="status" required>
                                    <option value="aktif">Aktif</option>
                                    <option value="isolir">Isolir</option>
                                </select>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">Tanggal Aktivasi</label>
                                <input type="date" class="form-control font-mono" name="activated_at" id="activated_at" required>
                            </div>

                            <div class="mb-3">
                                <label class="form-label text-muted">Jatuh Tempo (+1 Bulan)</label>
                                <input type="date" class="form-control font-mono bg-light" name="due_date" id="due_date" readonly>
                            </div>

                            <div class="d-flex gap-2 pt-1">
                                <button type="submit" class="btn btn-ops-primary flex-grow-1">
                                    <i class="bi bi-plus-lg me-1"></i>Simpan
                                </button>
                                <button type="reset" class="btn btn-ops-light">Reset</button>
                            </div>
                        </form>
                    </div>
                </div>

                <div class="col-lg-8">
                    <div class="panel-card">
                        <div class="panel-toolbar">
                            <span class="fw-semibold" style="font-size:0.85rem;">Daftar Terdaftar (<?= count($data) ?>)</span>
                            <div class="search-input-wrap">
                                <i class="bi bi-search"></i>
                                <input type="search" id="managementSearch" class="form-control" placeholder="Cari domain atau tanggal...">
                            </div>
                        </div>

                        <div class="table-responsive">
                            <table class="table-ops" id="managementTable">
                                <thead>
                                    <tr>
                                        <th>Subdomain</th>
                                        <th>Status</th>
                                        <th>Aktivasi</th>
                                        <th>Jatuh Tempo</th>
                                        <th class="text-end">Aksi</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($data as $domain => $info): ?>
                                    <tr data-search="<?= htmlspecialchars(strtolower($domain . ' ' . ($info['status'] ?? '') . ' ' . ($info['activated_at'] ?? '') . ' ' . ($info['due_date'] ?? ''))) ?>">
                                        <td>
                                            <div class="domain-cell">
                                                <span class="domain-name"><?= htmlspecialchars($domain) ?></span>
                                                <a href="https://<?= htmlspecialchars($domain) ?>" target="_blank" rel="noopener" class="domain-ext-link">
                                                    <i class="bi bi-box-arrow-up-right"></i>
                                                </a>
                                            </div>
                                        </td>
                                        <td>
                                            <?php if (($info['status'] ?? 'isolir') === 'aktif'): ?>
                                                <span class="badge-ops badge-aktif"><span class="status-dot"></span>Aktif</span>
                                            <?php else: ?>
                                                <span class="badge-ops badge-isolir"><span class="status-dot"></span>Isolir</span>
                                            <?php endif; ?>
                                        </td>
                                        <td class="font-mono text-muted" style="font-size:0.8rem;"><?= htmlspecialchars($info['activated_at'] ?? '-') ?></td>
                                        <td class="font-mono" style="font-size:0.8rem;font-weight:500;"><?= htmlspecialchars($info['due_date'] ?? '-') ?></td>
                                        <td class="text-end">
                                            <div class="d-inline-flex gap-1">
                                                <button type="button" class="btn btn-xs btn-ops-light" data-bs-toggle="modal"
                                                        data-bs-target="#editModal"
                                                        data-domain="<?= htmlspecialchars($domain, ENT_QUOTES, 'UTF-8') ?>"
                                                        data-status="<?= htmlspecialchars($info['status'] ?? 'isolir', ENT_QUOTES, 'UTF-8') ?>"
                                                        data-activated="<?= htmlspecialchars($info['activated_at'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                                                        data-due="<?= htmlspecialchars($info['due_date'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                                                        onclick="loadEditFormFromBtn(this)">
                                                    <i class="bi bi-pencil"></i> Edit
                                                </button>
                                                <form method="POST" class="m-0" onsubmit="return confirm('Hapus <?= htmlspecialchars(addslashes($domain)) ?>?');">
                                                    <?= csrf_field() ?>
                                                    <input type="hidden" name="action" value="delete">
                                                    <input type="hidden" name="domain" value="<?= htmlspecialchars($domain) ?>">
                                                    <button type="submit" class="btn btn-xs btn-ops-danger">
                                                        <i class="bi bi-trash"></i>
                                                    </button>
                                                </form>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                    <?php if (empty($data)): ?>
                                    <tr>
                                        <td colspan="5" class="text-center py-5 text-muted">
                                            Belum ada data pelanggan.
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
    </main>

    <div class="modal fade" id="editModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Edit Data Subdomain</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <?= csrf_field() ?>
                    <div class="modal-body">
                        <input type="hidden" name="action" value="edit">
                        <input type="hidden" name="old_domain" id="edit-old-domain">

                        <div class="mb-3">
                            <label class="form-label">Subdomain</label>
                            <input type="text" class="form-control font-mono" name="domain" id="edit-domain" required>
                        </div>

                        <div class="row g-3">
                            <div class="col-sm-6">
                                <label class="form-label">Status</label>
                                <select class="form-select" name="status" id="edit-status" required>
                                    <option value="aktif">Aktif</option>
                                    <option value="isolir">Isolir</option>
                                </select>
                            </div>
                            <div class="col-sm-6">
                                <label class="form-label">Tanggal Aktivasi</label>
                                <input type="date" class="form-control font-mono" name="activated_at" id="edit-activated_at" required>
                            </div>
                        </div>

                        <div class="mt-3">
                            <label class="form-label text-muted">Jatuh Tempo Otomatis</label>
                            <input type="date" class="form-control font-mono bg-light" name="due_date" id="edit-due_date" readonly>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-ops-light" data-bs-dismiss="modal">Batal</button>
                        <button type="submit" class="btn btn-ops-primary">Simpan Perubahan</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function calculateDueDate(activationDate) {
            if (!activationDate) return '';
            const [year, month, day] = activationDate.split('-').map(Number);
            if (!year || !month || !day) return '';
            const targetYear = month === 12 ? year + 1 : year;
            const targetMonth = month === 12 ? 1 : month + 1;
            const lastDay = new Date(targetYear, targetMonth, 0).getDate();
            const safeDay = Math.min(day, lastDay);
            return [targetYear, String(targetMonth).padStart(2, '0'), String(safeDay).padStart(2, '0')].join('-');
        }

        function syncDueDate(sourceId, targetId) {
            const activationInput = document.getElementById(sourceId);
            const dueInput = document.getElementById(targetId);
            if (!activationInput || !dueInput) return;
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
