<?php
require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../billing_helpers.php';

if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

$statusFile = STATUS_FILE;
$statusData = is_file($statusFile) ? json_decode((string) file_get_contents($statusFile), true) : [];
if (!is_array($statusData)) {
    $statusData = [];
}

$today = new DateTimeImmutable('today');
$changed = false;
foreach ($statusData as $domain => $info) {
    if (!is_array($info)) {
        $statusData[$domain] = [
            'status' => 'isolir',
            'activated_at' => null,
            'due_date' => null,
        ];
        $changed = true;
        continue;
    }
    $due = $info['due_date'] ?? null;
    $status = $info['status'] ?? 'isolir';

    if ($due) {
        $dueDateObj = parse_billing_date($due);
        if ($dueDateObj && $status === 'aktif' && $today > $dueDateObj) {
            $statusData[$domain]['status'] = 'isolir';
            $changed = true;
        }
    }
}

if ($changed) {
    save_status_data($statusFile, $statusData);
}

$flashMsg = $_SESSION['flash_msg'] ?? '';
$flashType = $_SESSION['flash_type'] ?? 'success';
unset($_SESSION['flash_msg'], $_SESSION['flash_type']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf()) {
        $_SESSION['flash_msg'] = 'Sesi form tidak valid (CSRF). Silakan coba lagi.';
        $_SESSION['flash_type'] = 'danger';
        write_audit_log('csrf_failed_dashboard', $_POST['domain'] ?? '-');
    } else {
        $action = $_POST['action'] ?? '';
        $domain = strtolower(trim((string) ($_POST['domain'] ?? '')));

        if (in_array($action, ['aktif', 'isolir', 'extend'], true) && $domain !== '' && isset($statusData[$domain])) {
            if ($action === 'aktif') {
                $statusData[$domain]['status'] = 'aktif';
                $statusData[$domain]['activated_at'] = date('Y-m-d');
                $statusData[$domain]['due_date'] = calculate_due_date_from_activation($statusData[$domain]['activated_at']);
                $_SESSION['flash_msg'] = "Layanan {$domain} diaktifkan.";
            } elseif ($action === 'isolir') {
                $statusData[$domain]['status'] = 'isolir';
                $_SESSION['flash_msg'] = "Layanan {$domain} diisolir.";
            } elseif ($action === 'extend') {
                $statusData[$domain]['due_date'] = calculate_extended_due_date($statusData[$domain]['due_date'] ?? null, $today);
                $_SESSION['flash_msg'] = "Jatuh tempo {$domain} diperpanjang 1 bulan.";
            }
            $_SESSION['flash_type'] = 'success';
            save_status_data($statusFile, $statusData);
            write_audit_log('dashboard_' . $action, $domain);
        } elseif ($action === 'add') {
            $validDomain = normalize_and_validate_domain($domain);
            $status = $_POST['status'] ?? 'aktif';
            $activated_at = $_POST['activated_at'] ?? '';
            $due_date = calculate_due_date_from_activation($activated_at);

            if ($validDomain === null) {
                $_SESSION['flash_msg'] = 'Format domain tidak valid.';
                $_SESSION['flash_type'] = 'danger';
            } elseif (!in_array($status, ['aktif', 'isolir'], true) || !$due_date) {
                $_SESSION['flash_msg'] = 'Status atau tanggal aktivasi tidak valid.';
                $_SESSION['flash_type'] = 'danger';
            } elseif (isset($statusData[$validDomain])) {
                $_SESSION['flash_msg'] = "Domain {$validDomain} sudah terdaftar.";
                $_SESSION['flash_type'] = 'danger';
            } else {
                $statusData[$validDomain] = [
                    'status' => $status,
                    'activated_at' => $activated_at,
                    'due_date' => $due_date,
                ];
                save_status_data($statusFile, $statusData);
                write_audit_log('domain_add', $validDomain, ['status' => $status, 'due_date' => $due_date]);
                $_SESSION['flash_msg'] = "Domain {$validDomain} berhasil ditambahkan.";
                $_SESSION['flash_type'] = 'success';
            }
        } elseif ($action === 'edit') {
            $old_domain = strtolower(trim((string) ($_POST['old_domain'] ?? '')));
            $validDomain = normalize_and_validate_domain($domain);
            $status = $_POST['status'] ?? 'isolir';
            $activated_at = $_POST['activated_at'] ?? '';
            $due_date = calculate_due_date_from_activation($activated_at);

            if ($validDomain === null || !in_array($status, ['aktif', 'isolir'], true) || !$due_date) {
                $_SESSION['flash_msg'] = 'Data perubahan tidak valid.';
                $_SESSION['flash_type'] = 'danger';
            } elseif ($validDomain !== $old_domain && isset($statusData[$validDomain])) {
                $_SESSION['flash_msg'] = "Domain {$validDomain} sudah ada.";
                $_SESSION['flash_type'] = 'danger';
            } else {
                if ($validDomain !== $old_domain && isset($statusData[$old_domain])) {
                    unset($statusData[$old_domain]);
                }
                $statusData[$validDomain] = [
                    'status' => $status,
                    'activated_at' => $activated_at,
                    'due_date' => $due_date,
                ];
                save_status_data($statusFile, $statusData);
                write_audit_log('domain_edit', $validDomain, ['old_domain' => $old_domain, 'status' => $status, 'due_date' => $due_date]);
                $_SESSION['flash_msg'] = "Data {$validDomain} diperbarui.";
                $_SESSION['flash_type'] = 'success';
            }
        } elseif ($action === 'delete') {
            if ($domain !== '' && isset($statusData[$domain])) {
                unset($statusData[$domain]);
                save_status_data($statusFile, $statusData);
                write_audit_log('domain_delete', $domain);
                $_SESSION['flash_msg'] = "Domain {$domain} dihapus.";
                $_SESSION['flash_type'] = 'success';
            }
        }
    }
    header('Location: dashboard.php');
    exit;
}

function days_left(?string $due_date_str): ?int
{
    if (empty($due_date_str)) {
        return null;
    }
    $due = parse_billing_date($due_date_str);
    if (!$due) {
        return null;
    }
    $now = new DateTimeImmutable('today');
    return (int) $now->diff($due)->format('%r%a');
}

$stats = [
    'total' => count($statusData),
    'aktif' => 0,
    'isolir' => 0,
    'due_soon' => 0,
];

foreach ($statusData as $info) {
    $status = $info['status'] ?? 'isolir';
    $daysLeft = days_left($info['due_date'] ?? null);

    if ($status === 'aktif') {
        $stats['aktif']++;
        if ($daysLeft !== null && $daysLeft >= 0 && $daysLeft <= 7) {
            $stats['due_soon']++;
        }
    } else {
        $stats['isolir']++;
    }
}

$adminUser = $_SESSION['admin_user'] ?? ADMIN_USER;
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard | WarungCloud Billing</title>
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
                    <a href="dashboard.php" class="nav-link active"><i class="bi bi-grid-1x2 me-1"></i>Overview</a>
                </li>
                <li class="nav-item">
                    <a href="management.php" class="nav-link"><i class="bi bi-sliders me-1"></i>Manajemen</a>
                </li>
                <li class="nav-item ms-lg-2 my-2 my-lg-0">
                    <span class="user-chip">
                        <i class="bi bi-person-fill"></i>
                        <?= htmlspecialchars($adminUser) ?>
                    </span>
                </li>
                <li class="nav-item ms-lg-1">
                    <a href="logout.php" class="btn btn-sm btn-outline-secondary text-light border-secondary px-2 py-1" style="font-size:0.78rem;">
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
                <h1 class="page-title">Status Layanan Subdomain</h1>
                <p class="page-meta"><?= $today->format('d M Y') ?></p>
            </div>
            <div class="d-flex align-items-center gap-2">
                <button type="button" class="btn btn-ops-primary d-inline-flex align-items-center gap-1" data-bs-toggle="modal" data-bs-target="#addModal">
                    <i class="bi bi-plus-lg"></i>
                    <span>Tambah Subdomain</span>
                </button>
            </div>
        </header>

        <?php if ($flashMsg !== ''): ?>
            <div class="alert alert-<?= htmlspecialchars($flashType) ?> alert-dismissible fade show py-2 px-3 mb-3 d-flex align-items-center justify-content-between" role="alert" style="font-size:0.84rem;border-radius:8px;">
                <div>
                    <i class="bi <?= $flashType === 'success' ? 'bi-check-circle-fill' : 'bi-exclamation-triangle-fill' ?> me-2"></i>
                    <?= htmlspecialchars($flashMsg) ?>
                </div>
                <button type="button" class="btn-close" data-bs-dismiss="alert" style="padding:0.65rem;"></button>
            </div>
        <?php endif; ?>

        <section class="kpi-grid">
            <div class="kpi-card active-filter" data-filter-card="all" onclick="setFilter('all')">
                <div>
                    <div class="kpi-label">Total Subdomain</div>
                    <div class="kpi-value"><?= $stats['total'] ?></div>
                </div>
                <span class="kpi-badge kpi-badge-neutral"><i class="bi bi-globe2"></i></span>
            </div>
            <div class="kpi-card" data-filter-card="aktif" onclick="setFilter('aktif')">
                <div>
                    <div class="kpi-label">Aktif</div>
                    <div class="kpi-value text-success"><?= $stats['aktif'] ?></div>
                </div>
                <span class="kpi-badge kpi-badge-success"><i class="bi bi-check-lg"></i></span>
            </div>
            <div class="kpi-card" data-filter-card="due_soon" onclick="setFilter('due_soon')">
                <div>
                    <div class="kpi-label">Jatuh Tempo &le; 7 Hari</div>
                    <div class="kpi-value text-warning"><?= $stats['due_soon'] ?></div>
                </div>
                <span class="kpi-badge kpi-badge-warning"><i class="bi bi-clock-history"></i></span>
            </div>
            <div class="kpi-card" data-filter-card="isolir" onclick="setFilter('isolir')">
                <div>
                    <div class="kpi-label">Isolir</div>
                    <div class="kpi-value text-danger"><?= $stats['isolir'] ?></div>
                </div>
                <span class="kpi-badge kpi-badge-danger"><i class="bi bi-slash-circle"></i></span>
            </div>
        </section>

        <section class="panel-card">
            <div class="panel-toolbar">
                <div class="filter-tabs" role="tablist">
                    <button type="button" class="filter-tab active" data-filter-btn="all" onclick="setFilter('all')">
                        Semua (<?= $stats['total'] ?>)
                    </button>
                    <button type="button" class="filter-tab" data-filter-btn="aktif" onclick="setFilter('aktif')">
                        Aktif (<?= $stats['aktif'] ?>)
                    </button>
                    <button type="button" class="filter-tab" data-filter-btn="due_soon" onclick="setFilter('due_soon')">
                        Segera Habis (<?= $stats['due_soon'] ?>)
                    </button>
                    <button type="button" class="filter-tab" data-filter-btn="isolir" onclick="setFilter('isolir')">
                        Isolir (<?= $stats['isolir'] ?>)
                    </button>
                </div>

                <div class="search-input-wrap">
                    <i class="bi bi-search"></i>
                    <input type="search" id="clientSearch" class="form-control" placeholder="Filter domain atau tanggal...">
                </div>
            </div>

            <div class="table-responsive">
                <table class="table-ops" id="clientTable">
                    <thead>
                        <tr>
                            <th>Subdomain</th>
                            <th>Status</th>
                            <th>Tgl Aktivasi</th>
                            <th>Jatuh Tempo</th>
                            <th>Sisa Waktu</th>
                            <th class="text-end">Kontrol</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($statusData as $domain => $info):
                        $status = $info['status'] ?? 'isolir';
                        $activated = $info['activated_at'] ?? '-';
                        $due = $info['due_date'] ?? '-';
                        $daysLeft = days_left($info['due_date'] ?? null);
                        $isDueSoon = ($status === 'aktif' && $daysLeft !== null && $daysLeft >= 0 && $daysLeft <= 7);

                        if ($status === 'aktif') {
                            $statusBadge = '<span class="badge-ops badge-aktif"><span class="status-dot"></span>Aktif</span>';
                            if ($daysLeft === null) {
                                $countBadge = '<span class="badge-ops badge-neutral">-</span>';
                            } elseif ($daysLeft > 7) {
                                $countBadge = '<span class="badge-ops badge-neutral font-mono">' . $daysLeft . ' hari</span>';
                            } elseif ($daysLeft > 0) {
                                $countBadge = '<span class="badge-ops badge-warning font-mono">' . $daysLeft . ' hari lagi</span>';
                            } elseif ($daysLeft === 0) {
                                $countBadge = '<span class="badge-ops badge-warning font-mono">Hari ini</span>';
                            } else {
                                $countBadge = '<span class="badge-ops badge-isolir font-mono">Lewat ' . abs($daysLeft) . ' hari</span>';
                            }
                        } else {
                            $statusBadge = '<span class="badge-ops badge-isolir"><span class="status-dot"></span>Isolir</span>';
                            $countBadge = '<span class="badge-ops badge-neutral">Nonaktif</span>';
                        }
                    ?>
                        <tr data-search="<?= htmlspecialchars(strtolower($domain . ' ' . $status . ' ' . $activated . ' ' . $due)) ?>"
                            data-status="<?= htmlspecialchars($status) ?>"
                            data-due-soon="<?= $isDueSoon ? '1' : '0' ?>">
                            <td>
                                <div class="domain-cell">
                                    <span class="domain-name"><?= htmlspecialchars($domain) ?></span>
                                    <a href="https://<?= htmlspecialchars($domain) ?>" target="_blank" rel="noopener" class="domain-ext-link" title="Buka <?= htmlspecialchars($domain) ?>">
                                        <i class="bi bi-box-arrow-up-right"></i>
                                    </a>
                                </div>
                            </td>
                            <td><?= $statusBadge ?></td>
                            <td class="font-mono text-muted" style="font-size:0.8rem;"><?= htmlspecialchars($activated) ?></td>
                            <td class="font-mono" style="font-size:0.8rem;font-weight:500;"><?= htmlspecialchars($due) ?></td>
                            <td><?= $countBadge ?></td>
                            <td class="text-end">
                                <div class="d-inline-flex flex-wrap justify-content-end gap-1">
                                    <form method="post" class="m-0">
                                        <?= csrf_field() ?>
                                        <input type="hidden" name="domain" value="<?= htmlspecialchars($domain) ?>">
                                        <input type="hidden" name="action" value="extend">
                                        <button type="submit" class="btn btn-xs btn-ops-light" title="Tambah 1 bulan dari jatuh tempo">
                                            <i class="bi bi-calendar-plus text-primary"></i>+1 Bln
                                        </button>
                                    </form>

                                    <form method="post" class="m-0">
                                        <?= csrf_field() ?>
                                        <input type="hidden" name="domain" value="<?= htmlspecialchars($domain) ?>">
                                        <input type="hidden" name="action" value="<?= $status === 'aktif' ? 'isolir' : 'aktif' ?>">
                                        <button type="submit" class="btn btn-xs <?= $status === 'aktif' ? 'btn-ops-warning' : 'btn-ops-success' ?>">
                                            <i class="bi <?= $status === 'aktif' ? 'bi-pause-fill' : 'bi-play-fill' ?>"></i>
                                            <?= $status === 'aktif' ? 'Isolir' : 'Aktifkan' ?>
                                        </button>
                                    </form>

                                    <button type="button" class="btn btn-xs btn-ops-light"
                                            data-bs-toggle="modal"
                                            data-bs-target="#editModal"
                                            data-domain="<?= htmlspecialchars($domain, ENT_QUOTES, 'UTF-8') ?>"
                                            data-status="<?= htmlspecialchars($status, ENT_QUOTES, 'UTF-8') ?>"
                                            data-activated="<?= htmlspecialchars($info['activated_at'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                                            data-due="<?= htmlspecialchars($info['due_date'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                                            onclick="loadEditModal(this)"
                                            title="Edit tanggal / domain">
                                        <i class="bi bi-pencil"></i>
                                    </button>

                                    <form method="post" class="m-0" onsubmit="return confirm('Hapus subdomain <?= htmlspecialchars(addslashes($domain)) ?>?');">
                                        <?= csrf_field() ?>
                                        <input type="hidden" name="domain" value="<?= htmlspecialchars($domain) ?>">
                                        <input type="hidden" name="action" value="delete">
                                        <button type="submit" class="btn btn-xs btn-ops-danger" title="Hapus">
                                            <i class="bi bi-trash"></i>
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    <?php if (empty($statusData)): ?>
                        <tr>
                            <td colspan="6" class="text-center py-5 text-muted">
                                Belum ada subdomain terdaftar. Klik <strong>Tambah Subdomain</strong> di kanan atas.
                            </td>
                        </tr>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </section>
    </div>
</main>

<!-- Modal Tambah -->
<div class="modal fade" id="addModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Tambah Subdomain Pelanggan</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="post">
                <?= csrf_field() ?>
                <input type="hidden" name="action" value="add">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Subdomain</label>
                        <input type="text" class="form-control font-mono" name="domain" placeholder="pelanggan.madignet.site" required>
                    </div>
                    <div class="row g-3">
                        <div class="col-sm-6">
                            <label class="form-label">Status Awal</label>
                            <select class="form-select" name="status" required>
                                <option value="aktif">Aktif</option>
                                <option value="isolir">Isolir</option>
                            </select>
                        </div>
                        <div class="col-sm-6">
                            <label class="form-label">Tanggal Aktivasi</label>
                            <input type="date" class="form-control font-mono" name="activated_at" id="add-activated" required>
                        </div>
                    </div>
                    <div class="mt-3">
                        <label class="form-label text-muted">Jatuh Tempo Otomatis (+1 Bulan)</label>
                        <input type="date" class="form-control font-mono bg-light" id="add-due" readonly>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-ops-light" data-bs-dismiss="modal">Batal</button>
                    <button type="submit" class="btn btn-ops-primary">Simpan Subdomain</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal Edit -->
<div class="modal fade" id="editModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Edit Data Subdomain</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="post">
                <?= csrf_field() ?>
                <input type="hidden" name="action" value="edit">
                <input type="hidden" name="old_domain" id="edit-old-domain">
                <div class="modal-body">
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
                            <input type="date" class="form-control font-mono" name="activated_at" id="edit-activated" required>
                        </div>
                    </div>
                    <div class="mt-3">
                        <label class="form-label text-muted">Jatuh Tempo (+1 Bulan dari Aktivasi)</label>
                        <input type="date" class="form-control font-mono bg-light" id="edit-due" readonly>
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
let currentFilter = 'all';

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

function bindDateSync(srcId, dstId) {
    const src = document.getElementById(srcId);
    const dst = document.getElementById(dstId);
    if (!src || !dst) return;
    const update = () => { dst.value = calculateDueDate(src.value); };
    src.addEventListener('input', update);
    src.addEventListener('change', update);
    update();
}

function loadEditModal(btn) {
    document.getElementById('edit-old-domain').value = btn.dataset.domain || '';
    document.getElementById('edit-domain').value = btn.dataset.domain || '';
    document.getElementById('edit-status').value = btn.dataset.status || 'isolir';
    document.getElementById('edit-activated').value = btn.dataset.activated || '';
    document.getElementById('edit-due').value = calculateDueDate(btn.dataset.activated) || btn.dataset.due || '';
}

function applyTableFilters() {
    const searchInput = document.getElementById('clientSearch');
    const keyword = searchInput ? searchInput.value.trim().toLowerCase() : '';
    const rows = document.querySelectorAll('#clientTable tbody tr[data-search]');

    rows.forEach(function (row) {
        const matchSearch = row.dataset.search.includes(keyword);
        let matchTab = true;
        if (currentFilter === 'aktif') {
            matchTab = row.dataset.status === 'aktif';
        } else if (currentFilter === 'isolir') {
            matchTab = row.dataset.status === 'isolir';
        } else if (currentFilter === 'due_soon') {
            matchTab = row.dataset.dueSoon === '1';
        }
        row.style.display = (matchSearch && matchTab) ? '' : 'none';
    });
}

function setFilter(filter) {
    currentFilter = filter;
    document.querySelectorAll('[data-filter-btn]').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filterBtn === filter);
    });
    document.querySelectorAll('[data-filter-card]').forEach(card => {
        card.classList.toggle('active-filter', card.dataset.filterCard === filter);
    });
    applyTableFilters();
}

document.addEventListener('DOMContentLoaded', function () {
    const today = new Date().toISOString().split('T')[0];
    const addAct = document.getElementById('add-activated');
    if (addAct) addAct.value = today;
    bindDateSync('add-activated', 'add-due');
    bindDateSync('edit-activated', 'edit-due');

    const searchInput = document.getElementById('clientSearch');
    if (searchInput) {
        searchInput.addEventListener('input', applyTableFilters);
    }
});
</script>
</body>
</html>
