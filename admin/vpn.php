<?php
require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../billing_helpers.php';
require_once __DIR__ . '/../routeros_api.php';

if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

$chrConfig = get_chr_config();
$flashMsg = $_SESSION['vpn_flash_msg'] ?? '';
$flashType = $_SESSION['vpn_flash_type'] ?? 'success';
$newClientScript = $_SESSION['vpn_new_client'] ?? null;
unset($_SESSION['vpn_flash_msg'], $_SESSION['vpn_flash_type'], $_SESSION['vpn_new_client']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf()) {
        $_SESSION['vpn_flash_msg'] = 'Sesi form tidak valid (CSRF). Silakan muat ulang halaman.';
        $_SESSION['vpn_flash_type'] = 'danger';
        header('Location: vpn.php');
        exit;
    }

    $action = $_POST['action'] ?? '';

    if ($action === 'save_chr_config') {
        $newCfg = [
            'host' => trim((string) ($_POST['chr_host'] ?? '')),
            'port' => max(1, (int) ($_POST['chr_port'] ?? 8728)),
            'user' => trim((string) ($_POST['chr_user'] ?? 'admin')),
            'pass' => (string) ($_POST['chr_pass'] ?? '') !== '' ? (string) $_POST['chr_pass'] : $chrConfig['pass'],
            'public_host' => trim((string) ($_POST['chr_public_host'] ?? '')) ?: trim((string) ($_POST['chr_host'] ?? '')),
            'default_local_ip' => trim((string) ($_POST['default_local_ip'] ?? '10.10.10.1')),
            'default_profile' => trim((string) ($_POST['default_profile'] ?? 'default-encryption')),
        ];
        save_chr_config($newCfg);
        write_audit_log('chr_config_updated', $newCfg['host']);
        $_SESSION['vpn_flash_msg'] = 'Konfigurasi koneksi CHR berhasil disimpan.';
        $_SESSION['vpn_flash_type'] = 'success';
        header('Location: vpn.php');
        exit;
    }

    // Koneksi ke CHR untuk aksi PPP & NAT
    $api = new RouterosApi();
    if (!$api->connect($chrConfig['host'], $chrConfig['user'], $chrConfig['pass'], $chrConfig['port'])) {
        $_SESSION['vpn_flash_msg'] = 'Gagal konek CHR: ' . $api->getLastError();
        $_SESSION['vpn_flash_type'] = 'danger';
        header('Location: vpn.php');
        exit;
    }

    if ($action === 'add_vpn') {
        $name = trim((string) ($_POST['vpn_user'] ?? ''));
        $password = trim((string) ($_POST['vpn_pass'] ?? ''));
        $service = trim((string) ($_POST['vpn_service'] ?? 'any'));
        $profile = trim((string) ($_POST['vpn_profile'] ?? 'default-encryption'));
        $localAddr = trim((string) ($_POST['local_address'] ?? ''));
        $remoteAddr = trim((string) ($_POST['remote_address'] ?? ''));
        $comment = trim((string) ($_POST['comment'] ?? ''));

        $portApi = trim((string) ($_POST['nat_port_api'] ?? ''));
        $toPortApi = trim((string) ($_POST['to_port_api'] ?? '8728')) ?: '8728';

        $portWinbox = trim((string) ($_POST['nat_port_winbox'] ?? ''));
        $toPortWinbox = trim((string) ($_POST['to_port_winbox'] ?? '8291')) ?: '8291';

        $portWeb = trim((string) ($_POST['nat_port_web'] ?? ''));
        $toPortWeb = trim((string) ($_POST['to_port_web'] ?? '80')) ?: '80';

        if ($name === '' || $password === '' || !filter_var($remoteAddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $_SESSION['vpn_flash_msg'] = 'Username, Password, dan IP Remote VPN (IPv4) wajib diisi dengan benar.';
            $_SESSION['vpn_flash_type'] = 'danger';
            header('Location: vpn.php');
            exit;
        }

        $secretParams = [
            'name' => $name,
            'password' => $password,
            'service' => in_array($service, ['any', 'l2tp', 'sstp', 'pptp', 'ovpn'], true) ? $service : 'any',
            'profile' => $profile !== '' ? $profile : 'default-encryption',
            'remote-address' => $remoteAddr,
            'comment' => $comment !== '' ? "VPN-{$name} | {$comment}" : "VPN-{$name}",
        ];
        if (filter_var($localAddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $secretParams['local-address'] = $localAddr;
        }

        $resSecret = $api->comm('/ppp/secret/add', $secretParams);
        if (isset($resSecret['!trap'])) {
            $errMsg = $resSecret['!trap'][0]['message'] ?? 'Gagal membuat PPP Secret';
            $_SESSION['vpn_flash_msg'] = "Gagal buat PPP Secret: {$errMsg}";
            $_SESSION['vpn_flash_type'] = 'danger';
            header('Location: vpn.php');
            exit;
        }

        $createdNats = [];
        $natRulesToCreate = [
            ['label' => 'API', 'dst_port' => $portApi, 'to_port' => $toPortApi],
            ['label' => 'WINBOX', 'dst_port' => $portWinbox, 'to_port' => $toPortWinbox],
            ['label' => 'WEB', 'dst_port' => $portWeb, 'to_port' => $toPortWeb],
        ];

        foreach ($natRulesToCreate as $rule) {
            $dstPort = (int) $rule['dst_port'];
            $toPort = (int) $rule['to_port'];
            if ($dstPort > 0 && $dstPort <= 65535 && $toPort > 0 && $toPort <= 65535) {
                $natComment = "VPN-{$name} [{$rule['label']}]" . ($comment !== '' ? " {$comment}" : '');
                $natRes = $api->comm('/ip/firewall/nat/add', [
                    'chain' => 'dstnat',
                    'protocol' => 'tcp',
                    'dst-port' => (string) $dstPort,
                    'action' => 'dst-nat',
                    'to-addresses' => $remoteAddr,
                    'to-ports' => (string) $toPort,
                    'comment' => $natComment,
                ]);
                if (!isset($natRes['!trap'])) {
                    $createdNats[] = "{$rule['label']}:{$dstPort}->{$toPort}";
                }
            }
        }

        write_audit_log('vpn_add', $name, ['remote_ip' => $remoteAddr, 'nats' => $createdNats]);
        $_SESSION['vpn_flash_msg'] = "Client VPN {$name} ({$remoteAddr}) + " . count($createdNats) . " rule NAT berhasil dibuat di CHR.";
        $_SESSION['vpn_flash_type'] = 'success';
        $_SESSION['vpn_new_client'] = [
            'user' => $name,
            'pass' => $password,
            'service' => $service,
            'remote_ip' => $remoteAddr,
            'local_ip' => $localAddr,
            'chr_host' => $chrConfig['public_host'] ?: $chrConfig['host'],
            'port_api' => $portApi,
            'port_winbox' => $portWinbox,
            'port_web' => $portWeb,
        ];
        header('Location: vpn.php');
        exit;
    }

    if ($action === 'toggle_secret') {
        $id = (string) ($_POST['secret_id'] ?? '');
        $name = (string) ($_POST['vpn_user'] ?? '');
        $disable = ($_POST['disable'] ?? 'true') === 'true' ? 'yes' : 'no';
        if ($id !== '') {
            $api->comm('/ppp/secret/set', [
                '.id' => $id,
                'disabled' => $disable,
            ]);
            // Jika di-disable, putuskan juga sesi aktifnya agar langsung terputus
            if ($disable === 'yes' && $name !== '') {
                $activeList = $api->comm('/ppp/active/print', ['?name' => $name]);
                foreach ($activeList as $act) {
                    if (is_array($act) && isset($act['.id'])) {
                        $api->comm('/ppp/active/remove', ['.id' => $act['.id']]);
                    }
                }
            }
            write_audit_log('vpn_toggle', $name, ['disabled' => $disable]);
            $_SESSION['vpn_flash_msg'] = "Status VPN {$name} berhasil diperbarui.";
            $_SESSION['vpn_flash_type'] = 'success';
        }
        header('Location: vpn.php');
        exit;
    }

    if ($action === 'delete_vpn') {
        $id = (string) ($_POST['secret_id'] ?? '');
        $name = trim((string) ($_POST['vpn_user'] ?? ''));
        $remoteIp = trim((string) ($_POST['remote_ip'] ?? ''));

        if ($id !== '') {
            $api->comm('/ppp/secret/remove', ['.id' => $id]);
        }

        // Putuskan koneksi aktif
        if ($name !== '') {
            $activeList = $api->comm('/ppp/active/print', ['?name' => $name]);
            foreach ($activeList as $act) {
                if (is_array($act) && isset($act['.id'])) {
                    $api->comm('/ppp/active/remove', ['.id' => $act['.id']]);
                }
            }
        }

        // Hapus otomatis semua rule dst-nat yang menuju ke IP remote client ini atau memiliki tag VPN-<name>
        $allNats = $api->comm('/ip/firewall/nat/print', ['?chain' => 'dstnat']);
        $removedNatCount = 0;
        foreach ($allNats as $key => $nat) {
            if ($key === '!trap' || !is_array($nat) || !isset($nat['.id'])) {
                continue;
            }
            $toAddr = $nat['to-addresses'] ?? '';
            $cmt = $nat['comment'] ?? '';
            $matchIp = ($remoteIp !== '' && $toAddr === $remoteIp);
            $matchTag = ($name !== '' && str_contains($cmt, "VPN-{$name}"));
            if ($matchIp || $matchTag) {
                $api->comm('/ip/firewall/nat/remove', ['.id' => $nat['.id']]);
                $removedNatCount++;
            }
        }

        write_audit_log('vpn_delete', $name, ['remote_ip' => $remoteIp, 'removed_nats' => $removedNatCount]);
        $_SESSION['vpn_flash_msg'] = "VPN {$name} beserta {$removedNatCount} rule Firewall NAT berhasil dihapus dari CHR.";
        $_SESSION['vpn_flash_type'] = 'success';
        header('Location: vpn.php');
        exit;
    }
}

// Ambil data live dari CHR jika host sudah diatur
$chrConnected = false;
$chrError = '';
$secrets = [];
$activeMap = [];
$natByIp = [];
$profiles = ['default', 'default-encryption'];

if ($chrConfig['host'] !== '') {
    $api = new RouterosApi();
    if ($api->connect($chrConfig['host'], $chrConfig['user'], $chrConfig['pass'], $chrConfig['port'], 4)) {
        $chrConnected = true;

        $rawProfiles = $api->comm('/ppp/profile/print');
        $fetchedProfiles = [];
        foreach ($rawProfiles as $k => $p) {
            if ($k !== '!trap' && is_array($p) && !empty($p['name'])) {
                $fetchedProfiles[] = $p['name'];
            }
        }
        if (!empty($fetchedProfiles)) {
            $profiles = array_values(array_unique($fetchedProfiles));
        }

        $rawActive = $api->comm('/ppp/active/print');
        foreach ($rawActive as $k => $a) {
            if ($k !== '!trap' && is_array($a) && !empty($a['name'])) {
                $activeMap[$a['name']] = $a;
            }
        }

        $rawNats = $api->comm('/ip/firewall/nat/print', ['?chain' => 'dstnat']);
        foreach ($rawNats as $k => $n) {
            if ($k !== '!trap' && is_array($n)) {
                $toIp = $n['to-addresses'] ?? '';
                if ($toIp !== '' && ($n['action'] ?? '') === 'dst-nat') {
                    $natByIp[$toIp][] = [
                        'id' => $n['.id'] ?? '',
                        'dst_port' => $n['dst-port'] ?? '',
                        'to_port' => $n['to-ports'] ?? '',
                        'protocol' => $n['protocol'] ?? 'tcp',
                        'comment' => $n['comment'] ?? '',
                        'disabled' => ($n['disabled'] ?? 'false') === 'true',
                    ];
                }
            }
        }

        $rawSecrets = $api->comm('/ppp/secret/print');
        foreach ($rawSecrets as $k => $s) {
            if ($k !== '!trap' && is_array($s) && isset($s['name'])) {
                $secrets[] = $s;
            }
        }
    } else {
        $chrError = $api->getLastError();
    }
}

$adminUser = $_SESSION['admin_user'] ?? ADMIN_USER;
$publicHost = $chrConfig['public_host'] ?: $chrConfig['host'];
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN CHR | WarungCloud Billing</title>
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
                    <a href="dashboard.php" class="nav-link"><i class="bi bi-grid-1x2 me-1"></i>Overview</a>
                </li>
                <li class="nav-item">
                    <a href="management.php" class="nav-link"><i class="bi bi-sliders me-1"></i>Manajemen</a>
                </li>
                <li class="nav-item">
                    <a href="vpn.php" class="nav-link active"><i class="bi bi-shield-lock me-1"></i>VPN CHR</a>
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
            <div class="d-flex align-items-center gap-2 flex-wrap">
                <h1 class="page-title">Manajemen VPN &amp; Port Forwarding CHR</h1>
                <?php if ($chrConnected): ?>
                    <span class="badge-ops badge-aktif"><span class="status-dot"></span>CHR Terhubung (<?= htmlspecialchars($chrConfig['host']) ?>)</span>
                <?php else: ?>
                    <span class="badge-ops badge-isolir"><span class="status-dot"></span>CHR Belum Terhubung</span>
                <?php endif; ?>
            </div>
            <div class="d-flex align-items-center gap-2">
                <button type="button" class="btn btn-ops-light d-inline-flex align-items-center gap-1" data-bs-toggle="modal" data-bs-target="#chrConfigModal">
                    <i class="bi bi-gear"></i>
                    <span>Koneksi CHR</span>
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

        <?php if (!$chrConnected): ?>
            <div class="panel-card p-4 mb-3 border-warning" style="background:#fffbeb;">
                <div class="d-flex flex-column flex-md-row align-items-md-center justify-content-between gap-3">
                    <div>
                        <div class="fw-bold text-dark mb-1"><i class="bi bi-plug-fill text-warning me-1"></i>Koneksi MikroTik CHR Belum Aktif</div>
                        <div class="text-muted" style="font-size:0.82rem;">
                            <?= $chrError !== '' ? htmlspecialchars($chrError) : 'Silakan masukkan IP/Domain CHR, Port API (default 8728), Username, dan Password CHR Anda.' ?>
                        </div>
                    </div>
                    <button type="button" class="btn btn-ops-primary flex-shrink-0" data-bs-toggle="modal" data-bs-target="#chrConfigModal">
                        <i class="bi bi-sliders me-1"></i>Atur Koneksi CHR
                    </button>
                </div>
            </div>
        <?php endif; ?>

        <div class="row g-3">
            <!-- Form Buat VPN + NAT Sekaligus -->
            <div class="col-lg-4">
                <div class="panel-card p-3">
                    <h2 class="h6 fw-bold mb-3 pb-2 border-bottom">Buat Client VPN + NAT Baru</h2>
                    <form method="post">
                        <?= csrf_field() ?>
                        <input type="hidden" name="action" value="add_vpn">

                        <div class="row g-2 mb-2">
                            <div class="col-7">
                                <label class="form-label">Username VPN</label>
                                <input type="text" class="form-control font-mono" name="vpn_user" placeholder="vpn-raskanet" required>
                            </div>
                            <div class="col-5">
                                <label class="form-label">Password</label>
                                <div class="input-group">
                                    <input type="text" class="form-control font-mono" name="vpn_pass" id="vpn_pass" required>
                                    <button type="button" class="btn btn-ops-light px-2" onclick="genPass()" title="Acak Password">
                                        <i class="bi bi-shuffle"></i>
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div class="row g-2 mb-2">
                            <div class="col-6">
                                <label class="form-label">Service</label>
                                <select class="form-select" name="vpn_service">
                                    <option value="any">any (Semua)</option>
                                    <option value="l2tp" selected>l2tp</option>
                                    <option value="sstp">sstp</option>
                                    <option value="pptp">pptp</option>
                                    <option value="ovpn">ovpn</option>
                                </select>
                            </div>
                            <div class="col-6">
                                <label class="form-label">Profile PPP</label>
                                <input type="text" class="form-control font-mono" name="vpn_profile" list="profileList" value="<?= htmlspecialchars($chrConfig['default_profile']) ?>" required>
                                <datalist id="profileList">
                                    <?php foreach ($profiles as $prof): ?>
                                        <option value="<?= htmlspecialchars($prof) ?>">
                                    <?php endforeach; ?>
                                </datalist>
                            </div>
                        </div>

                        <div class="row g-2 mb-2">
                            <div class="col-6">
                                <label class="form-label">Local IP (Gateway CHR)</label>
                                <input type="text" class="form-control font-mono" name="local_address" value="<?= htmlspecialchars($chrConfig['default_local_ip']) ?>" placeholder="10.10.10.1">
                            </div>
                            <div class="col-6">
                                <label class="form-label">Remote IP (Client)</label>
                                <input type="text" class="form-control font-mono" name="remote_address" placeholder="10.10.10.25" required>
                            </div>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Komentar / Subdomain Pelanggan</label>
                            <input type="text" class="form-control" name="comment" placeholder="raskanet.madignet.site">
                        </div>

                        <div class="p-2 rounded border bg-light mb-3">
                            <div class="fw-semibold mb-2" style="font-size:0.78rem;color:#334155;">
                                <i class="bi bi-arrow-left-right me-1"></i>Port Forwarding (Firewall dst-nat)
                            </div>

                            <div class="row g-2 align-items-center mb-2">
                                <div class="col-4">
                                    <span class="font-mono" style="font-size:0.76rem;">API Mikhmon</span>
                                </div>
                                <div class="col-4">
                                    <input type="number" class="form-control form-control-sm font-mono" name="nat_port_api" placeholder="Port CHR">
                                </div>
                                <div class="col-4">
                                    <input type="number" class="form-control form-control-sm font-mono" name="to_port_api" value="8728" placeholder="8728">
                                </div>
                            </div>

                            <div class="row g-2 align-items-center mb-2">
                                <div class="col-4">
                                    <span class="font-mono" style="font-size:0.76rem;">Winbox</span>
                                </div>
                                <div class="col-4">
                                    <input type="number" class="form-control form-control-sm font-mono" name="nat_port_winbox" placeholder="Port CHR">
                                </div>
                                <div class="col-4">
                                    <input type="number" class="form-control form-control-sm font-mono" name="to_port_winbox" value="8291" placeholder="8291">
                                </div>
                            </div>

                            <div class="row g-2 align-items-center">
                                <div class="col-4">
                                    <span class="font-mono" style="font-size:0.76rem;">WebFig (Ops)</span>
                                </div>
                                <div class="col-4">
                                    <input type="number" class="form-control form-control-sm font-mono" name="nat_port_web" placeholder="Kosong=Skip">
                                </div>
                                <div class="col-4">
                                    <input type="number" class="form-control form-control-sm font-mono" name="to_port_web" value="80" placeholder="80">
                                </div>
                            </div>
                        </div>

                        <button type="submit" class="btn btn-ops-primary w-100" <?= !$chrConnected ? 'disabled' : '' ?>>
                            <i class="bi bi-lightning-charge-fill me-1"></i>Buat PPP Secret &amp; Rule NAT
                        </button>
                    </form>
                </div>
            </div>

            <!-- Tabel Daftar Client VPN di CHR -->
            <div class="col-lg-8">
                <div class="panel-card">
                    <div class="panel-toolbar">
                        <div class="d-flex align-items-center gap-2">
                            <span class="fw-semibold" style="font-size:0.85rem;">Daftar PPP Secret di CHR (<?= count($secrets) ?>)</span>
                            <span class="badge-ops badge-aktif">Online: <?= count($activeMap) ?></span>
                        </div>
                        <div class="search-input-wrap">
                            <i class="bi bi-search"></i>
                            <input type="search" id="vpnSearch" class="form-control" placeholder="Cari user, IP, atau port...">
                        </div>
                    </div>

                    <div class="table-responsive">
                        <table class="table-ops" id="vpnTable">
                            <thead>
                                <tr>
                                    <th>User VPN</th>
                                    <th>IP Remote</th>
                                    <th>Port Forward (CHR &rarr; Lokal)</th>
                                    <th>Koneksi</th>
                                    <th class="text-end">Aksi</th>
                                </tr>
                            </thead>
                            <tbody>
                            <?php foreach ($secrets as $sec):
                                $sId = $sec['.id'] ?? '';
                                $sName = $sec['name'] ?? '';
                                $sPass = $sec['password'] ?? '';
                                $sService = $sec['service'] ?? 'any';
                                $sRemote = $sec['remote-address'] ?? '-';
                                $sLocal = $sec['local-address'] ?? $chrConfig['default_local_ip'];
                                $sComment = $sec['comment'] ?? '';
                                $sDisabled = ($sec['disabled'] ?? 'false') === 'true';
                                $isOnline = isset($activeMap[$sName]);
                                $uptime = $activeMap[$sName]['uptime'] ?? '';
                                $nats = ($sRemote !== '-' && isset($natByIp[$sRemote])) ? $natByIp[$sRemote] : [];

                                $portApiFound = '';
                                $portWinboxFound = '';
                                $portWebFound = '';
                                $natSearchStr = '';
                                foreach ($nats as $n) {
                                    $natSearchStr .= ' ' . $n['dst_port'] . ':' . $n['to_port'];
                                    if ($n['to_port'] === '8728') $portApiFound = $n['dst_port'];
                                    elseif ($n['to_port'] === '8291') $portWinboxFound = $n['dst_port'];
                                    elseif ($n['to_port'] === '80') $portWebFound = $n['dst_port'];
                                }
                            ?>
                                <tr data-search="<?= htmlspecialchars(strtolower($sName . ' ' . $sRemote . ' ' . $sComment . ' ' . $natSearchStr)) ?>">
                                    <td>
                                        <div class="domain-name"><?= htmlspecialchars($sName) ?></div>
                                        <div class="client-note">
                                            <span class="text-uppercase"><?= htmlspecialchars($sService) ?></span>
                                            <?= $sComment !== '' ? ' &middot; ' . htmlspecialchars($sComment) : '' ?>
                                        </div>
                                    </td>
                                    <td class="font-mono" style="font-size:0.8rem;"><?= htmlspecialchars($sRemote) ?></td>
                                    <td>
                                        <?php if (!empty($nats)): ?>
                                            <div class="d-flex flex-wrap gap-1">
                                                <?php foreach ($nats as $n): ?>
                                                    <span class="badge-ops badge-neutral font-mono" style="font-size:0.72rem;">
                                                        :<?= htmlspecialchars($n['dst_port']) ?>&rarr;<?= htmlspecialchars($n['to_port']) ?>
                                                    </span>
                                                <?php endforeach; ?>
                                            </div>
                                        <?php else: ?>
                                            <span class="text-muted" style="font-size:0.78rem;">-</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($sDisabled): ?>
                                            <span class="badge-ops badge-isolir"><span class="status-dot"></span>Disabled</span>
                                        <?php elseif ($isOnline): ?>
                                            <span class="badge-ops badge-aktif" title="Uptime: <?= htmlspecialchars($uptime) ?>">
                                                <span class="status-dot"></span>Online (<?= htmlspecialchars($uptime) ?>)
                                            </span>
                                        <?php else: ?>
                                            <span class="badge-ops badge-neutral">Offline</span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="text-end">
                                        <div class="d-inline-flex gap-1">
                                            <button type="button" class="btn btn-xs btn-ops-light"
                                                    data-user="<?= htmlspecialchars($sName, ENT_QUOTES, 'UTF-8') ?>"
                                                    data-pass="<?= htmlspecialchars($sPass, ENT_QUOTES, 'UTF-8') ?>"
                                                    data-service="<?= htmlspecialchars($sService, ENT_QUOTES, 'UTF-8') ?>"
                                                    data-remote="<?= htmlspecialchars($sRemote, ENT_QUOTES, 'UTF-8') ?>"
                                                    data-host="<?= htmlspecialchars($publicHost, ENT_QUOTES, 'UTF-8') ?>"
                                                    data-api="<?= htmlspecialchars($portApiFound, ENT_QUOTES, 'UTF-8') ?>"
                                                    data-winbox="<?= htmlspecialchars($portWinboxFound, ENT_QUOTES, 'UTF-8') ?>"
                                                    data-web="<?= htmlspecialchars($portWebFound, ENT_QUOTES, 'UTF-8') ?>"
                                                    onclick="showScriptModal(this)"
                                                    title="Lihat Script MikroTik Pelanggan & Info Mikhmon">
                                                <i class="bi bi-terminal"></i> Script
                                            </button>

                                            <form method="post" class="m-0">
                                                <?= csrf_field() ?>
                                                <input type="hidden" name="action" value="toggle_secret">
                                                <input type="hidden" name="secret_id" value="<?= htmlspecialchars($sId) ?>">
                                                <input type="hidden" name="vpn_user" value="<?= htmlspecialchars($sName) ?>">
                                                <input type="hidden" name="disable" value="<?= $sDisabled ? 'false' : 'true' ?>">
                                                <button type="submit" class="btn btn-xs <?= $sDisabled ? 'btn-ops-success' : 'btn-ops-warning' ?>" title="<?= $sDisabled ? 'Enable' : 'Disable' ?>">
                                                    <i class="bi <?= $sDisabled ? 'bi-play-fill' : 'bi-pause-fill' ?>"></i>
                                                </button>
                                            </form>

                                            <form method="post" class="m-0" onsubmit="return confirm('Hapus PPP Secret <?= htmlspecialchars(addslashes($sName)) ?> beserta semua rule NAT-nya di CHR?');">
                                                <?= csrf_field() ?>
                                                <input type="hidden" name="action" value="delete_vpn">
                                                <input type="hidden" name="secret_id" value="<?= htmlspecialchars($sId) ?>">
                                                <input type="hidden" name="vpn_user" value="<?= htmlspecialchars($sName) ?>">
                                                <input type="hidden" name="remote_ip" value="<?= htmlspecialchars($sRemote) ?>">
                                                <button type="submit" class="btn btn-xs btn-ops-danger" title="Hapus Secret + NAT">
                                                    <i class="bi bi-trash"></i>
                                                </button>
                                            </form>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            <?php if (empty($secrets)): ?>
                                <tr>
                                    <td colspan="5" class="text-center py-5 text-muted">
                                        <?= $chrConnected ? 'Belum ada PPP Secret di CHR.' : 'Hubungkan CHR terlebih dahulu untuk memuat daftar VPN.' ?>
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

<!-- Modal Konfigurasi Koneksi CHR -->
<div class="modal fade" id="chrConfigModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Pengaturan Koneksi MikroTik CHR</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="post">
                <?= csrf_field() ?>
                <input type="hidden" name="action" value="save_chr_config">
                <div class="modal-body">
                    <div class="row g-2 mb-3">
                        <div class="col-8">
                            <label class="form-label">IP / Hostname CHR (API)</label>
                            <input type="text" class="form-control font-mono" name="chr_host" value="<?= htmlspecialchars($chrConfig['host']) ?>" placeholder="103.xxx.xxx.xxx" required>
                        </div>
                        <div class="col-4">
                            <label class="form-label">Port API</label>
                            <input type="number" class="form-control font-mono" name="chr_port" value="<?= (int) $chrConfig['port'] ?>" required>
                        </div>
                    </div>
                    <div class="row g-2 mb-3">
                        <div class="col-6">
                            <label class="form-label">Username CHR</label>
                            <input type="text" class="form-control font-mono" name="chr_user" value="<?= htmlspecialchars($chrConfig['user']) ?>" required>
                        </div>
                        <div class="col-6">
                            <label class="form-label">Password CHR</label>
                            <input type="password" class="form-control font-mono" name="chr_pass" placeholder="<?= $chrConfig['pass'] !== '' ? '(Tetap / tidak diubah)' : 'Masukkan password' ?>">
                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Domain/IP Publik CHR (Untuk Script Pelanggan)</label>
                        <input type="text" class="form-control font-mono" name="chr_public_host" value="<?= htmlspecialchars($chrConfig['public_host']) ?>" placeholder="vpn.madignet.site / IP CHR">
                    </div>
                    <div class="row g-2">
                        <div class="col-6">
                            <label class="form-label">Default Gateway Local IP</label>
                            <input type="text" class="form-control font-mono" name="default_local_ip" value="<?= htmlspecialchars($chrConfig['default_local_ip']) ?>">
                        </div>
                        <div class="col-6">
                            <label class="form-label">Default PPP Profile</label>
                            <input type="text" class="form-control font-mono" name="default_profile" value="<?= htmlspecialchars($chrConfig['default_profile']) ?>">
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-ops-light" data-bs-dismiss="modal">Batal</button>
                    <button type="submit" class="btn btn-ops-primary">Simpan &amp; Tes Koneksi</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal Script MikroTik Pelanggan & Info Mikhmon -->
<div class="modal fade" id="scriptModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><i class="bi bi-terminal me-2"></i>Script MikroTik Pelanggan &amp; Data Mikhmon</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="row g-2 mb-3">
                    <div class="col-md-4">
                        <div class="p-2 border rounded bg-light">
                            <div class="text-muted" style="font-size:0.72rem;">IP/Host Mikhmon (API)</div>
                            <div class="font-mono fw-bold" id="info-mikhmon">-</div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="p-2 border rounded bg-light">
                            <div class="text-muted" style="font-size:0.72rem;">Remote Winbox</div>
                            <div class="font-mono fw-bold" id="info-winbox">-</div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="p-2 border rounded bg-light">
                            <div class="text-muted" style="font-size:0.72rem;">IP Lokal VPN Client</div>
                            <div class="font-mono fw-bold" id="info-remote-ip">-</div>
                        </div>
                    </div>
                </div>

                <label class="form-label d-flex justify-content-between align-items-center">
                    <span>Paste Script Ini di <strong>New Terminal</strong> MikroTik Pelanggan:</span>
                    <button type="button" class="btn btn-xs btn-ops-primary" onclick="copyRouterScript()">
                        <i class="bi bi-clipboard"></i> Salin Script
                    </button>
                </label>
                <textarea id="router-script-box" class="form-control font-mono bg-dark text-light" rows="7" readonly style="font-size:0.8rem;"></textarea>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
function genPass() {
    const chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let out = '';
    for (let i = 0; i < 8; i++) {
        out += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    document.getElementById('vpn_pass').value = out;
}

function buildClientScript(data) {
    const host = data.host || 'IP_CHR_ANDA';
    const user = data.user || '';
    const pass = data.pass || '';
    const svc = (data.service === 'any' ? 'l2tp' : data.service) || 'l2tp';

    let cmd = '';
    if (svc === 'l2tp') {
        cmd = `/interface l2tp-client add name="vpn-madignet" connect-to="${host}" user="${user}" password="${pass}" disabled=no comment="VPN Remote Madignet"`;
    } else if (svc === 'sstp') {
        cmd = `/interface sstp-client add name="vpn-madignet" connect-to="${host}" user="${user}" password="${pass}" disabled=no comment="VPN Remote Madignet"`;
    } else if (svc === 'pptp') {
        cmd = `/interface pptp-client add name="vpn-madignet" connect-to="${host}" user="${user}" password="${pass}" disabled=no comment="VPN Remote Madignet"`;
    } else {
        cmd = `/interface ovpn-client add name="vpn-madignet" connect-to="${host}" user="${user}" password="${pass}" disabled=no comment="VPN Remote Madignet"`;
    }

    return `# Paste di New Terminal MikroTik Pelanggan\n${cmd}\n/ip service set api disabled=no port=8728\n/ip service set winbox disabled=no port=8291`;
}

function populateAndOpenScriptModal(data) {
    const host = data.host || '-';
    document.getElementById('info-mikhmon').textContent = data.api ? `${host}:${data.api}` : '-';
    document.getElementById('info-winbox').textContent = data.winbox ? `${host}:${data.winbox}` : '-';
    document.getElementById('info-remote-ip').textContent = data.remote || '-';
    document.getElementById('router-script-box').value = buildClientScript(data);

    const modal = new bootstrap.Modal(document.getElementById('scriptModal'));
    modal.show();
}

function showScriptModal(btn) {
    populateAndOpenScriptModal({
        host: btn.dataset.host,
        user: btn.dataset.user,
        pass: btn.dataset.pass,
        service: btn.dataset.service,
        remote: btn.dataset.remote,
        api: btn.dataset.api,
        winbox: btn.dataset.winbox,
        web: btn.dataset.web
    });
}

function copyRouterScript() {
    const box = document.getElementById('router-script-box');
    navigator.clipboard.writeText(box.value);
}

document.addEventListener('DOMContentLoaded', function () {
    genPass();

    const searchInput = document.getElementById('vpnSearch');
    const rows = document.querySelectorAll('#vpnTable tbody tr[data-search]');
    if (searchInput && rows.length) {
        searchInput.addEventListener('input', function () {
            const kw = this.value.trim().toLowerCase();
            rows.forEach(r => {
                r.style.display = r.dataset.search.includes(kw) ? '' : 'none';
            });
        });
    }

    <?php if (is_array($newClientScript)): ?>
    populateAndOpenScriptModal(<?= json_encode([
        'host' => $newClientScript['chr_host'],
        'user' => $newClientScript['user'],
        'pass' => $newClientScript['pass'],
        'service' => $newClientScript['service'],
        'remote' => $newClientScript['remote_ip'],
        'api' => $newClientScript['port_api'],
        'winbox' => $newClientScript['port_winbox'],
        'web' => $newClientScript['port_web'],
    ]) ?>);
    <?php endif; ?>
});
</script>
</body>
</html>
