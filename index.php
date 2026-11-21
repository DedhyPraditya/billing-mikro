<?php
require_once __DIR__ . '/bootstrap.php';

if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: admin/login.php');
    exit;
}

header('Location: admin/dashboard.php');
exit;
