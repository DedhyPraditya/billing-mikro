<?php

function parse_billing_date(?string $date): ?DateTimeImmutable
{
    if (empty($date)) {
        return null;
    }

    return DateTimeImmutable::createFromFormat('Y-m-d', $date)
        ?: DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $date)
        ?: null;
}

function add_one_billing_month(DateTimeImmutable $date): DateTimeImmutable
{
    $year = (int) $date->format('Y');
    $month = (int) $date->format('n') + 1;
    $day = (int) $date->format('j');

    if ($month > 12) {
        $month = 1;
        $year++;
    }

    $lastDayOfTargetMonth = (int) (new DateTimeImmutable(sprintf('%04d-%02d-01', $year, $month)))->format('t');
    $safeDay = min($day, $lastDayOfTargetMonth);

    return $date->setDate($year, $month, $safeDay);
}

function calculate_due_date_from_activation(?string $activatedAt): ?string
{
    $activationDate = parse_billing_date($activatedAt);
    if (!$activationDate) {
        return null;
    }

    return add_one_billing_month($activationDate)->format('Y-m-d');
}

function calculate_extended_due_date(?string $currentDue, ?DateTimeImmutable $today = null): string
{
    $today = $today ?: new DateTimeImmutable('now');
    $baseDate = $today;

    $parsedDue = parse_billing_date($currentDue);
    if ($parsedDue && $parsedDue > $today) {
        $baseDate = $parsedDue;
    }

    return add_one_billing_month($baseDate)->format('Y-m-d');
}

function normalize_and_validate_domain(?string $domain): ?string
{
    if ($domain === null) {
        return null;
    }

    $domain = strtolower(trim($domain));
    if ($domain === '') {
        return null;
    }

    // Validasi format FQDN ketat (hanya huruf a-z, angka 0-9, tanda hubung, dan titik)
    if (!preg_match('/^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $domain)) {
        return null;
    }

    // Jika ALLOWED_DOMAIN_SUFFIX diset di config.php (misal '.madignet.cloud'), wajib cocok
    if (defined('ALLOWED_DOMAIN_SUFFIX') && ALLOWED_DOMAIN_SUFFIX !== '') {
        $suffix = '.' . ltrim(strtolower(trim((string) ALLOWED_DOMAIN_SUFFIX)), '.');
        if (!str_ends_with($domain, $suffix)) {
            return null;
        }
    }

    return $domain;
}

function save_status_data(string $statusFile, array $data): bool
{
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        return false;
    }

    return @file_put_contents($statusFile, $json, LOCK_EX) !== false;
}
