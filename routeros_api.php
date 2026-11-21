<?php

/**
 * Pure PHP RouterOS API Client (supports RouterOS v6.43+ & v7.x)
 */
class RouterosApi
{
    private $socket = null;
    private bool $connected = false;
    private string $lastError = '';
    private int $timeout = 5;

    public function getLastError(): string
    {
        return $this->lastError;
    }

    public function isConnected(): bool
    {
        return $this->connected;
    }

    public function connect(string $host, string $user, string $pass, int $port = 8728, int $timeout = 5): bool
    {
        $this->disconnect();
        $this->timeout = $timeout;
        $this->lastError = '';

        $host = trim($host);
        if ($host === '' || $user === '') {
            $this->lastError = 'Host atau username CHR belum diisi.';
            return false;
        }

        $errno = 0;
        $errstr = '';
        $this->socket = @fsockopen($host, $port, $errno, $errstr, $this->timeout);
        if (!$this->socket) {
            $this->lastError = "Gagal terhubung ke CHR {$host}:{$port} ({$errstr})";
            return false;
        }

        stream_set_timeout($this->socket, $this->timeout);

        // RouterOS v6.43+ / v7 plain login
        $this->write('/login', false);
        $this->write('=name=' . $user, false);
        $this->write('=password=' . $pass, true);

        $response = $this->read();
        if (isset($response[0]) && $response[0] === '!done') {
            if (!isset($response[1])) {
                $this->connected = true;
                return true;
            }
            // Legacy challenge-response fallback (< v6.43)
            if (preg_match('/^=ret=([0-9a-fA-F]+)$/', $response[1], $matches)) {
                $challenge = pack('H*', $matches[1]);
                $md5 = md5(chr(0) . $pass . $challenge);
                $this->write('/login', false);
                $this->write('=name=' . $user, false);
                $this->write('=response=00' . $md5, true);
                $response = $this->read();
                if (isset($response[0]) && $response[0] === '!done') {
                    $this->connected = true;
                    return true;
                }
            }
        }

        $msg = 'Login CHR ditolak (cek username/password atau service API port ' . $port . ').';
        foreach ($response as $line) {
            if (str_starts_with($line, '=message=')) {
                $msg = substr($line, 9);
            }
        }
        $this->lastError = $msg;
        $this->disconnect();
        return false;
    }

    public function disconnect(): void
    {
        if (is_resource($this->socket)) {
            @fclose($this->socket);
        }
        $this->socket = null;
        $this->connected = false;
    }

    public function comm(string $command, array $params = []): array
    {
        if (!$this->connected || !is_resource($this->socket)) {
            return ['!trap' => [['message' => 'Tidak terhubung ke CHR']]];
        }

        $count = count($params);
        $this->write($command, $count === 0);

        $i = 0;
        foreach ($params as $k => $v) {
            $i++;
            $isLast = ($i === $count);
            $k = (string) $k;
            $v = (string) $v;
            if (str_starts_with($k, '?')) {
                $this->write($k . '=' . $v, $isLast);
            } else {
                $this->write('=' . $k . '=' . $v, $isLast);
            }
        }

        $raw = $this->read();
        return $this->parseResponse($raw);
    }

    private function encodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        if ($length < 0x4000) {
            $length |= 0x8000;
            return chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        }
        if ($length < 0x200000) {
            $length |= 0xC00000;
            return chr(($length >> 16) & 0xFF) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        }
        if ($length < 0x10000000) {
            $length |= 0xE0000000;
            return chr(($length >> 24) & 0xFF) . chr(($length >> 16) & 0xFF) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        }
        return chr(0xF0) . chr(($length >> 24) & 0xFF) . chr(($length >> 16) & 0xFF) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
    }

    private function write(string $word, bool $endSentence = true): bool
    {
        if (!is_resource($this->socket)) {
            return false;
        }
        $len = strlen($word);
        $data = $this->encodeLength($len) . $word;
        if ($endSentence) {
            $data .= chr(0);
        }
        return @fwrite($this->socket, $data) !== false;
    }

    private function readLength(): int
    {
        $byte = @fread($this->socket, 1);
        if ($byte === false || $byte === '') {
            return 0;
        }
        $c = ord($byte);
        if (($c & 0x80) === 0x00) {
            return $c;
        }
        if (($c & 0xC0) === 0x80) {
            $b = ord((string) @fread($this->socket, 1));
            return (($c & ~0xC0) << 8) + $b;
        }
        if (($c & 0xE0) === 0xC0) {
            $b1 = ord((string) @fread($this->socket, 1));
            $b2 = ord((string) @fread($this->socket, 1));
            return (($c & ~0xE0) << 16) + ($b1 << 8) + $b2;
        }
        if (($c & 0xF0) === 0xE0) {
            $b1 = ord((string) @fread($this->socket, 1));
            $b2 = ord((string) @fread($this->socket, 1));
            $b3 = ord((string) @fread($this->socket, 1));
            return (($c & ~0xF0) << 24) + ($b1 << 16) + ($b2 << 8) + $b3;
        }
        $b1 = ord((string) @fread($this->socket, 1));
        $b2 = ord((string) @fread($this->socket, 1));
        $b3 = ord((string) @fread($this->socket, 1));
        $b4 = ord((string) @fread($this->socket, 1));
        return ($b1 << 24) + ($b2 << 16) + ($b3 << 8) + $b4;
    }

    private function read(): array
    {
        $response = [];
        $receivedDone = false;

        while (is_resource($this->socket)) {
            $length = $this->readLength();
            if ($length > 0) {
                $word = '';
                while (strlen($word) < $length) {
                    $chunk = @fread($this->socket, $length - strlen($word));
                    if ($chunk === false || $chunk === '') {
                        break;
                    }
                    $word .= $chunk;
                }
                $response[] = $word;
                if ($word === '!done' || $word === '!fatal') {
                    $receivedDone = true;
                }
            } else {
                if ($receivedDone) {
                    break;
                }
                $info = stream_get_meta_data($this->socket);
                if ($info['timed_out'] || feof($this->socket)) {
                    break;
                }
            }
        }

        return $response;
    }

    private function parseResponse(array $raw): array
    {
        $parsed = [];
        $current = null;
        $type = null;

        foreach ($raw as $word) {
            if (in_array($word, ['!re', '!trap', '!fatal', '!done'], true)) {
                if ($current !== null) {
                    if ($type === '!trap' || $type === '!fatal') {
                        $parsed['!trap'][] = $current;
                    } elseif (!empty($current)) {
                        $parsed[] = $current;
                    }
                }
                $type = $word;
                $current = [];
            } elseif (str_starts_with($word, '=')) {
                $parts = explode('=', substr($word, 1), 2);
                if (count($parts) === 2 && is_array($current)) {
                    $current[$parts[0]] = $parts[1];
                }
            }
        }

        if ($current !== null) {
            if ($type === '!trap' || $type === '!fatal') {
                $parsed['!trap'][] = $current;
            } elseif (!empty($current)) {
                $parsed[] = $current;
            }
        }

        return $parsed;
    }

    public function __destruct()
    {
        $this->disconnect();
    }
}

/**
 * Helper baca/simpan konfigurasi CHR
 */
function get_chr_config(): array
{
    $file = __DIR__ . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'chr_config.php';
    $saved = [];
    if (is_file($file)) {
        $raw = @file_get_contents($file);
        if (is_string($raw)) {
            $lines = explode("\n", $raw);
            if (isset($lines[1])) {
                $decoded = json_decode($lines[1], true);
                if (is_array($decoded)) {
                    $saved = $decoded;
                }
            }
        }
    }

    return [
        'host' => $saved['host'] ?? (defined('CHR_HOST') ? CHR_HOST : ''),
        'port' => (int) ($saved['port'] ?? (defined('CHR_PORT') ? CHR_PORT : 8728)),
        'user' => $saved['user'] ?? (defined('CHR_USER') ? CHR_USER : 'admin'),
        'pass' => $saved['pass'] ?? (defined('CHR_PASS') ? CHR_PASS : ''),
        'public_host' => $saved['public_host'] ?? ($saved['host'] ?? (defined('CHR_HOST') ? CHR_HOST : '')),
        'default_local_ip' => $saved['default_local_ip'] ?? '10.10.10.1',
        'default_profile' => $saved['default_profile'] ?? 'default-encryption',
    ];
}

function save_chr_config(array $config): bool
{
    $dir = __DIR__ . DIRECTORY_SEPARATOR . 'storage';
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }
    $file = $dir . DIRECTORY_SEPARATOR . 'chr_config.php';
    $payload = "<?php http_response_code(403); exit; ?>\n" . json_encode($config, JSON_UNESCAPED_SLASHES);
    return @file_put_contents($file, $payload, LOCK_EX) !== false;
}
