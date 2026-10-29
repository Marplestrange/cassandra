<?php
/**
 * CASSANDRA chat.php v8.0 - FINAL
 * ================================
 * CORRECTIFS :
 *   [FIX] Route POST explicite pour le chat
 *   [FIX] Gestion correcte du timeout dans run_agent()
 *   [FIX] Chargement du .env pour PHP
 *   [FIX] Fallback socket collector
 *   [FIX] Permissions sessions
 */

// ── Chargement .env pour PHP ─────────────────────────────────
function load_env_for_php(): void {
    $env_candidates = [
        '/root/.env',
        __DIR__ . '/.env',
        dirname(__DIR__) . '/.env',
        '/var/www/fastuser/data/www/chat.cassandra.center/.env',
    ];
    
    foreach ($env_candidates as $env_path) {
        if (file_exists($env_path)) {
            $lines = file($env_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if ($lines === false) continue;
            
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#') continue;
                if (strpos($line, '=') === false) continue;
                
                list($key, $value) = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value, " \t\n\r\0\x0B\"'");
                
                if (!getenv($key) && !isset($_ENV[$key])) {
                    putenv("$key=$value");
                    $_ENV[$key] = $value;
                    $_SERVER[$key] = $value;
                }
            }
            break;
        }
    }
}
load_env_for_php();

// ── Headers sécurité ─────────────────────────────────────────
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
header("Content-Security-Policy: default-src 'self'; "
     . "script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
     . "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
     . "font-src https://fonts.gstatic.com; "
     . "img-src 'self' data:; "
     . "connect-src 'self'");

// ── Configuration collector V5.2 ─────────────────────────────
define('COLLECTOR_DB', '/var/lib/cassandra/cassandra.db');
define('COLLECTOR_SOCKET', '/tmp/cassandra_knowledge.sock');
define('CACHE_TTL', 5);
define('CACHE_TTL_LONG', 30);

// ── Sessions sécurisées ───────────────────────────────────────
$session_dir = '/var/lib/cassandra/sessions';
if (!is_dir($session_dir)) {
    @mkdir($session_dir, 0755, true);
    @chmod($session_dir, 0755);
}
if (is_dir($session_dir) && is_writable($session_dir)) {
    session_save_path($session_dir);
} else {
    error_log("CASSANDRA: Session dir not writable: " . $session_dir);
}
session_start();

// ── CSRF ──────────────────────────────────────────────────────
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ── Chemins ───────────────────────────────────────────────────
$AGENT = __DIR__ . '/agent.py';
if (!file_exists($AGENT)) {
    $AGENT = '/root/agent.py';
}

// ============================================================
// HELPERS - SOCKET COLLECTOR V5.2
// ============================================================

/**
 * Appelle le socket UNIX du collector V5.2
 */
function call_collector_socket(string $command, int $timeout = 2): ?array {
    if (!file_exists(COLLECTOR_SOCKET)) {
        error_log("CASSANDRA: Socket collector introuvable - " . COLLECTOR_SOCKET);
        return null;
    }
    
    $socket = @socket_create(AF_UNIX, SOCK_STREAM, 0);
    if ($socket === false) {
        error_log("CASSANDRA: Impossible de créer le socket");
        return null;
    }
    
    @socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => $timeout, 'usec' => 0]);
    @socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, ['sec' => $timeout, 'usec' => 0]);
    
    if (!@socket_connect($socket, COLLECTOR_SOCKET)) {
        error_log("CASSANDRA: Connexion socket échouée");
        @socket_close($socket);
        return null;
    }
    
    @socket_write($socket, $command . "\n");
    
    $response = '';
    while ($chunk = @socket_read($socket, 4096)) {
        $response .= $chunk;
        if (strlen($chunk) < 4096) break;
    }
    
    @socket_close($socket);
    
    if (empty($response)) return null;
    
    $data = json_decode($response, true);
    return is_array($data) ? $data : null;
}

/**
 * Lecture directe de la base SQLite du collector
 */
function query_collector_db(string $sql, array $params = [], int $timeout = 5): array {
    if (!file_exists(COLLECTOR_DB)) {
        error_log("CASSANDRA: DB collector introuvable - " . COLLECTOR_DB);
        return [];
    }
    
    $db = null;
    try {
        $db = new SQLite3(COLLECTOR_DB, SQLITE3_OPEN_READONLY);
        $db->busyTimeout($timeout * 1000);
        $stmt = $db->prepare($sql);
        if (!$stmt) {
            return [];
        }
        foreach ($params as $key => $value) {
            $stmt->bindValue($key, $value);
        }
        $result = $stmt->execute();
        $rows = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $rows[] = $row;
        }
        return $rows;
    } catch (Exception $e) {
        error_log("CASSANDRA DB error: " . $e->getMessage());
        return [];
    } finally {
        if ($db) {
            $db->close();
        }
    }
}

/**
 * Cache APCu si disponible
 */
function cache_get(string $key, &$success = null) {
    if (function_exists('apcu_fetch')) {
        return apcu_fetch("cassandra_" . $key, $success);
    }
    $success = false;
    return null;
}

function cache_set(string $key, $value, int $ttl = 30): bool {
    if (function_exists('apcu_store')) {
        return apcu_store("cassandra_" . $key, $value, $ttl);
    }
    return false;
}

/**
 * Métriques temps réel avec fallback
 */
function get_realtime_metrics(): array {
    $cached = cache_get('metrics_realtime', $hit);
    if ($hit) return $cached;
    
    $socket_data = call_collector_socket('GET_METRICS', 2);
    if ($socket_data && isset($socket_data['cpu'])) {
        cache_set('metrics_realtime', $socket_data, CACHE_TTL);
        return $socket_data;
    }
    
    $db_data = query_collector_db(
        "SELECT cpu_pct, ram_pct, disk_pct, swap_pct, load_1m, load_5m, load_15m, 
                ram_total_gb, ram_used_gb, disk_total_gb, disk_used_gb, disk_free_gb,
                alerts, top_processes
         FROM metrics_realtime ORDER BY id DESC LIMIT 1"
    );
    
    if (!empty($db_data)) {
        $row = $db_data[0];
        $result = [
            'cpu' => $row['cpu_pct'] ?? 0,
            'ram' => $row['ram_pct'] ?? 0,
            'disk' => $row['disk_pct'] ?? 0,
            'swap' => $row['swap_pct'] ?? 0,
            'load' => ($row['load_1m'] ?? 0) . ' ' . ($row['load_5m'] ?? 0) . ' ' . ($row['load_15m'] ?? 0),
            'load_1m' => $row['load_1m'] ?? 0,
            'load_5m' => $row['load_5m'] ?? 0,
            'load_15m' => $row['load_15m'] ?? 0,
            'ram_total_gb' => $row['ram_total_gb'] ?? 0,
            'ram_used_gb' => $row['ram_used_gb'] ?? 0,
            'disk_total' => ($row['disk_total_gb'] ?? 0) . 'G',
            'disk_used' => ($row['disk_used_gb'] ?? 0) . 'G',
            'disk_avail' => ($row['disk_free_gb'] ?? 0) . 'G',
            'alerts' => json_decode($row['alerts'] ?? '[]', true),
            'top_processes' => json_decode($row['top_processes'] ?? '[]', true),
            'services' => [
                'nginx' => false,
                'php8.1-fpm' => false,
                'mysql' => false,
                'docker' => false,
            ]
        ];
        cache_set('metrics_realtime', $result, CACHE_TTL);
        return $result;
    }
    
    return ['cpu' => 0, 'ram' => 0, 'disk' => 0, 'load' => '0.0 0.0 0.0', 'alerts' => []];
}

/**
 * Dashboard complet (via socket GET_DASHBOARD)
 */
function get_dashboard_data(): array {
    $cached = cache_get('dashboard', $hit);
    if ($hit) return $cached;
    
    $socket_data = call_collector_socket('GET_DASHBOARD', 3);
    if ($socket_data) {
        cache_set('dashboard', $socket_data, CACHE_TTL_LONG);
        return $socket_data;
    }
    
    $sites = query_collector_db("SELECT COUNT(*) as count FROM web_sites");
    $databases = query_collector_db("SELECT COUNT(*) as count FROM databases");
    $ssl_expiring = query_collector_db("SELECT COUNT(*) as count FROM ssl_certificates WHERE days_left <= 30");
    $fail2ban = query_collector_db("SELECT COUNT(*) as count FROM fail2ban_banned_ips");
    $tailscale = query_collector_db("SELECT COUNT(*) as count FROM tailscale_peers WHERE online=1");
    $oom = query_collector_db("SELECT COUNT(*) as count FROM oom_events WHERE ts > datetime('now', '-24 hours')");
    $failed = query_collector_db("SELECT COUNT(*) as count FROM failed_units");
    $security = query_collector_db("SELECT COUNT(*) as count FROM package_versions WHERE security_upgrade=1");
    $fp_domains = query_collector_db("SELECT COUNT(*) as count FROM fastpanel_domains");
    
    $result = [
        'sites' => $sites[0]['count'] ?? 0,
        'databases' => $databases[0]['count'] ?? 0,
        'ssl_expiring' => $ssl_expiring[0]['count'] ?? 0,
        'fail2ban_banned' => $fail2ban[0]['count'] ?? 0,
        'tailscale_peers' => $tailscale[0]['count'] ?? 0,
        'oom_events_24h' => $oom[0]['count'] ?? 0,
        'failed_units' => $failed[0]['count'] ?? 0,
        'security_upgrades' => $security[0]['count'] ?? 0,
        'fastpanel_domains' => $fp_domains[0]['count'] ?? 0,
    ];
    cache_set('dashboard', $result, CACHE_TTL_LONG);
    return $result;
}

/**
 * Récupère les remotes Rclone
 */
function get_rclone_remotes(): array {
    $cached = cache_get('rclone_remotes', $hit);
    if ($hit) return $cached;
    
    $rows = query_collector_db("SELECT name, type, used_gb, files_count FROM rclone_remotes");
    $result = array_map(function($row) {
        return [
            'name' => $row['name'],
            'type' => $row['type'] ?? 'unknown',
            'used_gb' => floatval($row['used_gb'] ?? 0),
            'files' => intval($row['files_count'] ?? 0)
        ];
    }, $rows);
    
    if (empty($result)) {
        $remotes = query_collector_db("SELECT name FROM rclone_remotes");
        $result = array_column($remotes, 'name');
    }
    
    cache_set('rclone_remotes', $result, CACHE_TTL_LONG);
    return $result;
}

function get_ssl_certificates(): array {
    $cached = cache_get('ssl_certs', $hit);
    if ($hit) return $cached;
    
    $rows = query_collector_db(
        "SELECT domain, days_left, status, expiry_date FROM ssl_certificates ORDER BY days_left ASC LIMIT 50"
    );
    cache_set('ssl_certs', $rows, CACHE_TTL_LONG);
    return $rows;
}

function get_web_sites(): array {
    $cached = cache_get('web_sites', $hit);
    if ($hit) return $cached;
    
    $rows = query_collector_db(
        "SELECT domain, document_root, server_type, ssl_enabled, php_version FROM web_sites LIMIT 100"
    );
    cache_set('web_sites', $rows, CACHE_TTL_LONG);
    return $rows;
}

function get_oom_events(): array {
    $cached = cache_get('oom_events', $hit);
    if ($hit) return $cached;
    
    $rows = query_collector_db(
        "SELECT ts, killed_process, pid, memory_used_mb FROM oom_events ORDER BY id DESC LIMIT 20"
    );
    cache_set('oom_events', $rows, CACHE_TTL_LONG);
    return $rows;
}

function get_failed_units(): array {
    $cached = cache_get('failed_units', $hit);
    if ($hit) return $cached;
    
    $rows = query_collector_db(
        "SELECT unit, active_state, description FROM failed_units"
    );
    cache_set('failed_units', $rows, CACHE_TTL_LONG);
    return $rows;
}

function get_dns_servers(): array {
    $cached = cache_get('dns_servers', $hit);
    if ($hit) return $cached;
    
    $rows = query_collector_db(
        "SELECT server_type, version, running, zones_count FROM dns_servers"
    );
    cache_set('dns_servers', $rows, CACHE_TTL_LONG);
    return $rows;
}

function get_all_mounts(): array {
    $cached = cache_get('all_mounts', $hit);
    if ($hit) return $cached;
    
    $rows = query_collector_db(
        "SELECT mountpoint, device, fstype, total_gb, used_gb, percent FROM system_mounts"
    );
    cache_set('all_mounts', $rows, CACHE_TTL_LONG);
    return $rows;
}

function get_health_score(): ?array {
    $cached = cache_get('health_score', $hit);
    if ($hit) return $cached;
    
    $rows = query_collector_db(
        "SELECT score, status, breakdown FROM health_scores ORDER BY id DESC LIMIT 1"
    );
    if (!empty($rows)) {
        $result = [
            'score' => $rows[0]['score'],
            'status' => $rows[0]['status'],
            'breakdown' => json_decode($rows[0]['breakdown'] ?? '{}', true)
        ];
        cache_set('health_score', $result, CACHE_TTL_LONG);
        return $result;
    }
    return null;
}

function get_active_sessions(): array {
    $cached = cache_get('active_sessions', $hit);
    if ($hit) return $cached;
    
    $rows = query_collector_db(
        "SELECT user, ip, login_time FROM ssh_sessions ORDER BY id DESC LIMIT 20"
    );
    if (!empty($rows)) {
        $result = array_map(function($row) {
            return [
                'user' => $row['user'],
                'ip' => $row['ip'] ?: 'local',
                'login' => substr($row['login_time'] ?? '', 0, 16)
            ];
        }, $rows);
        cache_set('active_sessions', $result, CACHE_TTL_LONG);
        return $result;
    }
    return [];
}

function get_open_ports(): array {
    $cached = cache_get('open_ports', $hit);
    if ($hit) return $cached;
    
    $rows = query_collector_db(
        "SELECT port, protocol, process, state FROM open_ports ORDER BY port"
    );
    cache_set('open_ports', $rows, CACHE_TTL_LONG);
    return $rows;
}

function get_fail2ban_banned_ips(): array {
    $cached = cache_get('fail2ban_banned', $hit);
    if ($hit) return $cached;
    
    $rows = query_collector_db(
        "SELECT jail, ip, banned_at FROM fail2ban_banned_ips LIMIT 100"
    );
    cache_set('fail2ban_banned', $rows, CACHE_TTL_LONG);
    return $rows;
}

function get_recent_incidents(): array {
    $cached = cache_get('incidents', $hit);
    if ($hit) return $cached;
    
    $rows = query_collector_db(
        "SELECT id, ts, severity, category, title, resolved FROM incidents ORDER BY id DESC LIMIT 20"
    );
    cache_set('incidents', $rows, CACHE_TTL_LONG);
    return $rows;
}

// ============================================================
// AUTHENTIFICATION
// ============================================================

function is_authenticated(): bool {
    return !empty($_SESSION['cassandra_auth']);
}

function has_password_configured(): bool {
    if (isset($_SESSION['has_pwd'], $_SESSION['has_pwd_ts'])
        && time() - $_SESSION['has_pwd_ts'] < 60) {
        return $_SESSION['has_pwd'];
    }
    $hash = getenv('CASSANDRA_PASSWORD_HASH') ?: ($_ENV['CASSANDRA_PASSWORD_HASH'] ?? '');
    $has = !empty($hash);
    $_SESSION['has_pwd'] = $has;
    $_SESSION['has_pwd_ts'] = time();
    return $has;
}

function check_password(string $plain): bool {
    $hash = getenv('CASSANDRA_PASSWORD_HASH') ?: ($_ENV['CASSANDRA_PASSWORD_HASH'] ?? '');
    if (empty($hash)) return true;
    return hash('sha256', $plain) === $hash;
}

function require_auth(): void {
    if (!is_authenticated() && has_password_configured()) {
        if (php_sapi_name() === 'cli') return;
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['success' => false, 'error' => 'Non authentifié', 'auth_required' => true]);
        exit;
    }
}

// ============================================================
// ROUTES GET (données protégées) - DIRECT COLLECTOR
// ============================================================

// GET ?metrics
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['metrics'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_realtime_metrics());
    exit;
}

// GET ?dashboard
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['dashboard'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_dashboard_data());
    exit;
}

// GET ?rclone-remotes
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['rclone-remotes'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_rclone_remotes());
    exit;
}

// GET ?ssl-certs
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['ssl-certs'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_ssl_certificates());
    exit;
}

// GET ?web-sites
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['web-sites'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_web_sites());
    exit;
}

// GET ?oom-events
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['oom-events'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_oom_events());
    exit;
}

// GET ?failed-units
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['failed-units'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_failed_units());
    exit;
}

// GET ?dns-servers
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['dns-servers'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_dns_servers());
    exit;
}

// GET ?all-mounts
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['all-mounts'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_all_mounts());
    exit;
}

// GET ?health
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['health'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_health_score() ?? ['error' => 'Non disponible']);
    exit;
}

// GET ?active-sessions
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['active-sessions'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_active_sessions());
    exit;
}

// GET ?ports
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['ports'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_open_ports());
    exit;
}

// GET ?fail2ban-banned
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['fail2ban-banned'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_fail2ban_banned_ips());
    exit;
}

// GET ?incidents
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['incidents'])) {
    require_auth();
    header('Content-Type: application/json');
    echo json_encode(get_recent_incidents());
    exit;
}

// GET ?csrf
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['csrf'])) {
    header('Content-Type: application/json');
    echo json_encode([
        'token' => $_SESSION['csrf_token'],
        'auth_required' => has_password_configured(),
        'authenticated' => is_authenticated(),
    ]);
    exit;
}

// GET ?check-auth
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['check-auth'])) {
    header('Content-Type: application/json');
    echo json_encode([
        'auth_required' => has_password_configured(),
        'authenticated' => is_authenticated(),
    ]);
    exit;
}

// GET ?logout
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . str_replace('?' . $_SERVER['QUERY_STRING'], '', $_SERVER['REQUEST_URI']));
    exit;
}

// GET ?remote-hosts (depuis ENV)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['remote-hosts'])) {
    require_auth();
    header('Content-Type: application/json');
    
    $remote_hosts_config = getenv('REMOTE_HOSTS') ?: ($_ENV['REMOTE_HOSTS'] ?? '[]');
    $hosts = json_decode($remote_hosts_config, true);
    if (!is_array($hosts)) $hosts = [];
    
    $results = [];
    foreach ($hosts as $host) {
        $hostname = $host['host'] ?? '';
        $port = $host['port'] ?? 22;
        $reachable = false;
        
        $fp = @fsockopen($hostname, $port, $errno, $errstr, 2);
        if ($fp) {
            $reachable = true;
            fclose($fp);
        }
        
        $results[] = [
            'name' => $host['name'] ?? $hostname,
            'host' => $hostname,
            'port' => $port,
            'type' => $host['type'] ?? 'unknown',
            'reachable' => $reachable,
            'latency_ms' => null
        ];
    }
    
    echo json_encode($results);
    exit;
}

// ============================================================
// ROUTES POST VERS AGENT.PY
// ============================================================

/**
 * Lance agent.py avec gestion correcte du timeout
 */
function run_agent(array $args, string $stdin_data = '', int $timeout = 45): ?string {
    global $AGENT;
    
    if (!file_exists($AGENT)) {
        error_log("CASSANDRA: Agent introuvable - " . $AGENT);
        return json_encode(['success' => false, 'error' => 'Agent introuvable']);
    }

    $cmd = array_merge(['python3', $AGENT], $args);
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    
    $process = @proc_open($cmd, $descriptors, $pipes, null,
                         ['PATH' => '/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin']);
    
    if (!is_resource($process)) {
        return null;
    }

    // Écrire stdin si nécessaire
    if (!empty($stdin_data)) {
        fwrite($pipes[0], $stdin_data);
    }
    fclose($pipes[0]);

    // Lire stdout et stderr avec timeout
    $output = '';
    $stderr = '';
    $deadline = microtime(true) + $timeout;
    $timed_out = false;

    // Rendre les pipes non-bloquants
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

    while (true) {
        $remaining = $deadline - microtime(true);
        if ($remaining <= 0) {
            $timed_out = true;
            break;
        }

        $read = [$pipes[1], $pipes[2]];
        $write = null;
        $except = null;
        
        $sec = (int)$remaining;
        $usec = (int)(($remaining - $sec) * 1000000);
        
        $n = stream_select($read, $write, $except, $sec, $usec);
        if ($n === false) break;
        if ($n === 0) continue;
        
        foreach ($read as $stream) {
            $chunk = fread($stream, 65536);
            if ($chunk !== false && $chunk !== '') {
                if ($stream === $pipes[1]) {
                    $output .= $chunk;
                } else {
                    $stderr .= $chunk;
                }
            }
        }
        
        $status = proc_get_status($process);
        if (!$status['running'] && feof($pipes[1]) && feof($pipes[2])) {
            break;
        }
    }

    fclose($pipes[1]);
    fclose($pipes[2]);
    
    if ($timed_out) {
        proc_terminate($process, 9);
        proc_close($process);
        return null;
    }
    
    proc_close($process);
    
    if (!empty($stderr)) {
        error_log("CASSANDRA agent stderr: " . substr($stderr, 0, 500));
    }
    
    return $output ?: null;
}

// POST ?login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['login'])) {
    header('Content-Type: application/json');
    $password = trim($_POST['password'] ?? '');
    if (empty($password)) {
        echo json_encode(['success' => false, 'error' => 'Mot de passe vide']);
        exit;
    }
    if (check_password($password)) {
        $_SESSION['cassandra_auth'] = true;
        session_regenerate_id(true);
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        echo json_encode(['success' => true, 'csrf' => $_SESSION['csrf_token']]);
    } else {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Mot de passe incorrect']);
    }
    exit;
}

// POST ?exec-cmd
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['exec-cmd'])) {
    require_auth();
    header('Content-Type: application/json');

    $csrf = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Token CSRF invalide']);
        exit;
    }

    $raw_cmd = trim($_POST['cmd'] ?? '');
    if (empty($raw_cmd)) {
        echo json_encode(['success' => false, 'error' => 'Commande vide']);
        exit;
    }

    $cmd = $raw_cmd;
    if (preg_match('/^[A-Za-z0-9+\/=]+$/', $raw_cmd) && strlen($raw_cmd) % 4 === 0) {
        $decoded = base64_decode($raw_cmd, true);
        if ($decoded !== false) {
            $cmd = $decoded;
        }
    }

    $payload = json_encode(['cmd' => $cmd, 'session' => session_id()]);
    $output = run_agent(['--exec-cmd'], $payload, 20);
    $data = $output ? json_decode($output, true) : null;
    
    if ($data === null) {
        echo json_encode(['success' => false, 'error' => 'Timeout ou erreur agent']);
    } else {
        echo json_encode($data);
    }
    exit;
}

// POST ?resolve
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['resolve'])) {
    require_auth();
    header('Content-Type: application/json');

    $csrf = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Token CSRF invalide']);
        exit;
    }

    $incident_id = (int)($_POST['incident_id'] ?? 0);
    if ($incident_id <= 0 || $incident_id > 9999999) {
        echo json_encode(['success' => false, 'error' => 'ID incident invalide']);
        exit;
    }

    $note = substr(trim($_POST['note'] ?? ''), 0, 200);
    $output = run_agent(['--resolve', (string)$incident_id, $note], '', 10);
    $data = $output ? json_decode($output, true) : null;
    
    echo json_encode($data ?? ['success' => false, 'error' => 'Timeout']);
    exit;
}

// POST ?summarize
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['summarize'])) {
    require_auth();
    header('Content-Type: application/json');

    $csrf = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Token CSRF invalide']);
        exit;
    }

    $history_file = $session_dir . '/hist_' . hash('sha256', session_id()) . '.json';
    $history = [];
    if (file_exists($history_file)) {
        $history = json_decode(file_get_contents($history_file), true) ?: [];
    }

    if (count($history) < 2) {
        echo json_encode(['success' => false, 'error' => 'Historique insuffisant']);
        exit;
    }

    $payload = json_encode(['session' => session_id(), 'history' => $history]);
    $output = run_agent(['--summarize'], $payload, 30);
    $data = $output ? json_decode($output, true) : null;
    
    echo json_encode($data ?? ['success' => false, 'error' => 'Timeout']);
    exit;
}

// ============================================================
// POST → CHAT PRINCIPAL (route principale)
// ============================================================
// Vérifier que c'est bien une requête POST chat (pas les autres)
$is_chat_request = (
    $_SERVER['REQUEST_METHOD'] === 'POST' 
    && !isset($_GET['login'])
    && !isset($_GET['exec-cmd'])
    && !isset($_GET['resolve'])
    && !isset($_GET['summarize'])
);

if (!$is_chat_request) {
    // Si ce n'est pas une requête chat valide
    header('Content-Type: application/json');
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Requête invalide']);
    exit;
}

// Requête chat principale
require_auth();
header('Content-Type: application/json');

$csrf = $_POST['csrf'] ?? '';
if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Token CSRF invalide']);
    exit;
}

// Rate limiting
$now = time();
if (empty($_SESSION['rl_reset']) || $now > $_SESSION['rl_reset']) {
    $_SESSION['rl_count'] = 0;
    $_SESSION['rl_reset'] = $now + 3600;
}
$_SESSION['rl_count']++;
if ($_SESSION['rl_count'] > 60) {
    $wait = $_SESSION['rl_reset'] - $now;
    http_response_code(429);
    echo json_encode(['success' => false, 'error' => "Limite atteinte. Réessayez dans {$wait}s."]);
    exit;
}

$message = trim($_POST['message'] ?? '');
if (empty($message)) {
    echo json_encode(['success' => false, 'error' => 'Message vide']);
    exit;
}
if (mb_strlen($message) > 2000) {
    echo json_encode(['success' => false, 'error' => 'Message trop long (max 2000 car.)']);
    exit;
}

// Lecture historique
$history_file = $session_dir . '/hist_' . hash('sha256', session_id()) . '.json';
$history = [];
if (file_exists($history_file)) {
    $history = json_decode(file_get_contents($history_file), true) ?: [];
}

$payload = json_encode([
    'message' => $message,
    'history' => $history,
    'session' => session_id(),
], JSON_UNESCAPED_UNICODE);

$output = run_agent(['--chat'], $payload, 60);

if ($output === null) {
    echo json_encode([
        'success' => false,
        'error' => 'Timeout : l\'agent n\'a pas répondu dans les 60s.',
    ]);
    exit;
}

$result = json_decode($output, true);

if ($result && isset($result['success']) && $result['success'] === true) {
    $history[] = ['role' => 'user', 'content' => $message];
    $history[] = ['role' => 'assistant', 'content' => $result['response']];
    file_put_contents($history_file, json_encode(array_slice($history, -30)), LOCK_EX);

    echo json_encode([
        'success' => true,
        'response' => $result['response'],
        'csrf' => $_SESSION['csrf_token'],
        'msg_count' => (int)(count($history) / 2),
    ], JSON_UNESCAPED_UNICODE);
} else {
    $error = $result['error'] ?? substr($output ?? '', 0, 500) ?: 'Erreur inconnue';
    echo json_encode(['success' => false, 'error' => $error]);
}