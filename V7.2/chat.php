<?php
/**
 * CASSANDRA chat.php v7.2
 * ========================
 * CORRECTIONS v7.2 :
 *   [FIX] Route GET ?rclone-remotes pour liste directe
 *   [FIX] Route GET ?active-sessions pour sessions SSH
 *   [FIX] Route GET ?ports pour ports ouverts
 *   [FIX] Timeouts ajustés pour les appels Rclone
 *   [FIX] Cache metrics supprimé pour temps réel
 */

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

// ── Sessions sécurisées ───────────────────────────────────────
$session_dir = '/var/lib/cassandra/sessions';
if (!is_dir($session_dir)) {
    @mkdir($session_dir, 0700, true);
}
if (is_dir($session_dir) && is_writable($session_dir)) {
    session_save_path($session_dir);
}
session_start();

// ── CSRF ──────────────────────────────────────────────────────
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$AGENT = '/root/agent.py';

// ============================================================
// HELPERS
// ============================================================

/**
 * Lance agent.py avec proc_open + timeout.
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
    $process = proc_open($cmd, $descriptors, $pipes, null,
                         ['PATH' => '/bin:/usr/bin:/sbin:/usr/sbin']);
    if (!is_resource($process)) {
        return null;
    }

    if ($stdin_data !== '') {
        fwrite($pipes[0], $stdin_data);
    }
    fclose($pipes[0]);

    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

    $output   = '';
    $deadline = microtime(true) + $timeout;
    $timed_out = false;

    while (true) {
        $remaining = $deadline - microtime(true);
        if ($remaining <= 0) { $timed_out = true; break; }

        $read   = [$pipes[1]];
        $write  = null;
        $except = null;
        $sec    = (int)$remaining;
        $usec   = (int)(($remaining - $sec) * 1e6);

        $n = stream_select($read, $write, $except, $sec, $usec);
        if ($n === false) break;
        if ($n > 0) {
            $chunk = fread($pipes[1], 65536);
            if ($chunk !== false && $chunk !== '') {
                $output .= $chunk;
            } elseif (feof($pipes[1])) {
                break;
            }
        }
        $status = proc_get_status($process);
        if (!$status['running'] && feof($pipes[1])) break;
    }

    fclose($pipes[1]);
    fclose($pipes[2]);
    if ($timed_out) proc_terminate($process, 9);
    proc_close($process);

    return $timed_out ? null : ($output ?: null);
}

/**
 * Récupère les métriques TEMPS RÉEL (sans cache)
 */
function get_realtime_metrics() {
    $output = run_agent(['--metrics'], '', 15);
    if ($output) {
        $data = json_decode($output, true);
        if ($data && isset($data['cpu'])) {
            return $data;
        }
    }
    return null;
}

/** Construit le chemin du fichier historique de session. */
function get_history_file(): string {
    $dir = '/var/lib/cassandra/sessions';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    return $dir . '/hist_' . hash('sha256', session_id()) . '.json';
}

/** Lit l'historique de session (JSON). Nettoie si corrompu. */
function load_history(): array {
    $file = get_history_file();
    if (!file_exists($file)) return [];
    $raw     = file_get_contents($file);
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        @unlink($file);
        return [];
    }
    return $decoded;
}

/** Sauvegarde l'historique (30 derniers échanges max). */
function save_history(array $history): void {
    file_put_contents(get_history_file(), json_encode(array_slice($history, -30)), LOCK_EX);
}

/** Vérifie si l'utilisateur est authentifié. */
function is_authenticated(): bool {
    return !empty($_SESSION['cassandra_auth']);
}

/** Vérifie si un mot de passe est configuré dans l'agent. */
function has_password_configured(): bool {
    if (isset($_SESSION['has_pwd'], $_SESSION['has_pwd_ts'])
        && time() - $_SESSION['has_pwd_ts'] < 60) {
        return $_SESSION['has_pwd'];
    }
    $out = run_agent(['--check-auth'], json_encode(['password' => '']), 5);
    $d   = $out ? json_decode($out, true) : null;
    $has = !($d && isset($d['ok']) && $d['ok'] === true);
    $_SESSION['has_pwd']    = $has;
    $_SESSION['has_pwd_ts'] = time();
    return $has;
}

/** Middleware auth : bloque les routes protégées si non authentifié. */
function require_auth(): void {
    if (!is_authenticated() && has_password_configured()) {
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['success' => false, 'error' => 'Non authentifié', 'auth_required' => true]);
        exit;
    }
}

// ============================================================
// AUTHENTIFICATION
// ============================================================

// POST ?login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['login'])) {
    header('Content-Type: application/json');
    $password = trim($_POST['password'] ?? '');
    if (empty($password)) {
        echo json_encode(['success' => false, 'error' => 'Mot de passe vide']);
        exit;
    }
    $payload = json_encode(['password' => $password]);
    $output  = run_agent(['--check-auth'], $payload, 5);
    $result  = $output ? json_decode($output, true) : null;
    if ($result && !empty($result['ok'])) {
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

// GET ?logout
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

// GET ?check-auth (pour JS)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['check-auth'])) {
    header('Content-Type: application/json');
    echo json_encode([
        'auth_required' => has_password_configured(),
        'authenticated' => is_authenticated(),
    ]);
    exit;
}

// ============================================================
// ROUTES GET (données publiques)
// ============================================================

// GET ?csrf
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['csrf'])) {
    header('Content-Type: application/json');
    echo json_encode([
        'token'         => $_SESSION['csrf_token'],
        'auth_required' => has_password_configured(),
        'authenticated' => is_authenticated(),
    ]);
    exit;
}

// ============================================================
// ROUTES GET (données protégées)
// ============================================================

// GET ?metrics — TEMPS RÉEL
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['metrics'])) {
    require_auth();
    header('Content-Type: application/json');
    
    $data = get_realtime_metrics();
    if ($data) {
        echo json_encode($data);
    } else {
        echo json_encode(['error' => 'Métriques indisponibles']);
    }
    exit;
}

// GET ?sparklines
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['sparklines'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--sparklines'], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? ['cpu' => [], 'ram' => [], 'labels' => []]);
    exit;
}

// GET ?incidents
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['incidents'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--incidents'], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode(is_array($data) ? $data : []);
    exit;
}

// GET ?patterns
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['patterns'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--patterns'], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode(is_array($data) ? $data : []);
    exit;
}

// GET ?remote-hosts — Équipements distants
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['remote-hosts'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--remote-hosts'], '', 20);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? []);
    exit;
}

// [FIX] GET ?active-sessions — Sessions SSH actives
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['active-sessions'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--active-sessions'], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? []);
    exit;
}

// [FIX] GET ?ports — Ports ouverts
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['ports'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--ports'], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? []);
    exit;
}

// [FIX] GET ?rclone-remotes — Liste des remotes Rclone
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['rclone-remotes'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--rclone-remotes'], '', 15);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? []);
    exit;
}

// POST ?exec-cmd — Exécution explicite d'une commande
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

    // Décoder si la commande est en base64
    $cmd = $raw_cmd;
    if (preg_match('/^[A-Za-z0-9+\/=]+$/', $raw_cmd) && strlen($raw_cmd) % 4 === 0) {
        $decoded = base64_decode($raw_cmd, true);
        if ($decoded !== false) {
            $cmd = $decoded;
        }
    }

    $payload = json_encode(['cmd' => $cmd, 'session' => session_id()]);
    $output  = run_agent(['--exec-cmd'], $payload, 20);
    $data    = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? ['success' => false, 'error' => 'Timeout']);
    exit;
}

// ============================================================
// ROUTES POST
// ============================================================

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

    $note   = substr(trim($_POST['note'] ?? ''), 0, 200);
    $output = run_agent(['--resolve', (string)$incident_id, $note], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? ['success' => false, 'error' => 'Timeout']);
    exit;
}

// POST ?summarize
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['summarize'])) {
    require_auth();
    header('Content-Type: application/json');

    // Lecture CSRF depuis POST ou php://input (pour sendBeacon)
    $csrf = $_POST['csrf'] ?? '';
    if (empty($csrf)) {
        $raw_input = file_get_contents('php://input');
        if ($raw_input) {
            parse_str($raw_input, $parsed_input);
            $csrf = $parsed_input['csrf'] ?? '';
        }
    }

    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Token CSRF invalide']);
        exit;
    }

    $history = load_history();
    if (count($history) < 2) {
        echo json_encode(['success' => false, 'error' => 'Historique insuffisant']);
        exit;
    }

    try {
        $payload = json_encode(
            ['session' => session_id(), 'history' => $history],
            JSON_THROW_ON_ERROR
        );
    } catch (JsonException $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        exit;
    }

    $output = run_agent(['--summarize'], $payload, 30);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? ['success' => false, 'error' => 'Timeout']);
    exit;
}

// ============================================================
// POST → CHAT PRINCIPAL
// ============================================================
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Méthode non autorisée']);
    exit;
}

require_auth();
header('Content-Type: application/json');

// CSRF
$csrf = $_POST['csrf'] ?? '';
if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Token CSRF invalide']);
    exit;
}

// Rate limiting : 60 req / session / heure
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

// Validation message
$message = trim($_POST['message'] ?? '');
if (empty($message)) {
    echo json_encode(['success' => false, 'error' => 'Message vide']);
    exit;
}
if (mb_strlen($message) > 2000) {
    echo json_encode(['success' => false, 'error' => 'Message trop long (max 2000 car.)']);
    exit;
}

$history = load_history();
try {
    $payload = json_encode([
        'message' => $message,
        'history' => $history,
        'session' => session_id(),
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
} catch (JsonException $e) {
    echo json_encode(['success' => false, 'error' => 'Payload invalide : ' . $e->getMessage()]);
    exit;
}

$output = run_agent(['--chat'], $payload, 60);

if ($output === null) {
    echo json_encode([
        'success' => false,
        'error'   => 'Timeout : l\'agent n\'a pas répondu dans les 60s.',
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

$result = json_decode($output, true);

if ($result && isset($result['success']) && $result['success'] === true) {
    $history[] = ['role' => 'user',      'content' => $message];
    $history[] = ['role' => 'assistant', 'content' => $result['response']];
    save_history($history);

    echo json_encode([
        'success'   => true,
        'response'  => $result['response'],
        'csrf'      => $_SESSION['csrf_token'],
        'msg_count' => (int)(count($history) / 2),
    ], JSON_UNESCAPED_UNICODE);
} else {
    $error = $result['error'] ?? substr($output ?? '', 0, 500) ?? 'Erreur inconnue';
    echo json_encode(['success' => false, 'error' => $error], JSON_UNESCAPED_UNICODE);
}