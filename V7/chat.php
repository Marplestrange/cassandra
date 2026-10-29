<?php
/**
 * CASSANDRA chat.php v7.0
 * ========================
 * INTÉGRATIONS v7.0 :
 *   [KNOW-1] Route GET ?knowledge → connaissances système
 *   [KNOW-2] Route GET ?sync → synchronisation des connaissances
 *   [KNOW-3] Route GET ?websites → sites web hébergés
 *   [KNOW-4] Route GET ?containers → conteneurs Docker
 *   [KNOW-5] Route GET ?ssl → certificats SSL
 *   [KNOW-6] Route GET ?ports → ports ouverts
 *
 * CORRECTIONS v6.4 :
 *   [SEC-1] Route POST ?exec-cmd : exécution explicite d'une commande
 *   [BUG-SSE] SSE streaming : sauvegarde 'text' en historique
 *   [BUG-BEACON] sendBeacon ?summarize : lecture depuis php://input
 *   [BUG-9] Route GET ?scan-network correctement routée
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
// [I4] AUTHENTIFICATION
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

// [F1] GET ?metrics — TEMPS RÉEL
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

// [I3] GET ?sparklines
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['sparklines'])) {
    require_auth();
    header('Content-Type: application/json');
    $minutes = min((int)($_GET['minutes'] ?? 60), 1440);
    $output  = run_agent(['--sparklines', (string)$minutes], '', 10);
    $data    = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? ['cpu' => [], 'ram' => [], 'disk' => [], 'labels' => []]);
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

// GET ?history
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['history'])) {
    require_auth();
    header('Content-Type: application/json');
    $minutes = min((int)($_GET['minutes'] ?? 30), 1440);
    $output  = run_agent(['--history', (string)$minutes], '', 10);
    $data    = $output ? json_decode($output, true) : null;
    echo json_encode(is_array($data) ? $data : []);
    exit;
}

// GET ?last-audit
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['last-audit'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--last-audit'], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? ['summary' => null]);
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

// [KNOW-1] GET ?knowledge — Connaissances système
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['knowledge'])) {
    require_auth();
    header('Content-Type: application/json');
    $category = $_GET['category'] ?? '';
    if ($category) {
        $output = run_agent(['--knowledge', $category], '', 15);
    } else {
        $output = run_agent(['--knowledge'], '', 15);
    }
    $data = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? []);
    exit;
}

// [KNOW-2] GET ?sync — Synchronisation des connaissances
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['sync'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--sync'], '', 30);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? ['success' => false, 'error' => 'Sync failed']);
    exit;
}

// [KNOW-3] GET ?websites — Sites web hébergés
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['websites'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--knowledge', 'website'], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? []);
    exit;
}

// [KNOW-4] GET ?containers — Conteneurs Docker
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['containers'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--knowledge', 'container'], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? []);
    exit;
}

// [KNOW-5] GET ?ssl — Certificats SSL
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['ssl'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--knowledge', 'ssl'], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? []);
    exit;
}

// [KNOW-6] GET ?ports — Ports ouverts
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['ports'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--knowledge', 'port'], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? []);
    exit;
}

// GET ?remote-hosts — État des équipements distants
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['remote-hosts'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--remote-hosts'], '', 20);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? []);
    exit;
}

// GET ?scan-network
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['scan-network'])) {
    require_auth();
    header('Content-Type: application/json');
    $output = run_agent(['--scan-network'], '', 30);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? []);
    exit;
}

// [I5] GET ?cron
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['cron'])) {
    $cron_key = $_GET['key'] ?? '';
    $cron_secret = getenv('CASSANDRA_CRON_SECRET') ?: '';
    $is_local = in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true);
    if (!$is_local && ($cron_secret === '' || !hash_equals($cron_secret, $cron_key))) {
        http_response_code(403);
        echo json_encode(['error' => 'Accès non autorisé']);
        exit;
    }
    header('Content-Type: application/json');
    $output = run_agent(['--cron'], '', 60);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? ['error' => 'Timeout audit cron']);
    exit;
}

// [F2] [I1] GET ?stream — SSE streaming avec fallback
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['stream'])) {
    require_auth();

    $message = trim(urldecode($_GET['message'] ?? ''));
    if (empty($message)) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Message vide']);
        exit;
    }

    $history = load_history();

    try {
        $payload = json_encode([
            'message' => $message,
            'history' => $history,
            'session' => session_id(),
        ], JSON_THROW_ON_ERROR);
    } catch (JsonException $e) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Payload invalide : ' . $e->getMessage()]);
        exit;
    }

    // Headers SSE optimisés
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Accel-Buffering: no');
    header('Access-Control-Allow-Origin: *');
    
    if (ob_get_level()) ob_end_clean();
    ob_implicit_flush(true);
    
    error_log("CASSANDRA SSE: Starting stream for message: " . substr($message, 0, 50));

    $cmd = ['python3', $AGENT, '--stream'];
    $descriptors = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
    $process = proc_open($cmd, $descriptors, $pipes, null,
                         ['PATH' => '/bin:/usr/bin:/sbin:/usr/sbin']);

    if (!is_resource($process)) {
        error_log("CASSANDRA SSE: Failed to start agent process");
        echo "data: " . json_encode(['error' => 'Impossible de démarrer l\'agent']) . "\n\n";
        flush();
        exit;
    }

    fwrite($pipes[0], $payload);
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);

    $deadline = microtime(true) + 90;
    $full_reply = '';
    $last_history = null;
    $has_data = false;

    while (true) {
        if (microtime(true) > $deadline) {
            error_log("CASSANDRA SSE: Timeout reached");
            break;
        }
        if (connection_aborted()) {
            error_log("CASSANDRA SSE: Connection aborted by client");
            break;
        }

        $read   = [$pipes[1]];
        $write  = null;
        $except = null;
        $n = stream_select($read, $write, $except, 0, 200000);

        if ($n > 0) {
            $line = fgets($pipes[1], 4096);
            if ($line !== false) {
                if (str_starts_with($line, 'data: ')) {
                    $has_data = true;
                    echo $line . "\n";
                    flush();
                    
                    $json_part = substr($line, 6);
                    $parsed = json_decode($json_part, true);
                    if ($parsed && !empty($parsed['done'])) {
                        $last_history = $parsed['text'] ?? $parsed['full'] ?? '';
                        break;
                    }
                } else {
                    if (strlen(trim($line)) > 0) {
                        error_log("CASSANDRA SSE: Non-SSE output: " . substr($line, 0, 200));
                    }
                }
            }
        }

        $status = proc_get_status($process);
        if (!$status['running'] && feof($pipes[1])) {
            error_log("CASSANDRA SSE: Process finished");
            break;
        }
    }

    if (!$has_data) {
        error_log("CASSANDRA SSE: No data received from agent");
        echo "data: " . json_encode(['error' => 'Aucune réponse de l\'agent', 'fallback' => true]) . "\n\n";
        flush();
    }

    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);
    
    error_log("CASSANDRA SSE: Stream completed");

    if ($last_history !== null) {
        $history[] = ['role' => 'user', 'content' => $message];
        $history[] = ['role' => 'assistant', 'content' => $last_history];
        save_history($history);
    }
    exit;
}

// POST ?exec-cmd — Exécution EXPLICITE d'une commande
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
        'error'   => 'Timeout : l\'agent n\'a pas répondu dans les 60s. Réessayez.',
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

$result = json_decode($output, true);

if ($result && isset($result['success']) && $result['success'] === true) {
    $history[] = ['role' => 'user', 'content' => $message];
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