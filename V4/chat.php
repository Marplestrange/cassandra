<?php
/**
 * CASSANDRA chat.php v4.0
 * Corrections : proc_open+timeout, stdin payload, sessions sécurisées
 * Innovations : route history (sparklines), route resolve, route last-audit
 */

// ── Sécurité headers ─────────────────────────────────────────
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST');
header('Access-Control-Allow-Headers: Content-Type');

// ── Sessions sécurisées ───────────────────────────────────────
// FIX : stocker les sessions hors /tmp partagé
$session_save_path = '/var/lib/cassandra/sessions';
if (!is_dir($session_save_path)) {
    @mkdir($session_save_path, 0700, true);
}
if (is_dir($session_save_path) && is_writable($session_save_path)) {
    session_save_path($session_save_path);
}

session_start();

// ── Génération token CSRF ─────────────────────────────────────
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$AGENT_PATH = '/root/agent.py';

// ============================================================
// HELPER : appel agent avec proc_open + timeout (FIX CRITIQUE)
// Remplace shell_exec sans timeout. Passe le payload via stdin.
// ============================================================
function run_agent(array $args, string $stdin_data = '', int $timeout = 30): ?string {
    global $AGENT_PATH;

    if (!file_exists($AGENT_PATH)) {
        return null;
    }

    // Construire la commande avec les args
    $cmd = array_merge(['python3', $AGENT_PATH], $args);

    $descriptors = [
        0 => ['pipe', 'r'],  // stdin
        1 => ['pipe', 'w'],  // stdout
        2 => ['pipe', 'w'],  // stderr (ignoré)
    ];

    $process = proc_open($cmd, $descriptors, $pipes, null, ['PATH' => '/bin:/usr/bin:/sbin:/usr/sbin']);

    if (!is_resource($process)) {
        return null;
    }

    // Écrire le payload sur stdin si fourni
    if ($stdin_data !== '') {
        fwrite($pipes[0], $stdin_data);
    }
    fclose($pipes[0]);

    // Lire stdout avec timeout via stream_select
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

    $output    = '';
    $deadline  = microtime(true) + $timeout;
    $timed_out = false;

    while (true) {
        $remaining = $deadline - microtime(true);
        if ($remaining <= 0) {
            $timed_out = true;
            break;
        }

        $read   = [$pipes[1]];
        $write  = null;
        $except = null;
        $sec    = (int) $remaining;
        $usec   = (int)(($remaining - $sec) * 1e6);

        $n = stream_select($read, $write, $except, $sec, $usec);
        if ($n === false) {
            break;
        }
        if ($n > 0) {
            $chunk = fread($pipes[1], 65536);
            if ($chunk === false || $chunk === '') {
                if (feof($pipes[1])) break;
            } else {
                $output .= $chunk;
            }
        }

        // Vérifier si le processus est toujours actif
        $status = proc_get_status($process);
        if (!$status['running'] && feof($pipes[1])) {
            break;
        }
    }

    fclose($pipes[1]);
    fclose($pipes[2]);

    if ($timed_out) {
        proc_terminate($process, 9);
    }
    proc_close($process);

    return $timed_out ? null : ($output ?: null);
}

// ── Route : GET ?metrics ──────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['metrics'])) {
    header('Content-Type: application/json');
    $output = run_agent(['--metrics'], '', 10);
    if ($output) {
        $data = json_decode($output, true);
        echo ($data && isset($data['cpu']))
            ? json_encode($data)
            : json_encode(['error' => 'Métriques invalides']);
    } else {
        echo json_encode(['error' => 'Timeout ou agent introuvable']);
    }
    exit;
}

// ── Route : GET ?incidents ────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['incidents'])) {
    header('Content-Type: application/json');
    $output = run_agent(['--incidents'], '', 10);
    $data = $output ? json_decode($output, true) : null;
    echo json_encode(is_array($data) ? $data : []);
    exit;
}

// ── Route : GET ?history[&minutes=30] ─────────────────────────
// Nouveau : retourne l'historique métriques pour les sparklines
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['history'])) {
    header('Content-Type: application/json');
    $minutes = min((int)($_GET['minutes'] ?? 30), 1440); // max 24h
    $output  = run_agent(['--history', (string)$minutes], '', 10);
    $data    = $output ? json_decode($output, true) : null;
    echo json_encode(is_array($data) ? $data : []);
    exit;
}

// ── Route : GET ?last-audit ───────────────────────────────────
// Nouveau : dernier rapport d'audit proactif
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['last-audit'])) {
    header('Content-Type: application/json');
    $output = run_agent(['--last-audit'], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? ['summary' => null]);
    exit;
}

// ── Route : GET ?csrf ────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['csrf'])) {
    header('Content-Type: application/json');
    echo json_encode(['token' => $_SESSION['csrf_token']]);
    exit;
}

// ── Route : POST ?resolve ─────────────────────────────────────
// Nouveau : marquer un incident comme résolu depuis l'UI
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['resolve'])) {
    header('Content-Type: application/json');

    $csrf = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Token CSRF invalide']);
        exit;
    }

    $incident_id = (int)($_POST['incident_id'] ?? 0);
    if ($incident_id <= 0) {
        echo json_encode(['success' => false, 'error' => 'ID incident invalide']);
        exit;
    }

    $note   = substr(trim($_POST['note'] ?? ''), 0, 200);
    $output = run_agent(['--resolve', (string)$incident_id, $note], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? ['success' => false, 'error' => 'Timeout']);
    exit;
}

// ── Route : POST → message au chat ───────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Méthode non autorisée']);
    exit;
}

header('Content-Type: application/json');

// ── Vérification CSRF ─────────────────────────────────────────
$csrf = $_POST['csrf'] ?? '';
if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Token CSRF invalide']);
    exit;
}

// ── Rate limiting : 60 req / session / heure ─────────────────
$window = 3600;
$limit  = 60;
$now    = time();

if (empty($_SESSION['rl_reset']) || $now > $_SESSION['rl_reset']) {
    $_SESSION['rl_count'] = 0;
    $_SESSION['rl_reset'] = $now + $window;
}
$_SESSION['rl_count']++;

if ($_SESSION['rl_count'] > $limit) {
    $wait = $_SESSION['rl_reset'] - $now;
    http_response_code(429);
    echo json_encode([
        'success' => false,
        'error'   => "Limite atteinte. Réessayez dans {$wait}s."
    ]);
    exit;
}

// ── Validation du message ─────────────────────────────────────
$message = trim($_POST['message'] ?? '');
if (empty($message)) {
    echo json_encode(['success' => false, 'error' => 'Message vide']);
    exit;
}
if (mb_strlen($message) > 2000) {
    echo json_encode(['success' => false, 'error' => 'Message trop long (max 2000 car.)']);
    exit;
}

// ── Historique de session ─────────────────────────────────────
// FIX : stocké dans /var/lib/cassandra/sessions/ au lieu de /tmp
$hist_dir  = '/var/lib/cassandra/sessions';
if (!is_dir($hist_dir)) {
    @mkdir($hist_dir, 0700, true);
}
$history_file = rtrim($hist_dir, '/') . '/hist_' . session_id() . '.json';

$history = [];
if (file_exists($history_file)) {
    $raw     = file_get_contents($history_file);
    $history = json_decode($raw, true) ?: [];
}

// ── FIX CRITIQUE : payload via stdin (proc_open) ──────────────
// Remplace shell_exec + argv pour éviter l'exposition dans ps aux
$payload = json_encode([
    'message' => $message,
    'history' => $history,
    'session' => session_id(),
]);

$output = run_agent(['--chat'], $payload, 45); // 45s max pour l'API IA

if ($output === null) {
    echo json_encode([
        'success' => false,
        'error'   => 'Timeout : l\'agent n\'a pas répondu dans les délais (45s). Réessayez.'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

$result = json_decode($output, true);

if ($result && isset($result['success']) && $result['success'] === true) {
    $history[] = ['role' => 'user',      'content' => $message];
    $history[] = ['role' => 'assistant', 'content' => $result['response']];
    $history   = array_slice($history, -20);
    file_put_contents($history_file, json_encode($history), LOCK_EX);

    echo json_encode([
        'success'  => true,
        'response' => $result['response'],
        'csrf'     => $_SESSION['csrf_token'],
    ], JSON_UNESCAPED_UNICODE);
} else {
    $error = $result['error'] ?? substr($output ?? '', 0, 500) ?? 'Erreur inconnue';
    echo json_encode([
        'success' => false,
        'error'   => $error
    ], JSON_UNESCAPED_UNICODE);
}
