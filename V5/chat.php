<?php
/**
 * CASSANDRA chat.php v5.0
 * CORRECTIONS v4 → v5 :
 *   - Résumé auto de session stocké en mémoire long-terme (--summarize)
 *   - Route GET ?patterns pour les patterns d'incidents
 *   - Nettoyage du fichier d'historique session si vide / corrompu
 *   - Validation incident_id plus stricte (range check)
 *   - Headers Content-Security-Policy ajoutés
 *   - history_file : chemin garanti unique par session (plus safe)
 */

// ── Sécurité headers ─────────────────────────────────────────
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST');
header('Access-Control-Allow-Headers: Content-Type');
// INNOVATION v5 : CSP strict
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src https://fonts.gstatic.com; img-src 'self' data:");

// ── Sessions sécurisées ───────────────────────────────────────
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
// HELPER : appel agent avec proc_open + timeout
// ============================================================
function run_agent(array $args, string $stdin_data = '', int $timeout = 30): ?string {
    global $AGENT_PATH;

    if (!file_exists($AGENT_PATH)) {
        return null;
    }

    $cmd = array_merge(['python3', $AGENT_PATH], $args);

    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    $process = proc_open($cmd, $descriptors, $pipes, null, ['PATH' => '/bin:/usr/bin:/sbin:/usr/sbin']);

    if (!is_resource($process)) {
        return null;
    }

    if ($stdin_data !== '') {
        fwrite($pipes[0], $stdin_data);
    }
    fclose($pipes[0]);

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
        if ($n === false) break;
        if ($n > 0) {
            $chunk = fread($pipes[1], 65536);
            if ($chunk === false || $chunk === '') {
                if (feof($pipes[1])) break;
            } else {
                $output .= $chunk;
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

// ── Helper : chemin fichier historique (sécurisé) ────────────
function get_history_file(): string {
    $dir = '/var/lib/cassandra/sessions';
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    // FIX : hash du session_id pour éviter tout path traversal résiduel
    $safe_id = hash('sha256', session_id());
    return $dir . '/hist_' . $safe_id . '.json';
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
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['history'])) {
    header('Content-Type: application/json');
    $minutes = min((int)($_GET['minutes'] ?? 30), 1440);
    $output  = run_agent(['--history', (string)$minutes], '', 10);
    $data    = $output ? json_decode($output, true) : null;
    echo json_encode(is_array($data) ? $data : []);
    exit;
}

// ── Route : GET ?last-audit ───────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['last-audit'])) {
    header('Content-Type: application/json');
    $output = run_agent(['--last-audit'], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode($data ?? ['summary' => null]);
    exit;
}

// ── Route : GET ?patterns — INNOVATION v5 ────────────────────
// Retourne les patterns d'incidents détectés (apprentissage adaptatif)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['patterns'])) {
    header('Content-Type: application/json');
    $output = run_agent(['--patterns'], '', 10);
    $data   = $output ? json_decode($output, true) : null;
    echo json_encode(is_array($data) ? $data : []);
    exit;
}

// ── Route : GET ?csrf ────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['csrf'])) {
    header('Content-Type: application/json');
    echo json_encode(['token' => $_SESSION['csrf_token']]);
    exit;
}

// ── Route : POST ?resolve ─────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['resolve'])) {
    header('Content-Type: application/json');

    $csrf = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Token CSRF invalide']);
        exit;
    }

    $incident_id = (int)($_POST['incident_id'] ?? 0);
    // FIX : validation de range (pas juste > 0)
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

// ── Route : POST ?summarize — INNOVATION v5 ──────────────────
// Sauvegarde la mémoire long-terme d'une session (appelé par le JS à la fermeture)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['summarize'])) {
    header('Content-Type: application/json');

    $csrf = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Token CSRF invalide']);
        exit;
    }

    $history_file = get_history_file();
    $history = [];
    if (file_exists($history_file)) {
        $raw     = file_get_contents($history_file);
        $history = json_decode($raw, true) ?: [];
    }

    if (count($history) < 2) {
        echo json_encode(['success' => false, 'error' => 'Historique insuffisant']);
        exit;
    }

    $payload = json_encode([
        'session' => session_id(),
        'history' => $history,
    ]);
    $output = run_agent(['--summarize'], $payload, 20);
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
$history_file = get_history_file();
$history = [];

if (file_exists($history_file)) {
    $raw     = file_get_contents($history_file);
    $decoded = json_decode($raw, true);
    // FIX : nettoyage si le fichier est corrompu
    if (is_array($decoded)) {
        $history = $decoded;
    } else {
        @unlink($history_file);
    }
}

// ── Payload via stdin (sécurisé) ──────────────────────────────
$payload = json_encode([
    'message' => $message,
    'history' => $history,
    'session' => session_id(),
]);

$output = run_agent(['--chat'], $payload, 45);

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
    $history   = array_slice($history, -30); // FIX : 30 tours au lieu de 20
    file_put_contents($history_file, json_encode($history), LOCK_EX);

    echo json_encode([
        'success'  => true,
        'response' => $result['response'],
        'csrf'     => $_SESSION['csrf_token'],
        // INNOVATION v5 : retourner le nb de messages pour le JS
        'msg_count' => count($history) / 2,
    ], JSON_UNESCAPED_UNICODE);
} else {
    $error = $result['error'] ?? substr($output ?? '', 0, 500) ?? 'Erreur inconnue';
    echo json_encode([
        'success' => false,
        'error'   => $error
    ], JSON_UNESCAPED_UNICODE);
}
