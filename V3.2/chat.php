<?php
/**
 * CASSANDRA chat.php v3.2
 * Gère : chat IA, proxy métriques SSE, liste incidents
 */

// ── Sécurité headers ─────────────────────────────────────────
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST');
header('Access-Control-Allow-Headers: Content-Type');

session_start();

// ── Génération token CSRF ─────────────────────────────────────
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ── Route : GET /chat.php?metrics → proxy métriques ──────────
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['metrics'])) {
    header('Content-Type: application/json');
    
    // Vérifier que l'agent existe
    if (!file_exists('/root/agent.py')) {
        echo json_encode(['error' => 'Agent introuvable']);
        exit;
    }
    
    // 2>/dev/null pour ignorer les messages de debug sur stderr
    $output = shell_exec('python3 /root/agent.py --metrics 2>/dev/null');
    $data   = json_decode($output, true);
    
    if ($data && isset($data['cpu'])) {
        echo json_encode($data);
    } else {
        echo json_encode(['error' => 'Impossible de collecter les métriques', 'raw' => substr($output, 0, 200)]);
    }
    exit;
}

// ── Route : GET /chat.php?incidents → liste incidents ─────────
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['incidents'])) {
    header('Content-Type: application/json');
    
    if (!file_exists('/root/agent.py')) {
        echo json_encode(['error' => 'Agent introuvable']);
        exit;
    }
    
    // 2>/dev/null pour ignorer les messages de debug
    $output = shell_exec('python3 /root/agent.py --incidents 2>/dev/null');
    $data   = json_decode($output, true);
    
    if ($data && is_array($data)) {
        echo json_encode($data);
    } else {
        echo json_encode([]);
    }
    exit;
}

// ── Route : GET /chat.php?csrf → renvoie le token ────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['csrf'])) {
    header('Content-Type: application/json');
    echo json_encode(['token' => $_SESSION['csrf_token']]);
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
$history_file = sys_get_temp_dir() . '/cassandra_hist_' . session_id() . '.json';
$history = [];
if (file_exists($history_file)) {
    $raw = file_get_contents($history_file);
    $history = json_decode($raw, true) ?: [];
}

// ── Vérifier que l'agent existe ───────────────────────────────
if (!file_exists('/root/agent.py')) {
    echo json_encode(['success' => false, 'error' => 'Agent introuvable sur le serveur']);
    exit;
}

// ── Appel de l'agent Python ───────────────────────────────────
$payload = json_encode([
    'message' => $message,
    'history' => $history,
    'session' => session_id(),
]);

// Utiliser shell_exec avec redirection stderr pour ignorer les debug
$output = shell_exec('python3 /root/agent.py ' . escapeshellarg($payload) . ' 2>/dev/null');

$result = json_decode($output, true);

if ($result && isset($result['success']) && $result['success'] === true) {
    // Mise à jour de l'historique (20 derniers échanges)
    $history[] = ['role' => 'user',      'content' => $message];
    $history[] = ['role' => 'assistant', 'content' => $result['response']];
    $history   = array_slice($history, -20);
    file_put_contents($history_file, json_encode($history), LOCK_EX);
    
    // Renvoyer la réponse sans échappement supplémentaire
    echo json_encode([
        'success'  => true,
        'response' => $result['response'],
        'csrf'     => $_SESSION['csrf_token'],
    ], JSON_UNESCAPED_UNICODE);
    
} else {
    $error = isset($result['error']) ? $result['error'] : (isset($output) ? substr($output, 0, 500) : 'Erreur inconnue');
    echo json_encode([
        'success' => false,
        'error'   => $error
    ], JSON_UNESCAPED_UNICODE);
}