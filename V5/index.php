<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CASSANDRA — Infrastructure AI v5</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.1.5/purify.min.js" crossorigin="anonymous"></script>
<style>
/* ═══════════════════════════════════════════════
   RESET & VARIABLES
══════════════════════════════════════════════ */
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

:root {
    --bg:         #0a0a0f;
    --bg2:        #111118;
    --bg3:        #18181f;
    --panel:      #1c1c25;
    --border:     rgba(255,255,255,0.06);
    --border2:    rgba(255,255,255,0.12);
    --accent:     #00d4aa;
    --accent2:    #7c5cfc;
    --danger:     #ff4757;
    --warning:    #ffa502;
    --ok:         #2ed573;
    --text:       #e8e8f0;
    --muted:      #6b6b80;
    --mono:       'JetBrains Mono', monospace;
    --sans:       'Syne', sans-serif;
    --sidebar-w:  280px;
    --header-h:   52px;
}

body {
    font-family: var(--mono);
    background: var(--bg);
    color: var(--text);
    height: 100vh;
    display: grid;
    grid-template-rows: var(--header-h) 1fr;
    grid-template-columns: var(--sidebar-w) 1fr 300px;
    grid-template-areas:
        "header header header"
        "sidebar chat memory";
    overflow: hidden;
}

/* ═══════════════════════════════════════════════
   HEADER
══════════════════════════════════════════════ */
header {
    grid-area: header;
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    padding: 0 20px;
    gap: 16px;
    position: relative;
    z-index: 10;
}

.logo { font-family: var(--sans); font-weight: 800; font-size: 18px; letter-spacing: 0.08em; color: var(--accent); text-transform: uppercase; }
.logo-sub { font-size: 10px; color: var(--muted); font-weight: 300; letter-spacing: 0.15em; margin-left: 2px; text-transform: uppercase; }

.header-status { display: flex; align-items: center; gap: 6px; font-size: 11px; color: var(--muted); margin-left: auto; }
.status-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--ok); animation: pulse 2s ease-in-out infinite; }

@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

.header-time { font-size: 11px; color: var(--muted); font-family: var(--mono); margin-left: 20px; }

/* ═══════════════════════════════════════════════
   SIDEBAR
══════════════════════════════════════════════ */
#sidebar {
    grid-area: sidebar;
    background: var(--bg2);
    border-right: 1px solid var(--border);
    overflow-y: auto;
    padding: 16px 12px;
    display: flex;
    flex-direction: column;
    gap: 12px;
}

#sidebar::-webkit-scrollbar { width: 4px; }
#sidebar::-webkit-scrollbar-track { background: transparent; }
#sidebar::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }

.sidebar-title {
    font-family: var(--sans); font-size: 10px; font-weight: 600;
    letter-spacing: 0.2em; color: var(--muted); text-transform: uppercase;
    padding: 4px 4px 8px; border-bottom: 1px solid var(--border);
}

/* Jauges */
.gauge-row { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; }
.gauge-card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 10px 6px 8px; text-align: center; }
.gauge-label { font-size: 9px; letter-spacing: 0.12em; color: var(--muted); text-transform: uppercase; margin-bottom: 6px; }
.gauge-svg { display: block; margin: 0 auto; }
.gauge-val { font-size: 12px; font-weight: 600; margin-top: 4px; }

/* Sparklines */
.sparkline-wrap { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }
.sparkline-head { display: flex; justify-content: space-between; font-size: 10px; color: var(--muted); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.1em; }
.sparkline-head span:last-child { color: var(--text); font-weight: 600; }
canvas.sparkline { width: 100%; height: 36px; display: block; border-radius: 3px; }

/* Barres stat */
.stat-bar-wrap { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }
.stat-bar-head { display: flex; justify-content: space-between; font-size: 11px; color: var(--muted); margin-bottom: 6px; }
.stat-bar-head span:last-child { color: var(--text); font-weight: 600; }
.stat-bar-track { background: var(--bg3); border-radius: 2px; height: 4px; overflow: hidden; }
.stat-bar-fill { height: 100%; border-radius: 2px; transition: width 0.8s ease, background 0.4s; }

/* Services */
.services-wrap { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }
.service-row { display: flex; justify-content: space-between; align-items: center; padding: 5px 0; font-size: 11px; border-bottom: 1px solid var(--border); }
.service-row:last-child { border-bottom: none; }
.service-name { color: var(--muted); }
.svc-badge { font-size: 9px; font-weight: 600; letter-spacing: 0.08em; padding: 2px 8px; border-radius: 3px; }
.svc-ok  { background: rgba(46,213,115,0.12); color: var(--ok); }
.svc-err { background: rgba(255,71,87,0.12);  color: var(--danger); }

/* Load */
.load-card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; font-size: 11px; }
.load-vals { display: flex; gap: 16px; margin-top: 6px; color: var(--accent); font-size: 13px; font-weight: 600; }
.load-lbl { font-size: 9px; color: var(--muted); margin-top: 2px; }

/* Alertes */
.alerts-wrap { display: flex; flex-direction: column; gap: 6px; }
.alert-item { border-radius: 6px; padding: 8px 10px; font-size: 11px; display: flex; gap: 8px; align-items: flex-start; border-left: 3px solid; }
.alert-critical { background: rgba(255,71,87,0.08);  border-color: var(--danger);  color: #ffaab2; }
.alert-warning  { background: rgba(255,165,2,0.08);  border-color: var(--warning); color: #ffd08a; }
.alert-icon { flex-shrink: 0; }

/* ═══════════════════════════════════════════════
   CHAT
══════════════════════════════════════════════ */
#chat-area { grid-area: chat; display: flex; flex-direction: column; overflow: hidden; }

#messages { flex: 1; overflow-y: auto; padding: 20px 24px; display: flex; flex-direction: column; gap: 16px; }
#messages::-webkit-scrollbar { width: 4px; }
#messages::-webkit-scrollbar-track { background: transparent; }
#messages::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }

.msg { max-width: 88%; animation: fadeUp 0.2s ease; }
@keyframes fadeUp { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }

.msg-user { align-self: flex-end; }
.msg-user .bubble { background: var(--accent2); color: #fff; padding: 10px 14px; border-radius: 14px 14px 2px 14px; font-size: 13px; line-height: 1.5; }
.msg-bot { align-self: flex-start; max-width: 96%; }
.msg-bot .bubble { background: var(--panel); border: 1px solid var(--border); padding: 14px 16px; border-radius: 2px 14px 14px 14px; font-size: 13px; line-height: 1.6; }
.msg-meta { font-size: 10px; color: var(--muted); margin-top: 4px; padding: 0 4px; }

/* Contenu bulles */
.bubble h2 { font-family: var(--sans); font-size: 14px; font-weight: 600; color: var(--accent); margin: 10px 0 6px; border-bottom: 1px solid var(--border); padding-bottom: 4px; }
.bubble h3 { font-family: var(--sans); font-size: 13px; font-weight: 600; color: #a0a0c0; margin: 8px 0 4px; }
.bubble p  { margin: 4px 0; line-height: 1.5; }
.bubble ul, .bubble .info-list { padding-left: 18px; margin: 6px 0; list-style-type: none; }
.bubble li { margin: 3px 0; color: #c0c0d8; position: relative; }
.bubble li::before { content: "▹"; color: var(--accent); position: absolute; left: -14px; }
.bubble pre { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; font-size: 11px; overflow-x: auto; color: var(--accent); white-space: pre-wrap; word-break: break-all; margin: 8px 0; }
.bubble .command-block { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; margin: 10px 0; overflow: hidden; }
.bubble .command-header { background: var(--bg3); padding: 7px 12px; font-size: 11px; color: var(--accent); border-bottom: 1px solid var(--border); font-family: var(--mono); }
.bubble .result-header  { padding: 7px 12px; font-size: 10px; color: var(--muted); border-bottom: 1px solid var(--border); }
.bubble .result-content { padding: 10px 12px; font-size: 11px; font-family: var(--mono); }
.bubble table  { width: 100%; border-collapse: collapse; font-size: 11px; margin: 6px 0; }
.bubble th     { background: var(--bg3); color: var(--muted); padding: 5px 8px; text-align: left; font-weight: 600; letter-spacing: 0.05em; }
.bubble td     { padding: 4px 8px; border-bottom: 1px solid var(--border); color: #c8c8e0; }
.bubble .ok       { color: var(--ok);      font-weight: 600; }
.bubble .warning  { color: var(--warning); font-weight: 600; }
.bubble .critical { color: var(--danger);  font-weight: 600; }
.bubble hr { border: none; height: 1px; background: var(--border); margin: 12px 0; }
.bubble .svc-status { font-size: 11px; }
.bubble .svc-line   { padding: 2px 0; }
.bubble .log-output { font-size: 10px; max-height: 200px; overflow-y: auto; }
.bubble .log-line   { padding: 1px 0; border-bottom: 1px solid var(--border); }

/* Typing */
.typing { display: flex; gap: 4px; align-items: center; padding: 14px 16px; }
.typing-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--muted); animation: blink 1.2s ease-in-out infinite; }
.typing-dot:nth-child(2) { animation-delay: 0.2s; }
.typing-dot:nth-child(3) { animation-delay: 0.4s; }
@keyframes blink { 0%, 100% { opacity: 0.3; } 50% { opacity: 1; } }

/* Input */
#input-area { border-top: 1px solid var(--border); background: var(--bg2); padding: 14px 20px; display: flex; gap: 10px; align-items: flex-end; }
#input { flex: 1; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; color: var(--text); font-family: var(--mono); font-size: 13px; resize: none; min-height: 42px; max-height: 120px; outline: none; line-height: 1.5; transition: border-color 0.2s; }
#input:focus { border-color: var(--accent2); }
#input::placeholder { color: var(--muted); }

#send { background: var(--accent); border: none; border-radius: 8px; width: 42px; height: 42px; cursor: pointer; color: var(--bg); font-size: 18px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; transition: opacity 0.2s; }
#send:hover { opacity: 0.85; }
#send:disabled { opacity: 0.3; cursor: default; }

.quick-actions { display: flex; gap: 6px; flex-wrap: wrap; padding: 0 20px 10px; }
.qa-btn { background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; padding: 4px 10px; font-size: 11px; color: var(--muted); cursor: pointer; font-family: var(--mono); transition: border-color 0.2s, color 0.2s; white-space: nowrap; }
.qa-btn:hover { border-color: var(--accent); color: var(--accent); }

/* ═══════════════════════════════════════════════
   PANNEAU MÉMOIRE CONTEXTUELLE (droite)
══════════════════════════════════════════════ */
#memory-panel {
    grid-area: memory;
    background: var(--bg2);
    border-left: 1px solid var(--border);
    overflow-y: auto;
    padding: 16px 12px;
    display: flex;
    flex-direction: column;
    gap: 12px;
}

#memory-panel::-webkit-scrollbar { width: 4px; }
#memory-panel::-webkit-scrollbar-track { background: transparent; }
#memory-panel::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }

.mem-title { font-family: var(--sans); font-size: 10px; font-weight: 600; letter-spacing: 0.2em; color: var(--muted); text-transform: uppercase; padding: 4px 4px 8px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
.mem-refresh { cursor: pointer; color: var(--accent); font-size: 12px; opacity: 0.7; transition: opacity 0.2s; }
.mem-refresh:hover { opacity: 1; }

/* Audit */
.audit-card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; font-size: 11px; line-height: 1.5; }
.audit-card-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
.audit-status-ok       { color: var(--ok);     font-size: 9px; font-weight: 600; text-transform: uppercase; }
.audit-status-warning  { color: var(--warning); font-size: 9px; font-weight: 600; text-transform: uppercase; }
.audit-status-critical { color: var(--danger);  font-size: 9px; font-weight: 600; text-transform: uppercase; }
.audit-text { color: var(--muted); font-size: 11px; }

/* INNOVATION v5 : Panneau patterns */
.patterns-wrap { display: flex; flex-direction: column; gap: 6px; }

.pattern-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent2);
    border-radius: 6px;
    padding: 8px 10px;
    font-size: 11px;
}

.pattern-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
.pattern-cat  { color: var(--accent); font-weight: 600; text-transform: uppercase; font-size: 10px; letter-spacing: 0.08em; }
.pattern-count { background: rgba(124,92,252,0.15); color: var(--accent2); font-size: 9px; padding: 1px 6px; border-radius: 10px; }
.pattern-sev  { font-size: 10px; color: var(--muted); }
.pattern-fix  { font-size: 10px; color: var(--ok); margin-top: 3px; font-style: italic; }

/* Filtres */
.inc-filters { display: flex; gap: 4px; flex-wrap: wrap; margin-bottom: 4px; }
.inc-filter-btn { background: var(--bg3); border: 1px solid var(--border); border-radius: 4px; padding: 2px 8px; font-size: 10px; color: var(--muted); cursor: pointer; font-family: var(--mono); transition: border-color 0.15s, color 0.15s; }
.inc-filter-btn.active { border-color: var(--accent); color: var(--accent); }

/* Incidents */
.incident-card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; border-left: 3px solid var(--border2); transition: opacity 0.3s; }
.incident-card.severity-critical { border-left-color: var(--danger); }
.incident-card.severity-warning  { border-left-color: var(--warning); }
.incident-card.severity-info     { border-left-color: var(--accent); }
.incident-card.resolved          { opacity: 0.45; }

.inc-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
.inc-sev { font-size: 9px; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; padding: 2px 6px; border-radius: 3px; }
.sev-critical { background: rgba(255,71,87,0.15);  color: var(--danger); }
.sev-warning  { background: rgba(255,165,2,0.15);  color: var(--warning); }
.sev-info     { background: rgba(0,212,170,0.12);  color: var(--accent); }
.inc-time     { font-size: 10px; color: var(--muted); }
.inc-title    { font-size: 12px; color: var(--text); line-height: 1.4; }
.inc-cat      { font-size: 10px; color: var(--muted); margin-top: 3px; text-transform: uppercase; letter-spacing: 0.08em; }
.inc-resolved { font-size: 10px; color: var(--ok); margin-top: 3px; }

.resolve-btn { margin-top: 6px; background: none; border: 1px solid var(--border2); border-radius: 4px; padding: 3px 8px; font-size: 10px; color: var(--muted); cursor: pointer; font-family: var(--mono); width: 100%; text-align: left; transition: border-color 0.15s, color 0.15s; }
.resolve-btn:hover { border-color: var(--ok); color: var(--ok); }

/* Pagination */
.inc-pagination { display: flex; justify-content: center; gap: 6px; margin-top: 4px; }
.inc-page-btn { background: var(--bg3); border: 1px solid var(--border); border-radius: 4px; padding: 3px 10px; font-size: 10px; color: var(--muted); cursor: pointer; font-family: var(--mono); }
.inc-page-btn:disabled { opacity: 0.3; cursor: default; }
.inc-page-btn.active { border-color: var(--accent); color: var(--accent); }

.mem-empty { text-align: center; color: var(--muted); font-size: 12px; padding: 20px 0; }
.mem-stat-row { display: flex; justify-content: space-between; font-size: 11px; padding: 4px 0; border-bottom: 1px solid var(--border); color: var(--muted); }
.mem-stat-row span:last-child { color: var(--text); }

/* INNOVATION v5 : badge mémoire long-terme */
.memory-badge {
    display: inline-flex; align-items: center; gap: 4px;
    background: rgba(0,212,170,0.08);
    border: 1px solid rgba(0,212,170,0.2);
    border-radius: 4px; padding: 2px 8px; font-size: 10px;
    color: var(--accent); margin-top: 4px;
}

/* Toast notification */
.toast {
    position: fixed; bottom: 20px; right: 20px;
    background: var(--panel); border: 1px solid var(--border2);
    border-radius: 8px; padding: 10px 16px; font-size: 12px;
    color: var(--text); z-index: 100;
    animation: fadeUp 0.3s ease;
    box-shadow: 0 4px 20px rgba(0,0,0,0.4);
}
.toast.toast-ok      { border-color: var(--ok);     color: var(--ok); }
.toast.toast-warning { border-color: var(--warning); color: var(--warning); }

/* ═══════════════════════════════════════════════
   RESPONSIVE
══════════════════════════════════════════════ */
@media (max-width: 900px) {
    body { grid-template-columns: 1fr; grid-template-rows: var(--header-h) 1fr auto; grid-template-areas: "header" "chat" "sidebar"; }
    #memory-panel { display: none; }
    #sidebar { max-height: 220px; }
}
</style>
</head>
<body>

<!-- ═══════ HEADER ═══════ -->
<header>
    <div>
        <div class="logo">CASSANDRA</div>
        <div class="logo-sub">Infrastructure AI v5.0</div>
    </div>
    <div class="header-status">
        <div class="status-dot" id="dot"></div>
        <span id="status-txt">En ligne</span>
    </div>
    <div class="header-time" id="clock"></div>
</header>

<!-- ═══════ SIDEBAR MÉTRIQUES ═══════ -->
<aside id="sidebar">
    <div class="sidebar-title">Métriques système</div>

    <div class="gauge-row">
        <div class="gauge-card">
            <div class="gauge-label">CPU</div>
            <svg class="gauge-svg" width="56" height="56" viewBox="0 0 56 56">
                <circle cx="28" cy="28" r="22" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="5"/>
                <circle id="g-cpu" cx="28" cy="28" r="22" fill="none" stroke="#00d4aa" stroke-width="5"
                    stroke-dasharray="138.2" stroke-dashoffset="138.2"
                    stroke-linecap="round" transform="rotate(-90 28 28)" style="transition:stroke-dashoffset 0.8s ease,stroke 0.4s"/>
            </svg>
            <div class="gauge-val" id="v-cpu">–</div>
        </div>
        <div class="gauge-card">
            <div class="gauge-label">RAM</div>
            <svg class="gauge-svg" width="56" height="56" viewBox="0 0 56 56">
                <circle cx="28" cy="28" r="22" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="5"/>
                <circle id="g-ram" cx="28" cy="28" r="22" fill="none" stroke="#7c5cfc" stroke-width="5"
                    stroke-dasharray="138.2" stroke-dashoffset="138.2"
                    stroke-linecap="round" transform="rotate(-90 28 28)" style="transition:stroke-dashoffset 0.8s ease,stroke 0.4s"/>
            </svg>
            <div class="gauge-val" id="v-ram">–</div>
        </div>
        <div class="gauge-card">
            <div class="gauge-label">Disque</div>
            <svg class="gauge-svg" width="56" height="56" viewBox="0 0 56 56">
                <circle cx="28" cy="28" r="22" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="5"/>
                <circle id="g-disk" cx="28" cy="28" r="22" fill="none" stroke="#00d4aa" stroke-width="5"
                    stroke-dasharray="138.2" stroke-dashoffset="138.2"
                    stroke-linecap="round" transform="rotate(-90 28 28)" style="transition:stroke-dashoffset 0.8s ease,stroke 0.4s"/>
            </svg>
            <div class="gauge-val" id="v-disk">–</div>
        </div>
    </div>

    <div class="sparkline-wrap">
        <div class="sparkline-head"><span>CPU — 30 min</span><span id="spark-cpu-val">–</span></div>
        <canvas class="sparkline" id="spark-cpu" width="220" height="36"></canvas>
    </div>

    <div class="sparkline-wrap">
        <div class="sparkline-head"><span>RAM — 30 min</span><span id="spark-ram-val">–</span></div>
        <canvas class="sparkline" id="spark-ram" width="220" height="36"></canvas>
    </div>

    <div class="stat-bar-wrap">
        <div class="stat-bar-head"><span>RAM utilisée</span><span id="ram-detail">– / – Go</span></div>
        <div class="stat-bar-track"><div class="stat-bar-fill" id="bar-ram" style="width:0%;background:var(--accent2)"></div></div>
    </div>

    <div class="stat-bar-wrap">
        <div class="stat-bar-head"><span>Disque /</span><span id="disk-detail">– / –</span></div>
        <div class="stat-bar-track"><div class="stat-bar-fill" id="bar-disk" style="width:0%;background:var(--accent)"></div></div>
    </div>

    <div class="load-card">
        <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:0.12em">Load average</div>
        <div class="load-vals">
            <div><div id="load1">–</div><div class="load-lbl">1 min</div></div>
            <div><div id="load5">–</div><div class="load-lbl">5 min</div></div>
            <div><div id="load15">–</div><div class="load-lbl">15 min</div></div>
        </div>
    </div>

    <div class="services-wrap">
        <div class="sidebar-title" style="border:none;margin-bottom:6px">Services</div>
        <div id="services-list">
            <div class="service-row"><span class="service-name">nginx</span><span class="svc-badge">…</span></div>
            <div class="service-row"><span class="service-name">php-fpm</span><span class="svc-badge">…</span></div>
            <div class="service-row"><span class="service-name">mysql</span><span class="svc-badge">…</span></div>
            <div class="service-row"><span class="service-name">docker</span><span class="svc-badge">…</span></div>
        </div>
    </div>

    <div class="sidebar-title">Alertes actives</div>
    <div class="alerts-wrap" id="alerts-wrap">
        <div style="font-size:11px;color:var(--muted);padding:4px">Aucune alerte</div>
    </div>
</aside>

<!-- ═══════ CHAT ═══════ -->
<main id="chat-area">
    <div id="messages"></div>

    <div class="quick-actions" id="qa">
        <button class="qa-btn" onclick="qa('Quel est l\'état général du serveur ?')">État général</button>
        <button class="qa-btn" onclick="qa('Affiche l\'espace disque détaillé')">Disque</button>
        <button class="qa-btn" onclick="qa('État de la mémoire RAM et swap')">RAM</button>
        <button class="qa-btn" onclick="qa('Liste les services actifs')">Services</button>
        <button class="qa-btn" onclick="qa('Qui est connecté sur le serveur ?')">Connexions</button>
        <button class="qa-btn" onclick="qa('Montre les derniers logs nginx')">Logs nginx</button>
        <button class="qa-btn" onclick="qa('Quels sont les patterns d\'incidents récurrents ?')">Patterns</button>
    </div>

    <div id="input-area">
        <textarea id="input" placeholder="Demande à CASSANDRA… (Entrée pour envoyer)" rows="1"></textarea>
        <button id="send" onclick="sendMessage()" title="Envoyer">➤</button>
    </div>
</main>

<!-- ═══════ MÉMOIRE CONTEXTUELLE ═══════ -->
<aside id="memory-panel">
    <div class="mem-title">
        <span>Mémoire contextuelle</span>
        <span class="mem-refresh" onclick="loadIncidents()" title="Actualiser">↻</span>
    </div>

    <!-- Audit proactif -->
    <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:0.12em">Dernier audit auto</div>
    <div class="audit-card" id="audit-card">
        <div class="audit-card-head">
            <span id="audit-status" class="audit-status-ok">–</span>
            <span id="audit-ts" style="font-size:10px;color:var(--muted)">–</span>
        </div>
        <div class="audit-text" id="audit-text">Chargement…</div>
    </div>

    <!-- INNOVATION v5 : Patterns d'incidents -->
    <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:0.12em;margin-top:4px">
        Patterns détectés
        <span id="patterns-badge" class="memory-badge" style="display:none">🧠 apprentissage</span>
    </div>
    <div class="patterns-wrap" id="patterns-wrap">
        <div class="mem-empty">Chargement…</div>
    </div>

    <!-- Filtres incidents -->
    <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:0.12em;margin-top:4px">Incidents récents</div>
    <div class="inc-filters">
        <button class="inc-filter-btn active" data-filter="all" onclick="setFilter('all', this)">Tous</button>
        <button class="inc-filter-btn" data-filter="critical" onclick="setFilter('critical', this)">Critiques</button>
        <button class="inc-filter-btn" data-filter="warning" onclick="setFilter('warning', this)">Warnings</button>
        <button class="inc-filter-btn" data-filter="active" onclick="setFilter('active', this)">Actifs</button>
    </div>

    <div id="incidents-list"><div class="mem-empty">Chargement…</div></div>
    <div class="inc-pagination" id="inc-pagination"></div>

    <!-- Session courante -->
    <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:0.12em;margin-top:8px">Session courante</div>
    <div style="background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-top:4px">
        <div class="mem-stat-row"><span>Messages</span><span id="msg-count">0</span></div>
        <div class="mem-stat-row"><span>Commandes exec.</span><span id="cmd-count">0</span></div>
        <div class="mem-stat-row" style="border:none"><span>Durée session</span><span id="session-time">0 min</span></div>
    </div>

    <!-- INNOVATION v5 : bouton sauvegarder la mémoire manuellement -->
    <button id="save-memory-btn" onclick="saveSessionMemory()" style="
        background: rgba(0,212,170,0.08); border: 1px solid rgba(0,212,170,0.2);
        border-radius: 6px; padding: 7px 12px; font-size: 11px;
        color: var(--accent); cursor: pointer; font-family: var(--mono);
        width: 100%; text-align: center; transition: background 0.2s;
        margin-top: 4px;
    ">🧠 Sauvegarder la mémoire de session</button>
</aside>

<script>
// ══════════════════════════════════════════════
// ÉTAT GLOBAL
// ══════════════════════════════════════════════
let csrfToken    = '';
let msgCount     = 0;
let cmdCount     = 0;
let sessionStart = Date.now();
const CIRC       = 138.2;

let allIncidents = [];
let incFilter    = 'all';
let incPage      = 0;
const INC_PER_PAGE = 5;

// ══════════════════════════════════════════════
// CSRF
// ══════════════════════════════════════════════
async function loadCsrf() {
    try {
        const r = await fetch('chat.php?csrf');
        const d = await r.json();
        csrfToken = d.token;
    } catch(e) { console.error('CSRF fetch failed', e); }
}

// ══════════════════════════════════════════════
// HORLOGE
// ══════════════════════════════════════════════
function updateClock() {
    document.getElementById('clock').textContent =
        new Date().toLocaleTimeString('fr-FR', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}
setInterval(updateClock, 1000);
updateClock();

setInterval(() => {
    const mins = Math.floor((Date.now() - sessionStart) / 60000);
    document.getElementById('session-time').textContent = `${mins} min`;
}, 30000);

// ══════════════════════════════════════════════
// TOAST
// ══════════════════════════════════════════════
function showToast(msg, type = '') {
    const t = document.createElement('div');
    t.className = `toast ${type ? 'toast-' + type : ''}`;
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3000);
}

// ══════════════════════════════════════════════
// SPARKLINES
// ══════════════════════════════════════════════
function drawSparkline(canvasId, data, color, max = 100) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !data || data.length < 2) return;
    const ctx = canvas.getContext('2d');
    const W   = canvas.width;
    const H   = canvas.height;
    ctx.clearRect(0, 0, W, H);

    const pts = data.map((v, i) => ({
        x: (i / (data.length - 1)) * W,
        y: H - (Math.min(v, max) / max) * H
    }));

    ctx.beginPath();
    ctx.moveTo(pts[0].x, H);
    pts.forEach(p => ctx.lineTo(p.x, p.y));
    ctx.lineTo(pts[pts.length - 1].x, H);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, 0, H);
    grad.addColorStop(0, color + '55');
    grad.addColorStop(1, color + '00');
    ctx.fillStyle = grad;
    ctx.fill();

    ctx.beginPath();
    pts.forEach((p, i) => i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y));
    ctx.strokeStyle = color;
    ctx.lineWidth   = 1.5;
    ctx.stroke();

    const last = pts[pts.length - 1];
    ctx.beginPath();
    ctx.arc(last.x, last.y, 3, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
}

async function fetchHistory() {
    try {
        const r = await fetch('chat.php?history&minutes=30');
        const data = await r.json();
        if (!Array.isArray(data) || data.length < 2) return;

        const cpuVals = data.map(d => d.cpu || 0);
        const ramVals = data.map(d => d.ram || 0);
        drawSparkline('spark-cpu', cpuVals, '#00d4aa');
        drawSparkline('spark-ram', ramVals, '#7c5cfc');
        document.getElementById('spark-cpu-val').textContent = cpuVals[cpuVals.length - 1].toFixed(1) + '%';
        document.getElementById('spark-ram-val').textContent = ramVals[ramVals.length - 1].toFixed(1) + '%';
    } catch(e) { console.warn('History fetch error', e); }
}

// ══════════════════════════════════════════════
// MÉTRIQUES
// ══════════════════════════════════════════════
function gaugeOffset(pct) { return CIRC - (pct / 100) * CIRC; }
function gaugeColor(pct) {
    if (pct > 85) return 'var(--danger)';
    if (pct > 70) return 'var(--warning)';
    return 'var(--ok)';
}

function updateGauge(id, valId, pct) {
    const el = document.getElementById(id);
    const vl = document.getElementById(valId);
    el.style.strokeDashoffset = gaugeOffset(pct);
    el.style.stroke           = gaugeColor(pct);
    vl.textContent            = pct + '%';
    vl.style.color            = gaugeColor(pct);
}

function updateBar(barId, pct) {
    const el = document.getElementById(barId);
    el.style.width      = pct + '%';
    el.style.background = gaugeColor(pct);
}

async function fetchMetrics() {
    try {
        const r = await fetch('chat.php?metrics');
        const d = await r.json();
        if (d.error) return;

        updateGauge('g-cpu',  'v-cpu',  d.cpu  || 0);
        updateGauge('g-ram',  'v-ram',  d.ram  || 0);
        updateGauge('g-disk', 'v-disk', d.disk || 0);
        updateBar('bar-ram',  d.ram  || 0);
        updateBar('bar-disk', d.disk || 0);

        if (d.ram_used_gb !== undefined)
            document.getElementById('ram-detail').textContent = `${d.ram_used_gb} / ${d.ram_total_gb} Go`;
        if (d.disk_used)
            document.getElementById('disk-detail').textContent = `${d.disk_used} / ${d.disk_total}`;
        if (d.load) {
            const parts = d.load.split(' ');
            document.getElementById('load1').textContent  = parts[0] || '–';
            document.getElementById('load5').textContent  = parts[1] || '–';
            document.getElementById('load15').textContent = parts[2] || '–';
        }

        if (d.services) {
            const names = {'nginx':'nginx','php8.1-fpm':'php-fpm','mysql':'mysql','docker':'docker'};
            let html = '';
            for (const [svc, ok] of Object.entries(d.services)) {
                html += `<div class="service-row">
                    <span class="service-name">${names[svc] || escapeHtml(svc)}</span>
                    <span class="svc-badge ${ok ? 'svc-ok' : 'svc-err'}">${ok ? 'ACTIF' : 'ARRÊTÉ'}</span>
                </div>`;
            }
            document.getElementById('services-list').innerHTML = html;
        }

        const aw = document.getElementById('alerts-wrap');
        if (d.alerts && d.alerts.length > 0) {
            aw.innerHTML = d.alerts.map(a =>
                `<div class="alert-item alert-${a.level}">
                    <span class="alert-icon">${a.level === 'critical' ? '🔴' : '🟡'}</span>
                    <span>${escapeHtml(a.msg)}</span>
                </div>`
            ).join('');
            if (d.alerts.some(a => a.level === 'critical') && Notification.permission === 'granted') {
                new Notification('CASSANDRA — Alerte critique', {
                    body: d.alerts.filter(a => a.level === 'critical').map(a => a.msg).join('\n')
                });
            }
        } else {
            aw.innerHTML = '<div style="font-size:11px;color:var(--muted);padding:4px">Aucune alerte</div>';
        }
    } catch(e) { console.warn('Metrics fetch error', e); }
}

fetchMetrics();
setInterval(fetchMetrics, 30000);
setInterval(fetchHistory, 60000);

// ══════════════════════════════════════════════
// AUDIT PROACTIF
// ══════════════════════════════════════════════
async function loadLastAudit() {
    try {
        const r = await fetch('chat.php?last-audit');
        const d = await r.json();
        const statusEl = document.getElementById('audit-status');
        const textEl   = document.getElementById('audit-text');
        const tsEl     = document.getElementById('audit-ts');

        if (!d.summary) {
            textEl.textContent   = 'Aucun rapport. Planifiez : cron 0 * * * * python3 /root/agent.py --audit';
            statusEl.textContent = '–';
            return;
        }

        statusEl.className   = `audit-status-${d.status || 'ok'}`;
        statusEl.textContent = (d.status || 'ok').toUpperCase();
        tsEl.textContent     = (d.ts || '').slice(0, 16);
        textEl.textContent   = d.summary.slice(0, 200) + (d.summary.length > 200 ? '…' : '');
    } catch(e) { console.warn('Audit fetch error', e); }
}

// ══════════════════════════════════════════════
// INNOVATION v5 : PATTERNS D'INCIDENTS
// ══════════════════════════════════════════════
async function loadPatterns() {
    try {
        const r = await fetch('chat.php?patterns');
        const data = await r.json();
        const el   = document.getElementById('patterns-wrap');
        const badge = document.getElementById('patterns-badge');

        if (!Array.isArray(data) || data.length === 0) {
            el.innerHTML = '<div class="mem-empty">Aucun pattern détecté</div>';
            return;
        }

        badge.style.display = 'inline-flex';
        el.innerHTML = data.map(p => `
            <div class="pattern-card">
                <div class="pattern-head">
                    <span class="pattern-cat">${escapeHtml(p.category)}</span>
                    <span class="pattern-count">${p.occurrences}×</span>
                </div>
                <div class="pattern-sev">Sévérité: ${escapeHtml(p.avg_severity || '–')} · Dernier: ${escapeHtml((p.last_seen || '').slice(0, 10))}</div>
                ${p.suggested_fix ? `<div class="pattern-fix">💡 ${escapeHtml(p.suggested_fix)}</div>` : ''}
            </div>
        `).join('');
    } catch(e) { console.warn('Patterns fetch error', e); }
}

// ══════════════════════════════════════════════
// INCIDENTS
// ══════════════════════════════════════════════
async function loadIncidents() {
    try {
        const r = await fetch('chat.php?incidents');
        allIncidents = await r.json();
        if (!Array.isArray(allIncidents)) allIncidents = [];
        incPage = 0;
        renderIncidents();
    } catch(e) { console.warn('Incidents fetch error', e); }
}

function setFilter(filter, btn) {
    incFilter = filter;
    incPage   = 0;
    document.querySelectorAll('.inc-filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderIncidents();
}

function getFilteredIncidents() {
    return allIncidents.filter(i => {
        if (incFilter === 'all')    return true;
        if (incFilter === 'active') return !i.resolved;
        return i.severity === incFilter;
    });
}

function renderIncidents() {
    const filtered   = getFilteredIncidents();
    const el         = document.getElementById('incidents-list');
    const pagEl      = document.getElementById('inc-pagination');
    const totalPages = Math.ceil(filtered.length / INC_PER_PAGE);
    const pageItems  = filtered.slice(incPage * INC_PER_PAGE, (incPage + 1) * INC_PER_PAGE);

    if (filtered.length === 0) {
        el.innerHTML  = '<div class="mem-empty">Aucun incident correspondant</div>';
        pagEl.innerHTML = '';
        return;
    }

    el.innerHTML = pageItems.map(i => `
        <div class="incident-card severity-${i.severity} ${i.resolved ? 'resolved' : ''}" data-id="${i.id}">
            <div class="inc-head">
                <span class="inc-sev sev-${i.severity}">${escapeHtml(i.severity)}</span>
                <span class="inc-time">${escapeHtml(i.ts)}</span>
            </div>
            <div class="inc-title">${escapeHtml(i.title)}</div>
            <div class="inc-cat">${escapeHtml(i.category)}</div>
            ${i.resolved
                ? `<div class="inc-resolved">✓ Résolu ${i.resolved_at ? i.resolved_at.slice(0,16) : ''}</div>`
                : `<button class="resolve-btn" onclick="resolveIncident(${i.id}, this)">✓ Marquer comme résolu</button>`
            }
        </div>
    `).join('');

    if (totalPages <= 1) { pagEl.innerHTML = ''; return; }

    let pagHtml = `<button class="inc-page-btn" onclick="goPage(${incPage-1})" ${incPage===0?'disabled':''}>◀</button>`;
    for (let p = 0; p < totalPages; p++) {
        pagHtml += `<button class="inc-page-btn ${p===incPage?'active':''}" onclick="goPage(${p})">${p+1}</button>`;
    }
    pagHtml += `<button class="inc-page-btn" onclick="goPage(${incPage+1})" ${incPage===totalPages-1?'disabled':''}>▶</button>`;
    pagEl.innerHTML = pagHtml;
}

function goPage(p) {
    const filtered = getFilteredIncidents();
    const total    = Math.ceil(filtered.length / INC_PER_PAGE);
    if (p < 0 || p >= total) return;
    incPage = p;
    renderIncidents();
}

async function resolveIncident(incidentId, btn) {
    btn.disabled    = true;
    btn.textContent = 'Résolution…';
    try {
        const form = new URLSearchParams();
        form.append('csrf', csrfToken);
        form.append('incident_id', incidentId);
        form.append('note', 'Résolu manuellement depuis l\'interface');

        const r = await fetch('chat.php?resolve', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: form
        });
        const d = await r.json();

        if (d.success) {
            const inc = allIncidents.find(i => i.id === incidentId);
            if (inc) { inc.resolved = true; inc.resolved_at = new Date().toISOString().slice(0,16); }
            renderIncidents();
            showToast('Incident résolu ✓', 'ok');
        } else {
            btn.textContent = '✗ Erreur';
            btn.disabled    = false;
        }
    } catch(e) {
        btn.textContent = '✗ Erreur réseau';
        btn.disabled    = false;
    }
}

// ══════════════════════════════════════════════
// INNOVATION v5 : SAUVEGARDE MÉMOIRE LONG-TERME
// ══════════════════════════════════════════════
async function saveSessionMemory() {
    const btn = document.getElementById('save-memory-btn');
    btn.disabled    = true;
    btn.textContent = '🧠 Sauvegarde en cours…';
    try {
        const form = new URLSearchParams();
        form.append('csrf', csrfToken);

        const r = await fetch('chat.php?summarize', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: form
        });
        const d = await r.json();

        if (d.success) {
            showToast('Mémoire de session sauvegardée 🧠', 'ok');
            btn.textContent = '🧠 Mémoire sauvegardée ✓';
            setTimeout(() => {
                btn.textContent = '🧠 Sauvegarder la mémoire de session';
                btn.disabled    = false;
            }, 3000);
        } else {
            showToast(d.error || 'Erreur de sauvegarde', 'warning');
            btn.textContent = '🧠 Sauvegarder la mémoire de session';
            btn.disabled    = false;
        }
    } catch(e) {
        btn.textContent = '🧠 Sauvegarder la mémoire de session';
        btn.disabled    = false;
    }
}

// INNOVATION v5 : sauvegarder automatiquement à la fermeture de la page
window.addEventListener('beforeunload', () => {
    if (msgCount >= 2 && csrfToken) {
        const form = new URLSearchParams();
        form.append('csrf', csrfToken);
        navigator.sendBeacon('chat.php?summarize', form);
    }
});

// ══════════════════════════════════════════════
// UTILITAIRES
// ══════════════════════════════════════════════
function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, m =>
        ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])
    );
}

function sanitizeResponse(html) {
    if (typeof DOMPurify !== 'undefined') {
        return DOMPurify.sanitize(html, {
            ALLOWED_TAGS: ['h2','h3','p','ul','li','pre','div','span','table',
                           'thead','tbody','tr','th','td','strong','em','br','hr'],
            ALLOWED_ATTR: ['class', 'style'],
            FORBID_ATTR:  ['onclick','onerror','onload'],
        });
    }
    return html.replace(/<script[^>]*>.*?<\/script>/gi, '');
}

// ══════════════════════════════════════════════
// CHAT
// ══════════════════════════════════════════════
function timeStr() {
    return new Date().toLocaleTimeString('fr-FR', {hour:'2-digit',minute:'2-digit'});
}

function addMessage(content, sender) {
    const msgs   = document.getElementById('messages');
    const div    = document.createElement('div');
    div.className = `msg msg-${sender}`;
    const bubble = document.createElement('div');
    bubble.className = 'bubble';

    if (sender === 'bot') {
        bubble.innerHTML = sanitizeResponse(content);
        const cmds = bubble.querySelectorAll('.command-block').length;
        if (cmds > 0) { cmdCount += cmds; document.getElementById('cmd-count').textContent = cmdCount; }
    } else {
        bubble.textContent = content;
    }

    const meta     = document.createElement('div');
    meta.className = 'msg-meta';
    meta.textContent = sender === 'bot' ? `CASSANDRA · ${timeStr()}` : `Vous · ${timeStr()}`;

    div.appendChild(bubble);
    div.appendChild(meta);
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;

    if (sender === 'user') {
        msgCount++;
        document.getElementById('msg-count').textContent = msgCount;
    }
    return div;
}

function showTyping() {
    const msgs = document.getElementById('messages');
    const div  = document.createElement('div');
    div.className = 'msg msg-bot';
    div.id        = 'typing';
    div.innerHTML = `<div class="bubble"><div class="typing">
        <div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div>
    </div></div>`;
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
}

function removeTyping() {
    const t = document.getElementById('typing');
    if (t) t.remove();
}

async function sendMessage() {
    const input   = document.getElementById('input');
    const text    = input.value.trim();
    if (!text) return;

    input.value = '';
    input.style.height = 'auto';
    const sendBtn = document.getElementById('send');
    sendBtn.disabled = true;
    document.getElementById('dot').style.background       = 'var(--warning)';
    document.getElementById('status-txt').textContent     = 'Traitement…';

    addMessage(text, 'user');
    showTyping();

    try {
        const form = new URLSearchParams();
        form.append('message', text);
        form.append('csrf', csrfToken);

        const r = await fetch('chat.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: form
        });
        const d = await r.json();
        removeTyping();

        if (d.success) {
            if (d.csrf) csrfToken = d.csrf;
            addMessage(d.response, 'bot');
            loadIncidents();
            // Recharger les patterns après chaque échange
            loadPatterns();
        } else {
            addMessage(`<span style="color:var(--danger)">❌ Erreur : ${escapeHtml(d.error)}</span>`, 'bot');
        }
    } catch(e) {
        removeTyping();
        addMessage('<span style="color:var(--danger)">❌ Erreur de connexion au serveur</span>', 'bot');
    }

    sendBtn.disabled = false;
    document.getElementById('dot').style.background   = 'var(--ok)';
    document.getElementById('status-txt').textContent = 'En ligne';
}

function qa(text) {
    document.getElementById('input').value = text;
    sendMessage();
}

document.getElementById('input').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
});

document.getElementById('input').addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 120) + 'px';
});

// ══════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════
async function init() {
    await loadCsrf();
    fetchHistory();

    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }

    loadLastAudit();
    loadIncidents();
    loadPatterns();

    setInterval(loadIncidents,  60000);
    setInterval(loadLastAudit, 300000);
    setInterval(loadPatterns,  120000);

    const welcomeMsg = `Bonjour. Je suis <strong style="color:var(--accent)">CASSANDRA</strong>, votre agent d'infrastructure v5.0.<br><br>
    🧠 <strong>Mémoire long-terme</strong> — je me souviens de vos sessions précédentes.<br>
    📊 <strong>Apprentissage adaptatif</strong> — patterns d'incidents détectés automatiquement.<br>
    🛡️ <strong>DOMPurify + CSP</strong> actifs — sécurité renforcée.<br>
    🔄 <strong>Retry API</strong> × 3 avec backoff exponentiel.<br>
    🔍 <strong>shlex.split</strong> — parsing des commandes corrigé.<br>
    📋 <strong>Rotation des logs</strong> — plus de /tmp plein.<br><br>
    💡 Nouveautés v5 :<br>
    • Panneau <em>Patterns détectés</em> (apprentissage)<br>
    • Sauvegarde auto de session à la fermeture<br>
    • Bouton mémoire manuelle<br>
    • Commandes enrichies : iostat, vmstat, ping<br>
    • Historique étendu à 30 tours<br><br>
    🤖 Que souhaitez-vous contrôler ?`;

    addMessage(welcomeMsg, 'bot');
}

init();
</script>
</body>
</html>
