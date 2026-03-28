package webui

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phantom C2</title>
<style>
:root {
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
  width: 32px; height: 32px; background: linear-gradient(135deg, var(--accent), #4f46e5);
  border-radius: 8px; display: flex; align-items: center; justify-content: center;
  font-size: 16px; color: white;
}
.brand small { font-size: 10px; color: var(--text-muted); font-weight: 400; margin-left: 4px; }
.topbar-center { display: flex; gap: 2px; }
.tab {
  padding: 8px 16px; border-radius: 6px; cursor: pointer;
  color: var(--text-secondary); font-size: 12px; font-weight: 500;
  transition: all 0.2s; border: 1px solid transparent;
}
.tab:hover { color: var(--text-primary); background: var(--bg-hover); }
.tab.active {
  color: var(--accent-light); background: var(--accent-glow);
  border-color: rgba(124,58,237,0.3);
}
.topbar-right { display: flex; align-items: center; gap: 10px; }
.pulse { width: 8px; height: 8px; background: var(--green); border-radius: 50%; box-shadow: 0 0 8px var(--green); animation: pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
.top-label { font-size: 11px; color: var(--text-muted); }

/* ══════ LAYOUT ══════ */
.app { display: flex; height: calc(100vh - 52px); }
.sidebar {
  width: 56px; background: var(--bg-secondary); border-right: 1px solid var(--border);
  display: flex; flex-direction: column; align-items: center; padding: 12px 0; gap: 4px;
}
.sidebar-btn {
  width: 40px; height: 40px; border-radius: 10px; border: none; cursor: pointer;
  background: transparent; color: var(--text-muted); font-size: 18px;
  display: flex; align-items: center; justify-content: center; transition: all 0.2s;
  position: relative;
}
.sidebar-btn:hover { background: var(--bg-hover); color: var(--text-primary); }
.sidebar-btn.active { background: var(--accent-glow); color: var(--accent-light); }
.sidebar-btn .badge-count {
  position: absolute; top: 2px; right: 2px; width: 16px; height: 16px;
  background: var(--red); color: white; border-radius: 50%; font-size: 9px;
  display: flex; align-items: center; justify-content: center; font-weight: 700;
}
.sidebar-divider { width: 28px; height: 1px; background: var(--border); margin: 4px 0; }
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
      <div class="brand-icon">👻</div>
      Phantom <small>C2 v1.0.0</small>
    </div>
  </div>
  <div class="topbar-center">
    <div class="tab active" onclick="nav('dashboard')">Dashboard</div>
    <div class="tab" onclick="nav('agents')">Agents</div>
    <div class="tab" onclick="nav('listeners')">Listeners</div>
    <div class="tab" onclick="nav('tasks')">Tasks</div>
    <div class="tab" onclick="nav('terminal')">Terminal</div>
    <div class="tab" onclick="nav('events')">Events</div>
  </div>
  <div class="topbar-right">
    <div class="pulse"></div>
    <span class="top-label">Server Online</span>
  </div>
</div>

<div class="app">
  <!-- SIDEBAR ICONS -->
  <div class="sidebar">
    <button class="sidebar-btn active" onclick="nav('dashboard')" title="Dashboard">📊</button>
    <button class="sidebar-btn" onclick="nav('agents')" title="Agents">
      🖥️<span class="badge-count" id="sb-agents" style="display:none">0</span>
    </button>
    <button class="sidebar-btn" onclick="nav('listeners')" title="Listeners">📡</button>
    <button class="sidebar-btn" onclick="nav('tasks')" title="Tasks">📋</button>
    <div class="sidebar-divider"></div>
    <button class="sidebar-btn" onclick="nav('terminal')" title="Terminal">💻</button>
    <div class="sidebar-divider"></div>
    <button class="sidebar-btn" onclick="nav('events')" title="Events">📜</button>
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
        <div class="card-header"><h3><span>🖥️</span> All Agents</h3></div>
        <div class="card-body"><table>
          <thead><tr><th>Name</th><th>OS</th><th>Hostname</th><th>User</th><th>IP</th><th>Sleep</th><th>Last Seen</th><th>Status</th><th></th></tr></thead>
          <tbody id="all-agents"></tbody>
        </table></div>
      </div>
    </div>

    <!-- ══════ LISTENERS ══════ -->
    <div id="p-listeners" class="page">
      <div class="card">
        <div class="card-header"><h3><span>📡</span> Listeners</h3></div>
        <div class="card-body"><table>
          <thead><tr><th>Name</th><th>Type</th><th>Bind Address</th><th>Status</th></tr></thead>
          <tbody id="all-listeners"></tbody>
        </table></div>
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
    </div>

    <!-- ══════ EVENTS ══════ -->
    <div id="p-events" class="page">
      <div class="card">
        <div class="card-header"><h3><span>📜</span> Event Log</h3></div>
        <div class="card-body">
          <div class="event-log" id="event-log"><div class="event-item" style="color:var(--text-muted)">No events yet...</div></div>
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
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.sidebar-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
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

  // Agent badge count
  const sbBadge = document.getElementById('sb-agents');
  if (activeAgents > 0) { sbBadge.style.display='flex'; sbBadge.textContent=activeAgents; }
  else { sbBadge.style.display='none'; }

  // Dashboard agents (card view)
  const wrap = document.getElementById('dash-agents-wrap');
  if (agents.length > 0) {
    wrap.innerHTML = '<div class="agent-grid">' + agents.map(a =>
      '<div class="agent-card" onclick="selectAgent(\''+a.name+'\')">' +
      '<div class="agent-top"><div><div class="agent-name">'+a.name+'</div>' +
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
  document.getElementById('all-agents').innerHTML = agents.map(a =>
    '<tr><td><strong style="color:var(--accent-light)">'+a.name+'</strong></td><td>'+osIcon(a.os)+' '+a.os+'</td><td>'+a.hostname+'</td><td>'+a.username+'</td><td style="font-family:monospace">'+a.ip+'</td><td>'+a.sleep+'</td><td>'+a.last_seen+'</td><td>'+badge(a.status)+'</td><td><button class="qbtn" onclick="selectAgent(\''+a.name+'\')">Interact</button></td></tr>'
  ).join('') || '<tr><td colspan="9" class="empty">No agents</td></tr>';

  // Listeners
  document.getElementById('all-listeners').innerHTML = listeners.map(l =>
    '<tr><td style="font-weight:600">'+l.name+'</td><td>'+l.type+'</td><td style="font-family:monospace">'+l.bind+'</td><td>'+badge(l.status)+'</td></tr>'
  ).join('');

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
  div.textContent = text;
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

// ──── Init ────
refreshAll();
setInterval(refreshAll, 4000);
</script>
</body>
</html>`
