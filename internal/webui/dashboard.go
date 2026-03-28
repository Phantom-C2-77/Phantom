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
    <div class="tab" onclick="nav('payloads')">Payloads</div>
    <div class="tab" onclick="nav('files')">Files</div>
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
    <button class="sidebar-btn" onclick="nav('payloads')" title="Payloads">🔧</button>
    <button class="sidebar-btn" onclick="nav('files')" title="Files / Screenshots / Processes">📂</button>
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
          <canvas id="network-graph" height="200" style="width:100%;"></canvas>
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
                <label style="display:block;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Listener URL (Callback)</label>
                <input type="text" id="pl-url" value="https://127.0.0.1:443" placeholder="https://your-c2:443" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;">
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
            <div class="quick-actions" style="margin-bottom:10px;">
              <button class="qbtn" onclick="browseDir('/')">/ (root)</button>
              <button class="qbtn" onclick="browseDir('/home')">home</button>
              <button class="qbtn" onclick="browseDir('/etc')">etc</button>
              <button class="qbtn" onclick="browseDir('/tmp')">tmp</button>
              <button class="qbtn" onclick="browseDir('C:\\Users')">C:\Users</button>
              <button class="qbtn" onclick="browseDir('C:\\Windows')">C:\Windows</button>
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
  const w = canvas.width = canvas.parentElement.clientWidth;
  const h = canvas.height = 200;

  ctx.clearRect(0, 0, w, h);

  // Draw C2 server node in center-top
  const serverX = w / 2, serverY = 40;

  // Server node
  ctx.beginPath();
  ctx.arc(serverX, serverY, 20, 0, Math.PI * 2);
  ctx.fillStyle = 'rgba(124,58,237,0.2)';
  ctx.fill();
  ctx.strokeStyle = '#7c3aed';
  ctx.lineWidth = 2;
  ctx.stroke();
  ctx.fillStyle = '#a78bfa';
  ctx.font = 'bold 11px Inter';
  ctx.textAlign = 'center';
  ctx.fillText('C2', serverX, serverY + 4);

  // Server label
  ctx.fillStyle = '#5a6580';
  ctx.font = '10px Inter';
  ctx.fillText('Phantom Server', serverX, serverY + 35);

  if (agents.length === 0) {
    ctx.fillStyle = '#3a4060';
    ctx.font = '12px Inter';
    ctx.fillText('Deploy agents to see the network graph', w/2, h/2 + 20);
    return;
  }

  // Agent nodes in a row below
  const agentY = 140;
  const agentSpacing = Math.min(120, (w - 80) / agents.length);
  const startX = (w - (agents.length - 1) * agentSpacing) / 2;

  agents.forEach((a, i) => {
    const ax = startX + i * agentSpacing;
    const statusColor = a.status === 'active' ? '#10b981' : a.status === 'dormant' ? '#f59e0b' : '#ef4444';
    const osIcon = a.os === 'windows' ? '🪟' : a.os === 'linux' ? '🐧' : a.os === 'android' ? '📱' : '💻';

    // Connection line (server → agent)
    ctx.beginPath();
    ctx.moveTo(serverX, serverY + 20);
    // Curved line
    const cpY = (serverY + agentY) / 2;
    ctx.quadraticCurveTo(ax, cpY - 10, ax, agentY - 18);
    ctx.strokeStyle = statusColor;
    ctx.lineWidth = 1.5;
    ctx.globalAlpha = 0.5;
    ctx.stroke();
    ctx.globalAlpha = 1;

    // Animated dash for active agents
    if (a.status === 'active') {
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(serverX, serverY + 20);
      ctx.quadraticCurveTo(ax, cpY - 10, ax, agentY - 18);
      ctx.strokeStyle = statusColor;
      ctx.lineWidth = 1;
      ctx.globalAlpha = 0.8;
      ctx.stroke();
      ctx.globalAlpha = 1;
      ctx.setLineDash([]);
    }

    // Agent node — circle with glow
    ctx.beginPath();
    ctx.arc(ax, agentY, 16, 0, Math.PI * 2);
    ctx.fillStyle = a.status === 'active' ? 'rgba(16,185,129,0.15)' : a.status === 'dormant' ? 'rgba(245,158,11,0.15)' : 'rgba(239,68,68,0.15)';
    ctx.fill();
    ctx.strokeStyle = statusColor;
    ctx.lineWidth = 2;
    ctx.stroke();

    // Agent icon
    ctx.font = '14px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(osIcon, ax, agentY + 5);

    // Agent name
    ctx.fillStyle = '#8892b0';
    ctx.font = '9px Inter';
    ctx.fillText(a.name.length > 12 ? a.name.substring(0, 10) + '..' : a.name, ax, agentY + 32);

    // IP
    ctx.fillStyle = '#5a6580';
    ctx.font = '8px JetBrains Mono';
    ctx.fillText(a.ip, ax, agentY + 43);
  });
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
};

// ──── Files / Screenshot / Process / Notes / Search ────

function getSelectedFBAgent() {
  const sel = document.getElementById('fb-agent');
  if (!sel.value) { alert('Select an agent first'); return null; }
  return sel.value;
}

async function browseFiles() {
  const agent = getSelectedFBAgent(); if (!agent) return;
  const path = document.getElementById('fb-path').value || '/';
  const output = document.getElementById('fb-output');
  output.textContent = 'Requesting directory listing...';

  try {
    const resp = await fetch('/api/filebrowser?agent='+encodeURIComponent(agent)+'&path='+encodeURIComponent(path));
    const data = await resp.json();
    if (data.error) { output.textContent = 'Error: ' + data.error; return; }
    output.innerHTML = '<span style="color:var(--green)">Task queued (ID: '+data.task_id.substring(0,8)+')</span>\n\nWaiting for agent check-in...\nResults will appear in the agent detail / terminal.';

    // Poll for result
    for (let i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 3000));
      const detail = await fetchJ('/api/agent/' + agent);
      if (detail.tasks && detail.tasks.length > 0) {
        const task = detail.tasks.find(t => data.task_id.startsWith(t.id) || t.id.startsWith(data.task_id.substring(0,8)));
        if (task && task.output && task.status !== 'pending' && task.status !== 'sent') {
          output.innerHTML = '<span style="color:var(--green)">$ ls -la ' + path + '</span>\n\n' + task.output;
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
  const sel = document.getElementById('fb-agent');
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = '<option value="">Select an agent...</option>' + agents.map(a =>
    '<option value="'+a.name+'" '+(a.name===cur?'selected':'')+'>'+a.name+' ('+a.os+' / '+a.hostname+')</option>'
  ).join('');

  // Load notes if agent selected
  if (sel.value) loadNotes(sel.value);
}

document.getElementById('fb-agent').addEventListener('change', function() {
  if (this.value) loadNotes(this.value);
});

// ──── Payload Generator ────
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

      // Auto-download the file
      if (data.filepath) {
        const a = document.createElement('a');
        a.href = '/api/payload/download?file=' + encodeURIComponent(data.filepath);
        a.download = data.filename || 'payload';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      }
    } else {
      output.innerHTML = '<div style="color:var(--red);font-weight:600;">Generation Failed</div><div style="margin-top:8px;color:var(--text-muted);font-size:12px;">'+data.message+'</div>';
    }
  } catch(e) {
    output.innerHTML = '<div style="color:var(--red);">Error: '+e.message+'</div>';
  }

  btn.textContent = 'Generate Payload';
  btn.disabled = false;
}

// ──── Init ────
refreshAll();
setInterval(refreshAll, 4000);
</script>
</body>
</html>`
