// Package dashboard provides a local, embedded, zero-dependency web UI
// for agentburp, allowing security researchers to inspect live HTTP history,
// WebSocket frames, site maps, scanner findings, and OAST collaborator callbacks.
package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jojin1709/agentburp/internal/db"
	"github.com/jojin1709/agentburp/internal/export"
	"github.com/jojin1709/agentburp/internal/model"
	"github.com/jojin1709/agentburp/internal/oast"
	"github.com/jojin1709/agentburp/internal/report"
	"github.com/jojin1709/agentburp/internal/scope"
	"github.com/jojin1709/agentburp/internal/sitemap"
)

type Server struct {
	addr       string
	db         *db.DB
	scopeCfg   *scope.Config
	workspace  string
	oastServer *oast.Server
	httpServer *http.Server
}

func NewServer(addr string, database *db.DB, scopeCfg *scope.Config, workspace string, oastSrv *oast.Server) *Server {
	if addr == "" {
		addr = "127.0.0.1:8889"
	}
	if workspace == "" {
		workspace = "default"
	}
	return &Server{
		addr:       addr,
		db:         database,
		scopeCfg:   scopeCfg,
		workspace:  workspace,
		oastServer: oastSrv,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// REST APIs
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/api/history/", s.handleHistoryDetail)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/sitemap", s.handleSitemap)
	mux.HandleFunc("/api/ws", s.handleWS)
	mux.HandleFunc("/api/scope", s.handleScope)
	mux.HandleFunc("/api/oast/token", s.handleOASTToken)
	mux.HandleFunc("/api/oast/poll", s.handleOASTPoll)

	// Embedded Web Dashboard
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})

	return mux
}

func (s *Server) Start() error {
	s.httpServer = &http.Server{
		Addr:    s.addr,
		Handler: s.Handler(),
	}
	return s.httpServer.ListenAndServe()
}

func (s *Server) Close() error {
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	method := r.URL.Query().Get("method")
	bodySub := r.URL.Query().Get("body")
	status := 0
	if st := r.URL.Query().Get("status"); st != "" {
		status, _ = strconv.Atoi(st)
	}
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
		}
	}

	opts := db.SearchOpts{
		Workspace: s.workspace,
		Host:      host,
		Method:    method,
		Status:    status,
		BodyRegex: bodySub,
		Limit:     limit,
	}
	entries, err := s.db.Search(opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

func (s *Server) handleHistoryDetail(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/history/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	entry, err := s.db.GetEntry(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	curlCmd := export.ToCurl(entry)
	sampleFinding := &model.Finding{
		Module:     "agentburp",
		Title:      fmt.Sprintf("%s %s", entry.Method, entry.URL),
		Detail:     "Reproducible vulnerability test case",
		Confidence: "medium",
	}
	nucleiTmpl := report.Generate(report.Nuclei, sampleFinding, entry)

	resp := map[string]any{
		"entry":  entry,
		"curl":   curlCmd,
		"nuclei": nucleiTmpl,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	findings, err := s.db.ListFindings(s.workspace, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(findings)
}

func (s *Server) handleSitemap(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	opts := db.SearchOpts{
		Workspace: s.workspace,
		Host:      host,
		Limit:     500,
	}
	entries, err := s.db.Search(opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tree := sitemap.Build(entries)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tree)
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	var entryID int64
	if eid := r.URL.Query().Get("entry_id"); eid != "" {
		entryID, _ = strconv.ParseInt(eid, 10, 64)
	}
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
		}
	}
	frames, err := s.db.SearchWSFrames(s.workspace, entryID, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(frames)
}

func (s *Server) handleScope(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.scopeCfg == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"workspace": s.workspace})
		return
	}
	_ = json.NewEncoder(w).Encode(s.scopeCfg)
}

func (s *Server) handleOASTToken(w http.ResponseWriter, r *http.Request) {
	tok := oast.GenerateToken()
	url := ""
	if s.oastServer != nil {
		url = s.oastServer.URLForToken(tok)
	} else {
		url = fmt.Sprintf("http://127.0.0.1:9998/c/%s", tok)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": tok,
		"url":   url,
	})
}

func (s *Server) handleOASTPoll(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if s.oastServer != nil {
		// Server in-process
		req, _ := http.NewRequest("GET", "/api/poll?token="+tok, nil)
		s.oastServer.Handler().ServeHTTP(w, req)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode([]any{})
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>agentburp Dashboard — Security Control Center</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #0a0c10;
      --bg-surface: #11141c;
      --bg-surface-elevated: #161a24;
      --border: #232936;
      --text-main: #f0f3f8;
      --text-muted: #8b949e;
      --accent: #6366f1;
      --accent-glow: rgba(99, 102, 241, 0.25);
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --info: #06b6d4;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
      background-color: var(--bg-dark);
      color: var(--text-main);
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: hidden;
    }
    header {
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border);
      padding: 12px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 1.15rem;
      font-weight: 800;
      letter-spacing: -0.5px;
    }
    .brand span { color: var(--accent); }
    .pulse-dot {
      width: 10px; height: 10px;
      background: var(--success);
      border-radius: 50%;
      box-shadow: 0 0 10px var(--success);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16,185,129,0.7); }
      70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16,185,129,0); }
      100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16,185,129,0); }
    }
    nav {
      display: flex;
      gap: 6px;
      background: var(--bg-dark);
      padding: 4px;
      border-radius: 8px;
      border: 1px solid var(--border);
    }
    .nav-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }
    .nav-btn:hover { color: var(--text-main); }
    .nav-btn.active {
      background: var(--accent);
      color: #fff;
      box-shadow: 0 2px 8px var(--accent-glow);
    }
    main {
      flex: 1;
      display: flex;
      overflow: hidden;
    }
    .view-container {
      flex: 1;
      display: none;
      flex-direction: column;
      height: 100%;
      overflow: hidden;
    }
    .view-container.active { display: flex; }
    
    /* HTTP History Split View */
    .history-layout {
      display: flex;
      flex-direction: column;
      height: 100%;
    }
    .table-container {
      flex: 1;
      overflow-y: auto;
      border-bottom: 1px solid var(--border);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
      text-align: left;
    }
    th {
      background: var(--bg-surface);
      color: var(--text-muted);
      font-weight: 600;
      padding: 10px 14px;
      position: sticky;
      top: 0;
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 8px 14px;
      border-bottom: 1px solid var(--border);
      font-family: 'JetBrains Mono', monospace;
      white-space: nowrap;
    }
    tr:hover { background: var(--bg-surface-elevated); cursor: pointer; }
    tr.selected { background: var(--accent-glow); }
    
    .badge {
      display: inline-block;
      padding: 2px 7px;
      border-radius: 4px;
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
    }
    .b-get { background: #0284c7; color: #fff; }
    .b-post { background: #16a34a; color: #fff; }
    .b-put { background: #d97706; color: #fff; }
    .b-delete { background: #dc2626; color: #fff; }
    .b-status-2 { color: var(--success); }
    .b-status-3 { color: var(--info); }
    .b-status-4 { color: var(--warning); }
    .b-status-5 { color: var(--danger); }
    
    /* Inspector */
    .inspector {
      height: 340px;
      background: var(--bg-surface);
      display: flex;
      flex-direction: column;
    }
    .insp-header {
      padding: 8px 16px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 0.85rem;
    }
    .insp-tabs { display: flex; gap: 8px; }
    .insp-tab {
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      font-weight: 600;
      font-size: 0.8rem;
      padding: 4px 8px;
      border-radius: 4px;
    }
    .insp-tab.active { background: var(--bg-surface-elevated); color: var(--text-main); }
    .insp-body {
      flex: 1;
      overflow: auto;
      padding: 12px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      white-space: pre-wrap;
      word-break: break-all;
      color: #cbd5e1;
    }
    
    /* Cards & Tree layout */
    .cards-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
      gap: 16px;
      padding: 20px;
      overflow-y: auto;
    }
    .card {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .card-title { font-weight: 700; font-size: 0.95rem; display: flex; justify-content: space-between; }
    .card-detail { color: var(--text-muted); font-size: 0.82rem; line-height: 1.4; }
    
    /* Action buttons */
    .btn {
      background: var(--accent);
      color: #fff;
      border: none;
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
    }
    .btn-secondary { background: var(--bg-surface-elevated); color: var(--text-main); border: 1px solid var(--border); }
    .btn:hover { opacity: 0.9; }
  </style>
</head>
<body>

<header>
  <div class="brand">
    <div class="pulse-dot"></div>
    agentburp <span>Dashboard</span>
  </div>
  <nav>
    <button class="nav-btn active" onclick="switchTab('history')">HTTP History</button>
    <button class="nav-btn" onclick="switchTab('sitemap')">Site Map</button>
    <button class="nav-btn" onclick="switchTab('findings')">Scanner Findings</button>
    <button class="nav-btn" onclick="switchTab('ws')">WebSocket</button>
    <button class="nav-btn" onclick="switchTab('oast')">OAST Collaborator</button>
    <button class="nav-btn" onclick="switchTab('scope')">Scope Guard</button>
  </nav>
</header>

<main>
  <!-- HTTP History View -->
  <div id="v-history" class="view-container history-layout active">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Time</th>
            <th>Method</th>
            <th>Status</th>
            <th>Host</th>
            <th>Path</th>
            <th>Size</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody id="hist-tbody"></tbody>
      </table>
    </div>
    <div class="inspector">
      <div class="insp-header">
        <div class="insp-tabs">
          <button class="insp-tab active" onclick="switchInsp('req')">Request</button>
          <button class="insp-tab" onclick="switchInsp('resp')">Response</button>
          <button class="insp-tab" onclick="switchInsp('curl')">cURL</button>
          <button class="insp-tab" onclick="switchInsp('nuclei')">Nuclei Template</button>
        </div>
        <div id="insp-actions" style="display:flex; gap:8px;"></div>
      </div>
      <div id="insp-content" class="insp-body">Select a request above to inspect details...</div>
    </div>
  </div>

  <!-- Sitemap View -->
  <div id="v-sitemap" class="view-container">
    <div id="sitemap-content" class="cards-grid"></div>
  </div>

  <!-- Findings View -->
  <div id="v-findings" class="view-container">
    <div id="findings-content" class="cards-grid"></div>
  </div>

  <!-- WebSocket View -->
  <div id="v-ws" class="view-container">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Time</th>
            <th>Direction</th>
            <th>Opcode</th>
            <th>Length</th>
            <th>Payload Preview</th>
          </tr>
        </thead>
        <tbody id="ws-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- OAST View -->
  <div id="v-oast" class="view-container" style="padding: 24px; overflow-y:auto;">
    <div style="background:var(--bg-surface); padding:20px; border-radius:8px; border:1px solid var(--border); margin-bottom:20px;">
      <h3 style="margin-bottom:8px;">Out-of-Band Collaborator (OAST)</h3>
      <p style="color:var(--text-muted); font-size:0.85rem; margin-bottom:14px;">Generate an OAST correlation token to test blind SSRF, blind XSS, or blind command injection.</p>
      <button class="btn" onclick="genOASTToken()">Generate Callback Token</button>
      <div id="oast-token-box" style="margin-top:14px; font-family:'JetBrains Mono'; font-size:0.85rem; color:var(--info);"></div>
    </div>
    <div style="background:var(--bg-surface); padding:20px; border-radius:8px; border:1px solid var(--border);">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
        <h3>Incoming Callback Interactions</h3>
        <button class="btn btn-secondary" onclick="pollOAST()">Refresh Interactions</button>
      </div>
      <div id="oast-events" style="font-family:'JetBrains Mono'; font-size:0.8rem; color:var(--text-muted);">No callbacks recorded yet. Trigger a request with your token.</div>
    </div>
  </div>

  <!-- Scope View -->
  <div id="v-scope" class="view-container" style="padding:24px; overflow-y:auto;">
    <div style="background:var(--bg-surface); padding:20px; border-radius:8px; border:1px solid var(--border); max-width:800px;">
      <h3 style="margin-bottom:12px;">Active Declarative Scope</h3>
      <pre id="scope-json" style="font-family:'JetBrains Mono'; font-size:0.85rem; color:#cbd5e1;"></pre>
    </div>
  </div>
</main>

<script>
  let activeEntry = null;
  let activeEntryDetail = null;
  let activeInspTab = 'req';
  let activeOASTToken = '';

  function switchTab(name) {
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.view-container').forEach(v => v.classList.remove('active'));
    event.target.classList.add('active');
    document.getElementById('v-' + name).classList.add('active');

    if (name === 'history') loadHistory();
    if (name === 'sitemap') loadSitemap();
    if (name === 'findings') loadFindings();
    if (name === 'ws') loadWS();
    if (name === 'scope') loadScope();
  }

  async function loadHistory() {
    try {
      const res = await fetch('/api/history?limit=100');
      const data = await res.json();
      const tbody = document.getElementById('hist-tbody');
      tbody.innerHTML = '';
      (data || []).forEach(e => {
        const tr = document.createElement('tr');
        tr.onclick = () => selectRow(e.id, tr);
        const statusClass = 'b-status-' + Math.floor(e.status / 100);
        const methodClass = 'b-' + e.method.toLowerCase();
        const urlObj = new URL(e.url);
        tr.innerHTML = ` + "`" + `
          <td>${e.id}</td>
          <td>${new Date(e.timestamp).toLocaleTimeString()}</td>
          <td><span class="badge ${methodClass}">${e.method}</span></td>
          <td class="${statusClass}"><strong>${e.status}</strong></td>
          <td>${e.host}</td>
          <td>${urlObj.pathname}${urlObj.search}</td>
          <td>${e.length} B</td>
          <td>${e.duration_ms} ms</td>
        ` + "`" + `;
        tbody.appendChild(tr);
      });
    } catch(err) { console.error(err); }
  }

  async function selectRow(id, tr) {
    document.querySelectorAll('#hist-tbody tr').forEach(r => r.classList.remove('selected'));
    if (tr) tr.classList.add('selected');

    try {
      const res = await fetch('/api/history/' + id);
      activeEntryDetail = await res.json();
      renderInspector();
    } catch(err) { console.error(err); }
  }

  function switchInsp(tab) {
    activeInspTab = tab;
    document.querySelectorAll('.insp-tab').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    renderInspector();
  }

  function renderInspector() {
    if (!activeEntryDetail) return;
    const content = document.getElementById('insp-content');
    const d = activeEntryDetail;

    if (activeInspTab === 'req') {
      let h = d.entry.method + ' ' + d.entry.url + '\n';
      for (const [k, v] of Object.entries(d.entry.req_headers || {})) {
        h += k + ': ' + v + '\n';
      }
      h += '\n' + (d.entry.req_body || '[Empty Body]');
      content.textContent = h;
    } else if (activeInspTab === 'resp') {
      let h = 'HTTP/1.1 ' + d.entry.status + '\n';
      for (const [k, v] of Object.entries(d.entry.resp_headers || {})) {
        h += k + ': ' + v + '\n';
      }
      h += '\n' + (d.entry.resp_body || '[Empty Body]');
      content.textContent = h;
    } else if (activeInspTab === 'curl') {
      content.textContent = d.curl;
    } else if (activeInspTab === 'nuclei') {
      content.textContent = d.nuclei;
    }
  }

  async function loadSitemap() {
    try {
      const res = await fetch('/api/sitemap');
      const data = await res.json();
      const div = document.getElementById('sitemap-content');
      div.innerHTML = '';
      (data.hosts || []).forEach(h => {
        const card = document.createElement('div');
        card.className = 'card';
        let endpoints = (h.endpoints || []).map(ep => '<li style="margin-left:16px;">' + ep.method + ' ' + ep.path + '</li>').join('');
        card.innerHTML = ` + "`" + `
          <div class="card-title">${h.host} <span class="badge b-get">${(h.endpoints || []).length} endpoints</span></div>
          <div class="card-detail"><ul style="list-style-type:none;">${endpoints}</ul></div>
        ` + "`" + `;
        div.appendChild(card);
      });
    } catch(err) { console.error(err); }
  }

  async function loadFindings() {
    try {
      const res = await fetch('/api/findings');
      const data = await res.json();
      const div = document.getElementById('findings-content');
      div.innerHTML = '';
      (data || []).forEach(f => {
        const card = document.createElement('div');
        card.className = 'card';
        const confColor = f.confidence === 'high' ? 'var(--danger)' : (f.confidence === 'medium' ? 'var(--warning)' : 'var(--info)');
        card.innerHTML = ` + "`" + `
          <div class="card-title">
            <span>${f.title}</span>
            <span style="color:${confColor}; font-size:0.75rem; text-transform:uppercase;">[${f.confidence}]</span>
          </div>
          <div style="font-size:0.75rem; color:var(--accent);">Module: ${f.module} (Entry #${f.entry_id})</div>
          <div class="card-detail">${f.detail}</div>
        ` + "`" + `;
        div.appendChild(card);
      });
    } catch(err) { console.error(err); }
  }

  async function loadWS() {
    try {
      const res = await fetch('/api/ws?limit=100');
      const data = await res.json();
      const tbody = document.getElementById('ws-tbody');
      tbody.innerHTML = '';
      (data || []).forEach(f => {
        const tr = document.createElement('tr');
        const dirBadge = f.direction.includes('client->') ? '<span class="badge b-post">CLI->SRV</span>' : '<span class="badge b-get">SRV->CLI</span>';
        tr.innerHTML = ` + "`" + `
          <td>${f.id}</td>
          <td>${new Date(f.timestamp).toLocaleTimeString()}</td>
          <td>${dirBadge}</td>
          <td>${f.opcode_name} (${f.opcode})</td>
          <td>${f.length} B</td>
          <td>${f.payload.substring(0, 80)}</td>
        ` + "`" + `;
        tbody.appendChild(tr);
      });
    } catch(err) { console.error(err); }
  }

  async function loadScope() {
    try {
      const res = await fetch('/api/scope');
      const data = await res.json();
      document.getElementById('scope-json').textContent = JSON.stringify(data, null, 2);
    } catch(err) { console.error(err); }
  }

  async function genOASTToken() {
    try {
      const res = await fetch('/api/oast/token');
      const data = await res.json();
      activeOASTToken = data.token;
      document.getElementById('oast-token-box').innerHTML = ` + "`" + `
        <strong>Token:</strong> ${data.token}<br>
        <strong>Callback URL:</strong> <span style="user-select:all; background:var(--bg-dark); padding:2px 6px; border-radius:4px;">${data.url}</span>
      ` + "`" + `;
    } catch(err) { console.error(err); }
  }

  async function pollOAST() {
    try {
      const res = await fetch('/api/oast/poll?token=' + encodeURIComponent(activeOASTToken));
      const events = await res.json();
      const box = document.getElementById('oast-events');
      if (!events || events.length === 0) {
        box.textContent = 'No incoming interactions yet for token: ' + (activeOASTToken || 'all');
        return;
      }
      box.innerHTML = events.map(e => ` + "`" + `
        <div style="background:var(--bg-dark); padding:12px; border-radius:6px; margin-bottom:8px; border-left:3px solid var(--success);">
          <div style="color:var(--text-main); font-weight:700;">${e.method} from ${e.client_ip} at ${new Date(e.timestamp).toLocaleTimeString()}</div>
          <div style="color:var(--info);">URL: ${e.url}</div>
          <div style="color:var(--text-muted); font-size:0.75rem;">Body: ${e.body || '[None]'}</div>
        </div>
      ` + "`" + `).join('');
    } catch(err) { console.error(err); }
  }

  // Initial load
  loadHistory();
  setInterval(loadHistory, 3000);
</script>
</body>
</html>
`
