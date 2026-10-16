/**
 * agentburp — Production Documentation Interactive Engine
 * Pure Vanilla JavaScript • Zero Dependencies • Offline-First
 */

document.addEventListener('DOMContentLoaded', () => {
  initHeroTerminal();
  initLiveTerminalDemo();
  initCliSearch();
  initTabs();
  initCopyButtons();
  initScopeTester();
  initMcpPlayground();
  initFaqAccordion();
  initScrollspy();
  initMobileNav();
  initBackToTop();
});

/* ==========================================================================
   1. Hero Terminal Animation (Typing simulation)
   ========================================================================== */
function initHeroTerminal() {
  const terminalBody = document.getElementById('heroTerminalBody');
  if (!terminalBody) return;

  const sequence = [
    { type: 'cmd', text: 'agentburp workspace use fintech-audit', delay: 400 },
    { type: 'log', text: '[workspace] active workspace set to "fintech-audit"', delay: 300 },
    { type: 'cmd', text: 'agentburp proxy start --addr 127.0.0.1:8888', delay: 600 },
    { type: 'highlight', text: '[proxy] listening on 127.0.0.1:8888 (workspace=fintech-audit)', delay: 400 },
    { type: 'log', text: '[scope] loaded scope.yml • safe_mode: on • rate_limit: 10 req/s', delay: 350 },
    { type: 'cmd', text: 'curl -x http://127.0.0.1:8888 https://api.target.com/v1/user?id=42', delay: 700 },
    { type: 'success', text: '[proxy] intercepted GET https://api.target.com/v1/user?id=42 -> 200 OK (84ms)', delay: 400 },
    { type: 'log', text: '[db] stored transaction as history entry #12 in ~/.agentburp/history.db', delay: 300 },
    { type: 'cmd', text: 'agentburp scan 12', delay: 600 },
    { type: 'warn', text: '[scanner] heuristic alert: candidate IDOR parameter detected (param="id")', delay: 400 },
    { type: 'success', text: '[scanner] findings logged • ready for active replay or report generation', delay: 400 }
  ];

  let currentStep = 0;
  terminalBody.innerHTML = '';

  function executeStep() {
    if (currentStep >= sequence.length) {
      const cursorLine = document.createElement('div');
      cursorLine.className = 'term-line';
      cursorLine.innerHTML = '<span class="term-prompt">$</span> <span class="term-cursor"></span>';
      terminalBody.appendChild(cursorLine);
      return;
    }

    const item = sequence[currentStep];
    const line = document.createElement('div');
    line.className = 'term-line';

    if (item.type === 'cmd') {
      line.innerHTML = `<span class="term-prompt">$</span> <span class="term-cmd"></span><span class="term-cursor"></span>`;
      terminalBody.appendChild(line);
      typeText(line.querySelector('.term-cmd'), item.text, () => {
        const cursor = line.querySelector('.term-cursor');
        if (cursor) cursor.remove();
        currentStep++;
        setTimeout(executeStep, item.delay);
      });
    } else {
      let colorClass = 'term-log';
      if (item.type === 'success') colorClass = 'term-success';
      if (item.type === 'warn') colorClass = 'term-warn';
      if (item.type === 'highlight') colorClass = 'term-highlight';

      line.innerHTML = `<span class="${colorClass}">${item.text}</span>`;
      terminalBody.appendChild(line);
      terminalBody.scrollTop = terminalBody.scrollHeight;
      currentStep++;
      setTimeout(executeStep, item.delay);
    }
  }

  function typeText(targetElement, fullText, callback) {
    let index = 0;
    const interval = setInterval(() => {
      targetElement.textContent += fullText[index];
      index++;
      terminalBody.scrollTop = terminalBody.scrollHeight;
      if (index >= fullText.length) {
        clearInterval(interval);
        callback();
      }
    }, 28);
  }

  setTimeout(executeStep, 500);
}

/* ==========================================================================
   2. "See It in Action" Live Interactive Terminal Tabs
   ========================================================================== */
const terminalDemoData = {
  proxy: {
    command: 'agentburp proxy start --addr 127.0.0.1:8888 --scope scope.yml',
    output: `[INFO]  2026/10/16 11:44:10 scope.yml loaded (allow_hosts: 2, deny_hosts: 1)
[INFO]  safe_mode is ENABLED: active fuzzing requires --confirm
[INFO]  global rate limit set to 10 req/s (token bucket)
[PROXY] agentburp interceptor listening on 127.0.0.1:8888 (workspace=default)
[AUTH]  Forwarding allowed for *.target.com
[TRX]   GET http://target.com/api/user/1 -> 200 OK (length: 68, id: 1)
[TRX]   POST http://target.com/auth/login -> 302 Found (length: 0, id: 2)
[GUARD] DENIED request to payments.target.com (matches deny rule)`
  },
  history: {
    command: 'agentburp hist list --host target.com --limit 3',
    output: `[
  {
    "id": 1,
    "timestamp": "2026-10-16T11:44:05Z",
    "method": "GET",
    "url": "http://target.com/api/user/1",
    "host": "target.com",
    "status": 200,
    "length": 68,
    "duration_ms": 12,
    "workspace": "default"
  },
  {
    "id": 2,
    "timestamp": "2026-10-16T11:44:18Z",
    "method": "POST",
    "url": "http://target.com/auth/login",
    "host": "target.com",
    "status": 302,
    "length": 0,
    "duration_ms": 45,
    "workspace": "default"
  }
]`
  },
  repeater: {
    command: 'agentburp repeat 1 --set "Authorization: Bearer ATTACKER_JWT_PAYLOAD"',
    output: `{
  "original_id": 1,
  "replay_id": 3,
  "method": "GET",
  "url": "http://target.com/api/user/1",
  "status": 200,
  "diff_status": "identical_status",
  "length": 68,
  "headers_sent": {
    "Authorization": "Bearer ATTACKER_JWT_PAYLOAD",
    "Host": "target.com",
    "User-Agent": "agentburp/1.0"
  },
  "audit_logged": true
}`
  },
  fuzzer: {
    command: 'agentburp fuzz 1 --param id --range-from 1 --range-to 5 --confirm',
    output: `[AUDIT] Active operation confirmed by flag --confirm
[FUZZ]  Baseline: entry #1 (status=200, length=68)
[ANOM]  [+] Payload id=2 -> Status: 200, Length: 74 [Length delta: +6]
[ANOM]  [+] Payload id=3 -> Status: 403 Forbidden [Status mismatch]
[ANOM]  [+] Payload id=4 -> Status: 200, Length: 104 [Potential Admin IDOR]
[AUDIT] 5 requests sent, 3 anomalies logged to SQLite audit_log`
  },
  scanner: {
    command: 'agentburp scan 1',
    output: `[
  {
    "id": 1,
    "entry_id": 1,
    "type": "IDOR_CANDIDATE",
    "severity": "HIGH",
    "confidence": "HIGH",
    "summary": "Numerical sequential object identifier in query parameter 'id'",
    "evidence": "URL parameter id=1 returned private user object without tenant isolation check.",
    "cwe": "CWE-639",
    "recommendation": "Implement server-side authorization check enforcing user session ownership."
  }
]`
  },
  mcp: {
    command: 'agentburp mcp-serve --scope scope.yml',
    output: `[MCP-STDIO] Server initialized for Model Context Protocol v1.0
[MCP-STDIO] Available tools: history.search, repeater.replay, fuzzer.run, scanner.run, report.generate
<-- {"jsonrpc":"2.0","id":1,"method":"history.search","params":{"host":"target.com"}}
--> {"jsonrpc":"2.0","id":1,"result":{"matches":2,"entries":[{"id":1,"status":200}]}}
[MCP-STDIO] Tool execution logged to audit trail.`
  }
};

function initLiveTerminalDemo() {
  const tabs = document.querySelectorAll('.terminal-tab');
  const commandElem = document.getElementById('demoTerminalCmd');
  const outputElem = document.getElementById('demoTerminalOutput');

  if (!tabs.length || !commandElem || !outputElem) return;

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const key = tab.getAttribute('data-tab');
      const data = terminalDemoData[key];
      if (data) {
        commandElem.textContent = data.command;
        outputElem.textContent = data.output;
      }
    });
  });
}

/* ==========================================================================
   3. Searchable CLI Reference with Live Filtering
   ========================================================================== */
function initCliSearch() {
  const searchInput = document.getElementById('cliSearchInput');
  const cliCards = document.querySelectorAll('.cli-card');
  const emptyState = document.getElementById('cliSearchEmpty');

  if (!searchInput || !cliCards.length) return;

  searchInput.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    let visibleCount = 0;

    cliCards.forEach(card => {
      const text = card.textContent.toLowerCase();
      if (!query || text.includes(query)) {
        card.style.display = 'block';
        visibleCount++;
      } else {
        card.style.display = 'none';
      }
    });

    if (emptyState) {
      emptyState.style.display = visibleCount === 0 ? 'block' : 'none';
    }
  });

  // Shortcut Ctrl+K to jump to search
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      searchInput.focus();
      searchInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  });
}

/* ==========================================================================
   4. Tab Switcher System (Installation & General tabs)
   ========================================================================== */
function initTabs() {
  const tabContainers = document.querySelectorAll('.tab-container');

  tabContainers.forEach(container => {
    const buttons = container.querySelectorAll('.tab-btn');
    const panes = container.querySelectorAll('.tab-pane');

    buttons.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-target');

        buttons.forEach(b => b.classList.remove('active'));
        panes.forEach(p => p.classList.remove('active'));

        btn.classList.add('active');
        const activePane = container.querySelector(`#${targetId}`);
        if (activePane) activePane.classList.add('active');
      });
    });
  });
}

/* ==========================================================================
   5. Copy to Clipboard System with Visual Feedback
   ========================================================================== */
function initCopyButtons() {
  const copyButtons = document.querySelectorAll('.copy-btn');

  copyButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      let codeText = '';
      const targetSelector = btn.getAttribute('data-clipboard-target');
      
      if (targetSelector) {
        const targetElement = document.querySelector(targetSelector);
        if (targetElement) codeText = targetElement.textContent.trim();
      } else {
        const parentCode = btn.closest('.code-box')?.querySelector('code');
        if (parentCode) codeText = parentCode.textContent.trim();
      }

      // Strip leading "$ " if copying a shell prompt
      codeText = codeText.replace(/^\$\s+/gm, '');

      if (!codeText) return;

      navigator.clipboard.writeText(codeText).then(() => {
        const originalHTML = btn.innerHTML;
        btn.classList.add('copied');
        btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!`;

        setTimeout(() => {
          btn.classList.remove('copied');
          btn.innerHTML = originalHTML;
        }, 2000);
      }).catch(err => {
        console.error('Copy failed:', err);
      });
    });
  });
}

/* ==========================================================================
   6. Interactive Scope Visualizer & Rule Tester (Frontend Simulation)
   ========================================================================== */
function initScopeTester() {
  const input = document.getElementById('scopeTestInput');
  const resultBadge = document.getElementById('scopeTestResult');
  const resultReason = document.getElementById('scopeTestReason');
  const testBtn = document.getElementById('scopeTestBtn');

  if (!input || !resultBadge || !resultReason) return;

  const allowHosts = ['target.com', '*.target.com'];
  const denyHosts = ['payments.target.com'];

  function evaluateHost(rawHost) {
    let host = rawHost.trim().toLowerCase();
    if (!host) {
      resultBadge.className = 'result-badge';
      resultBadge.textContent = 'AWAITING INPUT';
      resultReason.textContent = 'Enter a domain to test against active scope rules.';
      return;
    }

    // Strip http/https and port if typed
    host = host.replace(/^[a-zA-Z]+:\/\//, '').split(':')[0].split('/')[0];

    // Check deny list first
    for (const deny of denyHosts) {
      if (hostMatches(deny, host)) {
        resultBadge.className = 'result-badge badge-blocked';
        resultBadge.textContent = '✕ REQUEST BLOCKED';
        resultReason.textContent = `Denied: matches explicit blacklist rule "${deny}".`;
        return;
      }
    }

    // Check allow list
    for (const allow of allowHosts) {
      if (hostMatches(allow, host)) {
        resultBadge.className = 'result-badge badge-allowed';
        resultBadge.textContent = '✓ REQUEST ALLOWED';
        resultReason.textContent = `Permitted: matches whitelist rule "${allow}". Forwarded to target.`;
        return;
      }
    }

    // Default deny
    resultBadge.className = 'result-badge badge-blocked';
    resultBadge.textContent = '✕ REQUEST BLOCKED';
    resultReason.textContent = 'Blocked by Default-Deny policy: host is not present in allow_hosts.';
  }

  function hostMatches(pattern, host) {
    if (pattern === host) return true;
    if (pattern.startsWith('*.')) {
      const suffix = pattern.substring(1); // .target.com
      return host.endsWith(suffix) || host === pattern.substring(2);
    }
    return false;
  }

  input.addEventListener('input', (e) => evaluateHost(e.target.value));
  if (testBtn) testBtn.addEventListener('click', () => evaluateHost(input.value));
}

/* ==========================================================================
   7. Interactive MCP Playground Simulator
   ========================================================================== */
const mcpPlaygroundData = {
  'history.search': {
    req: {
      jsonrpc: '2.0',
      id: 101,
      method: 'history.search',
      params: { host: 'api.target.com', limit: 5 }
    },
    res: {
      jsonrpc: '2.0',
      id: 101,
      result: {
        total_found: 2,
        entries: [
          { id: 12, method: 'GET', url: 'https://api.target.com/user/104', status: 200, length: 142 },
          { id: 13, method: 'PUT', url: 'https://api.target.com/user/104', status: 403, length: 45 }
        ]
      }
    }
  },
  'repeater.replay': {
    req: {
      jsonrpc: '2.0',
      id: 102,
      method: 'repeater.replay',
      params: {
        entry_id: 12,
        set_headers: { 'X-Forwarded-For': '127.0.0.1' },
        body: '{"role":"admin"}'
      }
    },
    res: {
      jsonrpc: '2.0',
      id: 102,
      result: {
        status: 200,
        length: 156,
        duration_ms: 38,
        response_body: '{"status":"success","role":"admin"}'
      }
    }
  },
  'fuzzer.run': {
    req: {
      jsonrpc: '2.0',
      id: 103,
      method: 'fuzzer.run',
      params: { baseline_id: 12, param: 'id', range_from: 100, range_to: 103, confirm: true }
    },
    res: {
      jsonrpc: '2.0',
      id: 103,
      result: {
        completed: 4,
        anomalies_detected: [
          { payload: '101', status: 200, length_delta: 34, reason: 'unauthorized_record_access' }
        ]
      }
    }
  },
  'scanner.run': {
    req: {
      jsonrpc: '2.0',
      id: 104,
      method: 'scanner.run',
      params: { entry_id: 12 }
    },
    res: {
      jsonrpc: '2.0',
      id: 104,
      result: {
        findings_count: 1,
        findings: [
          { type: 'IDOR', confidence: 'HIGH', cwe: 'CWE-639', severity: 'HIGH' }
        ]
      }
    }
  }
};

function initMcpPlayground() {
  const select = document.getElementById('mcpMethodSelect');
  const reqBox = document.getElementById('mcpReqJson');
  const resBox = document.getElementById('mcpResJson');

  if (!select || !reqBox || !resBox) return;

  function updateMcpView() {
    const method = select.value;
    const payload = mcpPlaygroundData[method];
    if (payload) {
      reqBox.textContent = JSON.stringify(payload.req, null, 2);
      resBox.textContent = JSON.stringify(payload.res, null, 2);
    }
  }

  select.addEventListener('change', updateMcpView);
  updateMcpView();
}

/* ==========================================================================
   8. FAQ Accordion (Accessible & Smooth)
   ========================================================================== */
function initFaqAccordion() {
  const items = document.querySelectorAll('.faq-item');

  items.forEach(item => {
    const question = item.querySelector('.faq-question');
    if (!question) return;

    question.addEventListener('click', () => {
      const isOpen = item.classList.contains('open');

      // Optional: close other accordions
      items.forEach(other => {
        if (other !== item) other.classList.remove('open');
      });

      item.classList.toggle('open', !isOpen);
    });

    question.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        question.click();
      }
    });
  });
}

/* ==========================================================================
   9. Scrollspy & Sticky Header Nav Highlighter
   ========================================================================== */
function initScrollspy() {
  const sections = document.querySelectorAll('.doc-section, .hero');
  const sidebarLinks = document.querySelectorAll('.sidebar-link');
  const headerLinks = document.querySelectorAll('.nav-link');

  function onScroll() {
    let currentId = '';
    const scrollPos = window.scrollY + 120;

    sections.forEach(sec => {
      const top = sec.offsetTop;
      const height = sec.offsetHeight;
      if (scrollPos >= top && scrollPos < top + height) {
        currentId = sec.getAttribute('id');
      }
    });

    if (currentId) {
      sidebarLinks.forEach(link => {
        link.classList.toggle('active', link.getAttribute('href') === `#${currentId}`);
      });
      headerLinks.forEach(link => {
        link.classList.toggle('active', link.getAttribute('href') === `#${currentId}`);
      });
    }
  }

  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
}

/* ==========================================================================
   10. Mobile Navigation Toggle
   ========================================================================== */
function initMobileNav() {
  const toggleBtn = document.getElementById('mobileMenuToggle');
  const sidebar = document.querySelector('.docs-sidebar');

  if (!toggleBtn || !sidebar) return;

  toggleBtn.addEventListener('click', () => {
    sidebar.classList.toggle('mobile-open');
    const isExpanded = sidebar.classList.contains('mobile-open');
    toggleBtn.setAttribute('aria-expanded', isExpanded);
  });

  // Close sidebar when clicking a link on mobile
  const links = sidebar.querySelectorAll('.sidebar-link');
  links.forEach(l => {
    l.addEventListener('click', () => {
      sidebar.classList.remove('mobile-open');
      toggleBtn.setAttribute('aria-expanded', 'false');
    });
  });
}

/* ==========================================================================
   11. Back to Top Button
   ========================================================================== */
function initBackToTop() {
  const btn = document.getElementById('backToTopBtn');
  if (!btn) return;

  window.addEventListener('scroll', () => {
    if (window.scrollY > 400) {
      btn.classList.add('visible');
    } else {
      btn.classList.remove('visible');
    }
  }, { passive: true });

  btn.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
}
