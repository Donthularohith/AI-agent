// ═══ AI Agent Governance SOC Dashboard — Logic ═══
const API = window.location.origin;
let agents = [];

// ── Tab Switching ──
function switchTab(id, btn) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  btn.classList.add('active');
}

// ── Toast ──
function toast(msg, type = 'ok') {
  const el = document.getElementById('toast');
  el.textContent = msg; el.className = 'toast ' + type + ' show';
  setTimeout(() => el.classList.remove('show'), 3000);
}

// ── API Fetch ──
async function api(path, opts = {}) {
  try {
    const r = await fetch(API + path, { headers: { 'Content-Type': 'application/json' }, ...opts });
    if (!r.ok) { const t = await r.text(); return { _err: true, status: r.status, detail: t }; }
    return await r.json();
  } catch (e) { return { _err: true, detail: e.message }; }
}

// ── Health ──
async function checkHealth() {
  const h = await api('/health');
  const el = document.getElementById('healthStatus');
  if (h._err) { el.className = 'status-pill error'; el.innerHTML = '<div class="pulse-dot"></div><span>Disconnected</span>'; return; }
  if (h.status === 'healthy') { el.className = 'status-pill'; el.innerHTML = '<div class="pulse-dot"></div><span>DB ✓ · OPA ✓ · Vault ✓</span>'; }
  else { el.className = 'status-pill degraded'; el.innerHTML = '<div class="pulse-dot"></div><span>DB ✓ · OPA ✗ · Vault ✗</span>'; }
}

// ── Load Agents ──
async function loadAgents() {
  const d = await api('/agents?page_size=100');
  if (d._err) { document.getElementById('agentTbody').innerHTML = '<tr><td colspan="7" class="center">❌ API unreachable</td></tr>'; return; }

  agents = d.agents || [];
  const total = d.total || agents.length;
  document.getElementById('kTotal').textContent = total;
  document.getElementById('kActive').textContent = agents.filter(a => a.status === 'active').length;
  document.getElementById('kSuspended').textContent = agents.filter(a => a.status === 'suspended').length;
  document.getElementById('kRevoked').textContent = agents.filter(a => a.status === 'revoked').length;
  document.getElementById('kHipaa').textContent = agents.filter(a => (a.compliance_tags||[]).includes('HIPAA')).length;

  // Populate all selects
  ['auditSelect','blastSelect','polAgent'].forEach(id => {
    const s = document.getElementById(id); const v = s.value;
    s.innerHTML = '<option value="">Select agent…</option>';
    agents.forEach(a => { s.innerHTML += `<option value="${a.agent_id}">${a.name} (${a.status})</option>`; });
    s.value = v;
  });

  if (!agents.length) { document.getElementById('agentTbody').innerHTML = '<tr><td colspan="7" class="center">No agents registered yet. Use the Register tab.</td></tr>'; return; }

  document.getElementById('agentTbody').innerHTML = agents.map(a => {
    const tags = (a.compliance_tags||[]).map(t => `<span class="badge ${t.toLowerCase()}">${t}</span>`).join(' ');
    const tools = (a.allowed_tools||[]).length;
    let actions = '';
    if (a.status === 'active') actions = `<button class="btn-suspend" onclick="doSuspend('${a.agent_id}','${a.name}')">⏸ Suspend</button>`;
    else if (a.status === 'suspended') actions = `<button class="btn-ok" onclick="doReactivate('${a.agent_id}','${a.name}')">▶ Reactivate</button>`;
    return `<tr>
      <td><strong>${a.name}</strong><div class="mono" style="color:var(--t3);margin-top:2px">${a.agent_id.substring(0,8)}…</div></td>
      <td><span class="badge ${a.status}">● ${a.status.toUpperCase()}</span></td>
      <td style="font-size:12px">${a.owner_email}</td>
      <td class="mono">${a.version}</td>
      <td>${tags||'—'}</td>
      <td class="mono">${tools} tools</td>
      <td>${actions}</td></tr>`;
  }).join('');
}

// ── Suspend / Reactivate ──
async function doSuspend(id, name) {
  if (!confirm(`Suspend "${name}"? Credentials will be revoked.`)) return;
  const r = await api(`/agents/${id}/suspend`, { method: 'POST' });
  if (r.status === 'suspended') { toast(`⏸ ${name} suspended`); loadAgents(); } else toast('Failed: ' + (r.detail||''), 'err');
}
async function doReactivate(id, name) {
  const r = await api(`/agents/${id}/reactivate`, { method: 'POST' });
  if (r.status === 'active') { toast(`▶ ${name} reactivated`); loadAgents(); } else toast('Failed', 'err');
}

// ── Audit ──
async function loadAudit() {
  const id = document.getElementById('auditSelect').value;
  const el = document.getElementById('auditBody');
  if (!id) { el.innerHTML = '<div class="empty">Select an agent.</div>'; return; }
  const d = await api(`/audit/agents/${id}?page_size=50`);
  const entries = d.entries || [];
  if (!entries.length) { el.innerHTML = '<div class="empty">No audit entries for this agent.</div>'; return; }
  el.innerHTML = entries.map(e => {
    const cls = e.outcome==='success'?'ok':e.outcome==='denied'?'denied':'err';
    return `<div class="tl-entry"><div class="tl-dot ${cls}"></div><div class="tl-body">
      <div class="tl-action">${e.action_type} → <span class="badge ${e.outcome==='success'?'active':'revoked'}">${e.outcome}</span></div>
      <div class="tl-meta">${e.tool_uri?'Tool: <span class="mono">'+e.tool_uri+'</span> · ':''}${e.resource?'Res: <span class="mono">'+e.resource+'</span> · ':''}${new Date(e.timestamp_utc).toLocaleString()}</div>
    </div></div>`;
  }).join('');
}

// ── Blast Radius ──
function showBlast() {
  const id = document.getElementById('blastSelect').value;
  const el = document.getElementById('blastBody');
  if (!id) { el.innerHTML = '<div class="empty">Select an agent.</div>'; return; }
  const a = agents.find(x => x.agent_id === id); if (!a) return;
  const res = a.allowed_resources||[], tools = a.allowed_tools||[];
  const phi = res.filter(r => /patient|emr/i.test(r));
  const wr = tools.filter(t => /write|admin|delete/i.test(t));
  const score = res.length*2 + tools.length*3 + phi.length*10;
  let lvl, clr, bg;
  if (score>=30||phi.length>0) { lvl='CRITICAL'; clr='var(--red)'; bg='rgba(239,68,68,.08)'; }
  else if (score>=15) { lvl='HIGH'; clr='var(--amber)'; bg='rgba(245,158,11,.08)'; }
  else { lvl='LOW'; clr='var(--green)'; bg='rgba(16,185,129,.08)'; }

  el.innerHTML = `
    <div class="risk-banner" style="background:${bg};border:1px solid ${clr}30">
      <div style="color:var(--t3);font-size:13px;margin-bottom:6px">ESTIMATED RISK IF COMPROMISED</div>
      <h1 style="color:${clr}">${lvl}</h1>
      <div style="color:var(--t3);font-size:12px;margin-top:6px">${phi.length} PHI resources · ${wr.length} write tools · depth ${a.max_delegation_depth}</div>
    </div>
    <div class="blast-grid">
      <div class="blast-list"><h3>📂 Resources (${res.length})</h3><ul>${res.map(r => `<li>${r}${/patient|emr/i.test(r)?'<span class="phi-tag">HIPAA/PHI</span>':''}</li>`).join('')}</ul></div>
      <div class="blast-list"><h3>🔧 Tools (${tools.length})</h3><ul>${tools.map(t => `<li>${t}${/write|admin/i.test(t)?'<span class="write-tag">WRITE</span>':''}</li>`).join('')}</ul></div>
    </div>
    ${lvl==='CRITICAL'?`<div style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:10px;padding:16px;margin-top:18px">
      <h3 style="color:var(--red);margin-bottom:8px">⚠ Recommended Actions</h3>
      <ol style="padding-left:18px;color:var(--t2);line-height:2;font-size:13px">
        <li>Immediately <strong>suspend</strong> this agent</li><li>Revoke all active credentials</li>
        <li>Review audit log for unauthorized PHI access</li><li>Notify HIPAA Privacy Officer</li>
      </ol></div>`:''}`;
}

// ── Policy Tester ──
async function testPolicy() {
  const agentId = document.getElementById('polAgent').value;
  const tool = document.getElementById('polTool').value;
  const resource = document.getElementById('polResource').value;
  const el = document.getElementById('polResult');
  if (!agentId||!tool) { toast('Select agent and enter tool URI','err'); return; }
  el.innerHTML = '<div class="center"><div class="spinner"></div></div>';
  const r = await api('/policy/decide', { method:'POST', body:JSON.stringify({ agent_id:agentId, action:'tool_call', tool_uri:tool, resource:resource||'default:resource', delegation_depth:0 }) });
  const ok = r.allow;
  const c = ok?'var(--green)':'var(--red)', b = ok?'rgba(16,185,129,.08)':'rgba(239,68,68,.08)';
  el.innerHTML = `<div class="pol-result" style="background:${b};border:1px solid ${c}30">
    <h2 style="color:${c}">${ok?'✅ ALLOWED':'❌ DENIED'}</h2>
    <div style="color:var(--t2);font-size:13px">Reason: <strong>${r.reason||'N/A'}</strong></div>
    ${(r.denied_reasons||[]).length?r.denied_reasons.map(x=>`<div style="color:var(--red);font-size:12px;margin-top:4px">• ${x}</div>`).join(''):''}
    <pre>${JSON.stringify(r,null,2)}</pre></div>`;
}

// ── Register Agent ──
async function registerAgent() {
  const name = document.getElementById('regName').value.trim();
  const version = document.getElementById('regVersion').value.trim();
  const email = document.getElementById('regEmail').value.trim();
  const purpose = document.getElementById('regPurpose').value.trim();
  const tools = document.getElementById('regTools').value.split(',').map(s=>s.trim()).filter(Boolean);
  const resources = document.getElementById('regResources').value.split(',').map(s=>s.trim()).filter(Boolean);
  const depth = parseInt(document.getElementById('regDepth').value)||0;
  const ttl = parseInt(document.getElementById('regTTL').value)||900;
  const days = parseInt(document.getElementById('regExpiry').value)||90;
  const tags = [...document.querySelectorAll('.regTag:checked')].map(c=>c.value);
  const el = document.getElementById('regResult');

  if (!name||!version||!email||!purpose||!tools.length||!resources.length) { toast('Fill all required fields','err'); return; }
  if (purpose.length<20) { toast('Purpose must be at least 20 characters','err'); return; }

  const expires = new Date(Date.now()+days*86400000).toISOString();
  el.innerHTML = '<div class="center"><div class="spinner"></div></div>';

  const r = await api('/agents', { method:'POST', body:JSON.stringify({
    name, version, owner_email:email, purpose, expires_at:expires,
    allowed_tools:tools, allowed_resources:resources,
    max_delegation_depth:depth, credential_ttl_seconds:ttl, anomaly_threshold:-0.3, compliance_tags:tags
  })});

  if (r._err) { el.innerHTML = `<div class="pol-result" style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25)"><h2 style="color:var(--red)">❌ Registration Failed</h2><pre>${r.detail}</pre></div>`; return; }

  el.innerHTML = `<div class="pol-result" style="background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.25)">
    <h2 style="color:var(--green)">✅ Agent Registered</h2>
    <div style="color:var(--t2);font-size:13px;margin-bottom:8px">ID: <span class="mono">${r.agent_id}</span></div>
    <pre>${JSON.stringify(r,null,2)}</pre></div>`;
  toast(`✅ ${name} registered!`);
  loadAgents();
}

// ── Refresh ──
async function refreshAll() {
  document.getElementById('lastRefresh').textContent = '…';
  await Promise.all([checkHealth(), loadAgents()]);
  document.getElementById('lastRefresh').textContent = new Date().toLocaleTimeString();
  toast('Dashboard refreshed');
}

// ── Init ──
document.addEventListener('DOMContentLoaded', async () => {
  await refreshAll();
  setInterval(async () => { await Promise.all([checkHealth(), loadAgents()]); document.getElementById('lastRefresh').textContent = new Date().toLocaleTimeString(); }, 15000);
});
