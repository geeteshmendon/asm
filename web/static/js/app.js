const API = '/api';

function $(id) { return document.getElementById(id) }

function toast(msg, t = 'success') {
  const el = document.createElement('div'); el.className = `toast ${t}`; el.textContent = msg;
  document.body.appendChild(el); setTimeout(() => el.remove(), 3000);
}

function showPage(page, data) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const el = $(page); if (!el) return;
  el.classList.add('active');
  document.querySelector('header').classList.toggle('visible', page !== 'hero');
  if (page === 'target-list') loadTargets();
  if (page === 'target-detail' && data) loadTargetDetail(data);
}

// ─── PAGE 1: HERO — just an input ───
$('heroForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  const input = $('heroInput'); const domain = input.value.trim();
  if (!domain) return;
  const btn = $('heroBtn'); btn.disabled = true; btn.textContent = 'Adding...';
  try {
    const r = await fetch(`${API}/targets`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    if (!r.ok) { const d = await r.json(); throw new Error(d.detail || 'Error'); }
    const t = await r.json();
    input.value = ''; toast('Target added! Scanning now...');
    // auto-start scan
    fetch(`${API}/targets/${t.id}/scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_type: 'full', scan_profile: 'light' })
    }).catch(() => {});
    showPage('target-list');
  } catch (e) { toast(e.message || 'Failed', 'error'); }
  btn.disabled = false; btn.textContent = '→';
});

// ─── PAGE 2: TARGET LIST ───
async function loadTargets() {
  try {
    const r = await fetch(`${API}/targets?per_page=100`);
    const d = await r.json();
    const grid = $('targetGrid');
    if (!d.targets.length) {
      grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1">🔭 No targets yet — add one above</div>`;
      return;
    }
    grid.innerHTML = d.targets.map(t => `
      <div class="target-card" onclick="showPage('target-detail',${t.id})">
        <div class="domain">${t.domain}</div>
        <div class="meta">
          <span>📦 ${t.asset_count || 0} assets</span>
          <span>⚠️ ${t.high_risk_count || 0} critical</span>
          <span>📊 <strong class="risk-${t.risk_score >= 7 ? 'high' : t.risk_score >= 4 ? 'medium' : 'none'}">${t.risk_score || 0}</strong></span>
          <span style="font-size:12px;color:var(--text3)">${t.last_scanned ? new Date(t.last_scanned).toLocaleDateString() : 'Not scanned'}</span>
        </div>
        <div class="actions" onclick="event.stopPropagation()">
          <button class="btn btn-sm btn-success" onclick="scanAndRefresh(${t.id})">Scan</button>
          <button class="btn btn-sm btn-danger" onclick="deleteTarget(${t.id},this)">✕</button>
        </div>
      </div>
    `).join('');
    $('totalTargets').textContent = `${d.total} target${d.total !== 1 ? 's' : ''}`;
  } catch (e) { toast('Failed to load', 'error'); }
}

async function scanAndRefresh(id) {
  try {
    await fetch(`${API}/targets/${id}/scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_type: 'full', scan_profile: 'light' })
    });
    toast('Scan started!');
    setTimeout(loadTargets, 2000);
  } catch (e) { toast('Scan failed', 'error'); }
}

async function deleteTarget(id, btn) {
  if (!confirm('Delete this target?')) return;
  btn.textContent = '...'; btn.disabled = true;
  try { await fetch(`${API}/targets/${id}`, { method: 'DELETE' }); toast('Deleted'); loadTargets(); }
  catch (e) { toast('Failed', 'error'); }
}

// Add from target list page
$('targetInput')?.addEventListener('keydown', async e => {
  if (e.key !== 'Enter') return;
  const input = $('targetInput'); const domain = input.value.trim();
  if (!domain) return;
  try {
    const r = await fetch(`${API}/targets`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    const t = await r.json(); input.value = '';
    fetch(`${API}/targets/${t.id}/scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_type: 'full', scan_profile: 'light' })
    }).catch(() => {});
    toast('Added! Scanning...'); loadTargets();
  } catch (e) { toast(e.message || 'Failed', 'error'); }
});

// ─── PAGE 3: TARGET DETAIL ───
let detailId = null;

async function loadTargetDetail(id) {
  detailId = id;
  try {
    const r = await fetch(`${API}/targets/${id}`);
    const t = await r.json();
    $('detailTitle').textContent = t.domain;
    $('detailSubtitle').textContent = `ID #${t.id} · Risk: ${t.risk_score || 0} · Added: ${t.added_at ? new Date(t.added_at).toLocaleDateString() : '-'}`;
    $('detailRisk').textContent = t.risk_score || 0;
    $('detailRisk').className = `risk-${t.risk_score >= 7 ? 'high' : t.risk_score >= 4 ? 'medium' : 'none'}`;
    $('detailStats').innerHTML = `
      <div class="stat-card"><div class="stat-label">Total Assets</div><div class="stat-value">${t.asset_count || 0}</div></div>
      <div class="stat-card"><div class="stat-label">Subdomains</div><div class="stat-value">${t.assets_by_type?.subdomain || 0}</div></div>
      <div class="stat-card"><div class="stat-label">Ports</div><div class="stat-value">${t.assets_by_type?.port || 0}</div></div>
      <div class="stat-card"><div class="stat-label">Vulnerabilities</div><div class="stat-value" style="color:var(--red)">${t.assets_by_type?.vulnerability || 0}</div></div>
      <div class="stat-card"><div class="stat-label">Technologies</div><div class="stat-value">${t.assets_by_type?.technology || 0}</div></div>
      <div class="stat-card"><div class="stat-label">Certificates</div><div class="stat-value">${t.assets_by_type?.certificate || 0}</div></div>
    `;
    fetchAssets(id);
    fetchScans(id);
    fetchClassification(id);
  } catch (e) { toast('Failed to load', 'error'); }
}

async function fetchAssets(id) {
  try {
    const r = await fetch(`${API}/targets/${id}/assets?per_page=200`);
    const d = await r.json(); const list = $('detailAssets');
    if (!d.assets || !d.assets.length) { list.innerHTML = '<div class="empty-state"><p>No assets yet — run a scan</p></div>'; return; }
    list.innerHTML = d.assets.map(a => `
      <div class="asset-item">
        <span class="badge badge-${a.asset_type}">${a.asset_type}</span>
        <span class="val">${a.value}</span>
        <span class="detail">${(a.details || '').substring(0, 50)}</span>
        <span class="risk risk-${a.risk_score >= 7 ? 'high' : a.risk_score >= 4 ? 'medium' : 'none'}">${a.risk_score || 0}</span>
      </div>
    `).join('');
    $('assetCount').textContent = `(${d.total})`;
  } catch (e) {}
}

async function fetchScans(id) {
  try {
    const r = await fetch(`${API}/jobs?target_id=${id}&per_page=20`);
    const d = await r.json(); const list = $('detailScans');
    if (!d.jobs.length) { list.innerHTML = '<div class="empty-state"><p>No scans yet</p></div>'; return; }
    list.innerHTML = d.jobs.map(j => `
      <div class="asset-item">
        <span class="badge badge-${j.status}">${j.status}</span>
        <span class="val">${j.scan_type} (${j.scan_profile || 'std'})</span>
        <span class="detail">${j.results_count || 0} results${j.error_message ? ' · ' + j.error_message.substring(0, 40) : ''}</span>
        <span style="font-size:11px;color:var(--text3)">${j.started_at ? new Date(j.started_at).toLocaleString() : '-'}</span>
      </div>
    `).join('');
  } catch (e) {}
}

async function fetchClassification(id) {
  try {
    const r = await fetch(`${API}/targets/${id}/classification`);
    const d = await r.json();
    let html = '';
    ['critical', 'high', 'medium', 'low'].forEach(level => {
      if (d[level]?.length) {
        const color = level === 'critical' ? 'var(--red)' : level === 'high' ? 'var(--orange)' : level === 'medium' ? 'var(--yellow)' : 'var(--green)';
        html += `<div style="margin-bottom:6px;font-size:13px"><strong style="color:${color}">${level.toUpperCase()} (${d[level].length})</strong>: ${d[level].map(a => a.value).join(', ').substring(0, 120)}</div>`;
      }
    });
    if (d.scan_recommendations?.length) {
      html += `<div style="margin-top:12px;padding:12px;background:rgba(56,189,248,0.1);border-radius:8px;font-size:13px"><strong style="color:var(--accent)">Recommendations:</strong><ul style="margin-top:4px">${d.scan_recommendations.map(r => `<li style="color:var(--text2);margin-top:4px">${r}</li>`).join('')}</ul></div>`;
    }
    $('detailClassification').innerHTML = html || '<div class="empty-state"><p>No data</p></div>';
  } catch (e) {}
}

async function refreshDetail() {
  if (detailId) { await loadTargetDetail(detailId); toast('Refreshed'); }
}

async function runScanFromDetail() {
  if (!detailId) return;
  try {
    const r = await fetch(`${API}/targets/${detailId}/scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_type: 'full', scan_profile: 'standard' })
    });
    const d = await r.json(); toast(`Scan #${d.job_id} started!`);
    setTimeout(() => { fetchAssets(detailId); fetchScans(detailId); }, 3000);
  } catch (e) { toast('Failed', 'error'); }
}
