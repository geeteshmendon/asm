const API = '/api';
let state = { targets: [], assets: [], targetPage: 1, assetPage: 1, scanPage: 1, currentTargetId: null, currentView: 'hero' };

function $(id) { return document.getElementById(id) }

function toast(msg, type = 'success') {
  const t = document.createElement('div'); t.className = `toast ${type}`; t.textContent = msg;
  document.body.appendChild(t); setTimeout(() => t.remove(), 3000);
}

// ─── Page Navigation ───
function showPage(page, data) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const el = $(page); if (!el) return;
  el.classList.add('active');
  state.currentView = page;
  document.querySelector('header').classList.toggle('visible', page !== 'hero');
  if (page === 'target-list') loadTargetList();
  if (page === 'target-detail') loadTargetDetail(data);
}

// ─── Dashboard / Landing Stats ───
async function loadHeroStats() {
  try {
    const r = await fetch(`${API}/dashboard`); const d = await r.json();
    $('hero-targets').textContent = d.total_targets || 0;
    $('hero-assets').textContent = d.total_assets || 0;
    $('hero-scans').textContent = d.completed_scans || 0;
  } catch (e) { }
}

// ─── Add Target from Hero ───
async function addTargetFromHero() {
  const input = $('heroInput'); const domain = input.value.trim();
  if (!domain) return toast('Enter a domain', 'error');
  try {
    await fetch(`${API}/targets`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain }) });
    input.value = ''; toast('Target added!');
    await loadTargetList(); showPage('target-list');
  } catch (e) { toast('Failed to add target', 'error'); }
}
$('heroInput')?.addEventListener('keydown', e => { if (e.key === 'Enter') addTargetFromHero() });

// ─── Target List ───
async function loadTargetList() {
  try {
    const r = await fetch(`${API}/targets?per_page=50&page=${state.targetPage}`);
    const d = await r.json(); state.targets = d.targets;
    const grid = $('targetGrid');
    if (!d.targets.length) {
      grid.innerHTML = `<div class="empty-state"><div class="icon">🔭</div><p>No targets yet</p><p style="font-size:13px">Add your first domain above</p></div>`;
      return;
    }
    grid.innerHTML = d.targets.map(t => `
      <div class="target-card animate-scale" onclick="showPage('target-detail',${t.id})">
        <div class="domain">${t.domain} <span class="tag">#${t.id}</span></div>
        <div class="meta">
          <span>📦 ${t.asset_count || 0} assets</span>
          <span>⚠️ ${t.high_risk_count || 0} high risk</span>
          <span>📊 score: <strong class="risk-${t.risk_score >= 7 ? 'high' : t.risk_score >= 4 ? 'medium' : 'none'}">${t.risk_score || 0}</strong></span>
          <span>🕐 ${t.last_scanned ? new Date(t.last_scanned).toLocaleDateString() : 'Never scanned'}</span>
        </div>
        <div class="actions">
          <button class="btn btn-sm btn-success" onclick="event.stopPropagation();runScanFromTarget(${t.id})">Scan</button>
          <button class="btn btn-sm btn-danger" onclick="event.stopPropagation();deleteTarget(${t.id})">Delete</button>
        </div>
      </div>
    `).join('');
    $('totalTargets').textContent = d.total;
  } catch (e) { toast('Failed to load targets', 'error'); }
}

async function addTargetFromList() {
  const input = $('targetInput'); const domain = input.value.trim();
  if (!domain) return;
  try {
    await fetch(`${API}/targets`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain }) });
    input.value = ''; toast('Target added');
    loadTargetList(); loadHeroStats();
  } catch (e) { toast('Failed to add', 'error'); }
}
$('targetInput')?.addEventListener('keydown', e => { if (e.key === 'Enter') addTargetFromList() });

async function deleteTarget(id) {
  if (!confirm('Delete this target and all its assets?')) return;
  try { await fetch(`${API}/targets/${id}`, { method: 'DELETE' }); toast('Deleted'); loadTargetList(); loadHeroStats(); }
  catch (e) { toast('Delete failed', 'error'); }
}

async function runScanFromTarget(id) {
  try {
    const r = await fetch(`${API}/targets/${id}/scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_type: 'full', scan_profile: 'standard' })
    });
    const d = await r.json(); toast(`Scan started! Job #${d.job_id}`);
    showPage('target-detail', id);
  } catch (e) { toast('Scan failed to start', 'error'); }
}

// ─── Target Detail ───
let detailTargetId = null;

async function loadTargetDetail(id) {
  detailTargetId = id;
  try {
    const [tr, dr] = await Promise.all([
      fetch(`${API}/targets/${id}`).then(r => r.json()),
      fetch(`${API}/dashboard`).then(r => r.json()),
    ]);
    const t = tr;
    $('detailTitle').textContent = t.domain;
    $('detailSubtitle').textContent = `Target #${t.id} · ${t.asset_count || 0} assets · Risk: ${t.risk_score || 0}`;
    $('detailRisk').textContent = t.risk_score || 0;
    $('detailRisk').className = `risk-${t.risk_score >= 7 ? 'high' : t.risk_score >= 4 ? 'medium' : 'none'}`;
    $('detailStats').innerHTML = `
      <div class="stat-card stagger">
        <div class="stat-label">Total Assets</div>
        <div class="stat-value">${t.asset_count || 0}</div>
      </div>
      <div class="stat-card stagger">
        <div class="stat-label">Subdomains</div>
        <div class="stat-value">${t.assets_by_type?.subdomain || 0}</div>
      </div>
      <div class="stat-card stagger">
        <div class="stat-label">Ports</div>
        <div class="stat-value">${t.assets_by_type?.port || 0}</div>
      </div>
      <div class="stat-card stagger">
        <div class="stat-label">Vulnerabilities</div>
        <div class="stat-value" style="color:var(--red)">${t.assets_by_type?.vulnerability || 0}</div>
      </div>
      <div class="stat-card stagger">
        <div class="stat-label">Technologies</div>
        <div class="stat-value">${t.assets_by_type?.technology || 0}</div>
      </div>
      <div class="stat-card stagger">
        <div class="stat-label">Certificates</div>
        <div class="stat-value">${t.assets_by_type?.certificate || 0}</div>
      </div>
    `;
    loadDetailAssets(id);
    loadDetailScans(id);
    loadDetailClassification(id);
  } catch (e) { toast('Failed to load target detail', 'error'); }
}

async function loadDetailAssets(id) {
  try {
    const r = await fetch(`${API}/targets/${id}/assets?per_page=100`);
    const d = await r.json(); const assets = d.assets || [];
    const list = $('detailAssets');
    if (!assets.length) { list.innerHTML = '<div class="empty-state"><p>No assets discovered yet</p></div>'; return; }
    list.innerHTML = assets.map(a => `
      <div class="asset-item">
        <span class="badge badge-${a.asset_type}">${a.asset_type}</span>
        <span class="val">${a.value}</span>
        <span class="detail">${(a.details || '').substring(0, 60)}</span>
        <span class="risk risk-${a.risk_score >= 7 ? 'high' : a.risk_score >= 4 ? 'medium' : 'none'}">${a.risk_score || 0}</span>
      </div>
    `).join('');
  } catch (e) { }
}

async function loadDetailScans(id) {
  try {
    const r = await fetch(`${API}/jobs?target_id=${id}&per_page=10`);
    const d = await r.json();
    const list = $('detailScans');
    if (!d.jobs.length) { list.innerHTML = '<div class="empty-state"><p>No scans yet</p></div>'; return; }
    list.innerHTML = d.jobs.map(j => `
      <div class="asset-item">
        <span class="badge badge-${j.status}">${j.status}</span>
        <span class="val">${j.scan_type} (${j.scan_profile || 'standard'})</span>
        <span class="detail">${j.results_count || 0} results</span>
        <span style="font-size:12px;color:var(--text3)">${j.started_at ? new Date(j.started_at).toLocaleString() : '-'}</span>
      </div>
    `).join('');
  } catch (e) { }
}

async function loadDetailClassification(id) {
  try {
    const r = await fetch(`${API}/targets/${id}/classification`);
    const d = await r.json();
    const list = $('detailClassification');
    if (!d) { list.innerHTML = '<div class="empty-state"><p>No data</p></div>'; return; }
    const sections = [];
    if (d.critical?.length) sections.push(`<strong style="color:var(--red)">Critical (${d.critical.length}):</strong> ${d.critical.map(a => a.value).join(', ')}`);
    if (d.high?.length) sections.push(`<strong style="color:var(--orange)">High (${d.high.length}):</strong> ${d.high.map(a => a.value).join(', ')}`);
    if (d.medium?.length) sections.push(`<strong style="color:var(--yellow)">Medium (${d.medium.length}):</strong> ${d.medium.map(a => a.value).join(', ')}`);
    let html = sections.map(s => `<div style="margin-bottom:8px;font-size:13px">${s}</div>`).join('');
    if (d.scan_recommendations?.length) {
      html += `<div style="margin-top:12px;padding:12px;background:rgba(56,189,248,0.1);border-radius:8px"><strong style="color:var(--accent)">Recommendations:</strong><ul style="margin-top:6px;font-size:13px;color:var(--text2)">${d.scan_recommendations.map(r => `<li>${r}</li>`).join('')}</ul></div>`;
    }
    list.innerHTML = html || '<div class="empty-state"><p>No data</p></div>';
  } catch (e) { }
}

async function runDetailScan() {
  if (!detailTargetId) return;
  try {
    const r = await fetch(`${API}/targets/${detailTargetId}/scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_type: 'full', scan_profile: 'standard' })
    });
    const d = await r.json(); toast(`Scan started! Job #${d.job_id}`);
    setTimeout(() => { loadDetailAssets(detailTargetId); loadDetailScans(detailTargetId); loadDetailClassification(detailTargetId); }, 2000);
  } catch (e) { toast('Scan failed', 'error'); }
}

// ─── Target List Search ───
let targetSearchTimeout;
function searchTargets() {
  clearTimeout(targetSearchTimeout);
  targetSearchTimeout = setTimeout(() => loadTargetList(), 300);
}

// ─── Init ───
loadHeroStats();
