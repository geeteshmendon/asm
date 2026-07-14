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

// ─── PAGE 1: HERO ───
$('heroForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  const input = $('heroInput'); const domain = input.value.trim();
  if (!domain) return;
  const btn = $('heroBtn'); btn.disabled = true; btn.textContent = '...';
  try {
    const r = await fetch(`${API}/targets`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    if (!r.ok) { const d = await r.json(); throw new Error(d.detail || 'Error'); }
    const t = await r.json();
    input.value = '';
    toast('Target added! Running deep scan...');
    fetch(`${API}/targets/${t.id}/scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_type: 'full', scan_profile: 'deep' })
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
      grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1"><div class="icon" style="font-size:48px">🔭</div><p>No targets yet</p><p style="font-size:13px;color:var(--text3)">Add your first domain above</p></div>`;
      return;
    }
    grid.innerHTML = d.targets.map(t => `
      <div class="target-card" onclick="showPage('target-detail',${t.id})">
        <div class="domain">${t.domain}</div>
        <div class="meta">
          <span>📦 ${t.asset_count || 0} assets</span>
          <span>⚠️ ${t.high_risk_count || 0} critical</span>
          <span>📊 <strong class="risk-${t.risk_score >= 7 ? 'high' : t.risk_score >= 4 ? 'medium' : 'none'}">Score: ${t.risk_score || 0}</strong></span>
          <span style="font-size:12px;color:var(--text3)">${t.last_scanned ? new Date(t.last_scanned).toLocaleDateString() : 'Not scanned'}</span>
        </div>
        <div class="actions" onclick="event.stopPropagation()">
          <button class="btn btn-sm btn-success" onclick="scanTarget(${t.id})">Deep Scan</button>
          <button class="btn btn-sm btn-danger" onclick="deleteTarget(${t.id},this)">✕</button>
        </div>
      </div>
    `).join('');
    $('totalTargets').textContent = `${d.total} target${d.total !== 1 ? 's' : ''}`;
  } catch (e) { toast('Failed to load', 'error'); }
}

async function scanTarget(id) {
  try {
    await fetch(`${API}/targets/${id}/scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_type: 'full', scan_profile: 'deep' })
    });
    toast('Deep scan started!');
    setTimeout(loadTargets, 3000);
  } catch (e) { toast('Scan failed', 'error'); }
}

async function deleteTarget(id, btn) {
  if (!confirm('Delete this target and all its data?')) return;
  btn.textContent = '...'; btn.disabled = true;
  try { await fetch(`${API}/targets/${id}`, { method: 'DELETE' }); toast('Deleted'); loadTargets(); }
  catch (e) { toast('Failed', 'error'); }
}

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
      body: JSON.stringify({ scan_type: 'full', scan_profile: 'deep' })
    }).catch(() => {});
    toast('Added! Deep scanning...'); loadTargets();
  } catch (e) { toast(e.message || 'Failed', 'error'); }
});

// ─── PAGE 3: COMPREHENSIVE TARGET REPORT ───
let detailId = null;

async function loadTargetDetail(id) {
  detailId = id;
  // Show loading state
  $('detailBody').innerHTML = `<div style="text-align:center;padding:60px"><div class="spinner" style="width:32px;height:32px;margin:0 auto 16px"></div><p style="color:var(--text3)">Loading comprehensive report...</p></div>`;
  try {
    // Fetch report and raw data in parallel
    const [reportRes, assetsRes, scansRes] = await Promise.all([
      fetch(`${API}/targets/${id}/report`).then(r => r.json()),
      fetch(`${API}/targets/${id}/assets?per_page=500`).then(r => r.json()),
      fetch(`${API}/jobs?target_id=${id}&per_page=10`).then(r => r.json()),
    ]);
    const r = reportRes;
    const allAssets = assetsRes.assets || [];
    const allScans = scansRes.jobs || [];

    $('detailTitle').textContent = r.domain;
    $('detailRating').textContent = r.security_rating;
    $('detailRating').style.color = r.security_rating === 'A' ? '#22c55e' : r.security_rating === 'B' ? '#3b82f6' : r.security_rating === 'C' ? '#f59e0b' : '#ef4444';

    // Stats cards
    const ab = r.asset_breakdown || {};
    $('detailStats').innerHTML = `
      <div class="stat-card"><div class="stat-label">Security Rating</div><div class="stat-value" style="color:${r.security_rating === 'A' ? '#22c55e' : r.security_rating === 'B' ? '#3b82f6' : r.security_rating === 'C' ? '#f59e0b' : '#ef4444'}">${r.security_rating}</div><div class="stat-sub">Risk: ${r.risk_score}</div></div>
      <div class="stat-card"><div class="stat-label">Total Assets</div><div class="stat-value">${r.total_assets || 0}</div></div>
      <div class="stat-card"><div class="stat-label">Vulnerabilities</div><div class="stat-value" style="color:var(--red)">${r.vulnerability_summary?.total || 0}</div><div class="stat-sub">${r.vulnerability_summary?.high || 0} high · ${r.vulnerability_summary?.medium || 0} medium</div></div>
      <div class="stat-card"><div class="stat-label">Subdomains</div><div class="stat-value">${ab.subdomains || 0}</div></div>
      <div class="stat-card"><div class="stat-label">Open Ports</div><div class="stat-value">${ab.ports || 0}</div></div>
      <div class="stat-card"><div class="stat-label">Technologies</div><div class="stat-value">${ab.technologies || 0}</div></div>
    `;

    // Vulnerabilities
    const vs = r.vulnerability_summary || {};
    const vulnList = $('detailVulns');
    if (vs.total > 0) {
      vulnList.innerHTML = (vs.top_findings || []).map(v => `
        <div class="asset-item">
          <span class="badge badge-${v.severity}">${v.severity}</span>
          <span class="val">${v.value}</span>
          <span class="detail">${(v.details || '').substring(0, 80)}</span>
          <span class="risk risk-${v.risk >= 7 ? 'high' : v.risk >= 4 ? 'medium' : 'low'}">${v.risk}</span>
        </div>
      `).join('');
      if (vs.total > 5) vulnList.innerHTML += `<div style="padding:12px;text-align:center;color:var(--text3);font-size:13px">... and ${vs.total - 5} more vulnerabilities</div>`;
    } else {
      vulnList.innerHTML = '<div class="empty-state" style="padding:20px"><p>No vulnerabilities found</p></div>';
    }

    // Technology Stack
    const techList = $('detailTech');
    if (r.technology_stack?.length) {
      techList.innerHTML = r.technology_stack.map(t => `<div class="asset-item"><span class="badge badge-technology">tech</span><span class="val">${t}</span></div>`).join('');
    } else {
      techList.innerHTML = '<div class="empty-state" style="padding:20px"><p>No technologies detected</p></div>';
    }

    // Open Ports
    const portList = $('detailPorts');
    if (r.open_ports?.length) {
      portList.innerHTML = r.open_ports.map(p => `<div class="asset-item"><span class="badge badge-port">port</span><span class="val">${p.port}</span><span class="detail">${(p.details || '').substring(0, 60)}</span></div>`).join('');
    } else {
      portList.innerHTML = '<div class="empty-state" style="padding:20px"><p>No open ports detected</p></div>';
    }

    // Subdomains
    const subList = $('detailSubdomains');
    if (r.subdomains?.length) {
      subList.innerHTML = r.subdomains.map(s => `<div class="asset-item"><span class="badge badge-subdomain">sub</span><span class="val">${s}</span></div>`).join('');
    } else {
      subList.innerHTML = '<div class="empty-state" style="padding:20px"><p>No subdomains discovered</p></div>';
    }

    // All Assets
    const assetList = $('detailAssets');
    if (allAssets.length) {
      assetList.innerHTML = allAssets.map(a => `
        <div class="asset-item">
          <span class="badge badge-${a.asset_type}">${a.asset_type}</span>
          <span class="val">${a.value}</span>
          <span class="detail">${(a.details || '').substring(0, 50)}</span>
          <span class="risk risk-${a.risk_score >= 7 ? 'high' : a.risk_score >= 4 ? 'medium' : 'none'}">${a.risk_score || 0}</span>
        </div>
      `).join('');
    } else {
      assetList.innerHTML = '<div class="empty-state" style="padding:20px"><p>No assets discovered yet</p></div>';
    }

    // Scans
    const scanList = $('detailScans');
    if (allScans.length) {
      scanList.innerHTML = allScans.map(j => `
        <div class="asset-item">
          <span class="badge badge-${j.status}">${j.status}</span>
          <span class="val">${j.scan_type} (${j.scan_profile || 'std'})</span>
          <span class="detail">${j.results_count || 0} findings</span>
          <span style="font-size:11px;color:var(--text3)">${j.started_at ? new Date(j.started_at).toLocaleString() : '-'}</span>
        </div>
      `).join('');
    } else {
      scanList.innerHTML = '<div class="empty-state" style="padding:20px"><p>No scans yet — run your first scan!</p></div>';
    }

  } catch (e) {
    $('detailBody').innerHTML = `<div class="empty-state"><p>⚠️ Failed to load report</p><p style="font-size:13px;color:var(--text3)">${e.message}</p></div>`;
    toast('Failed to load report', 'error');
  }
}

async function runComprehensiveScan() {
  if (!detailId) return;
  try {
    const r = await fetch(`${API}/targets/${detailId}/scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_type: 'full', scan_profile: 'deep' })
    });
    const d = await r.json();
    toast(`Deep scan #${d.job_id} started!`);
    setTimeout(() => loadTargetDetail(detailId), 5000);
  } catch (e) { toast('Scan failed', 'error'); }
}
