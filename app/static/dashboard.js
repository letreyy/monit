function renderTrend(trend) {
  const svg = document.getElementById('trend-svg');
  if (!svg) return;
  const labels = trend?.labels || [];
  const values = trend?.values || [];
  if (!labels.length) {
    svg.innerHTML = "<text x='20' y='40' fill='#64748b'>No trend data</text>";
    return;
  }

  const maxVal = Math.max(...values, 1);
  const points = values.map((v, i) => {
    const x = 20 + i * 90;
    const y = 140 - Math.floor((v / maxVal) * 110);
    return `${x},${y}`;
  }).join(' ');

  const labelsSvg = labels.map((label, i) => {
    const x = 20 + i * 90;
    return `<text x='${x}' y='158' font-size='10' fill='#667'>${label.slice(2)}</text>`;
  }).join('');

  svg.innerHTML = `
    <line x1='20' y1='140' x2='540' y2='140' stroke='#cbd5e1' stroke-width='1' />
    <polyline points='${points}' fill='rgba(14,165,233,0.15)' stroke='#0ea5e9' stroke-width='3' />
    ${labelsSvg}
  `;
}

function renderDashboard(payload) {
  const overview = payload.overview || {};
  const sources = payload.sources || {};
  const health = payload.worker_health || {};

  document.getElementById('kpi-all').textContent = overview.events_total ?? 0;
  document.getElementById('kpi-assets').textContent = `Across ${overview.assets_total ?? 0} assets`;
  document.getElementById('kpi-win').textContent = sources.windows ?? 0;
  document.getElementById('kpi-win-pct').textContent = `${sources.windows_pct ?? 0}% of all events`;
  document.getElementById('kpi-syslog').textContent = sources.syslog ?? 0;
  document.getElementById('kpi-syslog-pct').textContent = `${sources.syslog_pct ?? 0}% of all events`;
  document.getElementById('kpi-agentless').textContent = sources.agentless ?? 0;
  document.getElementById('kpi-agentless-pct').textContent = `${sources.agentless_pct ?? 0}% of all events`;

  const ring = document.getElementById('kpi-ring');
  ring.style.background = `conic-gradient(#0ea5e9 ${sources.agentless_pct ?? 0}%, #e2e8f0 0)`;

  document.getElementById('worker-health').innerHTML = `
    <b>Worker health:</b> ${health.running ? 'running' : 'stopped'} |
    enabled: ${health.enabled} | tracked: ${health.tracked} |
    failed: ${health.failed} | stale: ${health.stale} |
    cycles: ${health.cycle_count} | <a href='/worker/health'>JSON</a>
  `;

  renderTrend(payload.trend || {});

  const topRows = payload.top_assets?.length
    ? payload.top_assets.map((row) => `<tr><td>${row.asset_id}</td><td>${row.events}</td></tr>`).join('')
    : "<tr><td colspan='2'>No data</td></tr>";
  document.getElementById('top-assets-rows').innerHTML = topRows;

  const sev = payload.severity || {};
  document.getElementById('severity-rows').innerHTML = `
    <tr><td>Info</td><td>${sev.info ?? 0}</td></tr>
    <tr><td>Warning</td><td>${sev.warning ?? 0}</td></tr>
    <tr><td>Critical</td><td>${sev.critical ?? 0}</td></tr>
  `;

  const alerts = payload.recent_alerts?.length
    ? payload.recent_alerts.map((a) => `
      <div class='alert-item ${a.severity}'>
        <div class='alert-title'>${a.source}: ${String(a.message).slice(0, 110)}</div>
        <div class='alert-ts'>${a.timestamp}</div>
      </div>
    `).join('')
    : "<div class='muted'>No warning/critical events yet.</div>";
  document.getElementById('recent-alerts').innerHTML = alerts;

  const assetsRows = payload.assets_table?.length
    ? payload.assets_table.map((a) => `<tr><td><a href='/ui/assets/${a.id}'>${a.id}</a></td><td>${a.asset_type}</td><td>${a.location}</td><td>${a.events}</td><td>${a.alerts}</td><td>${a.insights}</td></tr>`).join('')
    : "<tr><td colspan='6'>No assets yet</td></tr>";
  document.getElementById('assets-rows').innerHTML = assetsRows;
}

async function refreshDashboardData() {
  try {
    const apiUrl = document.getElementById('dashboard-root')?.dataset?.api || '/dashboard/data';
    const res = await fetch(apiUrl);
    if (!res.ok) return;
    const payload = await res.json();
    renderDashboard(payload);
  } catch (_) {
    // keep last rendered state
  }
}

const initial = window.__DASHBOARD_INITIAL__ || {};
renderDashboard(initial);
setInterval(refreshDashboardData, 15000);
