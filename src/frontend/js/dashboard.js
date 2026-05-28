// ============================================================
// CHARTS
// ============================================================
let trafficChart = null;
let donutChart   = null;
let trafficData  = { labels: [], mbps_out: [], mbps_in: [] };

function initCharts() {
  initTrafficChart();
  initDonutChart();
}

function initTrafficChart() {
  const ctx = document.getElementById('trafficChart');
  if (!ctx) return;

  trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Salida (Mbps)',
          data: [],
          borderColor: '#4493f8',
          backgroundColor: 'rgba(68,147,248,0.06)',
          borderWidth: 1.5,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          pointHoverRadius: 3,
        },
        {
          label: 'Entrada (Mbps)',
          data: [],
          borderColor: '#3fb950',
          backgroundColor: 'rgba(63,185,80,0.04)',
          borderWidth: 1.5,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          pointHoverRadius: 3,
        },
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 200 },
      interaction: { intersect: false, mode: 'index' },
      plugins: {
        legend: {
          display: true,
          labels: {
            color: '#8b949e', font: { family: 'Roboto Mono', size: 11 },
            boxWidth: 10, padding: 14,
          }
        },
        tooltip: {
          backgroundColor: '#161b22', borderColor: '#30363d', borderWidth: 1,
          titleColor: '#8b949e', bodyColor: '#e6edf3',
          titleFont: { family: 'Roboto Mono', size: 10 },
          bodyFont: { family: 'Roboto Mono', size: 12 },
          padding: 10,
          callbacks: { label: c => ` ${c.dataset.label}: ${c.parsed.y.toFixed(3)} Mbps` }
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(48,54,61,0.5)', drawBorder: false },
          ticks: { color: '#484f58', font: { family: 'Roboto Mono', size: 9 }, maxTicksLimit: 8 },
          border: { display: false }
        },
        y: {
          grid: { color: 'rgba(48,54,61,0.5)', drawBorder: false },
          ticks: { color: '#484f58', font: { family: 'Roboto Mono', size: 9 }, callback: v => `${v} Mbps` },
          border: { display: false },
          min: 0,
        }
      }
    }
  });
}

function initDonutChart() {
  const ctx = document.getElementById('donutChart');
  if (!ctx) return;

  donutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['HTTP/HTTPS','DNS','SSH','ICMP','Otros'],
      datasets: [{
        data: [40.2, 18.7, 15.3, 10.1, 15.7],
        backgroundColor: ['#4493f8','#3fb950','#a371f7','#d29922','#484f58'],
        borderColor: '#1c2128',
        borderWidth: 2,
        hoverOffset: 5,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      cutout: '70%',
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#161b22', borderColor: '#30363d', borderWidth: 1,
          titleColor: '#8b949e', bodyColor: '#e6edf3',
          titleFont: { family: 'Roboto Mono', size: 10 },
          bodyFont: { family: 'Roboto Mono', size: 12 },
          padding: 10,
          callbacks: { label: c => ` ${c.parsed}%` }
        }
      }
    }
  });
}

// ============================================================
// UPDATE TRAFFIC CHART (live data from /traffic)
// ============================================================
function updateTrafficChart(traffic) {
  if (!trafficChart) return;
  const history = traffic.history || [];
  if (history.length === 0) return;

  const labels   = history.map(h => h.label);
  const out_data = history.map(h => h.mbps_out);
  const in_data  = history.map(h => h.mbps_in);

  trafficChart.data.labels              = labels;
  trafficChart.data.datasets[0].data    = out_data;
  trafficChart.data.datasets[1].data    = in_data;
  trafficChart.update('none'); // sin animación para fluidez
}

// ============================================================
// STATS UPDATE
// ============================================================
function updateStats(alerts, devices, traffic) {
  // Dispositivos
  setStatText('stat-devices', devices.length);

  // Alertas
  setStatText('stat-alerts', alerts.length);

  // Tráfico total
  if (traffic.total_tb >= 1) {
    setStatText('stat-traffic', traffic.total_tb.toFixed(2) + ' TB');
  } else {
    setStatText('stat-traffic', traffic.total_gb.toFixed(1) + ' GB');
  }

  // Ancho de banda actual
  const mbps = traffic.current_mbps || 0;
  setStatText('stat-bandwidth', mbps.toFixed(1) + ' Mbps');

  // Topbar badge
  const badge = document.getElementById('topbar-alert-badge');
  if (badge) {
    badge.textContent = alerts.length;
    badge.style.display = alerts.length > 0 ? 'flex' : 'none';
  }
}

function setStatText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// ============================================================
// NAV BADGE
// ============================================================
function updateNavBadge(count) {
  const b = document.getElementById('nav-alerts-badge');
  if (b) b.textContent = count;
}

// ============================================================
// ALERTS PANEL (Dashboard sidebar)
// ============================================================
function updateAlertsPanel(alerts) {
  const panel = document.getElementById('alerts-panel');
  if (!panel) return;
  const recent = [...alerts].reverse().slice(0, 5);
  if (recent.length === 0) {
    panel.innerHTML = `<div style="padding:20px;text-align:center;color:#484f58;font-size:12px">Sin alertas recientes</div>`;
    return;
  }
  panel.innerHTML = recent.map(a => {
    const { icon, cls } = alertMeta(a.event);
    return `
      <div class="alert-item" onclick="navigateTo('alerts')">
        <div class="alert-icon ${cls}"><i class="${icon}"></i></div>
        <div class="alert-content">
          <div class="alert-title">${fmtEvent(a.event)}</div>
          <div class="alert-desc">${alertDesc(a)}</div>
        </div>
        <div class="alert-time">${a.timestamp}</div>
      </div>`;
  }).join('');
}

// ============================================================
// TABLES
// ============================================================
function renderDevicesTable(devices) {
  const html = buildDevicesHtml(devices);
  ['devices-tbody','devices-tbody-full'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  });
  // update filters cache
  if (window._devicesCache !== undefined) window._devicesCache = devices;
}

function buildDevicesHtml(devices) {
  if (!devices || devices.length === 0)
    return `<tr><td colspan="6" style="text-align:center;padding:24px;color:#484f58;font-size:12px">Sin dispositivos registrados</td></tr>`;

  return [...devices].reverse().map(d => {
    const badge = d.approved
      ? `<span class="badge approved"><span class="badge-dot"></span>Autorizado</span>`
      : `<span class="badge blocked"><span class="badge-dot"></span>Bloqueado</span>`;

    const btn = !d.approved
      ? `<button class="btn-approve" onclick="doApprove('${d.mac_src}')"><i class="fas fa-check"></i> Aprobar</button>`
      : `<span style="color:#484f58;font-size:11px;font-family:monospace">—</span>`;

    return `
      <tr>
        <td class="td-name">
          <div class="td-device">
            <span class="device-icon"><i class="fas fa-network-wired"></i></span>
            ${d.mac_src || '—'}
          </div>
        </td>
        <td>${d.mac_dst || '—'}</td>
        <td>${d.event  || '—'}</td>
        <td>${d.timestamp || '—'}</td>
        <td>${badge}</td>
        <td>${btn}</td>
      </tr>`;
  }).join('');
}

function renderAlertsTable(alerts) {
  const tbody = document.getElementById('alerts-tbody');
  if (!tbody) return;
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:24px;color:#484f58;font-size:12px">Sin alertas registradas</td></tr>`;
    return;
  }
  tbody.innerHTML = [...alerts].reverse().map(a => {
    const { badgeCls } = alertMeta(a.event);
    return `
      <tr>
        <td><span class="alert-type-badge ${badgeCls}">${a.event}</span></td>
        <td>${a.ip_src || '<span style="color:#484f58">—</span>'}</td>
        <td>${alertDetail(a)}</td>
        <td>${a.timestamp}</td>
        <td><span class="badge warning"><span class="badge-dot"></span>Activa</span></td>
      </tr>`;
  }).join('');
}

// ============================================================
// HELPERS
// ============================================================
function alertMeta(event) {
  const m = {
    DOS_ATTACK: { icon:'fas fa-bolt',        cls:'red',    badgeCls:'dos'       },
    SYN_FLOOD:  { icon:'fas fa-water',       cls:'yellow', badgeCls:'syn'       },
    PORT_SCAN:  { icon:'fas fa-magnifying-glass', cls:'purple', badgeCls:'port' },
    NEW_DEVICE: { icon:'fas fa-satellite-dish', cls:'blue', badgeCls:'new_device' },
    MOTION:     { icon:'fas fa-person-running', cls:'blue', badgeCls:'motion'  },
  };
  return m[event] || { icon:'fas fa-bell', cls:'blue', badgeCls:'info' };
}

function alertDesc(a) {
  if (a.event === 'DOS_ATTACK') return `IP: ${a.ip_src||'?'} — ${a.packets??'?'} paquetes`;
  if (a.event === 'SYN_FLOOD')  return `IP: ${a.ip_src||'?'} — ${a.syn_packets??'?'} SYN pkts`;
  if (a.event === 'PORT_SCAN')  return `IP: ${a.ip_src||'?'} — ${(a.ports_detected||[]).length} puertos`;
  if (a.event === 'NEW_DEVICE') return `IP: ${a.ip_src||'Asignando...'}`;
  return `IP: ${a.ip_src||'—'}`;
}

function alertDetail(a) {
  if (a.event === 'DOS_ATTACK') return `<span style="color:#f85149;font-family:monospace">${a.packets} pkts</span>`;
  if (a.event === 'SYN_FLOOD')  return `<span style="color:#d29922;font-family:monospace">${a.syn_packets} SYN pkts</span>`;
  if (a.event === 'PORT_SCAN') {
    const p = (a.ports_detected||[]).slice(0,5).join(', ');
    return `<span style="color:#a371f7;font-family:monospace">${p}${(a.ports_detected||[]).length>5?'…':''}</span>`;
  }
  return `<span style="color:#484f58">—</span>`;
}

function fmtEvent(ev) {
  return { DOS_ATTACK:'Ataque DoS', SYN_FLOOD:'SYN Flood', PORT_SCAN:'Escaneo de Puertos', NEW_DEVICE:'Nuevo Dispositivo', MOTION:'Movimiento' }[ev] || ev;
}
