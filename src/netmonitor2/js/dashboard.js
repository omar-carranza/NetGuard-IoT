// ============================================================
// CHARTS
// ============================================================
let trafficChart = null;
let donutChart   = null;

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
          borderWidth: 1.5, fill: true, tension: 0.4,
          pointRadius: 0, pointHoverRadius: 3,
        },
        {
          label: 'Entrada (Mbps)',
          data: [],
          borderColor: '#3fb950',
          backgroundColor: 'rgba(63,185,80,0.04)',
          borderWidth: 1.5, fill: true, tension: 0.4,
          pointRadius: 0, pointHoverRadius: 3,
        },
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 200 },
      interaction: { intersect: false, mode: 'index' },
      plugins: {
        legend: {
          display: true,
          labels: { color: '#8b949e', font: { family: 'Roboto Mono', size: 11 }, boxWidth: 10, padding: 14 }
        },
        tooltip: {
          backgroundColor: '#161b22', borderColor: '#30363d', borderWidth: 1,
          titleColor: '#8b949e', bodyColor: '#e6edf3',
          titleFont: { family: 'Roboto Mono', size: 10 },
          bodyFont:  { family: 'Roboto Mono', size: 12 },
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
          border: { display: false }, min: 0,
        }
      }
    }
  });
}

// ── Donut: HTTP / TCP / UDP / Otros ──────────────────────
const DONUT_COLORS = ['#4493f8', '#3fb950', '#d29922', '#484f58'];
const DONUT_LABELS = ['HTTP', 'TCP', 'UDP', 'Otros'];

function initDonutChart() {
  const ctx = document.getElementById('donutChart');
  if (!ctx) return;
  donutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: DONUT_LABELS,
      datasets: [{
        data: [25, 25, 25, 25],   // placeholder hasta recibir datos
        backgroundColor: DONUT_COLORS,
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
          bodyFont:  { family: 'Roboto Mono', size: 12 },
          padding: 10,
          callbacks: { label: c => ` ${c.label}: ${c.parsed.toFixed(1)}%` }
        }
      }
    }
  });
}

// ── Update donut from /protocol-stats ───────────────────
function updateDonutChart(stats) {
  if (!donutChart || !stats) return;

  const http  = stats.http  || 0;
  const tcp   = stats.tcp   || 0;
  const udp   = stats.udp   || 0;
  const other = stats.other || 0;
  const total = stats.total || 0;

  donutChart.data.datasets[0].data = [http, tcp, udp, other];
  donutChart.update('none');

  // Legend
  updateDonutLegend({ http, tcp, udp, other, total });

  // Center
  const center = document.getElementById('donut-center-val');
  if (center) center.textContent = total > 0 ? `${total} pkts` : '—';
}

function updateDonutLegend({ http, tcp, udp, other, total }) {
  const items = [
    { id: 'legend-http',  val: http,  color: '#4493f8' },
    { id: 'legend-tcp',   val: tcp,   color: '#3fb950' },
    { id: 'legend-udp',   val: udp,   color: '#d29922' },
    { id: 'legend-other', val: other, color: '#484f58' },
  ];
  items.forEach(({ id, val, color }) => {
    const el = document.getElementById(id);
    if (el) { el.textContent = `${val.toFixed(1)}%`; el.style.color = color; }
  });
  const sub = document.getElementById('legend-total');
  if (sub && total > 0) sub.textContent = `${total} paquetes`;
}

// ============================================================
// TRAFFIC CHART UPDATE
// ============================================================
function updateTrafficChart(traffic) {
  if (!trafficChart) return;
  const history = traffic.history || [];
  if (history.length === 0) return;
  trafficChart.data.labels           = history.map(h => h.label);
  trafficChart.data.datasets[0].data = history.map(h => h.mbps_out);
  trafficChart.data.datasets[1].data = history.map(h => h.mbps_in);
  trafficChart.update('none');
}

// ============================================================
// STATS UPDATE
// ============================================================
function updateStats(alerts, devices, traffic) {
  // Dispositivos APROBADOS solamente
  const approved = devices.filter(d => d.approved || d.status === 'approved').length;
  const pending  = devices.filter(d => d.status === 'pending').length;
  setStatText('stat-devices', approved);
  setStatText('stat-pending', pending > 0 ? `+${pending} pendiente${pending > 1 ? 's' : ''}` : '');

  setStatText('stat-alerts', alerts.length);

  if (traffic.total_tb >= 1) {
    setStatText('stat-traffic', traffic.total_tb.toFixed(2) + ' TB');
  } else {
    setStatText('stat-traffic', traffic.total_gb.toFixed(1) + ' GB');
  }

  const mbps = traffic.current_mbps || 0;
  setStatText('stat-bandwidth', mbps.toFixed(1) + ' Mbps');

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
// ALERTS PANEL
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
// DEVICE TABLE
// ============================================================
function renderDevicesTable(devices) {
  const html = buildDevicesHtml(devices);
  ['devices-tbody', 'devices-tbody-full'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  });
  if (window._devicesCache !== undefined) window._devicesCache = devices;
}

function buildDevicesHtml(devices) {
  if (!devices || devices.length === 0)
    return `<tr><td colspan="5" style="text-align:center;padding:24px;color:#484f58;font-size:12px">Sin dispositivos registrados</td></tr>`;

  return [...devices].reverse().map(d => {
    const mac = d.mac_src || '—';
    const ip  = d.ip_src  || '—';

    let statusBadge;
    if (d.status === 'approved' || d.approved) {
      statusBadge = `<span class="badge approved"><span class="badge-dot"></span>Autorizado</span>`;
    } else if (d.status === 'ignored') {
      statusBadge = `<span class="badge" style="background:rgba(72,79,88,.15);color:#484f58">Ignorado</span>`;
    } else {
      statusBadge = `<span class="badge warning"><span class="badge-dot"></span>Pendiente</span>`;
    }

    let actionBtn;
    if (d.status === 'pending' && !d.approved) {
      actionBtn = `
        <button class="btn-approve" onclick="doApprove('${mac}')"><i class="fas fa-check"></i> Aprobar</button>
        <button class="btn-ignore" onclick="doIgnore('${mac}')" style="margin-left:4px;padding:4px 8px;background:rgba(72,79,88,.1);border:1px solid #30363d;border-radius:5px;color:#8b949e;font-family:'Roboto Mono',monospace;font-size:11px;cursor:pointer"><i class="fas fa-ban"></i></button>`;
    } else {
      actionBtn = `<span style="color:#484f58;font-size:11px;font-family:monospace">—</span>`;
    }

    return `
      <tr>
        <td class="td-name">
          <div class="td-device">
            <span class="device-icon"><i class="fas fa-network-wired"></i></span>${mac}
          </div>
        </td>
        <td>${ip}</td>
        <td>${d.timestamp || '—'}</td>
        <td>${statusBadge}</td>
        <td>${actionBtn}</td>
      </tr>`;
  }).join('');
}

// ── Alerts Table ─────────────────────────────────────────
function renderAlertsTable(alerts) {
  const tbody = document.getElementById('alerts-tbody');
  if (!tbody) return;
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:24px;color:#484f58;font-size:12px">Sin alertas</td></tr>`;
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
    DOS_ATTACK: { icon:'fas fa-bolt',             cls:'red',    badgeCls:'dos'        },
    SYN_FLOOD:  { icon:'fas fa-water',            cls:'yellow', badgeCls:'syn'        },
    PORT_SCAN:  { icon:'fas fa-magnifying-glass', cls:'purple', badgeCls:'port'       },
    NEW_DEVICE: { icon:'fas fa-satellite-dish',   cls:'blue',   badgeCls:'new_device' },
    MOTION:     { icon:'fas fa-person-running',   cls:'blue',   badgeCls:'motion'     },
  };
  return m[event] || { icon:'fas fa-bell', cls:'blue', badgeCls:'info' };
}

function alertDesc(a) {
  if (a.event === 'DOS_ATTACK') return `IP: ${a.ip_src||'?'} — ${a.packets??'?'} paquetes`;
  if (a.event === 'SYN_FLOOD')  return `IP: ${a.ip_src||'?'} — ${a.syn_packets??'?'} SYN pkts`;
  if (a.event === 'PORT_SCAN')  return `IP: ${a.ip_src||'?'} — ${(a.ports_detected||[]).length} puertos`;
  if (a.event === 'NEW_DEVICE') return `IP: ${a.ip_src||'—'}`;
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
  return { DOS_ATTACK:'Ataque DoS', SYN_FLOOD:'SYN Flood', PORT_SCAN:'Escaneo de Puertos',
           NEW_DEVICE:'Nuevo Dispositivo', MOTION:'Movimiento' }[ev] || ev;
}
