// ============================================================
// API CONFIG
// ============================================================
const API_BASE = 'http://localhost:5000';
const POLL_MS  = 3000;

let seenAlertKeys    = new Set();
let seenDeviceMACs   = new Set();   // MACs ya procesadas con SweetAlert
let pollingActive    = false;
let pollTimer        = null;

// ============================================================
// FETCH HELPERS
// ============================================================
async function apiFetch(path) {
  const r = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' }
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

async function apiPost(path, body) {
  const r = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ============================================================
// CONNECTION INDICATOR
// ============================================================
function setConnected(ok) {
  document.querySelectorAll('.conn-bar').forEach(el => {
    if (ok) {
      el.className = 'conn-bar';
      el.innerHTML = `<span class="live-indicator"></span> Conectado`;
    } else {
      el.className = 'conn-bar disconnected';
      el.innerHTML = `<i class="fas fa-circle-exclamation"></i> Sin conexión — ${API_BASE}`;
    }
  });
}

// ============================================================
// POLL LOOP
// ============================================================
async function pollLoop() {
  try {
    const [alerts, devices, traffic, protoStats] = await Promise.all([
      apiFetch('/alerts'),
      apiFetch('/devices'),
      apiFetch('/traffic?limit=60'),
      apiFetch('/protocol-stats'),
    ]);

    setConnected(true);

    // ── Alertas nuevas
    alerts.forEach(a => {
      const key = `${a.event}_${a.timestamp}_${a.ip_src}`;
      if (!seenAlertKeys.has(key)) {
        seenAlertKeys.add(key);
        if (pollingActive) handleNewAlert(a);
      }
    });

    // ── Dispositivos nuevos en estado pending
    if (pollingActive) {
      devices.forEach(d => {
        if (d.status === 'pending' && !seenDeviceMACs.has(d.mac_src)) {
          seenDeviceMACs.add(d.mac_src);
          showNewDevicePrompt(d);
        }
      });
    } else {
      // primera carga: marcar todos los vistos para no disparar retroactivamente
      devices.forEach(d => seenDeviceMACs.add(d.mac_src));
    }

    updateStats(alerts, devices, traffic);
    updateTrafficChart(traffic);
    updateDonutChart(protoStats);
    renderDevicesTable(devices);
    renderAlertsTable(alerts);
    updateAlertsPanel(alerts);
    updateNavBadge(alerts.length);

    pollingActive = true;

  } catch (e) {
    setConnected(false);
  }

  pollTimer = setTimeout(pollLoop, POLL_MS);
}

function startPolling() {
  if (pollTimer) clearTimeout(pollTimer);
  pollLoop();
}

// ============================================================
// NUEVO DISPOSITIVO — SweetAlert Aceptar / Ignorar
// ============================================================
function showNewDevicePrompt(device) {
  const mac   = device.mac_src   || '—';
  const ip    = device.ip_src    || 'Desconocida';
  const ts    = device.timestamp || '—';
  const event = device.event     || 'NEW_DEVICE';

  Swal.fire({
    background: '#1c2128',
    color: '#e6edf3',
    icon: 'question',
    title: 'Nuevo dispositivo detectado',
    html: `
      <div style="font-size:13px;color:#8b949e;text-align:left">
        <table style="width:100%;border-collapse:collapse;font-family:'Roboto Mono',monospace">
          <tr style="border-bottom:1px solid #21262d">
            <td style="padding:8px 6px;color:#484f58;font-size:11px;text-transform:uppercase;letter-spacing:.5px">IP</td>
            <td style="padding:8px 6px;color:#4493f8;font-weight:600">${ip}</td>
          </tr>
          <tr style="border-bottom:1px solid #21262d">
            <td style="padding:8px 6px;color:#484f58;font-size:11px;text-transform:uppercase;letter-spacing:.5px">MAC</td>
            <td style="padding:8px 6px;color:#e6edf3;font-weight:600">${mac}</td>
          </tr>
          <tr style="border-bottom:1px solid #21262d">
            <td style="padding:8px 6px;color:#484f58;font-size:11px;text-transform:uppercase;letter-spacing:.5px">Timestamp</td>
            <td style="padding:8px 6px;color:#e6edf3">${ts}</td>
          </tr>
          <tr>
            <td style="padding:8px 6px;color:#484f58;font-size:11px;text-transform:uppercase;letter-spacing:.5px">Estado</td>
            <td style="padding:8px 6px">
              <span style="background:rgba(210,153,34,.12);color:#d29922;border:1px solid rgba(210,153,34,.25);
                           padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600">⏳ Pendiente</span>
            </td>
          </tr>
        </table>
        <div style="margin-top:12px;font-size:12px;color:#484f58">
          ¿Deseas autorizar este dispositivo en la red?
        </div>
      </div>`,
    showConfirmButton: true,
    showDenyButton: true,
    showCancelButton: false,
    confirmButtonText: '<i class="fas fa-check"></i> Aceptar',
    denyButtonText:    '<i class="fas fa-ban"></i> Ignorar',
    confirmButtonColor: '#3fb950',
    denyButtonColor:    '#484f58',
    customClass: { popup: 'swal-dark' },
    allowOutsideClick: false,
  }).then(async result => {
    if (result.isConfirmed) {
      await doApprove(mac, true);  // silent=true (no pregunta de nuevo)
    } else if (result.isDenied) {
      await doIgnore(mac);
    }
  });
}

// ============================================================
// APPROVE / IGNORE
// ============================================================
async function doApprove(mac, silent = false) {
  if (!silent) {
    const confirm = await Swal.fire({
      background: '#1c2128', color: '#e6edf3',
      icon: 'question',
      title: 'Autorizar dispositivo',
      html: `<div style="font-size:13px;color:#8b949e">¿Agregar <b style="color:#4493f8;font-family:monospace">${mac}</b> a la lista de MACs autorizadas?</div>`,
      confirmButtonText: 'Sí, Autorizar',
      confirmButtonColor: '#3fb950',
      showCancelButton: true,
      cancelButtonText: 'Cancelar',
      cancelButtonColor: '#30363d',
    });
    if (!confirm.isConfirmed) return;
  }

  try {
    await apiPost('/approve', { mac });
    Swal.fire({
      background: '#1c2128', color: '#e6edf3',
      icon: 'success',
      title: 'Dispositivo autorizado',
      html: `<div style="font-size:13px;color:#8b949e">
               MAC <b style="color:#3fb950;font-family:monospace">${mac}</b> agregada correctamente.
             </div>`,
      timer: 2200, timerProgressBar: true, showConfirmButton: false,
    });
  } catch (e) {
    Swal.fire({ background: '#1c2128', color: '#e6edf3', icon: 'error', title: 'Error', text: e.message });
  }
}

async function doIgnore(mac) {
  try {
    await apiPost('/ignore', { mac });
    Swal.fire({
      background: '#1c2128', color: '#e6edf3',
      icon: 'info',
      title: 'Dispositivo ignorado',
      html: `<div style="font-size:13px;color:#8b949e">
               MAC <b style="color:#8b949e;font-family:monospace">${mac}</b> marcada como ignorada.
             </div>`,
      timer: 1800, timerProgressBar: true, showConfirmButton: false,
    });
  } catch (e) {
    console.warn('[IGNORE ERROR]', e);
  }
}

// ============================================================
// SWEETALERT — Alertas de seguridad
// ============================================================
function handleNewAlert(alert) {
  switch (alert.event) {
    case 'DOS_ATTACK':  showDosAlert(alert);    break;
    case 'SYN_FLOOD':   showSynFloodAlert(alert); break;
    case 'PORT_SCAN':   showPortScanAlert(alert); break;
    default:            showGenericAlert(alert);
  }
  flashAlertBadge();
}

const SWAL_BASE = {
  background: '#1c2128',
  color: '#e6edf3',
  customClass: { popup: 'swal-dark' },
  confirmButtonColor: '#4493f8',
  cancelButtonColor: '#30363d',
};

function alertRowsHtml(rows, note) {
  const r = rows.map(([label, val, color]) =>
    `<div style="display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid #21262d">
       <span style="color:#484f58;font-size:11px;text-transform:uppercase;letter-spacing:.5px">${label}</span>
       <span style="color:${color};font-weight:600;font-family:'Roboto Mono',monospace">${val}</span>
     </div>`
  ).join('');
  return `
    <div style="font-size:13px;text-align:left">
      <div style="background:#161b22;padding:12px 14px;border-radius:6px;border:1px solid #21262d;margin-bottom:10px">${r}</div>
      <div style="color:#8b949e;font-size:12px">${note}</div>
    </div>`;
}

function showDosAlert(a) {
  Swal.fire({
    ...SWAL_BASE, icon: 'error', title: 'DOS Attack Detectado',
    html: alertRowsHtml([
      ['IP Origen', a.ip_src || '—', '#f85149'],
      ['Paquetes',  a.packets ?? '—', '#f85149'],
      ['Timestamp', a.timestamp, '#8b949e'],
    ], 'Volumen anormal de tráfico detectado. Posible ataque de denegación de servicio.'),
    confirmButtonText: 'Entendido', confirmButtonColor: '#f85149',
    showCancelButton: true, cancelButtonText: 'Ver Alertas',
  }).then(r => { if (r.dismiss === Swal.DismissReason.cancel) navigateTo('alerts'); });
}

function showSynFloodAlert(a) {
  Swal.fire({
    ...SWAL_BASE, icon: 'warning', title: 'SYN Flood Detectado',
    html: alertRowsHtml([
      ['IP Origen',  a.ip_src      || '—', '#d29922'],
      ['SYN Pkts',   a.syn_packets ?? '—', '#d29922'],
      ['Timestamp',  a.timestamp,          '#8b949e'],
    ], 'Inundación de paquetes SYN. Posible saturación de conexiones TCP.'),
    confirmButtonText: 'Entendido', confirmButtonColor: '#d29922',
    showCancelButton: true, cancelButtonText: 'Ver Alertas',
  }).then(r => { if (r.dismiss === Swal.DismissReason.cancel) navigateTo('alerts'); });
}

function showPortScanAlert(a) {
  const ports    = (a.ports_detected || []).slice(0, 12);
  const portsHtml = ports.map(p =>
    `<span style="background:#21262d;padding:2px 7px;border-radius:4px;margin:2px;display:inline-block;
                  color:#a371f7;font-family:monospace;font-size:11px">${p}</span>`
  ).join('');
  Swal.fire({
    ...SWAL_BASE, icon: 'info', title: 'Port Scan Detectado',
    html: `
      <div style="font-size:13px;text-align:left">
        <div style="background:#161b22;padding:12px 14px;border-radius:6px;border:1px solid #21262d;margin-bottom:10px">
          <div style="display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid #21262d">
            <span style="color:#484f58;font-size:11px;text-transform:uppercase;letter-spacing:.5px">IP Origen</span>
            <span style="color:#a371f7;font-weight:600;font-family:monospace">${a.ip_src || '—'}</span>
          </div>
          <div style="display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid #21262d">
            <span style="color:#484f58;font-size:11px;text-transform:uppercase;letter-spacing:.5px">Puertos (${(a.ports_detected||[]).length})</span>
            <div style="text-align:right">${portsHtml}</div>
          </div>
          <div style="display:flex;justify-content:space-between;padding:7px 0">
            <span style="color:#484f58;font-size:11px;text-transform:uppercase;letter-spacing:.5px">Timestamp</span>
            <span style="color:#8b949e;font-family:monospace">${a.timestamp}</span>
          </div>
        </div>
        <div style="color:#8b949e;font-size:12px">Escaneo activo de puertos. Posible reconocimiento de red.</div>
      </div>`,
    confirmButtonText: 'Entendido', confirmButtonColor: '#a371f7',
    showCancelButton: true, cancelButtonText: 'Ver Alertas',
  }).then(r => { if (r.dismiss === Swal.DismissReason.cancel) navigateTo('alerts'); });
}

function showGenericAlert(a) {
  Swal.fire({
    ...SWAL_BASE, icon: 'info', title: a.event || 'Alerta',
    html: `<pre style="background:#161b22;padding:10px;border-radius:6px;text-align:left;
                        font-size:12px;color:#8b949e;overflow:auto">${JSON.stringify(a, null, 2)}</pre>`,
    confirmButtonText: 'OK',
  });
}

function flashAlertBadge() {
  const b = document.getElementById('nav-alerts-badge');
  if (!b) return;
  b.style.transform  = 'scale(1.4)';
  b.style.transition = 'transform .2s';
  setTimeout(() => { b.style.transform = 'scale(1)'; }, 300);
}

window.doApprove = doApprove;
window.doIgnore  = doIgnore;
window.NetAPI    = { startPolling, apiFetch, apiPost, API_BASE };
