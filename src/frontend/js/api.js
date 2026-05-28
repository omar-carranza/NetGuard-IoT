// ============================================================
// API CONFIG
// ============================================================
const API_BASE = 'http://localhost:5000';
const POLL_MS  = 3000;

let seenAlertKeys  = new Set();
let pollingActive  = false;
let pollTimer      = null;

// ============================================================
// FETCH
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
    const [alerts, devices, traffic] = await Promise.all([
      apiFetch('/alerts'),
      apiFetch('/devices'),
      apiFetch('/traffic?limit=60'),
    ]);

    setConnected(true);

    // Check new alerts (only after first load)
    alerts.forEach(a => {
      const key = `${a.event}_${a.timestamp}_${a.ip_src}`;
      if (!seenAlertKeys.has(key)) {
        seenAlertKeys.add(key);
        if (pollingActive) handleNewAlert(a);
      }
    });

    // Update UI
    updateStats(alerts, devices, traffic);
    updateTrafficChart(traffic);
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
// SWEETALERT2 — Alertas únicas por tipo
// ============================================================
function handleNewAlert(alert) {
  switch (alert.event) {
    case 'DOS_ATTACK':  showDosAlert(alert);    break;
    case 'SYN_FLOOD':   showSynFloodAlert(alert); break;
    case 'PORT_SCAN':   showPortScanAlert(alert); break;
    case 'NEW_DEVICE':  showNewDeviceAlert(alert); break;
    default:            showGenericAlert(alert);
  }
  flashAlertBadge();
}

const SWAL_DEFAULTS = {
  background: '#1c2128',
  color: '#e6edf3',
  customClass: { popup: 'swal-dark' },
  confirmButtonColor: '#4493f8',
  cancelButtonColor: '#30363d',
};

function showDosAlert(a) {
  Swal.fire({
    ...SWAL_DEFAULTS,
    icon: 'error',
    title: 'DOS ATTACK Detectado',
    html: alertHtml([
      ['IP Origen',  a.ip_src  || '—', '#f85149'],
      ['Paquetes',   a.packets ?? '—', '#f85149'],
      ['Timestamp',  a.timestamp,      '#8b949e'],
    ], 'Volumen anormal de tráfico. Posible denegación de servicio.'),
    confirmButtonText: 'Entendido',
    confirmButtonColor: '#f85149',
    showCancelButton: true,
    cancelButtonText: 'Ver Alertas',
  }).then(r => { if (r.dismiss === Swal.DismissReason.cancel) navigateTo('alerts'); });
}

function showSynFloodAlert(a) {
  Swal.fire({
    ...SWAL_DEFAULTS,
    icon: 'warning',
    title: 'SYN Flood Detectado',
    html: alertHtml([
      ['IP Origen',   a.ip_src      || '—', '#d29922'],
      ['SYN pkts',    a.syn_packets ?? '—', '#d29922'],
      ['Timestamp',   a.timestamp,          '#8b949e'],
    ], 'Inundación de paquetes SYN. Posible saturación de conexiones TCP.'),
    confirmButtonText: 'Entendido',
    confirmButtonColor: '#d29922',
    showCancelButton: true,
    cancelButtonText: 'Ver Alertas',
  }).then(r => { if (r.dismiss === Swal.DismissReason.cancel) navigateTo('alerts'); });
}

function showPortScanAlert(a) {
  const ports = (a.ports_detected || []).slice(0, 12);
  const portsHtml = ports.map(p =>
    `<span style="background:#21262d;padding:2px 6px;border-radius:4px;margin:2px;display:inline-block;color:#a371f7;font-family:monospace">${p}</span>`
  ).join('');

  Swal.fire({
    ...SWAL_DEFAULTS,
    icon: 'info',
    title: 'Port Scan Detectado',
    html: `
      <div style="font-size:13px;color:#8b949e;text-align:left">
        <div style="background:#161b22;padding:12px;border-radius:6px;border:1px solid #30363d;margin-bottom:10px;line-height:2">
          <div><span style="color:#484f58">IP Origen:</span> <b style="color:#a371f7">${a.ip_src || '—'}</b></div>
          <div><span style="color:#484f58">Puertos (${(a.ports_detected||[]).length}):</span></div>
          <div style="margin-top:4px">${portsHtml}</div>
          <div style="margin-top:6px"><span style="color:#484f58">Timestamp:</span> ${a.timestamp}</div>
        </div>
        <div style="color:#c0c0c0;font-size:12px">Escaneo activo detectado. Posible reconocimiento de la red.</div>
      </div>`,
    confirmButtonText: 'Entendido',
    confirmButtonColor: '#a371f7',
    showCancelButton: true,
    cancelButtonText: 'Ver Alertas',
  }).then(r => { if (r.dismiss === Swal.DismissReason.cancel) navigateTo('alerts'); });
}

function showNewDeviceAlert(a) {
  Swal.fire({
    ...SWAL_DEFAULTS,
    icon: 'question',
    title: 'Nuevo Dispositivo Detectado',
    html: alertHtml([
      ['IP',         a.ip_src || 'Asignando...', '#4493f8'],
      ['Timestamp',  a.timestamp,                '#8b949e'],
    ], 'Se detectó un dispositivo nuevo en la red.'),
    confirmButtonText: 'Ver Dispositivos',
    confirmButtonColor: '#4493f8',
    showCancelButton: true,
    cancelButtonText: 'Ignorar',
  }).then(r => { if (r.isConfirmed) navigateTo('devices'); });
}

function showGenericAlert(a) {
  Swal.fire({
    ...SWAL_DEFAULTS,
    icon: 'info',
    title: a.event || 'Alerta',
    html: `<pre style="background:#161b22;padding:10px;border-radius:6px;text-align:left;font-size:12px;color:#8b949e;overflow:auto">${JSON.stringify(a, null, 2)}</pre>`,
    confirmButtonText: 'OK',
  });
}

// Helper HTML para filas de datos
function alertHtml(rows, note) {
  const rowsHtml = rows.map(([label, val, color]) =>
    `<div><span style="color:#484f58">${label}:</span> <b style="color:${color}">${val}</b></div>`
  ).join('');
  return `
    <div style="font-size:13px;color:#8b949e;text-align:left">
      <div style="background:#161b22;padding:12px;border-radius:6px;border:1px solid #30363d;margin-bottom:10px;line-height:2.1">
        ${rowsHtml}
      </div>
      <div style="color:#c0c0c0;font-size:12px">${note}</div>
    </div>`;
}

function flashAlertBadge() {
  const b = document.getElementById('nav-alerts-badge');
  if (!b) return;
  b.style.transform = 'scale(1.4)';
  b.style.transition = 'transform 0.2s';
  setTimeout(() => { b.style.transform = 'scale(1)'; }, 300);
}

// ============================================================
// APPROVE DEVICE  (SweetAlert confirm)
// ============================================================
async function doApprove(mac) {
  const result = await Swal.fire({
    ...SWAL_DEFAULTS,
    icon: 'question',
    title: 'Autorizar Dispositivo',
    html: `<div style="font-size:13px;color:#8b949e">¿Agregar <b style="color:#4493f8;font-family:monospace">${mac}</b> a la lista de MACs autorizadas?</div>`,
    confirmButtonText: 'Sí, Autorizar',
    confirmButtonColor: '#3fb950',
    showCancelButton: true,
    cancelButtonText: 'Cancelar',
  });

  if (!result.isConfirmed) return;

  try {
    await apiPost('/approve', { mac });
    Swal.fire({
      ...SWAL_DEFAULTS,
      icon: 'success',
      title: 'Dispositivo Autorizado',
      html: `<div style="font-size:13px;color:#8b949e">MAC <b style="color:#3fb950;font-family:monospace">${mac}</b> agregada correctamente.</div>`,
      timer: 2000,
      timerProgressBar: true,
      showConfirmButton: false,
    });
  } catch (e) {
    Swal.fire({
      ...SWAL_DEFAULTS,
      icon: 'error',
      title: 'Error',
      text: `No se pudo conectar con la API: ${e.message}`,
    });
  }
}

window.doApprove = doApprove;

window.NetAPI = { startPolling, apiFetch, apiPost, API_BASE };
