// ============================================================
// FILTER STATE
// ============================================================
window._devicesCache  = [];
window._alertsCache   = [];
let _deviceFilter     = 'all';
let _alertTypeFilter  = 'ALL';

// ============================================================
// DEVICE FILTERS
// ============================================================
function filterDevicesByStatus(status) {
  _deviceFilter = status;
  document.querySelectorAll('.filter-btn[data-dev-filter]').forEach(b => {
    b.classList.toggle('active', b.dataset.devFilter === status);
  });
  applyDeviceFilters();
}

function filterDevicesTable() { applyDeviceFilters(); }

function applyDeviceFilters() {
  const q = (document.getElementById('device-search')?.value || '').toLowerCase();
  let list = window._devicesCache || [];
  if (_deviceFilter === 'approved') list = list.filter(d =>  d.approved);
  if (_deviceFilter === 'blocked')  list = list.filter(d => !d.approved);
  if (q) list = list.filter(d =>
    (d.mac_src||'').toLowerCase().includes(q) ||
    (d.mac_dst||'').toLowerCase().includes(q) ||
    (d.event  ||'').toLowerCase().includes(q)
  );
  const html = buildDevicesHtml(list);
  ['devices-tbody','devices-tbody-full'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  });
}

// ============================================================
// ALERT FILTERS
// ============================================================
function filterAlertsByType(type) {
  _alertTypeFilter = type;
  document.querySelectorAll('.filter-btn[data-alert-filter]').forEach(b => {
    b.classList.toggle('active', b.dataset.alertFilter === type);
  });
  applyAlertFilters();
}

function filterAlertsTable() { applyAlertFilters(); }

function applyAlertFilters() {
  const q = (document.getElementById('alert-search')?.value || '').toLowerCase();
  let list = window._alertsCache || [];
  if (_alertTypeFilter !== 'ALL') list = list.filter(a => a.event === _alertTypeFilter);
  if (q) list = list.filter(a =>
    (a.event  ||'').toLowerCase().includes(q) ||
    (a.ip_src ||'').toLowerCase().includes(q) ||
    (a.timestamp||'').toLowerCase().includes(q)
  );
  renderAlertsFiltered(list);
}

function renderAlertsFiltered(alerts) {
  const tbody = document.getElementById('alerts-tbody');
  if (!tbody) return;
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:24px;color:#484f58;font-size:12px">Sin resultados</td></tr>`;
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
// Hook into render functions to cache data
// ============================================================
const _origRenderDevices = window.renderDevicesTable;
window.renderDevicesTable = function(devices) {
  window._devicesCache = devices || [];
  _origRenderDevices(devices);
};

const _origRenderAlerts = window.renderAlertsTable;
window.renderAlertsTable = function(alerts) {
  window._alertsCache = alerts || [];
  if (_alertTypeFilter === 'ALL' && !(document.getElementById('alert-search')?.value))
    _origRenderAlerts(alerts);
  else
    applyAlertFilters();
};
