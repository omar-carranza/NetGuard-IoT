// ============================================================
// NAVIGATION
// ============================================================
function navigateTo(section) {
  document.querySelectorAll('.nav-item[data-section]').forEach(el => {
    el.classList.toggle('active', el.dataset.section === section);
  });
  document.querySelectorAll('.page-section').forEach(el => {
    el.classList.toggle('active', el.id === `section-${section}`);
  });

  const titles = {
    dashboard: { title: 'Dashboard',     sub: 'Resumen general del estado de la red' },
    devices:   { title: 'Dispositivos',  sub: 'Gestión y monitoreo de dispositivos conectados' },
    alerts:    { title: 'Alertas',        sub: 'Registro de eventos de seguridad detectados' },
  };
  const info = titles[section] || titles.dashboard;
  const t = document.getElementById('topbar-title');
  const s = document.getElementById('topbar-sub');
  if (t) t.textContent = info.title;
  if (s) s.textContent = info.sub;
  window._activeSection = section;
}

// Datetime
function updateDateTime() {
  const el = document.getElementById('datetime-display');
  if (!el) return;
  el.textContent = new Date().toLocaleString('es-MX', {
    day:'2-digit', month:'short', year:'numeric',
    hour:'2-digit', minute:'2-digit',
  });
}

// Uptime from page load
const _startTime = Date.now();
function updateUptime() {
  const el = document.getElementById('uptime-display');
  if (!el) return;
  const s = Math.floor((Date.now() - _startTime) / 1000);
  const h = String(Math.floor(s/3600)).padStart(2,'0');
  const m = String(Math.floor((s%3600)/60)).padStart(2,'0');
  const ss = String(s%60).padStart(2,'0');
  el.textContent = `${h}h ${m}m ${ss}s`;
}

// Last update clock
function updateLastUpdate() {
  const el = document.getElementById('last-update');
  if (!el) return;
  el.textContent = new Date().toLocaleTimeString('es-MX');
}

// Refresh button
function bindRefresh() {
  const btn = document.getElementById('refresh-btn');
  if (!btn) return;
  btn.addEventListener('click', () => {
    btn.classList.add('spinning');
    setTimeout(() => btn.classList.remove('spinning'), 800);
  });
}

// ============================================================
// INIT
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  // Nav clicks
  document.querySelectorAll('.nav-item[data-section]').forEach(el => {
    el.addEventListener('click', () => navigateTo(el.dataset.section));
  });

  // data-goto links
  document.querySelectorAll('[data-goto]').forEach(el => {
    el.addEventListener('click', e => { e.preventDefault(); navigateTo(el.dataset.goto); });
  });

  initCharts();
  updateDateTime();
  setInterval(updateDateTime,   30_000);
  setInterval(updateUptime,      1_000);
  setInterval(updateLastUpdate,  1_000);
  updateUptime();
  updateLastUpdate();
  bindRefresh();
  NetAPI.startPolling();
  navigateTo('dashboard');
});

window.navigateTo = navigateTo;
