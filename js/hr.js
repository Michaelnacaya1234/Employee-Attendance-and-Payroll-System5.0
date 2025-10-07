const baseApiUrl = `${location.origin}/intro/api`;

/**
 * ENSURE SWEETALERT2 ASSETS ARE LOADED FOR HR PORTAL
 * Dynamically loads SweetAlert2 CSS and JavaScript with Tailwind compatibility fixes
 * Prevents duplicate loading and ensures proper initialization
 */
async function ensureSweetAlertAssetsHR(){
  try {
    if (window.__swalReadyHR) return;
    let pending = 0;
    const done = () => { pending = Math.max(0, pending - 1); if (pending === 0) window.__swalReadyHR = true; };
    if (!document.getElementById('swal2-css')){
      pending++;
      const link = document.createElement('link');
      link.id = 'swal2-css';
      link.rel = 'stylesheet';
      link.href = 'https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css';
      link.onload = done; link.onerror = done;
      document.head.appendChild(link);
    }
    if (!window.Swal){
      pending++;
      const s = document.createElement('script');
      s.id = 'swal2-js';
      s.src = 'https://cdn.jsdelivr.net/npm/sweetalert2@11';
      s.onload = done; s.onerror = done;
      document.head.appendChild(s);
    }
    // Tailwind reset fix for SweetAlert2 buttons and inputs
    if (!document.getElementById('swal2-tailwind-fix')){
      const st = document.createElement('style');
      st.id = 'swal2-tailwind-fix';
      st.textContent = `
        .swal2-styled{color:#fff !important;}
        .swal2-styled.swal2-confirm{background-color:#2563EB !important;border:0 !important;}
        .swal2-styled.swal2-cancel{background-color:#6B7280 !important;border:0 !important;}
        .swal2-select{background-color:#ffffff !important;color:#111827 !important;border:1px solid #d1d5db !important;border-radius:0.5rem !important;padding:0.5rem 0.75rem !important;}
      `;
      document.head.appendChild(st);
    }
    if (pending > 0){
      await new Promise((resolve) => {
        const iv = setInterval(() => { if (window.__swalReadyHR || window.Swal) { clearInterval(iv); window.__swalReadyHR = true; resolve(); } }, 30);
      });
    } else {
      window.__swalReadyHR = true;
    }
  } catch {}
}

/**
 * DISPLAY TOAST NOTIFICATION FOR HR INTERFACE
 * Shows temporary notification messages using SweetAlert2 toast
 * Supports multiple notification types (success, error, warning, info)
 */
function showSweetToastHR(message, type = 'info'){
  try {
    if (!window.Swal){ try { console.log(message); } catch {} return; }
    const icon = ['success','error','warning','info','question'].includes(String(type)) ? String(type) : 'info';
    const Toast = Swal.mixin({ toast: true, position: 'top-end', showConfirmButton: false, timer: 1500, timerProgressBar: true });
    Toast.fire({ icon, title: String(message || '') });
  } catch {}
}

/**
 * DELETE NOTIFICATION FROM HR SYSTEM
 * Removes notification via API and displays feedback toast
 * Returns boolean indicating operation success
 */
async function deleteNotificationHR(notificationId){
  try {
    const fd = new FormData();
    fd.append('operation', 'deleteNotification');
    fd.append('json', JSON.stringify({ notification_id: notificationId }));
    await axios.post(`${baseApiUrl}/notifications.php`, fd, { withCredentials: true });
    showSweetToastHR('Notification deleted', 'success');
    return true;
  } catch (err) {
    try { console.error('Failed to delete notification', err); } catch {}
    showSweetToastHR('Failed to delete notification', 'error');
    return false;
  }
}

function escapeHtmlHR(s){ return String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c])); }
function formatTimeHR(iso){ try { if (!iso) return ''; const d = new Date(iso); if (isNaN(d)) return String(iso); return d.toLocaleString('en-US', { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' }); } catch { return String(iso || ''); } }

/**
 * OPEN HR NOTIFICATIONS MODAL DIALOG
 * Displays all notifications in SweetAlert2 modal with interactive controls
 * Supports mark as read and delete operations for individual notifications
 */
async function openHrNotificationsSwal(){
  try { await ensureSweetAlertAssetsHR(); } catch {}
  if (!window.Swal) return;
  try {
    const resp = await axios.get(`${baseApiUrl}/notifications.php`, { params: { operation: 'getNotifications' }, withCredentials: true });
    const data = (resp && resp.data && (resp.data.notifications || resp.data)) || [];
    const notifications = Array.isArray(data) ? data : [];
    const content = notifications.length ? notifications.map(n => {
      const id = n.id || n.notification_id || n.notificationID || '';
      const msg = escapeHtmlHR(n.message || n.text || n.title || 'Notification');
      const whenRaw = n.created_at || n.createdAt || n.created || '';
      const unread = !n.read_at && !n.readAt && !n.read;
      return `
        <div class="sw-notif-item ${unread ? 'bg-blue-50' : 'bg-white'} rounded-lg border border-gray-200 p-3 mb-2">
          <div class="flex items-start gap-3">
            <div>
              <div class="text-sm text-gray-800">${msg}</div>
              <div class="mt-1 text-xs text-gray-500">${escapeHtmlHR(formatTimeHR(whenRaw))}</div>
            </div>
                      </div>
        </div>`;
    }).join('') : '<div class="text-sm text-gray-500">No notifications</div>';

    const hasUnread = notifications.some(n => !n.read_at && !n.readAt && !n.read);
    const result = await Swal.fire({
      title: 'Notifications',
      html: `<div class="text-left max-h-80 overflow-y-auto">${content}</div>`,
      showCloseButton: true,
      showCancelButton: true,
      cancelButtonText: 'Close',
      showConfirmButton: hasUnread,
      confirmButtonText: 'Mark all read',
      focusConfirm: false,
      didOpen: () => {
        const html = Swal.getHtmlContainer();
        if (!html) return;
      }
    });

    if (result.isConfirmed && hasUnread){
      try {
        const unread = notifications.filter(n => !n.read_at && !n.readAt && !n.read);
        await Promise.all(unread.map(n => markNotificationAsRead(n.id || n.notification_id || n.notificationID)));
        try { await renderHeaderNotifications(); } catch {}
        showSweetToastHR('All notifications marked as read', 'success');
      } catch { showSweetToastHR('Failed to mark all as read', 'error'); }
    }
  } catch (e) {
    try { console.error('Failed to load notifications', e); } catch {}
  }
}

/**
 * ATTACH NOTIFICATION CLICK HANDLER TO HR HEADER
 * Wires notification toggle button to open SweetAlert2 modal
 * Prevents duplicate event listener attachment
 */
function attachSweetHeaderNotifHR(){
  try {
    if (window.__hrSweetNotifWired) return; window.__hrSweetNotifWired = true;
    const btn = document.getElementById('notif-toggle');
    if (!btn) return;
    btn.addEventListener('click', async (e) => {
      e.stopImmediatePropagation();
      e.preventDefault();
      try { await ensureSweetAlertAssetsHR(); } catch {}
      const dropdown = document.getElementById('notif-dropdown');
      if (dropdown) { try { dropdown.classList.add('hidden'); } catch {} }
      await openHrNotificationsSwal();
    }, true); // capture phase to override any existing listeners
  } catch {}
}

// Wire SweetAlert2 notifications for HR on DOM ready
(function(){
  const run = async () => {
    try { await ensureSweetAlertAssetsHR(); } catch {}
    // Prevent legacy wiring if present
    try { window.__hrNotifHeaderWired = true; } catch {}
    try { attachSweetHeaderNotifHR(); } catch {}
    try { if (typeof renderHeaderNotifications === 'function') { await renderHeaderNotifications(); } } catch {}
    // Set up periodic badge refresh (single interval)
    try {
      if (window.__hrNotifInterval){ try { clearInterval(window.__hrNotifInterval); } catch {} }
      window.__hrNotifInterval = setInterval(async () => { try { await renderHeaderNotifications(); } catch {} }, 30000);
    } catch {}
  };
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', run); } else { run(); }
})();

/**
 * LOAD ANIME.JS ANIMATION LIBRARY FOR HR PORTAL
 * Dynamically imports anime.js for HR page animations
 * Returns anime instance or null if loading fails
 */
async function ensureAnimeHR(){
  return new Promise((resolve) => {
    if (window.anime) return resolve(window.anime);
    const s = document.createElement('script');
    s.src = 'https://cdnjs.cloudflare.com/ajax/libs/animejs/3.2.1/anime.min.js';
    s.async = true;
    s.onload = () => resolve(window.anime);
    s.onerror = () => resolve(null);
    document.head.appendChild(s);
  });
}

/**
 * STYLE HR NOTIFICATION HEADER BUTTON
 * Applies amber color theme to notification toggle and badge
 * Distinguishes HR interface from other user roles
 */
function styleHeaderNotif(){
  try {
    const btn = document.getElementById('notif-toggle');
    const badge = document.getElementById('notif-badge');
    if (btn) {
      btn.classList.add('bg-amber-50','ring-amber-200','hover:bg-amber-100');
      btn.classList.remove('ring-gray-200','hover:bg-gray-50');
      const svg = btn.querySelector('svg');
      if (svg) {
        svg.classList.add('text-amber-600');
        svg.classList.remove('text-gray-600');
      }
    }
    if (badge) {
      badge.classList.add('bg-amber-600');
      badge.classList.remove('bg-red-600');
    }
  } catch {}
}
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', styleHeaderNotif);
} else {
  try { styleHeaderNotif(); } catch {}
}

/**
 * DISPLAY TOAST NOTIFICATION WITH TIMEOUT
 * Creates temporary notification messages with close button
 * Supports multiple types (success, warning, error, info) with auto-removal
 */
function showToast(message, type = 'info', timeout = 4000) {
  try {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      container.className = 'fixed top-4 right-4 z-[9999] space-y-2';
      document.body.appendChild(container);
    }
    
    const colors = {
      success: 'bg-green-600',
      warning: 'bg-amber-600', 
      error: 'bg-red-600',
      info: 'bg-blue-600'
    };
    
    const toast = document.createElement('div');
    toast.className = `${colors[type] || colors.info} text-white px-4 py-3 rounded-lg shadow-lg text-sm max-w-xs transform transition-all duration-300 translate-x-full`;
    toast.textContent = String(message);
    
    // Close button
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'ml-3 text-white/80 hover:text-white';
    close.innerHTML = '×';
    close.addEventListener('click', () => {
      toast.classList.add('translate-x-full');
      setTimeout(() => toast.remove(), 300);
    });
    
    toast.appendChild(close);
    container.appendChild(toast);
    
    // Animate in
    setTimeout(() => toast.classList.remove('translate-x-full'), 100);
    
    // Auto remove
    if (timeout > 0) {
      setTimeout(() => {
        toast.classList.add('translate-x-full');
        setTimeout(() => toast.remove(), 300);
      }, timeout);
    }
  } catch {}
}

// Make showToast globally available
window.showToast = showToast;

/**
 * CONVERT STRING TO TITLE CASE FORMAT
 * Capitalizes first letter of each word while preserving spaces and hyphens
 * Used for formatting display names and labels
 */
function toTitleCase(s){
  return String(s || '')
    .toLowerCase()
    .split(/([ -])/)
    .map(part => (/^[ -]$/.test(part) ? part : part.charAt(0).toUpperCase() + part.slice(1)))
    .join('');
}
/**
 * HR PORTAL ROUTING CONFIGURATION
 * Defines navigation routes and their corresponding render functions
 * Manages dynamic content loading for different HR sections
 */
const routes = {
  /**
   * RENDER HR DASHBOARD WITH ANALYTICS AND CALENDAR
   * Displays summary cards, attendance trends, and holiday calendar
   * Includes welcome header with personalized user information
   */
  dashboard: async () => {
    const app = document.getElementById('app');
    app.innerHTML = `
      <section class="mb-6">
        <div class="sticky top-0 z-10 relative overflow-hidden rounded-xl bg-gradient-to-r from-primary-700 to-primary-600 text-white shadow">
          <div class="absolute -right-16 -top-16 w-64 h-64 rounded-full bg-white/10"></div>
          <div class="p-6 flex items-center justify-between relative">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 rounded-full bg-white/20 flex items-center justify-center">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-6 h-6 text-white">
                  <path d="M12 12c2.21 0 4-1.79 4-4S14.21 4 12 4 8 5.79 8 8s1.79 4 4 4zm0 2c-3.33 0-8 1.67-8 5v1h16v-1c0-3.33-4.67-5-8-5z"/>
                </svg>
              </div>
              <div>
                <h1 class="text-2xl font-semibold">Welcome, <span id="welcome-name">HR</span></h1>
                <div class="mt-1 text-white/90 text-sm flex items-center gap-2">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-4 h-4"><path d="M12 8a1 1 0 011 1v3h3a1 1 0 110 2h-4a1 1 0 01-1-1V9a1 1 0 011-1z"/><path fill-rule="evenodd" d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zm0-18a8 8 0 100 16 8 8 0 000-16z" clip-rule="evenodd"/></svg>
                  <span id="welcome-date"></span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
      <section class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4 mb-4" id="summary-cards-top"></section>
      <section class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6" id="summary-cards-bottom"></section>

      <!-- HR Graphs -->
      <section class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div class="bg-white rounded-lg shadow p-4">
          <div class="flex items-center justify-between mb-3">
            <h3 class="font-semibold">Attendance Rate Trend (Last 30 Days)</h3>
          </div>
          <div class="h-64">
            <canvas id="hrAttendanceTrend"></canvas>
          </div>
        </div>
        <div class="bg-white rounded-lg shadow p-4">
          <div class="flex items-center justify-between mb-3">
            <h3 class="font-semibold">Absence by Department</h3>
          </div>
          <div class="h-64">
            <canvas id="hrAbsenceByDept"></canvas>
          </div>
        </div>
      </section>
            <!-- Holidays Calendar (Read-only) -->
      <section class="grid grid-cols-1 gap-4 mb-6">
        <div class="bg-white rounded-lg shadow p-4" id="holidays-calendar-card-hr">
          <div class="flex items-center justify-between mb-3">
            <h3 class="font-semibold">Calendar</h3>
            <div class="flex items-center gap-2">
              <button id="hr-cal-prev" class="px-2 py-1 text-xs border rounded">Prev</button>
              <div id="hr-cal-title" class="text-sm font-medium min-w-[8rem] text-center"></div>
              <button id="hr-cal-next" class="px-2 py-1 text-xs border rounded">Next</button>
            </div>
          </div>
          <div id="hr-calendar" class="grid grid-cols-7 gap-px bg-gray-200 rounded overflow-hidden text-xs"></div>
          <div class="text-[10px] text-gray-500 mt-2">Legend: <span class="inline-block w-3 h-3 bg-rose-500 align-middle mr-1"></span> Holiday • <span class="inline-block w-3 h-3 bg-primary-500 align-middle mr-1"></span> Today • <span class="inline-block w-3 h-3 bg-rose-200 align-middle mr-1"></span> Sun • <span class="inline-block w-3 h-3 bg-blue-200 align-middle mr-1"></span> Sat</div>
        </div>
      </section>
      <section class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
              </section>`;

    await renderSummaryCards();
    await renderHolidayCalendarHR();
    await renderHrAttendanceTrend();
    await renderHrAbsenceByDepartment();

    // Welcome header content
    try {
      const me = await currentUser();
      const welcomeNameEl = document.getElementById('welcome-name');
      if (welcomeNameEl && me) {
        const displayName = (() => {
          const first = (me.first_name || '').trim();
          const last = (me.last_name || '').trim();
          if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
          const u = (me.username || '').trim();
          if (u.includes('@')) return u.split('@')[0];
          return u || 'HR';
        })();
        welcomeNameEl.textContent = displayName;
      }
    } catch {}
    const dateEl = document.getElementById('welcome-date');
    if (dateEl) {
      if (window.__hrWelcomeInterval) { try { clearInterval(window.__hrWelcomeInterval); } catch {} }
      const tick = () => {
        const now = new Date();
        dateEl.textContent = now.toLocaleString('en-US');
      };
      tick();
      window.__hrWelcomeInterval = setInterval(tick, 1000);
    }

    // Auto rollover daily on HR dashboard: refresh attendance snapshot and charts when the date changes
    let __hrDashDayKey = new Date().toLocaleDateString('en-CA');
    function __hrMaybeRollover(){
      const d = new Date().toLocaleDateString('en-CA');
      if (d !== __hrDashDayKey) {
        __hrDashDayKey = d;
        try { renderSummaryCards(); } catch {}
        try { renderAttendanceSnapshot(); } catch {}
        try { renderHrAttendanceTrend(); } catch {}
        try { renderHrAbsenceByDepartment(); } catch {}
      }
    }
    try {
      setInterval(__hrMaybeRollover, 60000);
      window.addEventListener('focus', __hrMaybeRollover);
      document.addEventListener('visibilitychange', __hrMaybeRollover);
    } catch {}

    function monthNameHR(m){ return new Date(2000, m-1, 1).toLocaleString('en-US', { month: 'long' }); }
    async function renderHolidayCalendarHR(){
      const container = document.getElementById('hr-calendar');
      const title = document.getElementById('hr-cal-title');
      if (!container || !title) return;
      if (!window.__hrCalState){ const now = new Date(); window.__hrCalState = { year: now.getFullYear(), month: now.getMonth()+1 }; }
      const { year, month } = window.__hrCalState;
      title.textContent = `${monthNameHR(month)} ${year}`;
      // headers
      const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
      container.innerHTML = '';
      days.forEach(d => {
        const h = document.createElement('div');
        const isSun = d === 'Sun';
        const isSat = d === 'Sat';
        h.className = `p-2 text-center font-medium ${isSun ? 'bg-rose-100 text-rose-700' : isSat ? 'bg-blue-100 text-blue-700' : 'bg-gray-50 text-gray-600'}`;
        h.textContent = d;
        container.appendChild(h);
      });
      const first = new Date(year, month-1, 1);
      const startIdx = first.getDay();
      const daysInMonth = new Date(year, month, 0).getDate();
      const todayStr = new Date().toLocaleDateString('en-CA');
      // fetch
      let holidays = [];
      try {
        const res = await axios.get(`${baseApiUrl}/holidays.php`, { params: { operation: 'list', month, year } });
        holidays = Array.isArray(res.data) ? res.data : [];
      } catch {}
      const holiMap = new Map((holidays||[]).map(h => [String(h.holiday_date), h]));
      // blanks
      for (let i=0;i<startIdx;i++){
        const dayIdx = i % 7; // 0=Sun ... 6=Sat
        const isSun = dayIdx === 0;
        const isSat = dayIdx === 6;
        const cell = document.createElement('div');
        cell.className = `p-2 h-20 ${isSun ? 'bg-rose-50' : isSat ? 'bg-blue-50' : 'bg-white'}`;
        container.appendChild(cell);
      }
      // days
      for (let d=1; d<=daysInMonth; d++){
        const dateStr = `${year}-${String(month).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
        const isToday = dateStr === todayStr;
        const hol = holiMap.get(dateStr);
        const dayIdx = new Date(year, month-1, d).getDay(); // 0=Sun..6=Sat
        const isSun = dayIdx === 0;
        const isSat = dayIdx === 6;
        const cell = document.createElement('div');
        let cellCls = 'relative p-2 h-24 hover:bg-gray-50 cursor-pointer bg-white';
        if (isSun) cellCls = cellCls.replace('bg-white', 'bg-rose-50');
        else if (isSat) cellCls = cellCls.replace('bg-white', 'bg-blue-50');
        if (hol) cellCls += ' border-l-4 border-rose-400';
        cell.className = cellCls;
        cell.setAttribute('data-date', dateStr);
        const todayBadge = isToday ? '<span class="absolute top-1 right-1 text-[10px] px-1 py-0.5 rounded bg-primary-600 text-white">Today</span>' : '';
        if (isToday) { cell.className += ' bg-primary-50 ring-2 ring-primary-300'; }
        const dayNumCls = isSun ? 'text-rose-600' : (isSat ? 'text-blue-600' : 'text-gray-500');
        const topBarClass = hol ? 'bg-rose-500' : (isToday ? 'bg-primary-500' : (isSun ? 'bg-rose-300' : (isSat ? 'bg-blue-300' : 'bg-gray-200')));
        const topBarHtml = `<div class="absolute left-0 right-0 top-0 h-1 ${topBarClass}"></div>`;
        cell.innerHTML = `
          ${topBarHtml}
          <div class="text-[11px] ${dayNumCls}">${d}</div>
          ${hol ? `<div class=\"mt-1 text-[11px] px-1 py-0.5 rounded bg-rose-500 text-white inline-block\" title=\"${(hol.holiday_name||'').replace(/"/g,'&quot;')}${hol.description ? ' — ' + String(hol.description).replace(/"/g,'&quot;') : ''}\">${(hol.holiday_name||'').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>` : ''}
          ${todayBadge}`;
        if (hol) { cell.addEventListener('click', () => openHolidayViewHR(hol)); }
        container.appendChild(cell);
      }
      // Minimal calendar cell animation (match admin)
      try {
        const anime = await ensureAnimeHR();
        if (anime) {
          const dayCells = Array.from(container.querySelectorAll('[data-date]'));
          if (dayCells.length) {
            dayCells.forEach(c => { c.style.transformOrigin = '50% 50%'; });
            anime({
              targets: dayCells,
              translateY: [4, 0],
              scale: [0.99, 1],
              easing: 'easeOutQuad',
              duration: 280,
              delay: anime.stagger(8)
            });
            dayCells.forEach(cell => {
              cell.addEventListener('mouseenter', () => {
                anime.remove(cell);
                anime({ targets: cell, scale: 1.02, duration: 120, easing: 'easeOutQuad' });
              });
              cell.addEventListener('mouseleave', () => {
                anime.remove(cell);
                anime({ targets: cell, scale: 1.0, duration: 140, easing: 'easeOutQuad' });
              });
            });
          }
          if (title) {
            anime.remove(title);
            anime({ targets: title, translateX: [-6, 0], scale: [0.98, 1], duration: 220, easing: 'easeOutQuad' });
          }
        }
      } catch {}

      // controls
      const prev = document.getElementById('hr-cal-prev');
      const next = document.getElementById('hr-cal-next');
      if (prev && !prev.__wired){ prev.__wired = true; prev.addEventListener('click', async () => { let {year, month} = window.__hrCalState; month--; if (month===0){ month=12; year--; } window.__hrCalState = { year, month }; await renderHolidayCalendarHR(); }); }
      if (next && !next.__wired){ next.__wired = true; next.addEventListener('click', async () => { let {year, month} = window.__hrCalState; month++; if (month===13){ month=1; year++; } window.__hrCalState = { year, month }; await renderHolidayCalendarHR(); }); }
    }

    function openHolidayViewHR(row){
      try {
        let modal = document.getElementById('hrHolidayViewModal');
        if (!modal){
          modal = document.createElement('div');
          modal.id = 'hrHolidayViewModal';
          modal.className = 'fixed inset-0 z-50 hidden';
          document.body.appendChild(modal);
        }
        const esc = (s) => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        const date = String(row.holiday_date||'').slice(0,10);
        modal.innerHTML = `
          <div class="absolute inset-0 bg-black/50" data-close="true"></div>
          <div class="relative mx-auto mt-24 w-full max-w-md">
            <div class="bg-white rounded-lg shadow">
              <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold">Holiday Details</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
              <div class="p-4 text-sm space-y-2">
                <div><span class="text-gray-500">Date:</span> <span>${esc(date)}</span></div>
                <div><span class="text-gray-500">Holiday:</span> <span>${esc(row.holiday_name)}</span></div>
                <div><span class="text-gray-500">Description:</span><div class="mt-1 whitespace-pre-wrap">${esc(row.description)}</div></div>
              </div>
              <div class="flex justify-end gap-2 border-t px-4 py-3">
                <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
              </div>
            </div>
          </div>`;
        modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
        modal.classList.remove('hidden');
      } catch {}
    }

    async function renderSummaryCards(){
      const [summaryRes, payrollRes] = await Promise.all([
        axios.get(`${baseApiUrl}/reports.php`, { params: { operation: 'dashboardSummary' } }),
        axios.get(`${baseApiUrl}/reports.php`, { params: { operation: 'payrollSummary' } })
      ]);
      const s = summaryRes.data || { total_employees: 0, present_today: 0, pending_leaves: 0 };
      const p = payrollRes.data || { total_net_pay: 0 };

      // Recompute HR dashboard cards to include only active Manager and Employee roles (exclude all HR)
      const todayStr = new Date().toLocaleDateString('en-CA');
      const [empRes, attRes, leaveRes] = await Promise.all([
        axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
        axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: todayStr, end_date: todayStr } }),
        axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listApproved', start_date: todayStr, end_date: todayStr } })
      ]);
      const empList = Array.isArray(empRes.data) ? empRes.data : [];
      const allowed = empList.filter(e => {
        const role = String(e.user_role || e.role || '').toLowerCase();
        const st = String(e.status || '').toLowerCase();
        return (role === 'manager' || role === 'employee') && st !== 'inactive';
      });
      const totalAllowed = allowed.length;
      const allowedIds = new Set(allowed.map(e => String(e.employee_id)));
      const attRows = Array.isArray(attRes.data) ? attRes.data : [];
      const leaveRows = Array.isArray(leaveRes.data) ? leaveRes.data : [];
      const presentIds = new Set();
      attRows.forEach(r => {
        const st = String(r.status || '').toLowerCase();
        if (allowedIds.has(String(r.employee_id)) && ['present','late','undertime','leave'].includes(st)) {
          presentIds.add(String(r.employee_id));
        }
      });
      leaveRows.forEach(lr => {
        if (allowedIds.has(String(lr.employee_id))) {
          presentIds.add(String(lr.employee_id));
        }
      });
      const presentAllowed = presentIds.size;
      const absentToday = Math.max(0, totalAllowed - presentAllowed);
      const peso = (n) => `₱${Number(n || 0).toLocaleString('en-PH', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

      const topCards = [
        { label: 'Total Employees', value: totalAllowed, color: 'blue', icon: 'users', id: 'total' },
        { label: 'Present Today', value: presentAllowed, color: 'emerald', icon: 'check', id: 'present' },
        { label: 'Absent Today', value: absentToday, color: 'rose', icon: 'x', id: 'absent' }
      ];
      const bottomCards = [
        { label: 'Pending Leave Requests', value: s.pending_leaves, color: 'amber', icon: 'clock', id: 'pending_leaves' },
        { label: 'Payroll Processed This Month', value: peso(p.total_net_pay), color: 'fuchsia', icon: 'currency', id: 'payroll_processed' }
      ];

      const iconSvg = (name, cls = 'text-gray-600') => {
        if (name === 'users') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M12 12a4 4 0 100-8 4 4 0 000 8z"/><path d="M2 20c0-3.314 4.03-6 10-6s10 2.686 10 6v1H2v-1z"/></svg>`;
        if (name === 'check') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.2l-3.5-3.5a1 1 0 10-1.4 1.4l4.2 4.2a1 1 0 001.4 0l10-10a1 1 0 10-1.4-1.4L9 16.2z"/></svg>`;
        if (name === 'x') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M6.225 4.811a1 1 0 011.414 0L12 9.172l4.361-4.361a1 1 0 111.414 1.414L13.414 10.586l4.361 4.361a1 1 0 01-1.414 1.414L12 12l-4.361 4.361a1 1 0 01-1.414-1.414l4.361-4.361-4.361-4.361a1 1 0 010-1.414z"/></svg>`;
        if (name === 'clock') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M12 8a1 1 0 011 1v3h3a1 1 0 110 2h-4a1 1 0 01-1-1V9a1 1 0 011-1z"/><path fill-rule="evenodd" d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zM4 12a8 8 0 1116 0 8 8 0 01-16 0z" clip-rule="evenodd"/></svg>`;
        if (name === 'currency') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M13 5a3 3 0 013 3h2a5 5 0 00-5-5V1h-2v2a5 5 0 000 10h2a3 3 0 110 6h-2a3 3 0 01-3-3H6a5 5 0 005 5v2h2v-2a5 5 0 000-10h-2a3 3 0 110-6h2z"/></svg>`;
        return '';
      };

      const renderCard = (c) => {
        const clickable = c.id === 'absent' || c.id === 'total' || c.id === 'present' || c.id === 'pending_leaves' || c.id === 'payroll_processed';
        const palMap = {
          blue: { bg: 'bg-blue-50', text: 'text-blue-600', ring: 'ring-blue-200' },
          emerald: { bg: 'bg-emerald-50', text: 'text-emerald-600', ring: 'ring-emerald-200' },
          rose: { bg: 'bg-rose-50', text: 'text-rose-600', ring: 'ring-rose-200' },
          amber: { bg: 'bg-amber-50', text: 'text-amber-600', ring: 'ring-amber-200' },
          fuchsia: { bg: 'bg-fuchsia-50', text: 'text-fuchsia-600', ring: 'ring-fuchsia-200' }
        };
        const pal = palMap[c.color] || { bg: 'bg-gray-100', text: 'text-gray-600', ring: 'ring-gray-200' };
        return `
          <div class="rounded-lg bg-white shadow ${clickable ? 'cursor-pointer hover:shadow-md' : ''}" data-card-id="${c.id || ''}">
            <div class="p-4 flex items-center gap-3">
              <div class="w-10 h-10 rounded-full ${pal.bg} ${pal.ring} ring-1 flex items-center justify-center">${iconSvg(c.icon, pal.text)}</div>
              <div>
                <div class="text-xs uppercase tracking-wide text-gray-500">${c.label}</div>
                <div class="text-2xl font-semibold">${c.value}</div>
              </div>
            </div>
          </div>`;
      };

      const topWrap = document.getElementById('summary-cards-top');
      const bottomWrap = document.getElementById('summary-cards-bottom');
      if (topWrap) topWrap.innerHTML = topCards.map(renderCard).join('');
      if (bottomWrap) bottomWrap.innerHTML = bottomCards.map(renderCard).join('');
      
      // Minimal dashboard card animations (match admin dashboard)
      try {
      const anime = await ensureAnimeHR();
      if (anime) {
      const topCardsEls = topWrap ? Array.from(topWrap.children) : [];
      const bottomCardsEls = bottomWrap ? Array.from(bottomWrap.children) : [];
      const cards = [...topCardsEls, ...bottomCardsEls];
      if (cards.length) {
      cards.forEach(c => { c.style.transformOrigin = '50% 50%'; });
      anime({
      targets: cards,
      translateY: [6, 0],
      scale: [0.98, 1],
      easing: 'easeOutQuad',
      duration: 360,
      delay: anime.stagger(50)
      });
      cards.forEach(card => {
      card.addEventListener('mouseenter', () => {
      anime.remove(card);
      anime({ targets: card, scale: 1.02, duration: 140, easing: 'easeOutQuad' });
      });
      card.addEventListener('mouseleave', () => {
      anime.remove(card);
      anime({ targets: card, scale: 1.0, duration: 160, easing: 'easeOutQuad' });
      });
      });
      }
      }
      } catch {}

      // Wire Absent Today card to show list and allow marking absentees (HR scope)
      async function showAbsentTodayList(){
        try {
          const todayStr = new Date().toLocaleDateString('en-CA');
          const [empRes, attRes, leaveRes] = await Promise.all([
            axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
            axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: todayStr, end_date: todayStr } }),
            axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listApproved', start_date: todayStr, end_date: todayStr } })
          ]);
          const empList = Array.isArray(empRes.data) ? empRes.data : [];
          // HR allowed set: managers and employees, exclude inactive
          const allowed = empList.filter(e => {
            const role = String(e.user_role || e.role || '').toLowerCase();
            const st = String(e.status || '').toLowerCase();
            return (role === 'manager' || role === 'employee') && st !== 'inactive';
          });
          const allowedIds = new Set(allowed.map(e => String(e.employee_id)));
          const attRows = Array.isArray(attRes.data) ? attRes.data : [];
          const leaveRows = Array.isArray(leaveRes.data) ? leaveRes.data : [];

          const union = new Set();
          attRows.forEach(r => {
            const eid = String(r.employee_id || '');
            if (!allowedIds.has(eid)) return;
            const st = String(r.status || '').toLowerCase();
            const d = String(r.attendance_date || r.date || r.created_at || r.time_in || '').slice(0,10);
            if (d === todayStr && ['present','late','undertime','leave'].includes(st)) union.add(eid);
          });
          leaveRows.forEach(lr => {
            const s = String(lr.start_date || lr.date || lr.work_date || '').slice(0,10);
            const e = String(lr.end_date || lr.start_date || lr.date || lr.work_date || '').slice(0,10);
            if (!s || !e) return;
            if (s <= todayStr && todayStr <= e) {
              const eid = String(lr.employee_id || '');
              if (allowedIds.has(eid)) union.add(eid);
            }
          });
          const absentees = allowed.filter(e => !union.has(String(e.employee_id)));

          let modal = document.getElementById('hrAbsentListModal');
          if (!modal){
            modal = document.createElement('div');
            modal.id = 'hrAbsentListModal';
            modal.className = 'fixed inset-0 z-50 hidden';
            document.body.appendChild(modal);
          }
          const t = (s) => { try { return toTitleCase ? toTitleCase(String(s||'')) : String(s||''); } catch { return String(s||''); } };
          let selectedIds = new Set();
          let query = '';
          const getFiltered = () => {
            const q = (query || '').toLowerCase();
            if (!q) return absentees.slice();
            return absentees.filter(e => {
              const name = `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.trim();
              const dept = String(e.department || '').toLowerCase();
              return name.includes(q) || dept.includes(q);
            });
          };
          const renderTable = () => {
            const wrap = document.getElementById('hr-absent-table-wrap');
            if (!wrap) return;
            const list = getFiltered();
            if (!list.length){
              wrap.innerHTML = '<div class="text-sm text-gray-500">No absent today</div>';
              return;
            }
            const rowsHtml = list.map(e => `
              <tr>
                <td class="px-3 py-2 text-sm text-gray-700 w-8">
                  <input type="checkbox" class="hr-absent-select" data-emp-id="${e.employee_id}" ${selectedIds.has(String(e.employee_id)) ? 'checked' : ''} />
                </td>
                <td class="px-3 py-2 text-sm text-gray-700">${t(`${e.first_name || ''} ${e.last_name || ''}`.trim())}</td>
                <td class="px-3 py-2 text-sm text-gray-700">${t(e.department || '')}</td>
              </tr>`).join('');
            wrap.innerHTML = `
              <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                  <tr>
                    <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600 w-8"><input type="checkbox" id="hr-absent-select-all" /></th>
                    <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
                    <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Department</th>
                  </tr>
                </thead>
                <tbody id="hr-absent-tbody" class="divide-y divide-gray-200 bg-white">${rowsHtml}</tbody>
              </table>`;
            const tbody = document.getElementById('hr-absent-tbody');
            if (tbody){
              tbody.querySelectorAll('.hr-absent-select').forEach(cb => {
                cb.addEventListener('change', () => {
                  const id = String(cb.getAttribute('data-emp-id'));
                  if (cb.checked) selectedIds.add(id); else selectedIds.delete(id);
                  const btn = document.getElementById('hr-absent-mark-btn');
                  if (btn) btn.disabled = selectedIds.size === 0;
                  const selectAll = document.getElementById('hr-absent-select-all');
                  if (selectAll) {
                    const allSelectedNow = list.every(e => selectedIds.has(String(e.employee_id)));
                    const someSelectedNow = list.some(e => selectedIds.has(String(e.employee_id)));
                    selectAll.checked = allSelectedNow;
                    selectAll.indeterminate = !allSelectedNow && someSelectedNow;
                  }
                });
              });
            }
            // Wire Select All checkbox
            const selectAll = document.getElementById('hr-absent-select-all');
            if (selectAll) {
              const visibleIds = list.map(e => String(e.employee_id));
              const allSel = visibleIds.every(id => selectedIds.has(id));
              const someSel = visibleIds.some(id => selectedIds.has(id));
              selectAll.checked = allSel;
              selectAll.indeterminate = !allSel && someSel;
              selectAll.addEventListener('change', () => {
                if (selectAll.checked) {
                  visibleIds.forEach(id => selectedIds.add(id));
                } else {
                  visibleIds.forEach(id => selectedIds.delete(id));
                }
                const tb = document.getElementById('hr-absent-tbody');
                if (tb) tb.querySelectorAll('.hr-absent-select').forEach(cb => { cb.checked = selectAll.checked; });
                const btn = document.getElementById('hr-absent-mark-btn');
                if (btn) btn.disabled = selectedIds.size === 0;
                selectAll.indeterminate = false;
              });
            }
          };

          modal.innerHTML = `
            <div class="absolute inset-0 bg-black/50" data-close="true"></div>
            <div class="relative mx-auto mt-20 w-full max-w-2xl">
              <div class="bg-white rounded-lg shadow max-h-[80vh] flex flex-col">
                <div class="flex items-center justify-between border-b px-4 py-3">
                  <h5 class="font-semibold">Absent Today (${absentees.length})</h5>
                  <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
                </div>
                <div class="p-4">
                <div class="mb-3 flex items-center gap-2">
                <div class="relative">
                <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
                <input id="hr-absent-search" class="w-64 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name or department" />
                </div>
                <button id="hr-absent-clear" class="text-xs text-gray-600 border rounded px-2 py-1">Clear</button>
                <a href="#attendance" class="ml-auto text-primary-700 text-sm hover:underline">Open Attendance</a>
                </div>
                <div id="hr-absent-table-wrap" class="overflow-auto max-h-[48vh]"></div>
                </div>
                <div class="flex justify-between items-center gap-2 border-t px-4 py-3">
                  <div class="text-xs text-gray-500">Select employees to mark as absent. These will be recorded in today's attendance.</div>
                  <div class="flex items-center gap-2">
                    <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
                    <button id="hr-absent-mark-btn" class="px-3 py-2 text-sm rounded bg-rose-600 text-white disabled:opacity-50" disabled>Mark selected as Absent</button>
                  </div>
                </div>
              </div>
            </div>`;

          // Wire close buttons with cleanup and day-change watchers
          let __hrAbsentModalTimer = null;
          let __hrAbsentModalDayKey = todayStr;
          const __hrAbsentMaybeRollover = async () => {
            try {
              const d = new Date().toLocaleDateString('en-CA');
              if (d !== __hrAbsentModalDayKey) {
                __hrAbsentModalDayKey = d;
                try { closeModal(); } catch {}
                await showAbsentTodayList();
              }
            } catch {}
          };
          const onFocus = () => { __hrAbsentMaybeRollover(); };
          const onVis = () => { __hrAbsentMaybeRollover(); };
          const closeModal = () => {
            modal.classList.add('hidden');
            try { if (__hrAbsentModalTimer) { clearInterval(__hrAbsentModalTimer); __hrAbsentModalTimer = null; } } catch {}
            try { window.removeEventListener('focus', onFocus); } catch {}
            try { document.removeEventListener('visibilitychange', onVis); } catch {}
          };
          modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeModal));

          // Wire search
          const searchInp = document.getElementById('hr-absent-search');
          const clearBtn = document.getElementById('hr-absent-clear');
          if (searchInp){ searchInp.addEventListener('input', () => { query = (searchInp.value||'').trim(); renderTable(); }); }
          if (clearBtn){ clearBtn.addEventListener('click', () => { if (searchInp) searchInp.value=''; query=''; renderTable(); }); }

          // Wire mark action
          const markBtn = document.getElementById('hr-absent-mark-btn');
          if (markBtn){
            markBtn.addEventListener('click', async () => {
              if (selectedIds.size === 0) return;
              const confirmed = await (async function confirmAbsAll(){
                return new Promise((resolve)=>{
                  let cm = document.getElementById('hrAbsentConfirmModal');
                  if (!cm) { cm = document.createElement('div'); cm.id='hrAbsentConfirmModal'; cm.className='fixed inset-0 z-50 hidden'; document.body.appendChild(cm); }
                  cm.innerHTML = `
                    <div class="absolute inset-0 bg-black/50" data-close="true"></div>
                    <div class="relative mx-auto mt-32 w-full max-w-md">
                      <div class="bg-white rounded-lg shadow">
                        <div class="px-4 py-3 border-b"><h5 class="font-semibold text-gray-900">Confirm</h5></div>
                        <div class="p-4 text-sm text-gray-700">Are you sure you want to mark all as absent?</div>
                        <div class="px-4 py-3 border-t flex justify-end gap-2">
                          <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
                          <button id="hr-absent-confirm-ok" class="px-3 py-2 text-sm rounded bg-rose-600 text-white">Confirm</button>
                        </div>
                      </div>
                    </div>`;
                  const closeEls = cm.querySelectorAll('[data-close="true"]');
                  closeEls.forEach(el => el.addEventListener('click', () => { cm.classList.add('hidden'); resolve(false); }, { once: true }));
                  const okBtn = cm.querySelector('#hr-absent-confirm-ok');
                  if (okBtn) okBtn.addEventListener('click', () => { cm.classList.add('hidden'); resolve(true); }, { once: true });
                  cm.classList.remove('hidden');
                });
              })();
              if (!confirmed) return;
              const ids = Array.from(selectedIds);
              let ok = 0, fail = 0;
              for (const id of ids){
                try {
                  const payload = { employee_id: id, attendance_date: todayStr, status: 'absent', time_in: null, time_out: null, remarks: 'Marked absent (HR dashboard)' };
                  const fd = new FormData();
                  fd.append('operation', 'recordAttendance');
                  fd.append('json', JSON.stringify(payload));
                  const res = await axios.post(`${baseApiUrl}/attendance.php`, fd);
                  const success = String(res.data) === '1' || res.data === 1 || (res.data && res.data.success === 1);
                  if (success) ok++; else fail++;
                } catch { fail++; }
              }
              try { showToast(`Marked as Absent: ${ok} | Failed: ${fail} (Add Other)`, fail ? 'warning' : 'success'); } catch {}
              // Immediately empty the Absent Today list in the modal
              try {
                selectedIds = new Set();
                const wrap = document.getElementById('hr-absent-table-wrap');
                if (wrap) wrap.innerHTML = '<div class="text-sm text-gray-500">No absentees for today.</div>';
                const title = modal.querySelector('h5');
                if (title) title.textContent = 'Absent Today (0)';
                const markButton = document.getElementById('hr-absent-mark-btn');
                if (markButton) markButton.disabled = true;
                const searchInp2 = document.getElementById('hr-absent-search');
                if (searchInp2) { searchInp2.value = ''; searchInp2.disabled = true; }
                const selectAllCb = document.getElementById('hr-absent-select-all');
                if (selectAllCb) { selectAllCb.checked = false; selectAllCb.indeterminate = false; selectAllCb.disabled = true; }
              } catch {}
              try { await renderAttendanceSnapshot(); } catch {}
              try { await renderSummaryCards(); } catch {}
            });
          }

          // Initial render
          renderTable();
          modal.classList.remove('hidden');
          // Setup day-change refresh
          try {
            if (__hrAbsentModalTimer) { clearInterval(__hrAbsentModalTimer); }
            __hrAbsentModalTimer = setInterval(__hrAbsentMaybeRollover, 60000);
            window.addEventListener('focus', onFocus);
            document.addEventListener('visibilitychange', onVis);
          } catch {}
        } catch (e) {
        try { alert('Failed to load absent list'); } catch {}
        }
        }
        async function showAllEmployeesList(){
        try {
        const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
        const all = Array.isArray(res.data) ? res.data : [];
        const list = all.filter(e => {
        const role = String(e.user_role || e.role || '').toLowerCase();
        const st = String(e.status || '').toLowerCase();
        return (role === 'manager' || role === 'employee') && st !== 'inactive';
        });
        let modal = document.getElementById('hrEmpAllListModal');
        if (!modal) { modal = document.createElement('div'); modal.id = 'hrEmpAllListModal'; modal.className = 'fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
        let query = '';
        const renderTable = () => {
        const rows = (!query ? list : list.filter(e => {
        const name = `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`;
        const dept = String(e.department || '').toLowerCase();
        const pos = String(e.position || '').toLowerCase();
        const st = String(e.status || '').toLowerCase();
        return name.includes(query) || dept.includes(query) || pos.includes(query) || st.includes(query);
        }));
        const wrap = document.getElementById('hr-empall-table-wrap');
        if (!wrap) return;
        if (!rows.length) { wrap.innerHTML = '<div class="text-sm text-gray-500">No matches</div>'; return; }
        const trs = rows.map(e => `
        <tr>
        <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(`${e.first_name || ''} ${e.last_name || ''}`.trim())}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(e.department || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(e.position || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(e.status || '')}</td>
        </tr>`).join('');
        wrap.innerHTML = `
        <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
        <tr>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Department</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Position</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
        </tr>
        </thead>
        <tbody class="divide-y divide-gray-200 bg-white">${trs}</tbody>
        </table>`;
        };
        modal.innerHTML = `
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-3xl">
        <div class="bg-white rounded-lg shadow max-h-[80vh] flex flex-col">
        <div class="flex items-center justify-between border-b px-4 py-3">
        <h5 class="font-semibold">Employees (${list.length})</h5>
        <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
        </div>
        <div class="p-4">
        <div class="mb-3 flex items-center gap-2">
        <div class="relative">
        <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
        <input id="hr-empall-search" class="w-64 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, department, position, status" />
        </div>
        <button id="hr-empall-clear" class="text-xs text-gray-600 border rounded px-2 py-1">Clear</button>
        <a href="#employees" class="ml-auto text-primary-700 text-sm hover:underline">Open Employees</a>
        </div>
        <div id="hr-empall-table-wrap" class="overflow-auto max-h-[48vh]"></div>
        </div>
        <div class="flex justify-end items-center gap-2 border-t px-4 py-3">
        <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
        </div>
        </div>
        </div>`;
        modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
        const si = document.getElementById('hr-empall-search');
        const sc = document.getElementById('hr-empall-clear');
        if (si) si.addEventListener('input', () => { query = (si.value || '').trim().toLowerCase(); renderTable(); });
        if (sc) sc.addEventListener('click', () => { if (si) si.value=''; query=''; renderTable(); });
        renderTable();
        modal.classList.remove('hidden');
        } catch {
        try { alert('Failed to load employees'); } catch {}
        }
        }
        async function showPresentTodayList(){
        try {
        const todayStr = new Date().toLocaleDateString('en-CA');
        const [empRes, attRes, leaveRes] = await Promise.all([
        axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
        axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: todayStr, end_date: todayStr } }),
        axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listApproved', start_date: todayStr, end_date: todayStr } })
        ]);
        const empList = Array.isArray(empRes.data) ? empRes.data : [];
        const allowed = empList.filter(e => {
        const role = String(e.user_role || e.role || '').toLowerCase();
        const st = String(e.status || '').toLowerCase();
        return (role === 'manager' || role === 'employee') && st !== 'inactive';
        });
        const allowedMap = new Map(allowed.map(e => [String(e.employee_id), e]));
        const attRows = Array.isArray(attRes.data) ? attRes.data : [];
        const leaveRows = Array.isArray(leaveRes.data) ? leaveRes.data : [];
        const presentMap = new Map();
        attRows.forEach(r => {
        const eid = String(r.employee_id || '');
        if (!allowedMap.has(eid)) return;
        const st = String(r.status || '').toLowerCase();
        if (['present','late','undertime','on time','ontime','present today','present_today'].includes(st) || (r.time_in && r.time_in !== '' && r.time_in !== '00:00:00')) {
        const base = allowedMap.get(eid) || {};
        presentMap.set(eid, { ...(base), status: st || (r.time_in ? 'present' : ''), time_in: r.time_in || '', time_out: r.time_out || '' });
        }
        });
        leaveRows.forEach(lr => {
        const s = String(lr.start_date || lr.date || lr.work_date || '').slice(0,10);
        const e = String(lr.end_date || lr.start_date || lr.date || lr.work_date || '').slice(0,10);
        if (!s || !e) return;
        if (s <= todayStr && todayStr <= e) {
        const eid = String(lr.employee_id || '');
        if (!allowedMap.has(eid)) return;
        if (!presentMap.has(eid)) {
        const base = allowedMap.get(eid) || {};
        presentMap.set(eid, { ...(base), status: 'leave', time_in: '', time_out: '' });
        }
        }
        });
        const list = Array.from(presentMap.values());
        let modal = document.getElementById('hrPresentTodayModal');
        if (!modal) { modal = document.createElement('div'); modal.id = 'hrPresentTodayModal'; modal.className = 'fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
        let query = '';
        const renderTable = () => {
        const filtered = (!query ? list : list.filter(e => {
        const name = `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.trim();
        const dept = String(e.department || '').toLowerCase();
        const st = String(e.status || '').toLowerCase();
        return name.includes(query) || dept.includes(query) || st.includes(query);
        }));
        const wrap = document.getElementById('hr-present-table-wrap');
        if (!wrap) return;
        if (!filtered.length) { wrap.innerHTML = '<div class="text-sm text-gray-500">No present today</div>'; return; }
        const rowsHtml = filtered.map(e => `
        <tr>
        <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(`${e.first_name || ''} ${e.last_name || ''}`.trim())}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(e.department || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(e.status || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${e.time_in || ''}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${e.time_out || ''}</td>
        </tr>`).join('');
        wrap.innerHTML = `
        <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
        <tr>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Department</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time In</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time Out</th>
        </tr>
        </thead>
        <tbody class="divide-y divide-gray-200 bg-white">${rowsHtml}</tbody>
        </table>`;
        };
        modal.innerHTML = `
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-3xl">
        <div class="bg-white rounded-lg shadow max-h-[80vh] flex flex-col">
        <div class="flex items-center justify-between border-b px-4 py-3">
        <h5 class="font-semibold">Present Today (${list.length})</h5>
        <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
        </div>
        <div class="p-4">
        <div class="mb-3 flex items-center gap-2">
        <div class="relative">
        <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
        <input id="hr-present-search" class="w-64 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, department, status" />
        </div>
        <button id="hr-present-clear" class="text-xs text-gray-600 border rounded px-2 py-1">Clear</button>
        <a href="#attendance" class="ml-auto text-primary-700 text-sm hover:underline">Open Attendance</a>
        </div>
        <div id="hr-present-table-wrap" class="overflow-auto max-h-[48vh]"></div>
        </div>
        <div class="flex justify-end items-center gap-2 border-t px-4 py-3">
        <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
        </div>
        </div>
        </div>`;
        modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
        const si = document.getElementById('hr-present-search');
        const sc = document.getElementById('hr-present-clear');
        if (si) si.addEventListener('input', () => { query = (si.value || '').trim().toLowerCase(); renderTable(); });
        if (sc) sc.addEventListener('click', () => { if (si) si.value=''; query=''; renderTable(); });
        renderTable();
        modal.classList.remove('hidden');
        } catch {
        try { alert('Failed to load present list'); } catch {}
        }
        }
        async function showPendingLeavesList(){
        try {
        const res = await axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listPending' } });
        const rows = Array.isArray(res.data) ? res.data : [];
        let modal = document.getElementById('hrPendingLeavesModal');
        if (!modal) { modal = document.createElement('div'); modal.id = 'hrPendingLeavesModal'; modal.className = 'fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
        const daysInclusive = (start, end) => {
        try {
        const parse = (s) => { const [y,m,d] = String(s||'').split('-').map(n=>parseInt(n,10)); return Date.UTC(y||1970,(m||1)-1,d||1); };
        const a = parse(start), b = parse(end || start);
        if (!Number.isFinite(a) || !Number.isFinite(b)) return '';
        const diff = Math.floor((b - a) / 86400000) + 1;
        return diff > 0 ? diff : 1;
        } catch { return ''; }
        };
        let query = '';
        const renderTable = () => {
        const list = (!query ? rows : rows.filter(r => {
        const name = `${(r.first_name||'').toLowerCase()} ${(r.last_name||'').toLowerCase()}`.trim();
        const type = String(r.leave_type || '').toLowerCase();
        const dates = `${String(r.start_date||'')} ${String(r.end_date||'')}`.toLowerCase();
        const reason = String(r.reason || '').toLowerCase();
        const status = String(r.status || '').toLowerCase();
        return name.includes(query) || type.includes(query) || dates.includes(query) || reason.includes(query) || status.includes(query);
        }));
        const wrap = document.getElementById('hr-pendleaves-table-wrap');
        if (!wrap) return;
        if (!list.length) { wrap.innerHTML = '<div class="text-sm text-gray-500">No pending leaves.</div>'; return; }
        const trs = list.map((r, idx) => {
        const name = toTitleCase(`${r.first_name || ''} ${r.last_name || ''}`.trim());
        const type = toTitleCase(r.leave_type || '');
        const dateRange = `${r.start_date || ''} → ${r.end_date || ''}`;
        const days = daysInclusive(r.start_date, r.end_date);
        const reason = (r.reason || '').toString();
        const submitted = (() => { try { const s = String(r.created_at || ''); return s ? new Date(s).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : ''; } catch { return String(r.created_at || ''); } })();
        const status = toTitleCase(r.status || 'pending');
        return `
        <tr>
        <td class="px-3 py-2 text-sm text-gray-700">${idx+1}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${name}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${type}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${dateRange}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${days}</td>
        <td class="px-3 py-2 text-sm text-gray-700 truncate max-w-[16rem]" title="${reason.replace(/\"/g,'&quot;')}">${reason}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${submitted}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${status}</td>
        </tr>`;
        }).join('');
        wrap.innerHTML = `
        <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
        <tr>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Type</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Dates</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Days</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Reason</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Submitted</th>
        <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
        </tr>
        </thead>
        <tbody class="divide-y divide-gray-200 bg-white">${trs}</tbody>
        </table>`;
        };
        modal.innerHTML = `
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-5xl">
        <div class="bg-white rounded-lg shadow max-h-[80vh] flex flex-col">
        <div class="flex items-center justify-between border-b px-4 py-3">
        <h5 class="font-semibold">Pending Leave Requests (${rows.length})</h5>
        <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
        </div>
        <div class="p-4">
        <div class="mb-3 flex items-center gap-2">
        <div class="relative">
        <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
        <input id="hr-pendleaves-search" class="w-72 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, type, date, reason, status" />
        </div>
        <button id="hr-pendleaves-clear" class="text-xs text-gray-600 border rounded px-2 py-1">Clear</button>
        <a href="#LeaveRequests" class="ml-auto text-primary-700 text-sm hover:underline">Open Leave Management</a>
        </div>
        <div id="hr-pendleaves-table-wrap" class="overflow-auto max-h-[48vh]"></div>
        </div>
        <div class="flex justify-end items-center gap-2 border-t px-4 py-3">
        <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
        </div>
        </div>
        </div>`;
        modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
        const si = document.getElementById('hr-pendleaves-search');
        const sc = document.getElementById('hr-pendleaves-clear');
        if (si) si.addEventListener('input', () => { query = (si.value || '').trim().toLowerCase(); renderTable(); });
        if (sc) sc.addEventListener('click', () => { if (si) si.value=''; query=''; renderTable(); });
        renderTable();
        modal.classList.remove('hidden');
        } catch {
        try { alert('Failed to load pending leaves'); } catch {}
        }
        }
        try {
        const absentEl = topWrap && topWrap.querySelector('[data-card-id="absent"]');
        if (absentEl) absentEl.addEventListener('click', async () => { await showAbsentTodayList(); });
        const totalEl = topWrap && topWrap.querySelector('[data-card-id="total"]');
        if (totalEl) totalEl.addEventListener('click', async () => { await showAllEmployeesList(); });
        const presentEl = topWrap && topWrap.querySelector('[data-card-id="present"]');
        if (presentEl) presentEl.addEventListener('click', async () => { await showPresentTodayList(); });
        const pendingEl = bottomWrap && bottomWrap.querySelector('[data-card-id="pending_leaves"]');
        if (pendingEl) pendingEl.addEventListener('click', async () => { await showPendingLeavesList(); });
        const payrollProcessedEl = bottomWrap && bottomWrap.querySelector('[data-card-id="payroll_processed"]');
        if (payrollProcessedEl) payrollProcessedEl.addEventListener('click', () => { location.hash = '#payroll'; });
        } catch {}
    }

    // Removed HR-specific employee counters in favor of unified dashboard metrics

    async function renderAttendanceSnapshot(){
      const container = document.getElementById('attendance-table');
      if (!container) return;
      const params = { operation: 'getAttendance', start_date: new Date().toLocaleDateString('en-CA'), end_date: new Date().toLocaleDateString('en-CA') };
      const res = await axios.get(`${baseApiUrl}/attendance.php`, { params });
      let rows = res.data || [];
      // Exclude HR users from HR dashboard snapshot (Manager/Employee roles only)
      try {
        const empRes = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
        const empList = Array.isArray(empRes.data) ? empRes.data : [];
        const allowed = empList.filter(e => {
          const role = String(e.user_role || e.role || '').toLowerCase();
          const st = String(e.status || '').toLowerCase();
          return (role === 'manager' || role === 'employee') && st !== 'inactive';
        });
        const allowedIds = new Set(allowed.map(e => String(e.employee_id)));
        rows = rows.filter(r => allowedIds.has(String(r.employee_id)));
        // Fallback: ensure any row with position 'hr' is excluded
        rows = rows.filter(r => String(r.position || '').toLowerCase() !== 'hr');
      } catch {}
      const table = document.createElement('table');
      table.className = 'min-w-full divide-y divide-gray-200';
      table.innerHTML = `
        <thead class="bg-gray-50"><tr>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Department</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time In</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time Out</th>
        </tr></thead><tbody class="divide-y divide-gray-200 bg-white"></tbody>`;
      const tbody = table.querySelector('tbody');
      rows.forEach(r => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(`${r.first_name} ${r.last_name}`)}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(r.department || '')}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(r.status || '')}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${r.time_in || ''}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${r.time_out || ''}</td>`;
        tbody.appendChild(tr);
      });
      document.getElementById('attendance-table').innerHTML = '';
      document.getElementById('attendance-table').appendChild(table);
    }

    async function renderLeaves(){
      if (!document.getElementById('leaves-table')) return;
      const res = await axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listPending' } });
      const rows = res.data || [];
      const table = document.createElement('table');
      table.className = 'min-w-full divide-y divide-gray-200';
      table.innerHTML = `
        <thead class="bg-gray-50"><tr>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Dates</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Actions</th>
        </tr></thead><tbody class="divide-y divide-gray-200 bg-white"></tbody>`;
      const tbody = table.querySelector('tbody');
      rows.forEach(r => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(`${r.first_name} ${r.last_name}`)}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${r.start_date} → ${r.end_date}</td>
          <td class="px-3 py-2 text-sm">
            <button data-view="${r.leave_id}" class="px-2 py-1 text-xs rounded border border-gray-300 text-gray-700 hover:bg-gray-50">View</button>
          </td>`;
        tbody.appendChild(tr);
      });
      const wrap = document.getElementById('leaves-table');
      wrap.innerHTML = '';
      wrap.appendChild(table);

      tbody.querySelectorAll('[data-view]').forEach(btn => btn.addEventListener('click', async (e) => {
        const id = e.currentTarget.getAttribute('data-view');
        try {
          const lr = rows.find(x => String(x.leave_id) === String(id));
          if (lr) {
            openLeaveView(lr);
          } else {
            // Fallback fetch
            const res = await axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'getLeave', leave_id: id } });
            const leave = res.data || {};
            openLeaveView(leave);
          }
        } catch {}
      }));
    }

    async function renderHrAttendanceTrend(){
      try {
        // Build last 30 days labels (inclusive up to today)
        const end = new Date();
        const start = new Date();
        start.setDate(end.getDate() - 29);
        const labels = [];
        const dateKeys = [];
        for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
          dateKeys.push(d.toLocaleDateString('en-CA'));
          labels.push(d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
        }

        // Compute today's attendance rate only
        const todayStr = new Date().toLocaleDateString('en-CA');
        const [empRes, attRes, leaveRes] = await Promise.all([
          axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
          axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: todayStr, end_date: todayStr } }),
          axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listApproved', start_date: todayStr, end_date: todayStr } })
        ]);
        const empList = Array.isArray(empRes.data) ? empRes.data : [];
        const allowed = empList.filter(e => {
          const role = String(e.user_role || e.role || '').toLowerCase();
          const st = String(e.status || '').toLowerCase();
          return (role === 'manager' || role === 'employee') && st !== 'inactive';
        });
        const totalAllowed = allowed.length;
        const allowedIds = new Set(allowed.map(e => String(e.employee_id)));

        const attRows = Array.isArray(attRes.data) ? attRes.data : [];
        const leaveRows = Array.isArray(leaveRes.data) ? leaveRes.data : [];
        const presentIds = new Set();
        attRows.forEach(r => {
          const st = String(r.status || '').toLowerCase();
          const ds = (r.attendance_date || r.date || r.created_at || r.time_in || '').toString().slice(0,10);
          if (ds === todayStr && allowedIds.has(String(r.employee_id)) && ['present','late','undertime','leave'].includes(st)) {
            presentIds.add(String(r.employee_id));
          }
        });
        leaveRows.forEach(lr => {
          const s = String(lr.start_date || lr.date || lr.work_date || '').slice(0,10);
          const e = String(lr.end_date || lr.start_date || lr.date || lr.work_date || '').slice(0,10);
          if (s && e && s <= todayStr && todayStr <= e && allowedIds.has(String(lr.employee_id))) {
            presentIds.add(String(lr.employee_id));
          }
        });
        const todayRate = totalAllowed > 0 ? Math.round((presentIds.size / totalAllowed) * 100) : 0;

        // Build 30-day series with only today's value populated
        const rate = dateKeys.map(k => (k === todayStr ? todayRate : 0));

        const ctx = document.getElementById('hrAttendanceTrend');
        if (!ctx) return;
        if (window.__hrAttendanceTrendChart) { try { window.__hrAttendanceTrendChart.destroy(); } catch {} }
        window.__hrAttendanceTrendChart = new Chart(ctx, {
          type: 'line',
          data: {
            labels,
            datasets: [{
              label: 'Attendance Rate %',
              data: rate,
              borderColor: '#3b82f6',
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              borderWidth: 3,
              fill: true,
              tension: 0.4
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { y: { beginAtZero: true, max: 100, ticks: { callback: (v) => `${v}%` } } },
            plugins: { legend: { position: 'top' } }
          }
        });
      } catch {}
    }

    async function renderHrAbsenceByDepartment(){
      try {
        const res = await axios.get(`${baseApiUrl}/reports.php`, { params: { operation: 'absenceByDepartment', days: 30 } });
        const data = res.data || { labels: [], counts: [] };
        const ctx = document.getElementById('hrAbsenceByDept');
        if (!ctx) return;
        new Chart(ctx, {
          type: 'pie',
          data: {
            labels: data.labels || [],
            datasets: [{
              data: data.counts || [],
              backgroundColor: ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#14b8a6', '#f97316', '#6366f1']
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom' } },
            onClick: async (evt, elements) => {
              if (!elements || !elements.length) return;
              const idx = elements[0].index;
              const label = (data.labels || [])[idx];
              if (label) {
                await openAbsenceDeptDetails(label);
              }
            }
          }
        });
      } catch {}
    }

    function ensureAbsenceDeptModal(){
      if (document.getElementById('absenceDeptModal')) return;
      const modal = document.createElement('div');
      modal.id = 'absenceDeptModal';
      modal.className = 'fixed inset-0 z-50 hidden';
      modal.innerHTML = `
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-2xl">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3">
              <h5 id="absenceDeptTitle" class="font-semibold">Absences</h5>
              <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
            </div>
            <div id="absenceDeptBody" class="p-4 text-sm text-gray-700"></div>
            <div class="flex justify-end gap-2 border-t px-4 py-3">
              <button class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700" data-close="true">Close</button>
            </div>
          </div>
        </div>`;
      document.body.appendChild(modal);
      modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
    }

    async function openAbsenceDeptDetails(department){
      ensureAbsenceDeptModal();
      const modal = document.getElementById('absenceDeptModal');
      const title = document.getElementById('absenceDeptTitle');
      const body = document.getElementById('absenceDeptBody');
      if (!modal || !body) return;
      if (title) title.textContent = `Absences — ${toTitleCase(department)}`;
      body.innerHTML = '<div class="text-gray-500">Loading...</div>';
      try {
        const end = new Date();
        const start = new Date();
        start.setDate(end.getDate() - 29);
        const startStr = start.toLocaleDateString('en-CA');
        const endStr = end.toLocaleDateString('en-CA');
        const params = { operation: 'getAttendance', start_date: startStr, end_date: endStr };
        const res = await axios.get(`${baseApiUrl}/attendance.php`, { params });
        const rows = Array.isArray(res.data) ? res.data : [];
        const deptLc = (department || '').toLowerCase();
        const filtered = rows.filter(r => (r.status || '').toLowerCase() === 'absent' && (r.department || '').toLowerCase() === deptLc);
        if (!filtered.length){
          body.innerHTML = '<div class="text-gray-600">No absence records found for the last 30 days.</div>';
        } else {
          const byEmp = new Map();
          filtered.forEach(r => {
            const key = String(r.employee_id || `${r.first_name}|${r.last_name}`);
            if (!byEmp.has(key)) byEmp.set(key, { name: `${r.first_name || ''} ${r.last_name || ''}`.trim(), dates: [] });
            const dateOnly = (r.date || r.created_at || r.time_in || '').toString().slice(0,10);
            const set = byEmp.get(key);
            if (dateOnly && !set.dates.includes(dateOnly)) set.dates.push(dateOnly);
          });
          const items = Array.from(byEmp.values()).map(x => ({ name: x.name, count: x.dates.length, dates: x.dates.sort() }));
          items.sort((a,b) => b.count - a.count || a.name.localeCompare(b.name));
          body.innerHTML = `
            <div class="text-xs text-gray-500 mb-2">Last 30 days</div>
            <div class="divide-y divide-gray-200">
              ${items.map(it => `
                <div class="py-2">
                  <div class="flex items-center justify-between">
                    <div class="font-medium">${toTitleCase(it.name || 'Unknown')}</div>
                    <div class="text-gray-600">${it.count} ${it.count === 1 ? 'day' : 'days'}</div>
                  </div>
                  ${it.dates.length ? `<div class="mt-1 text-xs text-gray-500">${it.dates.join(', ')}</div>` : ''}
                </div>
              `).join('')}
            </div>`;
        }
      } catch {
        body.innerHTML = '<div class="text-red-600">Failed to load details.</div>';
      }
      modal.classList.remove('hidden');
    }

    function openLeaveView(leave){
      let modal = document.getElementById('leaveViewModal');
      if (!modal){
        modal = document.createElement('div');
        modal.id = 'leaveViewModal';
        modal.className = 'fixed inset-0 z-50 hidden';
        modal.innerHTML = `
          <div class="absolute inset-0 bg-black/50" data-close="true"></div>
          <div class="relative mx-auto mt-24 w-full max-w-lg">
            <div class="bg-white rounded-lg shadow">
              <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold">Leave Details</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
              <div class="p-4 text-sm space-y-2">
                <div><span class="text-gray-500">Employee:</span> <span id="lv-emp"></span></div>
                <div><span class="text-gray-500">Dates:</span> <span id="lv-dates"></span></div>
                <div><span class="text-gray-500">Reason:</span> <div id="lv-reason" class="mt-1 whitespace-pre-wrap"></div></div>
                <div><span class="text-gray-500">Status:</span> <span id="lv-status"></span></div>
              </div>
              <div class="flex justify-end gap-2 border-t px-4 py-3">
                <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
              </div>
            </div>
          </div>`;
        document.body.appendChild(modal);
        modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
      }
      modal.querySelector('#lv-emp').textContent = toTitleCase(`${leave.first_name} ${leave.last_name}`);
      modal.querySelector('#lv-dates').textContent = `${leave.start_date} → ${leave.end_date}`;
      modal.querySelector('#lv-reason').textContent = leave.reason || '';
      modal.querySelector('#lv-status').textContent = toTitleCase(leave.status || 'pending');
      modal.classList.remove('hidden');
    }

    async function renderPayrollStatus(){
      const wrap = document.getElementById('payroll-summary');
      if (!wrap) return;
      const res = await axios.get(`${baseApiUrl}/reports.php`, { params: { operation: 'payrollSummary' } });
      const data = res.data || { total_net_pay: 0, total_deductions: 0, total_overtime_pay: 0 };
      wrap.innerHTML = `
        <ul class="divide-y divide-gray-200">
          <li class="flex items-center justify-between py-2"><span>Total Net Pay (period)</span><strong>${Number(data.total_net_pay || 0).toFixed(2)}</strong></li>
          <li class="flex items-center justify-between py-2"><span>Total Deductions</span><strong>${Number(data.total_deductions || 0).toFixed(2)}</strong></li>
          <li class="flex items-center justify-between py-2"><span>Total Overtime Pay</span><strong>${Number(data.total_overtime_pay || 0).toFixed(2)}</strong></li>
        </ul>`;
    }


  },
  employees: async () => {
    const module = await import('./modules/employees.js');
    await module.render();
  },
  attendance: async () => {
    const module = await import('./modules/attendance.js');
    await module.render();
  },
  overtime: async () => {
    const app = document.getElementById('app');
    app.innerHTML = `
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-xl font-semibold text-gray-900">Overtime</h2>
        <div class="flex items-center gap-2">
          <button id="btn-qr-scan-ot" class="inline-flex items-center px-3 py-2 text-sm rounded border text-gray-700 hover:bg-gray-50">Scan QR</button>
          <button id="btn-add-ot" class="inline-flex items-center px-3 py-2 text-sm font-medium rounded bg-primary-600 text-white hover:bg-primary-700">Record Overtime</button>
        </div>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <div class="mb-3 flex items-center justify-between gap-3">
          <div class="flex items-center gap-3">
            <div class="relative">
              <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
              <input id="ot-filter-emp" class="w-56 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search by name or ID" />
            </div>
            <select id="ot-filter-dept" class="border rounded px-2 py-1 text-sm">
              <option value="">All Departments</option>
            </select>
          </div>
          <div class="flex items-center gap-2 text-sm text-gray-600">
            <span>Rows per page</span>
            <select id="ot-page-size" class="border rounded px-2 py-1">
              <option value="10" selected>10</option>
              <option value="25">25</option>
              <option value="50">50</option>
            </select>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
              <tr>
                <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
                <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
                <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Department</th>
                <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Reason</th>
                <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Date</th>
                <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time In</th>
                <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time Out</th>
                <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Total Hours</th>
                <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
                <th class="px-3 py-2 text-right text-xs font-semibold text-gray-600">Actions</th>
              </tr>
            </thead>
            <tbody id="ot-tbody" class="divide-y divide-gray-200 bg-white"></tbody>
          </table>
        </div>
        <div id="ot-pagination" class="mt-3 flex items-center justify-between text-sm text-gray-600"></div>
      </div>

      <div id="qrOtModal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-lg">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3">
              <h5 class="font-semibold">QR Overtime Scanner</h5>
              <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
            </div>
            <div class="p-4">
              <div id="qr-reader-ot" class="w-full max-w-sm mx-auto"></div>
              <div id="qr-feedback-ot" class="text-sm text-center mt-2"></div>
              <div class="flex justify-center gap-2 mt-3">
                <button id="qr-stop-ot" class="px-3 py-1 text-sm rounded border">Stop</button>
                <button id="qr-resume-ot" class="px-3 py-1 text-sm rounded border hidden">Scan Again</button>
              </div>
            </div>
            <div class="flex justify-end gap-2 border-t px-4 py-3">
              <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
            </div>
          </div>
        </div>
      </div>

      <div id="otModal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-lg">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3">
              <h5 class="font-semibold">Record Overtime</h5>
              <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
            </div>
            <div class="p-4">
              <form id="ot-form" class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div class="md:col-span-2">
                  <label class="block text-sm text-gray-600 mb-1">Employee</label>
                  <input id="ot-emp-search" type="text" placeholder="Search employee..." class="w-full border rounded px-3 py-2 text-sm mb-2" />
                  <select id="ot-emp" class="w-full border rounded px-3 py-2" required></select>
                </div>
                <div>
                  <label class="block text-sm text-gray-600 mb-1">Date</label>
                  <input type="date" id="ot-date" class="w-full border rounded px-3 py-2" required />
                </div>
                <div class="md:col-span-2 text-xs text-gray-500 bg-blue-50 border border-blue-200 rounded px-3 py-2">
                  Time In/Out are captured via QR scan after approval (8:30 PM–10:00 PM).
                </div>
                <div class="md:col-span-2">
                  <label class="block text-sm text-gray-600 mb-1">Reason</label>
                  <textarea id="ot-reason" rows="3" class="w-full border rounded px-3 py-2" placeholder="Reason..."></textarea>
                </div>
              </form>
            </div>
            <div class="flex justify-end gap-2 border-t px-4 py-3">
              <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
              <button id="ot-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
            </div>
          </div>
        </div>
      </div>`;

    // Functions and wiring (copied to mirror Admin Overtime behavior)
    const apiBase = baseApiUrl;
    let qrScanner = null;
    // Continuous scan throttling (standby like attendance scanner)
    let scanningBusy = false;
    let lastDecodedText = '';
    let lastScanTime = 0;
    let employeesCache = [];
    let otRows = [];
    let otPage = 1;
    let otEditContext = null;

    async function ensureQrScanLib(){
      if (window.Html5Qrcode) return;
      await new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = 'https://unpkg.com/html5-qrcode';
        s.onload = resolve; s.onerror = reject;
        document.head.appendChild(s);
      });
    }
    function setFeedback(elOrId, type, message) {
      try {
        const el = typeof elOrId === 'string' ? document.getElementById(elOrId) : elOrId;
        if (!el) return;
        const styles = {
          success: 'bg-green-50 text-green-700 border border-green-200',
          error: 'bg-red-50 text-red-700 border border-red-200',
          warning: 'bg-amber-50 text-amber-700 border border-amber-200',
          info: 'bg-blue-50 text-blue-700 border border-blue-200'
        };
        const klass = styles[type] || styles.info;
        el.innerHTML = `<div class="inline-flex items-center justify-center px-3 py-2 rounded ${klass}">${message}</div>`;
      } catch {}
    }
    function today(){ const d=new Date(); const y=d.getFullYear(); const m=String(d.getMonth()+1).padStart(2,'0'); const day=String(d.getDate()).padStart(2,'0'); return `${y}-${m}-${day}`; }
    function nowHHMM(){ const d=new Date(); const hh=String(d.getHours()).padStart(2,'0'); const mm=String(d.getMinutes()).padStart(2,'0'); return `${hh}:${mm}`; }
    function compareTimesHHMM(a,b){ try{ const [ah,am]=String(a||'').split(':').map(Number); const [bh,bm]=String(b||'').split(':').map(Number); const at=(ah||0)*60+(am||0); const bt=(bh||0)*60+(bm||0); return at===bt?0:(at>bt?1:-1);}catch{return 0;} }
    function capitalizeWords(str){ if(!str) return ''; return String(str).split(' ').map(w=>w?(w.charAt(0).toUpperCase()+w.slice(1).toLowerCase()):'').join(' ');}
    function formatDate(dateStr){ if(!dateStr) return ''; try{ const d=new Date(dateStr); if(isNaN(d.getTime())) return String(dateStr); return d.toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'});}catch{return String(dateStr||'');} }
    function formatTimeOfDay(timeStr){ if(!timeStr) return ''; try{ const parts=String(timeStr).split(':'); if(parts.length<2) return String(timeStr); let h=parseInt(parts[0],10); const m=parseInt(parts[1],10)||0; if(!Number.isFinite(h)) return String(timeStr); const ampm=h>=12?'PM':'AM'; h=h%12; if(h===0) h=12; const mm=String(m).padStart(2,'0'); return `${h}:${mm} ${ampm}`;}catch{return String(timeStr||'');} }
    function getStatusBadgeClass(status){
      const s = String(status || '').toLowerCase();
      // Overtime progression statuses
      if (s === 'incomplete') return 'bg-blue-100 text-blue-700 ring-blue-600/20';
      if (s === 'completed') return 'bg-green-100 text-green-700 ring-green-600/20';
      // Fallback to approval-oriented statuses
      if (s.includes('approve')) return 'bg-green-100 text-green-700 ring-green-600/20';
      if (s.includes('pending') || s.includes('await')) return 'bg-amber-100 text-amber-700 ring-amber-600/20';
      if (s.includes('reject') || s.includes('deny')) return 'bg-red-100 text-red-700 ring-red-600/20';
      if (s.includes('in') || s.includes('ongoing') || s.includes('progress')) return 'bg-blue-100 text-blue-700 ring-blue-600/20';
      if (s.includes('done') || s.includes('complete') || s.includes('closed')) return 'bg-gray-100 text-gray-700 ring-gray-500/20';
      return 'bg-gray-100 text-gray-700 ring-gray-500/20';
    }

    async function hasApprovedOvertimeForToday(employeeId){
      try {
        const res = await axios.get(`${apiBase}/overtime.php`, { params: { operation: 'listApproved' } });
        const rows = Array.isArray(res.data) ? res.data : [];
        const t = today();
        return rows.some(r => String(r.employee_id) === String(employeeId)
          && String(r.work_date) === String(t)
          && /^(approved|approve)$/i.test(String(r.status || '')));
      } catch { return false; }
    }

    function calcDurationStr(start,end){ try{ const toMinutes=(t)=>{ const parts=String(t).split(':').map(n=>parseInt(n,10)); const h=parts[0]||0,m=parts[1]||0,s=parts[2]||0; let total=h*60+m+Math.round(s/60); return Number.isFinite(total)?total:NaN;}; let a=toMinutes(start), b=toMinutes(end); if(!Number.isFinite(a)||!Number.isFinite(b)) return '-'; if(b<a) b+=24*60; const diff=b-a; if(diff<0) return '-'; const hh=Math.floor(diff/60); const mm=diff%60; return `${hh}h ${mm}m`; }catch{ return '-'; } }
    function formatHoursMinutesFromHours(hrs){ const n=Number(hrs); if(!Number.isFinite(n)||n<0) return '-'; const totalMinutes=Math.round(n*60); const h=Math.floor(totalMinutes/60); const m=totalMinutes%60; return `${h}h ${m}m`; }

    function parseEmployeeIdFromText(text){ try{ const s=String(text||'').trim(); const m=s.match(/EMP(\d{4})-(\d{3,})/i); if(m && m[2]){ const n=Number(m[2]); if(Number.isFinite(n) && n>0) return n; } const n2=Number(s); if(Number.isFinite(n2) && n2>0) return n2; return null; }catch{ return null; } }

    function buildFormData(map){ const fd=new FormData(); Object.entries(map).forEach(([k,v])=>fd.append(k,v)); return fd; }

    async function logOvertimeScan(employeeId){
      const feedback = document.getElementById('qr-feedback-ot');
      try {
        const work_date = today();
        const res = await axios.post(`${apiBase}/overtime.php`, buildFormData({ operation: 'logScan', json: JSON.stringify({ employee_id: employeeId, work_date }) }));
        const data = res && res.data ? res.data : null;
        if (!data || data.success != 1) {
          if (feedback) setFeedback(feedback, 'error', (data && data.message) ? data.message : 'Failed to record overtime.');
          return;
        }
        let msg = 'Overtime recorded.';
        if (data.action === 'in') msg = 'Overtime time in recorded.';
        else if (data.action === 'out') msg = 'Overtime time out recorded.';
        else if (data.action === 'done') msg = 'Overtime already completed for today.';
        if (feedback) {
          const t = (data.action === 'in' || data.action === 'out') ? 'success' : (data.action === 'done' ? 'info' : 'success');
          setFeedback(feedback, t, msg);
        }
        try { await fetchApprovedOvertime(); } catch {}
      } catch (e) {
        if (feedback) setFeedback(feedback, 'error', 'Failed to record overtime.');
      }
    }

    function ensureQrOtModal(){
      const modal = document.getElementById('qrOtModal');
      if (!modal) return;
      modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', async () => { await stopScanner(); modal.classList.add('hidden'); }));
      const stopBtn = modal.querySelector('#qr-stop-ot');
      const resumeBtn = modal.querySelector('#qr-resume-ot');
      if (stopBtn) stopBtn.addEventListener('click', async () => { await stopScanner(); });
      if (resumeBtn) resumeBtn.addEventListener('click', async () => { resumeBtn.classList.add('hidden'); await startScannerInto('qr-reader-ot', 'qr-feedback-ot', 'qr-resume-ot'); });
    }

    async function startScannerInto(readerId, feedbackId, resumeBtnId){
      const feedback = document.getElementById(feedbackId);
      try {
        await ensureQrScanLib();
        if (!window.Html5Qrcode) { if (feedback) setFeedback(feedback, 'error', 'Scanner library failed to load.'); return; }
        if (qrScanner) { try { await qrScanner.stop(); qrScanner.clear(); } catch {} }
        qrScanner = new window.Html5Qrcode(readerId);
        if (feedback) setFeedback(feedback, 'info', 'Point the camera at the QR code');
        const onScanSuccess = async (decodedText) => {
          try {
            let eid = null;
            try {
              const data = JSON.parse(decodedText);
              const type = data && data.type ? String(data.type).toLowerCase() : '';
              if (type === 'employee') {
                if (data && (data.employee_id || data.id)) {
                  const n = Number(data.employee_id || data.id);
                  if (Number.isFinite(n) && n > 0) eid = n;
                }
                if (!eid && data && data.code) { eid = parseEmployeeIdFromText(data.code); }
              }
            } catch {}
            if (!eid) { eid = parseEmployeeIdFromText(decodedText); }
            if (!eid) { if (feedback) setFeedback(feedback, 'error', 'Invalid or unsupported QR code.'); return; }
            const now = nowHHMM();
            const allowedStart = '20:30';
            const allowedEnd = '22:00';
            if (compareTimesHHMM(now, allowedStart) < 0 || compareTimesHHMM(now, allowedEnd) > 0) {
              if (feedback) setFeedback(feedback, 'warning', 'Overtime scan allowed only between 8:30 PM and 10:00 PM.');
              return;
            }
            const approved = await hasApprovedOvertimeForToday(eid);
            if (!approved) {
              if (feedback) setFeedback(feedback, 'warning', 'No approved overtime request for today. Request Approval required before scanning.');
              return;
            }
            // Keep camera running with throttling to avoid duplicate scans
            const nowTs = Date.now();
            if (scanningBusy) return;
            if (decodedText === lastDecodedText && (nowTs - lastScanTime) < 1500) return;
            scanningBusy = true;
            lastDecodedText = decodedText;
            lastScanTime = nowTs;
            await logOvertimeScan(eid);
            scanningBusy = false;
          } catch (e) {
            if (feedback) setFeedback(feedback, 'error', 'Error processing QR.');
          }
        };
        const onScanFailure = () => {};
        await qrScanner.start({ facingMode: 'environment' }, { fps: 10, qrbox: 250 }, onScanSuccess, onScanFailure);
        // Enforce scanner shutdown at 10:01 PM
        try {
          if (compareTimesHHMM(nowHHMM(), '22:01') >= 0) {
            try { alert('Scanner closed. Please contact HR or Admin to open again.'); } catch {}
            await stopScanner();
            const modal = document.getElementById('qrOtModal');
            if (modal) modal.classList.add('hidden');
            return;
          }
          if (window.__hrQrShutdownTimer) { clearInterval(window.__hrQrShutdownTimer); window.__hrQrShutdownTimer = null; }
          window.__hrQrShutdownTimer = setInterval(async () => {
            try {
              if (compareTimesHHMM(nowHHMM(), '22:01') >= 0) {
                try { alert('Scanner closed. Please contact HR or Admin to open again.'); } catch {}
                await stopScanner();
                const modal = document.getElementById('qrOtModal');
                if (modal) modal.classList.add('hidden');
              }
            } catch {}
          }, 10000);
        } catch {}
      } catch (e) {
        if (feedback) setFeedback(feedback, 'error', 'Camera permission denied or unavailable.');
      }
    }

    async function stopScanner(){ try { if (qrScanner) { await qrScanner.stop(); qrScanner.clear(); } } catch {} const fb=document.getElementById('qr-feedback-ot'); if (fb) { try { setFeedback(fb,'info','Scanner stopped.'); } catch {} } }

    async function loadEmployeesSelect(selectedId){
      if (employeesCache.length === 0){
        try {
          const res = await axios.get(`${apiBase}/employees.php`, { params: { operation: 'getEmployees' } });
          employeesCache = Array.isArray(res.data) ? res.data : [];
        } catch { employeesCache = []; }
      }
      const searchInput = document.getElementById('ot-emp-search');
      const select = document.getElementById('ot-emp');
      if (!select) return;
      const renderOptions = (list, selId) => {
        select.innerHTML = '';
        list.forEach(e => {
          const opt = document.createElement('option');
          opt.value = e.employee_id;
          opt.textContent = `${(e.first_name||'').trim()} ${(e.last_name||'').trim()}`.replace(/\s+/g,' ').trim();
          if (selId && String(selId) === String(e.employee_id)) opt.selected = true;
          select.appendChild(opt);
        });
      };
      renderOptions(employeesCache, selectedId);
      if (searchInput){
        searchInput.value = '';
        searchInput.oninput = () => {
          const q = (searchInput.value||'').toLowerCase().trim();
          const filtered = !q ? employeesCache : employeesCache.filter(e => (`${e.first_name||''} ${e.last_name||''}`.toLowerCase().includes(q)) || String(e.email||'').toLowerCase().includes(q));
          renderOptions(filtered, select.value);
        };
      }
    }

    function resetOtForm(){ const d=document.getElementById('ot-date'); if(d) d.value=''; const si=document.getElementById('ot-start'); if(si) si.value=''; const so=document.getElementById('ot-end'); if(so) so.value=''; const r=document.getElementById('ot-reason'); if(r) r.value=''; const s=document.getElementById('ot-emp-search'); if(s) s.value=''; }

    function wireOtModal(){
      const modal = document.getElementById('otModal');
      if (!modal) return;
      const closeEls = modal.querySelectorAll('[data-close="true"]');
      const close = () => { modal.classList.add('hidden'); otEditContext = null; };
      closeEls.forEach(el => el.addEventListener('click', close));
      const saveBtn = modal.querySelector('#ot-save');
      if (saveBtn) saveBtn.addEventListener('click', async () => {
        const employee_id = document.getElementById('ot-emp')?.value;
        const work_date = document.getElementById('ot-date')?.value;
        const reason = document.getElementById('ot-reason')?.value || '';
        if (!employee_id || !work_date) { alert('Select employee and date'); return; }
        try {
          if (otEditContext && otEditContext.ot_id){
            const fd = new FormData();
            fd.append('operation', 'updateOvertime');
            fd.append('json', JSON.stringify({ ot_id: otEditContext.ot_id, employee_id, work_date, reason }));
            await axios.post(`${apiBase}/overtime.php`, fd);
            alert('Overtime updated. Time In/Out will be recorded via QR after approval.');
          } else {
            const fd = new FormData();
            fd.append('operation', 'requestOvertime');
            fd.append('json', JSON.stringify({ employee_id, work_date, reason }));
            await axios.post(`${apiBase}/overtime.php`, fd);
            alert('Overtime request submitted (pending). Employee must scan to record overtime.');
          }
          close();
          await fetchApprovedOvertime();
        } catch (e){
          alert('Failed to save overtime');
        }
      });
    }

    function getPageSize(){ const sel=document.getElementById('ot-page-size'); const n=sel?parseInt(sel.value,10):10; return Number.isFinite(n)&&n>0?n:10; }
    function getFilterTerm(){ const inp=document.getElementById('ot-filter-emp'); return (inp&&inp.value?String(inp.value):'').trim().toLowerCase(); }
    function getFilterDept(){ const sel=document.getElementById('ot-filter-dept'); return (sel&&sel.value?String(sel.value):'').trim().toLowerCase(); }
    function filterRows(rows){
      const term = getFilterTerm();
      const dept = getFilterDept();
      return rows.filter(r => {
        const name = `${r.first_name||''} ${r.last_name||''}`.toLowerCase();
        const idStr = String(r.employee_id||r.employeeId||'').toLowerCase();
        const empMatch = term === '' ? true : (name.includes(term) || idStr.includes(term));
        if (!empMatch) return false;
        if (dept === '') return true;
        const rowDept = (r.department || '').toString().toLowerCase();
        if (rowDept) return rowDept === dept;
        const emp = employeesCache.find(e => String(e.employee_id) === String(r.employee_id));
        const empDept = emp && emp.department ? String(emp.department).toLowerCase() : '';
        return empDept === dept;
      });
    }

    function renderPagination(total){
      const pag=document.getElementById('ot-pagination'); if(!pag) return;
      const pageSize=getPageSize(); const totalPages=Math.max(1, Math.ceil(total/pageSize)); if(otPage>totalPages) otPage=totalPages;
      const start= total===0?0: (otPage-1)*pageSize + 1; const end = Math.min(total, otPage*pageSize);
      pag.innerHTML = `
        <div>Showing ${start}-${end} of ${total}</div>
        <div class="flex items-center gap-2">
          <button id="ot-prev" class="px-2 py-1 border rounded text-sm" ${otPage<=1?'disabled':''}>Prev</button>
          <span class="text-sm">Page ${otPage} / ${totalPages}</span>
          <button id="ot-next" class="px-2 py-1 border rounded text-sm" ${otPage>=totalPages?'disabled':''}>Next</button>
        </div>`;
      const prev=document.getElementById('ot-prev'); const next=document.getElementById('ot-next');
      if(prev) prev.onclick=()=>{ if(otPage>1){ otPage--; renderTable(); } };
      if(next) next.onclick=()=>{ if(otPage<totalPages){ otPage++; renderTable(); } };
    }

    async function editOtRow(row){
      const modal = document.getElementById('otModal');
      if (!modal) return;
      try { const title = modal.querySelector('h5'); if (title) title.textContent = 'Edit Overtime'; const save = modal.querySelector('#ot-save'); if (save) save.textContent = 'Update'; } catch {}
      otEditContext = { ot_id: row.ot_id || row.id };
      await loadEmployeesSelect(row.employee_id);
      const d=document.getElementById('ot-date'); if(d) d.value = row.work_date || '';
      const si=document.getElementById('ot-start'); if(si) si.value = row.start_time || '';
      const so=document.getElementById('ot-end'); if(so) so.value = row.end_time || '';
      const rzn=document.getElementById('ot-reason'); if(rzn) rzn.value = row.reason || '';
      const sel=document.getElementById('ot-emp'); if (sel) sel.value = String(row.employee_id || '');
      const sInp=document.getElementById('ot-emp-search'); if (sInp) sInp.value = '';
      modal.classList.remove('hidden');
    }

    async function deleteOtRow(row){
      const otId = row && (row.ot_id || row.id);
      if (!otId) return;
      if (!confirm('Delete this overtime record?')) return;
      try{
        const fd = new FormData();
        fd.append('operation', 'deleteOvertime');
        fd.append('json', JSON.stringify({ ot_id: otId }));
        await axios.post(`${apiBase}/overtime.php`, fd);
      } catch {}
      await fetchApprovedOvertime();
    }

    function openOtFloatingMenu(btn, row){
      const existing = document.getElementById('ot-floating-menu');
      if (existing) existing.remove();
      const rect = btn.getBoundingClientRect();
      const menu = document.createElement('div');
      menu.id = 'ot-floating-menu';
      menu.className = 'fixed z-50 w-36 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5';
      menu.style.top = `${Math.round(rect.bottom + 8)}px`;
      const left = Math.round(rect.right - 144);
      menu.style.left = `${left}px`;
      menu.innerHTML = `
        <div class="py-1">
          <button class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50" data-float-action="edit">Edit</button>
          <button class="w-full text-left px-3 py-2 text-sm text-red-600 hover:bg-gray-50" data-float-action="delete">Delete</button>
        </div>`;
      document.body.appendChild(menu);
      const onDocClick = (ev) => { if (menu && !menu.contains(ev.target) && ev.target !== btn) { try { menu.remove(); } catch {} } };
      setTimeout(() => document.addEventListener('click', onDocClick, { once: true }), 0);
      const eBtn = menu.querySelector('[data-float-action="edit"]');
      const dBtn = menu.querySelector('[data-float-action="delete"]');
      if (eBtn) eBtn.addEventListener('click', async () => { try { menu.remove(); } catch {} await editOtRow(row); });
      if (dBtn) dBtn.addEventListener('click', async () => { try { menu.remove(); } catch {} await deleteOtRow(row); });
    }

    function renderTable(){
      const tbody = document.getElementById('ot-tbody');
      if (!tbody) return;
      const rows = filterRows(otRows);
      const pageSize = getPageSize();
      const startIdx = (otPage - 1) * pageSize;
      const pageRows = rows.slice(startIdx, startIdx + pageSize);
      tbody.innerHTML = pageRows.map((r, idx) => {
        const n = startIdx + idx + 1;
        const emp = capitalizeWords(`${r.first_name || ''} ${r.last_name || ''}`.trim());
        const reason = (r.reason || '').toString();
        const dept = (() => {
          const d = (r.department || '').toString();
          if (d) return d;
          const empRow = employeesCache.find(e => String(e.employee_id) === String(r.employee_id));
          return empRow && empRow.department ? empRow.department : '';
        })();
        const statusText = (() => {
          if (r.start_time && !r.end_time) return 'Incomplete';
          if (r.start_time && r.end_time) return 'Completed';
          return capitalizeWords(r.status || '');
        })();
        const totalHours = (() => {
          // Live total runs until 10:00 PM; after that it stops increasing (capped at 22:00)
          if (r.start_time && r.end_time) return calcDurationStr(r.start_time, r.end_time);
          if (r.start_time && !r.end_time) {
            const now = nowHHMM();
            const endCap = compareTimesHHMM(now, '22:00') > 0 ? '22:00' : now;
            return calcDurationStr(r.start_time, endCap);
          }
          return '';
        })();
        return `<tr>
          <td class="px-3 py-2 text-sm text-gray-700">${n}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${emp || ''}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${dept ? capitalizeWords(dept) : ''}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${reason || ''}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${formatDate(r.work_date)}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${formatTimeOfDay(r.start_time) || ''}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${formatTimeOfDay(r.end_time) || ''}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${totalHours}</td>
          <td class="px-3 py-2 text-sm text-gray-700"><span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ring-1 ${getStatusBadgeClass(statusText)}">${statusText || ''}</span></td>
          <td class="px-3 py-2 text-right text-sm">
            <div class="relative inline-block text-left">
              <button class="inline-flex items-center justify-center w-8 h-8 rounded hover:bg-gray-100" aria-label="Actions" data-ot-menu-toggle data-idx="${idx}">
                <span class="text-gray-600 font-bold text-lg">•••</span>
              </button>
            </div>
          </td>
        </tr>`;
      }).join('');

      // Wire per-row menu actions
      tbody.querySelectorAll('[data-ot-menu-toggle]').forEach((btn) => {
        const idx = parseInt(btn.getAttribute('data-idx'), 10);
        btn.addEventListener('click', (ev) => {
          ev.preventDefault(); ev.stopPropagation();
          openOtFloatingMenu(btn, pageRows[idx]);
        });
      });

      renderPagination(rows.length);
    }

    async function fetchApprovedOvertime(){
      try {
        const res = await axios.get(`${apiBase}/overtime.php`, { params: { operation: 'listApproved' } });
        const data = Array.isArray(res.data) ? res.data : [];
        otRows = data.filter(r => !!r.start_time);
        otPage = 1;
        renderTable();
      } catch (e) {
        otRows = [];
        renderTable();
      }
    }

    // Wire up controls
    ensureQrScanLib().catch(()=>{});
    ensureQrOtModal();
    wireOtModal();
    const scanBtn = document.getElementById('btn-qr-scan-ot');
    if (scanBtn) scanBtn.addEventListener('click', async () => {
      const modal = document.getElementById('qrOtModal');
      if (modal) modal.classList.remove('hidden');
      await startScannerInto('qr-reader-ot', 'qr-feedback-ot', 'qr-resume-ot');
    });
    const addBtn = document.getElementById('btn-add-ot');
    if (addBtn) addBtn.addEventListener('click', async () => {
      const modal = document.getElementById('otModal');
      otEditContext = null;
      await loadEmployeesSelect();
      resetOtForm();
      if (modal) { try { const title = modal.querySelector('h5'); if (title) title.textContent = 'Record Overtime'; const save = modal.querySelector('#ot-save'); if (save) save.textContent = 'Save'; } catch {} }
      if (modal) modal.classList.remove('hidden');
    });

    fetchApprovedOvertime();
    // Populate departments and prefetch employees for dept join
    async function populateDepartmentsDropdown(){
      try {
        const sel = document.getElementById('ot-filter-dept');
        if (!sel) return;
        const res = await axios.get(`${apiBase}/employees.php`, { params: { operation: 'getDepartments' } });
        const list = Array.isArray(res.data) ? res.data : [];
        const current = sel.value;
        sel.innerHTML = '<option value="">All Departments</option>' + list.map(d => `<option value="${String(d)}">${String(d)}</option>`).join('');
        if (current && list.includes(current)) sel.value = current;
      } catch {}
    }
    populateDepartmentsDropdown();
    (async () => {
      try {
        const res = await axios.get(`${apiBase}/employees.php`, { params: { operation: 'getEmployees' } });
        employeesCache = Array.isArray(res.data) ? res.data : [];
        renderTable();
      } catch { employeesCache = []; renderTable(); }
    })();

    const filterInp = document.getElementById('ot-filter-emp');
    if (filterInp) filterInp.addEventListener('input', () => { otPage = 1; renderTable(); });
    const deptSel = document.getElementById('ot-filter-dept');
    if (deptSel) deptSel.addEventListener('change', () => { otPage = 1; renderTable(); });
    const pageSel = document.getElementById('ot-page-size');
    if (pageSel) pageSel.addEventListener('change', () => { otPage = 1; renderTable(); });
  },
  payroll: async () => {
    const module = await import('./modules/payroll.js');
    await module.render();
  },
  reports: async () => {
    const module = await import('./modules/reports.js');
    await module.render();
  },
    'leave-management': async () => {
    const module = await import('./modules/leaves.js');
    await module.render();
  },
  requestapproval: async () => {
    const app = document.getElementById('app');
    app.innerHTML = `
      <div class="flex items-center justify-between mb-3">
        <h3 class="font-semibold">Request Approval</h3>
        <div class="flex items-center gap-2">
          <button id="hr-btn-file-ot" class="inline-flex items-center px-3 py-2 text-sm font-medium rounded bg-primary-600 text-white hover:bg-primary-700">Request Overtime</button>
        </div>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <div class="mb-3 flex items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <div class="relative">
              <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
              <input id="hr-req-search-input" class="w-56 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, type, date, reason" />
            </div>
            <select id="hr-req-status-filter" class="border rounded px-2 py-1 text-sm">
              <option value="pending" selected>Pending</option>
              <option value="approved">Approved</option>
              <option value="rejected">Rejected</option>
            </select>
            <select id="hr-req-dept-filter" class="ml-2 border rounded px-2 py-1 text-sm">
              <option value="">All Departments</option>
            </select>
          </div>
          <div class="flex items-center gap-2 text-sm text-gray-600">
            <span>Rows per page</span>
            <select id="hr-req-page-size" class="border rounded px-2 py-1">
              <option value="5">5</option>
              <option value="10" selected>10</option>
              <option value="20">20</option>
              <option value="50">50</option>
            </select>
          </div>
        </div>
        <div id="hr-req-approval-table" class="overflow-x-auto"></div>
        <div id="hr-req-pagination" class="mt-3 flex items-center justify-between text-sm text-gray-600"></div>
      </div>

      <div id="hrOtModal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-lg">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold">Request Overtime</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
            <div class="p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Employee</label>
                <input id="hr-ot-emp-search" class="w-full border rounded px-3 py-2 mb-2" placeholder="Search employee..." />
                <select id="hr-ot-emp" class="w-full border rounded px-3 py-2"></select>
              </div>
                            <div>
                <label class="block text-sm text-gray-600 mb-1">Date</label>
                <input id="hr-ot-date" type="date" class="w-full border rounded px-3 py-2" />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Time In</label>
                <input id="hr-ot-in" type="time" class="w-full border rounded px-3 py-2" />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Time Out</label>
                <input id="hr-ot-out" type="time" class="w-full border rounded px-3 py-2" />
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Reason</label>
                <textarea id="hr-ot-reason" rows="3" class="w-full border rounded px-3 py-2"></textarea>
              </div>
            </div>
            <div class="flex justify-end gap-2 border-t px-4 py-3">
              <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
              <button id="hr-ot-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Submit</button>
            </div>
          </div>
        </div>
      </div>

      <div id="hrUtModal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-lg">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold">Request Undertime</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
            <div class="p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Employee</label>
                <input id="hr-ut-emp-search" class="w-full border rounded px-3 py-2 mb-2" placeholder="Search employee..." />
                <select id="hr-ut-emp" class="w-full border rounded px-3 py-2"></select>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Date</label>
                <input id="hr-ut-date" type="date" class="w-full border rounded px-3 py-2" />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Hours</label>
                <input id="hr-ut-hours" type="number" step="0.25" min="0.25" class="w-full border rounded px-3 py-2" placeholder="e.g., 1" />
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Reason</label>
                <textarea id="hr-ut-reason" rows="3" class="w-full border rounded px-3 py-2"></textarea>
              </div>
            </div>
            <div class="flex justify-end gap-2 border-t px-4 py-3">
              <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
              <button id="hr-ut-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Submit</button>
            </div>
          </div>
        </div>
      </div>`;

    const wrap = document.getElementById('hr-req-approval-table');
    wrap.innerHTML = '<div class="text-gray-500">Loading...</div>';

    // Load employees for OT/UT
    let _hrEmployees = [];
    async function loadEmployeesList(){
      try {
        const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
        _hrEmployees = Array.isArray(res.data) ? res.data : [];
      } catch { _hrEmployees = []; }
    }
    function renderEmpOptions(selectId, list, selected){
      const sel = document.getElementById(selectId);
      if (!sel) return;
      sel.innerHTML = '';
      const cur = selected != null ? String(selected) : '';
      list.forEach(e => {
        const opt = document.createElement('option');
        opt.value = e.employee_id;
        opt.textContent = toTitleCase(`${e.first_name || ''} ${e.last_name || ''}`);
        if (cur && String(cur) === String(e.employee_id)) opt.selected = true;
        sel.appendChild(opt);
      });
    }
    function wireSearchEmp(inputId, selectId){
      const input = document.getElementById(inputId);
      if (!input) return;
      input.oninput = () => {
        const q = (input.value || '').toLowerCase().trim();
        const selected = document.getElementById(selectId)?.value || '';
        const filtered = !q ? _hrEmployees.slice() : _hrEmployees.filter(e => `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.includes(q) || String(e.email||'').toLowerCase().includes(q));
        renderEmpOptions(selectId, filtered, selected);
      };
    }

    // Modal controls
    const otModal = document.getElementById('hrOtModal');
    const utModal = document.getElementById('hrUtModal');
    const openOt = async () => { await loadEmployeesList(); renderEmpOptions('hr-ot-emp', _hrEmployees); wireSearchEmp('hr-ot-emp-search', 'hr-ot-emp'); if (otModal) otModal.classList.remove('hidden'); };
    const closeOt = () => { if (otModal) otModal.classList.add('hidden'); };
    const openUt = async () => { await loadEmployeesList(); renderEmpOptions('hr-ut-emp', _hrEmployees); wireSearchEmp('hr-ut-emp-search', 'hr-ut-emp'); if (utModal) utModal.classList.remove('hidden'); };
    const closeUt = () => { if (utModal) utModal.classList.add('hidden'); };

    const otBtn = document.getElementById('hr-btn-file-ot');
    const utBtn = document.getElementById('hr-btn-file-ut');
    if (otBtn) otBtn.addEventListener('click', openOt);
    if (utBtn) utBtn.addEventListener('click', openUt);
    if (otModal) otModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeOt));
    if (utModal) utModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeUt));

    const otSave = document.getElementById('hr-ot-save');
    if (otSave) otSave.addEventListener('click', async () => {
      const employee_id = document.getElementById('hr-ot-emp')?.value;
      const work_date = document.getElementById('hr-ot-date')?.value;
      const reason = document.getElementById('hr-ot-reason')?.value || '';
      const tIn = document.getElementById('hr-ot-in')?.value || '';
      const tOut = document.getElementById('hr-ot-out')?.value || '';
      const toMinutes = (t) => { const parts = String(t).split(':').map(n => parseInt(n,10)); if (parts.length < 2 || Number.isNaN(parts[0]) || Number.isNaN(parts[1])) return NaN; return parts[0]*60 + parts[1]; };
      const a = toMinutes(tIn);
      const b = toMinutes(tOut);
      if (!employee_id || !work_date || !Number.isFinite(a) || !Number.isFinite(b)) { alert('Select employee, date and valid time in/out'); return; }
      let diff = b - a; if (diff <= 0) diff += 24*60;
      const hoursVal = Math.round((diff / 60) * 100) / 100;
      const fd = new FormData();
      fd.append('operation', 'requestOvertime');
      fd.append('json', JSON.stringify({ employee_id, work_date, hours: hoursVal, reason }));
      try { await axios.post(`${window.baseApiUrl}/overtime.php`, fd); closeOt(); alert('Overtime request submitted'); await routes.requestapproval(); } catch { alert('Failed to submit overtime'); }
    });

    const utSave = document.getElementById('hr-ut-save');
    if (utSave) utSave.addEventListener('click', async () => {
      const employee_id = document.getElementById('hr-ut-emp')?.value;
      const work_date = document.getElementById('hr-ut-date')?.value;
      const hours = Number(document.getElementById('hr-ut-hours')?.value || '0');
      const reason = document.getElementById('hr-ut-reason')?.value || '';
      if (!employee_id || !work_date || !Number.isFinite(hours) || hours <= 0) { alert('Select employee, date and valid hours'); return; }
      const fd = new FormData();
      fd.append('operation', 'requestUndertime');
      fd.append('json', JSON.stringify({ employee_id, work_date, hours, reason }));
      try { await axios.post(`${window.baseApiUrl}/undertime.php`, fd); closeUt(); alert('Undertime request submitted'); await routes.requestapproval(); } catch { alert('Failed to submit undertime'); }
    });

    // Search & pagination state
    let allItems = [];
    let query = '';
    let page = 1;
    let pageSize = 10;
    let statusFilter = 'pending';
    let deptFilter = '';

    const searchInput = document.getElementById('hr-req-search-input');
    const pageSizeSelect = document.getElementById('hr-req-page-size');
    const pager = document.getElementById('hr-req-pagination');
    const statusSelect = document.getElementById('hr-req-status-filter');
    const deptSelect = document.getElementById('hr-req-dept-filter');

    const statusBadge = (st) => {
      const s = String(st || '').toLowerCase();
      let cls = 'inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full ring-1 ';
      let label = 'Pending';
      if (s === 'approved' || s === 'approve') { cls += 'bg-green-50 text-green-700 ring-green-200'; label = 'Approved'; }
      else if (s === 'rejected' || s === 'reject') { cls += 'bg-red-50 text-red-700 ring-red-200'; label = 'Rejected'; }
      else { cls += 'bg-yellow-50 text-yellow-700 ring-yellow-200'; label = 'Pending'; }
      return `<span class="${cls}">${label}</span>`;
    };

    const formatWorkDate = (s) => {
      if (!s) return '';
      try {
        const d = new Date(String(s).includes('T') ? s : `${s}T00:00:00`);
        if (isNaN(d.getTime())) return s;
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
      } catch { return s; }
    };

    const calcHoursDecimal = (start, end) => {
      try {
        const toMin = (t) => {
          const parts = String(t).split(':').map(n => parseInt(n,10));
          const h = parts[0]||0, m = parts[1]||0, s = parts[2]||0;
          return h*60 + m + Math.round(s/60);
        };
        let a = toMin(start), b = toMin(end);
        if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
        if (b < a) b += 24*60;
        const diffMin = b - a;
        if (diffMin <= 0) return null;
        return diffMin / 60;
      } catch { return null; }
    };

    const formatHours = (hrs) => {
      const n = Number(hrs);
      if (!Number.isFinite(n)) return '';
      const isInt = Math.abs(n - Math.round(n)) < 1e-9;
      const s = isInt ? String(Math.round(n)) : String(n);
      return `${s}H`;
    };

    const getFiltered = () => {
      const q = (query || '').toLowerCase();
      const s = (statusFilter || 'pending').toLowerCase();
      const d = (deptFilter || '').toLowerCase();
      let base = allItems.slice();
      if (s !== 'all') {
        base = base.filter(it => {
          const st = String(it.status || '').toLowerCase();
          if (s === 'approved' || s === 'approve') return st === 'approved' || st === 'approve';
          if (s === 'rejected' || s === 'reject') return st === 'rejected' || st === 'reject';
          return st === 'pending';
        });
      }
      if (d) {
        base = base.filter(it => {
          const emp = _hrEmployees.find(e => String(e.employee_id) === String(it.employee_id));
          const dept = (emp && emp.department ? emp.department : (it.department || '')).toLowerCase();
          return dept === d;
        });
      }
      if (!q) return base;
      return base.filter(it => {
        const name = `${it.first_name || ''} ${it.last_name || ''}`.toLowerCase();
        const type = (it.kind || '').toLowerCase();
        const date = (it.work_date || '').toLowerCase();
        const reason = (it.reason || '').toLowerCase();
        const st = (it.status || '').toLowerCase();
        return name.includes(q) || type.includes(q) || date.includes(q) || reason.includes(q) || st.includes(q);
      });
    };

    const render = () => {
      const rows = getFiltered();
      const total = rows.length;
      const totalPages = Math.max(1, Math.ceil(total / pageSize));
      if (page > totalPages) page = totalPages;
      const startIdx = (page - 1) * pageSize;
      const endIdx = Math.min(startIdx + pageSize, total);
      const pageRows = rows.slice(startIdx, endIdx);

      const table = document.createElement('table');
      table.className = 'min-w-full divide-y divide-gray-200';
      table.innerHTML = `
        <thead class="bg-gray-50"><tr>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Department</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Type</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Date</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Overtime Hours</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Reason</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
          <th class="px-3 py-2 text-right text-xs font-semibold text-gray-600">Actions</th>
        </tr></thead>
        <tbody class="divide-y divide-gray-200 bg-white"></tbody>`;
      const tbody = table.querySelector('tbody');
      if (!pageRows.length) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="9" class="px-3 py-6 text-sm text-center text-gray-500">No requests found</td>`;
        tbody.appendChild(tr);
      } else {
        pageRows.forEach((it, idx) => {
          const tr = document.createElement('tr');
          const name = toTitleCase(`${it.first_name || ''} ${it.last_name || ''}`.trim());
          const dept = (() => {
            const emp = _hrEmployees.find(e => String(e.employee_id) === String(it.employee_id));
            return emp && emp.department ? toTitleCase(emp.department) : '';
          })();
          const fmtTime = (t) => {
            try {
              const parts = String(t).split(':').map(n => parseInt(n,10));
              if (parts.length < 2 || isNaN(parts[0]) || isNaN(parts[1])) return '';
              let h = parts[0], m = parts[1];
              const ampm = h >= 12 ? 'PM' : 'AM';
              h = h % 12; if (h === 0) h = 12;
              const mm = String(m).padStart(2, '0');
              return `${h}:${mm} ${ampm}`;
            } catch { return ''; }
          };
          const workRange = (() => {
            const si = it.start_time || '';
            const ei = it.end_time || '';
            if (si && ei) return `${fmtTime(si)} → ${fmtTime(ei)}`;
            if (si && !ei) return `${fmtTime(si)} → -`;
            return '-';
          })();
          const formatHM = (hrs) => {
            const n = Number(hrs);
            if (!Number.isFinite(n) || n <= 0) return '';
            const total = Math.round(n * 60);
            const h = Math.floor(total / 60);
            const m = total % 60;
            return `${h}h ${m}m`;
          };
          const hoursStr = (() => {
            if (it.hours != null) {
              const n = Number(it.hours);
              if (Number.isFinite(n) && n > 0) return formatHM(n);
            }
            const dec = calcHoursDecimal(it.start_time, it.end_time);
            if (dec != null) return formatHM(dec);
            return '';
          })();
          tr.innerHTML = `
            <td class="px-3 py-2 text-sm text-gray-700">${startIdx + idx + 1}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${name}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${dept}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${it.kind}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${formatWorkDate(it.work_date) || ''}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${hoursStr}</td>
            <td class="px-3 py-2 text-sm text-gray-700 truncate max-w-[20rem]" title="${(it.reason||'').replace(/\"/g,'&quot;')}">${it.reason || ''}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${statusBadge(it.status)}</td>
            <td class="px-3 py-2 text-sm text-right">
              <div class="relative inline-block text-left" data-hr-req-menu-container>
                <button class="inline-flex items-center justify-center w-8 h-8 rounded hover:bg-gray-100" aria-label="Actions" data-action="menu-toggle">
                  <span class="text-gray-600 font-bold text-lg">•••</span>
                </button>
                <div class="hidden origin-top-right absolute right-0 mt-2 w-36 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 z-10" role="menu" data-menu>
                  <div class="py-1">
                    ${(() => {
                      const st = String((it.status||'')).toLowerCase();
                      if (st === 'pending') {
                        return `
                          <button class="w-full text-left px-3 py-2 text-sm text-blue-700 hover:bg-gray-50" data-menu-action="edit">Edit</button>
                          <button class="w-full text-left px-3 py-2 text-sm text-green-700 hover:bg-gray-50" data-menu-action="approve">Approve</button>
                          <button class="w-full text-left px-3 py-2 text-sm text-red-600 hover:bg-gray-50" data-menu-action="reject">Reject</button>
                        `;
                      }
                      // approved/rejected: no actions
                      return '';
                    })()}
                  </div>
                </div>
              </div>
            </td>`;
          const container = tr.querySelector('[data-hr-req-menu-container]');
          const toggle = container?.querySelector('[data-action="menu-toggle"]');
          const menu = container?.querySelector('[data-menu]');
          if (toggle && menu) {
            toggle.addEventListener('click', (ev) => {
              ev.preventDefault(); ev.stopPropagation();
              // Close other menus
              tbody.querySelectorAll('[data-hr-req-menu-container] [data-menu]').forEach(m => { if (m !== menu) m.classList.add('hidden'); });
              const wasHidden = menu.classList.contains('hidden');
              menu.classList.toggle('hidden');
              // When opening, temporarily disable scrollbars on the table wrapper
              const wrap = container.closest('.overflow-x-auto');
              if (wasHidden) {
                if (wrap) {
                  window.__hrReqPrevScrollWrap = wrap;
                  window.__hrReqPrevOverflowX = wrap.style.overflowX;
                  window.__hrReqPrevOverflowY = wrap.style.overflowY;
                  wrap.style.overflowX = 'visible';
                  wrap.style.overflowY = 'visible';
                }
              } else {
                if (window.__hrReqPrevScrollWrap) {
                  window.__hrReqPrevScrollWrap.style.overflowX = window.__hrReqPrevOverflowX || '';
                  window.__hrReqPrevScrollWrap.style.overflowY = window.__hrReqPrevOverflowY || '';
                  window.__hrReqPrevScrollWrap = null;
                  window.__hrReqPrevOverflowX = null;
                  window.__hrReqPrevOverflowY = null;
                }
              }
            });
            menu.querySelectorAll('[data-menu-action]').forEach(btn => {
              btn.addEventListener('click', async () => {
                const action = btn.getAttribute('data-menu-action');
                if (action === 'edit') {
                  await openEditRequestModalHR(it);
                } else if (action === 'approve') {
                  await submitDecision(it, 'approve');
                  await routes.requestapproval();
                } else if (action === 'reject') {
                  await submitDecision(it, 'reject');
                  await routes.requestapproval();
                }
                menu.classList.add('hidden');
                // Restore scrollbars if we disabled them when opening
                if (window.__hrReqPrevScrollWrap) {
                  window.__hrReqPrevScrollWrap.style.overflowX = window.__hrReqPrevOverflowX || '';
                  window.__hrReqPrevScrollWrap.style.overflowY = window.__hrReqPrevOverflowY || '';
                  window.__hrReqPrevScrollWrap = null;
                  window.__hrReqPrevOverflowX = null;
                  window.__hrReqPrevOverflowY = null;
                }
              });
            });
          }
          tbody.appendChild(tr);
        });
        // Wire global click close for HR request approval menus
        if (!window.__hrReqMenuGlobalClose) {
          window.__hrReqMenuGlobalClose = true;
          document.addEventListener('click', () => {
            document.querySelectorAll('[data-hr-req-menu-container] [data-menu]').forEach(m => m.classList.add('hidden'));
            // Restore scroll state for table wrapper if modified
            if (window.__hrReqPrevScrollWrap) {
              window.__hrReqPrevScrollWrap.style.overflowX = window.__hrReqPrevOverflowX || '';
              window.__hrReqPrevScrollWrap.style.overflowY = window.__hrReqPrevOverflowY || '';
              window.__hrReqPrevScrollWrap = null;
              window.__hrReqPrevOverflowX = null;
              window.__hrReqPrevOverflowY = null;
            }
          });
        }
      }
      wrap.innerHTML = '';
      wrap.appendChild(table);

      if (pager) {
        const showingFrom = total === 0 ? 0 : (startIdx + 1);
        const showingTo = endIdx;
        pager.innerHTML = `
          <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${total}</span></div>
          <div class="flex items-center gap-2">
            <button id="hr-req-prev" class="px-1.5 py-0.5 text-xs rounded border ${page <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
            <span>Page ${page} of ${totalPages}</span>
            <button id="hr-req-next" class="px-1.5 py-0.5 text-xs rounded border ${page >= totalPages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
          </div>`;
        const prev = document.getElementById('hr-req-prev');
        const next = document.getElementById('hr-req-next');
        if (prev) prev.addEventListener('click', () => { if (page > 1) { page -= 1; render(); } });
        if (next) next.addEventListener('click', () => { if (page < totalPages) { page += 1; render(); } });
      }
    };

    if (searchInput) searchInput.addEventListener('input', () => { query = (searchInput.value || '').trim(); page = 1; render(); });
    if (pageSizeSelect) pageSizeSelect.addEventListener('change', () => {
      const n = Number(pageSizeSelect.value);
      pageSize = Number.isFinite(n) && n > 0 ? n : 10;
      page = 1;
      render();
    });
    if (statusSelect) statusSelect.addEventListener('change', () => {
      statusFilter = (statusSelect.value || 'pending').toLowerCase();
      page = 1;
      render();
    });
    if (deptSelect) deptSelect.addEventListener('change', () => {
      deptFilter = (deptSelect.value || '').toLowerCase();
      page = 1;
      render();
    });

    // Prefetch employees for department join and populate dept filter
    try { await loadEmployeesList(); } catch { _hrEmployees = []; }
    const deptSelEl = document.getElementById('hr-req-dept-filter');
    if (deptSelEl) {
      const depts = Array.from(new Set((_hrEmployees || []).map(e => e.department).filter(Boolean))).sort((a,b)=>String(a).localeCompare(String(b)));
      deptSelEl.innerHTML = '<option value="">All Departments</option>' + depts.map(d => `<option value="${String(d)}">${String(d)}</option>`).join('');
    }

    // Load OT pending items only (exclude undertime)
    try {
      const otRes = await axios.get(`${window.baseApiUrl}/overtime.php`, { params: { operation: 'listAll' } });
      const ots = (otRes.data || []).map(r => ({ kind: 'Overtime', id: r.ot_id, employee_id: r.employee_id, first_name: r.first_name, last_name: r.last_name, work_date: r.work_date, hours: r.hours, reason: r.reason, status: r.status, start_time: r.start_time, end_time: r.end_time }));
      allItems = ots.sort((a, b) => String(b.work_date || '').localeCompare(String(a.work_date || '')));
      render();
    } catch (e) {
      wrap.innerHTML = '<div class="text-red-600">Failed to load requests</div>';
    }

    async function openEditRequestModalHR(request) {
      // Create modal overlay
      const modalOverlay = document.createElement('div');
      modalOverlay.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
      modalOverlay.id = 'hr-edit-request-modal';

      // Create modal content with floating card design matching admin style
      const modalContent = document.createElement('div');
      modalContent.className = 'bg-white rounded-lg shadow-xl max-w-md w-full mx-4';
      
      modalContent.innerHTML = `
        <div class="flex items-center justify-between border-b px-4 py-3">
          <h5 class="font-semibold">Edit ${request.kind} Request</h5>
          <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
        </div>
        <div class="p-4">
          <form id="hr-edit-request-form" class="space-y-4">
            <div>
              <label class="block text-sm text-gray-600 mb-1">Work Date</label>
              <input type="date" id="hr-edit-work-date" class="w-full border rounded px-3 py-2" value="${request.work_date || ''}">
            </div>
            ${request.kind === 'Overtime' ? `
              <div class="grid grid-cols-2 gap-3">
                <div>
                  <label class="block text-sm text-gray-600 mb-1">Start Time</label>
                  <input type="time" id="hr-edit-start-time" class="w-full border rounded px-3 py-2" value="${request.start_time || ''}">
                </div>
                <div>
                  <label class="block text-sm text-gray-600 mb-1">End Time</label>
                  <input type="time" id="hr-edit-end-time" class="w-full border rounded px-3 py-2" value="${request.end_time || ''}">
                </div>
              </div>
            ` : `
            <div>
              <label class="block text-sm text-gray-600 mb-1">Hours</label>
              <input type="number" step="0.5" min="0" id="hr-edit-hours" class="w-full border rounded px-3 py-2" value="${request.hours || ''}">
            </div>
            `}
            <div>
              <label class="block text-sm text-gray-600 mb-1">Reason</label>
              <textarea id="hr-edit-reason" rows="3" class="w-full border rounded px-3 py-2" placeholder="Enter reason...">${request.reason || ''}</textarea>
            </div>
          </form>
        </div>
        <div class="flex justify-end gap-2 border-t px-4 py-3">
          <button type="button" id="hr-edit-cancel" class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
          <button type="button" id="hr-edit-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save Changes</button>
        </div>
      `;

      modalOverlay.appendChild(modalContent);
      document.body.appendChild(modalOverlay);

      // Event handlers
      const cancelBtn = document.getElementById('hr-edit-cancel');
      const saveBtn = document.getElementById('hr-edit-save');
      const workDateInput = document.getElementById('hr-edit-work-date');
      const startTimeInput = document.getElementById('hr-edit-start-time');
      const endTimeInput = document.getElementById('hr-edit-end-time');
      const hoursInput = document.getElementById('hr-edit-hours');
      const reasonInput = document.getElementById('hr-edit-reason');

      // Auto-calculate hours for overtime requests
      if (request.kind === 'Overtime' && startTimeInput && endTimeInput) {
        const calculateHours = () => {
          const start = startTimeInput.value;
          const end = endTimeInput.value;
          if (start && end) {
            const startTime = new Date(`2000-01-01T${start}:00`);
            const endTime = new Date(`2000-01-01T${end}:00`);
            if (endTime > startTime) {
              const diffMs = endTime - startTime;
              const hours = diffMs / (1000 * 60 * 60);
              // For overtime requests, we don't show the hours field but still calculate internally
            }
          }
        };
        startTimeInput.addEventListener('change', calculateHours);
        endTimeInput.addEventListener('change', calculateHours);
      }

      // Close modal function
      const closeModal = () => {
        document.body.removeChild(modalOverlay);
      };

      // Cancel button and close button
      cancelBtn.addEventListener('click', closeModal);
      modalOverlay.querySelector('[data-close="true"]').addEventListener('click', closeModal);

      // Click outside to close
      modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) closeModal();
      });

      // Save button
      saveBtn.addEventListener('click', async () => {
        const workDate = workDateInput.value.trim();
        const reason = reasonInput.value.trim();

        // Validation
        if (!workDate) {
          alert('Please select a work date');
          return;
        }
        if (!reason) {
          alert('Please enter a reason');
          return;
        }

        try {
          const fd = new FormData();
          
          if (request.kind === 'Overtime') {
            fd.append('operation', 'updateOvertime');
            const payload = {
              ot_id: request.id,
              employee_id: request.employee_id,
              work_date: workDate,
              reason: reason
            };
            
            // For overtime, we might have start/end times
            if (startTimeInput && endTimeInput) {
              payload.start_time = startTimeInput.value;
              payload.end_time = endTimeInput.value;
            }
            
            fd.append('json', JSON.stringify(payload));
            await axios.post(window.baseApiUrl + '/overtime.php', fd);
          } else {
            // For undertime requests, we still need hours
            const hours = parseFloat(hoursInput.value) || 0;
            if (hours <= 0) {
              alert('Please enter valid hours');
              return;
            }
            fd.append('operation', 'updateUndertime');
            const payload = {
              ut_id: request.id,
              employee_id: request.employee_id,
              work_date: workDate,
              hours: hours,
              reason: reason
            };
            fd.append('json', JSON.stringify(payload));
            await axios.post(window.baseApiUrl + '/undertime.php', fd);
          }
          
          alert('Request updated successfully');
          closeModal();
          await routes.requestapproval(); // Refresh the table
        } catch (error) {
          console.error('Error updating request:', error);
          alert('Error updating request: ' + (error.response?.data?.message || error.message || 'Unknown error'));
        }
      });
    }

    async function submitDecision(it, op){
      const fd = new FormData();
      fd.append('operation', op === 'approve' ? 'approve' : 'reject');
      if (it.kind === 'Overtime') {
        fd.append('json', JSON.stringify({ ot_id: it.id }));
        await axios.post(`${window.baseApiUrl}/overtime.php`, fd);
      } else {
        fd.append('json', JSON.stringify({ ut_id: it.id }));
        await axios.post(`${window.baseApiUrl}/undertime.php`, fd);
      }
    }
  }
};

function handleRoute() {
  const hash = location.hash.replace('#', '') || 'dashboard';
  const route = routes[hash] || routes.dashboard;
  route();
}

window.addEventListener('hashchange', handleRoute);


document.addEventListener('DOMContentLoaded', async () => {
  // Determine if this is a cold start (first tab after all tabs were closed)
  const sessionKey = 'introAppAlive';
  const isFirstLoadInThisTab = !sessionStorage.getItem(sessionKey);
  if (isFirstLoadInThisTab) sessionStorage.setItem(sessionKey, '1');
  const prevOpenTabs = Number(localStorage.getItem('introOpenTabs') || '0');
  localStorage.setItem('introOpenTabs', String(prevOpenTabs + 1));
  window.addEventListener('unload', () => {
    const n = Number(localStorage.getItem('introOpenTabs') || '1');
    localStorage.setItem('introOpenTabs', String(Math.max(0, n - 1)));
  });

  // Skip cold-start logout if we just logged in via login page redirect
  const justLoggedIn = sessionStorage.getItem('introJustLoggedIn') === '1';
  if (justLoggedIn) {
    try { sessionStorage.removeItem('introJustLoggedIn'); } catch {}
  }

  // If this is a true cold start AND user was authenticated, force logout (unless just logged in)
  if (!justLoggedIn && isFirstLoadInThisTab && prevOpenTabs === 0) {
    try {
      const meCheck = await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
      if (meCheck.data && meCheck.data.authenticated) {
        try { await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'logout' }, withCredentials: true }); } catch {}
        location.href = '/intro/master/login.html';
        return;
      }
    } catch {}
  }

  const me = await currentUser();
  if (!me || me.role !== 'hr') {
    location.href = '/intro/master/login.html';
    return;
  }
  fillProfile(me);
  wireProfileMenu();
  wireHeaderNotifications();
  mountProfileModal();
  try {
    const btn = document.getElementById('btn-help');
    if (btn) {
      btn.addEventListener('click', () => {
        Swal.fire({
          title: 'Help & Support',
          html: `
            <div class="text-left">
              <p class="mb-3">Need assistance? Here are some ways to get help:</p>
              <ul class="list-disc list-inside space-y-2 text-sm">
                <li><strong>System Administrator:</strong> Contact your IT department</li>
                <li><strong>HR Support:</strong> Reach out to your HR team</li>
                <li><strong>Technical Issues:</strong> Report bugs or technical problems</li>
                <li><strong>Training:</strong> Request additional training sessions</li>
              </ul>
              <p class="mt-4 text-sm text-gray-600">
                For immediate assistance, please contact your system administrator or HR department.
              </p>
            </div>
          `,
          icon: 'info',
          confirmButtonText: 'Got it',
          confirmButtonColor: '#3b82f6'
        });
      });
    }
  } catch {}
  handleRoute();
});

async function currentUser(){
  try {
    const res = await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
    return res.data && res.data.user ? res.data.user : null;
  } catch { return null; }
}

async function markNotificationAsRead(notificationId){
  try {
    const fd = new FormData();
    fd.append('operation', 'markAsRead');
    fd.append('json', JSON.stringify({ notification_id: notificationId }));
    await axios.post(`${baseApiUrl}/notifications.php`, fd, { withCredentials: true });
    return true;
  } catch { return false; }
}

async function renderHeaderNotifications(){
  const badge = document.getElementById('notif-badge');
  const listEl = document.getElementById('hr-notif-dropdown-list');
  if (!badge || !listEl) return;
  try {
    const response = await axios.get(`${baseApiUrl}/notifications.php`, { params: { operation: 'getNotifications' }, withCredentials: true });
    const notifications = (response.data && response.data.success) ? (response.data.notifications || []) : [];
    const unread = notifications.filter(n => !n.read_at).length;
    try { sessionStorage.setItem('introUnreadNotifCount', String(unread)); } catch {}
    if (unread > 0) {
      badge.textContent = unread;
      badge.classList.remove('hidden');
      // Apply employee-like zoom pulse animation
      try { badge.classList.add('animate-zoom-pulse'); } catch {}
    } else {
      badge.classList.add('hidden');
      try { badge.classList.remove('animate-zoom-pulse'); } catch {}
    }

    listEl.innerHTML = notifications.length ? notifications.map(n => `
      <div class="px-4 py-2 border-t first:border-t-0 ${n.read_at ? 'opacity-75' : ''}">
        <div class="text-sm ${n.read_at ? 'text-gray-600' : 'text-gray-800 font-medium'}">${escapeHtml(n.message || '')}</div>
        <div class="text-xs text-gray-400 mt-0.5">${formatTime(n.created_at)}</div>
        <div class="mt-2 text-xs">
          ${!n.read_at ? `<button data-action="mark-read" data-id="${n.id}" class="px-2 py-1 rounded border border-primary-600 text-primary-700">Mark read</button>` : ''}
        </div>
      </div>
    `).join('') : '<div class="px-4 py-6 text-sm text-gray-500 text-center">No notifications</div>';

    listEl.querySelectorAll('[data-action="mark-read"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        await markNotificationAsRead(id);
        await renderHeaderNotifications();
      });
    });
  } catch {}
}

function wireHeaderNotifications(){
  if (window.__hrNotifHeaderWired) return;
  window.__hrNotifHeaderWired = true;
  const toggle = document.getElementById('notif-toggle');
  const dropdown = document.getElementById('notif-dropdown');
  const closeBtn = document.getElementById('notif-close');
  const markAllBtn = document.getElementById('notif-mark-all');
  if (!toggle || !dropdown) return;
  const close = () => dropdown.classList.add('hidden');
  toggle.addEventListener('click', async (e) => {
    e.stopPropagation();
    dropdown.classList.toggle('hidden');
    if (!dropdown.classList.contains('hidden')) { await renderHeaderNotifications(); }
  });
  if (closeBtn) closeBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      const response = await axios.get(`${baseApiUrl}/notifications.php`, { params: { operation: 'getNotifications' }, withCredentials: true });
      const notifications = (response.data && response.data.success) ? (response.data.notifications || []) : [];
      const unread = notifications.filter(n => !n.read_at);
      await Promise.all(unread.map(n => markNotificationAsRead(n.id)));
      await renderHeaderNotifications();
    } catch {}
    close();
  });
  if (markAllBtn) markAllBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      const response = await axios.get(`${baseApiUrl}/notifications.php`, { params: { operation: 'getNotifications' }, withCredentials: true });
      const notifications = (response.data && response.data.success) ? (response.data.notifications || []) : [];
      const unread = notifications.filter(n => !n.read_at);
      await Promise.all(unread.map(n => markNotificationAsRead(n.id)));
      await renderHeaderNotifications();
    } catch {}
  });
  document.addEventListener('click', (e) => {
    if (!dropdown.contains(e.target) && !toggle.contains(e.target)) close();
  });
  // refresh badge periodically
  setInterval(renderHeaderNotifications, 30000);
  renderHeaderNotifications();
}

function escapeHtml(str){
  try { return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;'); } catch { return String(str || ''); }
}
function formatTime(iso){ try { const d = new Date(iso); return d.toLocaleString(); } catch { return ''; } }

function wireProfileMenu(){
  const asideLogout = document.getElementById('btn-logout');
  if (asideLogout){
    asideLogout.addEventListener('click', async () => {
      try { await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'logout' }, withCredentials: true }); } catch {}
      location.href = '/intro/master/login.html';
    });
  }
  const trigger = document.getElementById('profile-trigger');
  const menu = document.getElementById('profile-menu');
  const headerLogout = document.getElementById('header-logout');
  const headerProfile = document.getElementById('header-profile');
  if (trigger && menu){
    trigger.addEventListener('click', (e) => {
      e.preventDefault();
      menu.classList.toggle('hidden');
    });
    document.addEventListener('click', (e) => {
      if (!menu.classList.contains('hidden')){
        const within = trigger.contains(e.target) || menu.contains(e.target);
        if (!within) menu.classList.add('hidden');
      }
    });
  }
  if (headerLogout){
    headerLogout.addEventListener('click', async () => {
      const result = await Swal.fire({
        title: 'Confirm Logout',
        text: 'Are you sure you want to logout?',
        icon: 'question',
        showCancelButton: true,
        confirmButtonColor: '#dc2626',
        cancelButtonColor: '#6b7280',
        confirmButtonText: 'Yes, logout',
        cancelButtonText: 'Cancel'
      });
      
      if (result.isConfirmed) {
        try { await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'logout' }, withCredentials: true }); } catch {}
        location.href = '/intro/master/login.html';
      }
    });
  }
  if (headerProfile){
    headerProfile.addEventListener('click', async () => {
      menu && menu.classList.add('hidden');
      await openProfile();
    });
  }
}

function fillProfile(user){
  const nameEl = document.getElementById('profile-name');
  const roleEl = document.getElementById('profile-role');
  const avatarEl = document.getElementById('profile-avatar');
  const displayName = (() => {
    const first = (user.first_name || '').trim();
    const last = (user.last_name || '').trim();
    if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
    const u = (user.username || '').trim();
    if (u.includes('@')) return u.split('@')[0];
    return u || 'HR';
  })();
  if (nameEl) nameEl.textContent = displayName;
  if (roleEl) roleEl.textContent = user.role || 'hr';
  if (avatarEl) avatarEl.textContent = (displayName || 'H').substring(0,1).toUpperCase();
}

function buildFormData(map) {
  const fd = new FormData();
  Object.entries(map).forEach(([k, v]) => fd.append(k, v));
  return fd;
}

// removed unload-based auto logout to avoid logging out on refresh

function mountProfileModal(){
  if (document.getElementById('hrProfileModal')) return;
  const modal = document.createElement('div');
  modal.id = 'hrProfileModal';
  modal.className = 'fixed inset-0 z-50 hidden';
  modal.innerHTML = `
    <div class="absolute inset-0 bg-black/50" data-close="true"></div>
    <div class="relative mx-auto mt-24 w-full max-w-md">
      <div class="bg-white rounded-lg shadow">
        <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold">My Profile</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
        <div class="p-4 grid gap-3">
          <div>
            <label class="block text-sm text-gray-600 mb-1">First name</label>
            <input id="hrp-first" class="w-full border rounded px-3 py-2" />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Last name</label>
            <input id="hrp-last" class="w-full border rounded px-3 py-2" />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Email/Username</label>
            <input id="hrp-email" type="email" class="w-full border rounded px-3 py-2" />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Phone</label>
            <input id="hrp-phone" class="w-full border rounded px-3 py-2" />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">New Password (optional)</label>
            <input id="hrp-password" type="password" class="w-full border rounded px-3 py-2" placeholder="Leave blank to keep current password" />
          </div>
        </div>
        <div class="flex justify-end gap-2 border-t px-4 py-3">
          <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
          <button id="hrp-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
        </div>
      </div>
    </div>`;
  document.body.appendChild(modal);
  modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
  const saveBtn = modal.querySelector('#hrp-save');
  if (saveBtn){
    saveBtn.addEventListener('click', async () => {
      await saveProfile();
    });
  }
}

async function openProfile(){
  const modal = document.getElementById('hrProfileModal');
  if (!modal) return;
  try {
    // Get current session user
    const meRes = await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
    const me = meRes.data && meRes.data.user ? meRes.data.user : null;
    if (!me) { alert('Not authenticated'); return; }
    let details = { first_name: '', last_name: '', email: me.username || '', phone: '' };
    if (me.employee_id){
      const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployee', employee_id: me.employee_id } });
      details = res.data || details;
    }
    modal.dataset.me = JSON.stringify(me || {});
    modal.dataset.orig = JSON.stringify(details || {});
    const g = (id) => document.getElementById(id);
    if (g('hrp-first')) g('hrp-first').value = details.first_name || '';
    if (g('hrp-last')) g('hrp-last').value = details.last_name || '';
    if (g('hrp-email')) g('hrp-email').value = details.email || me.username || '';
    if (g('hrp-phone')) g('hrp-phone').value = details.phone || '';
    if (g('hrp-password')) g('hrp-password').value = '';
    modal.classList.remove('hidden');
  } catch {
    alert('Unable to load profile');
  }
}

async function saveProfile(){
  const modal = document.getElementById('hrProfileModal');
  if (!modal) return;
  const me = (() => { try { return JSON.parse(modal.dataset.me || '{}'); } catch { return {}; } })();
  const orig = (() => { try { return JSON.parse(modal.dataset.orig || '{}'); } catch { return {}; } })();
  const first = (document.getElementById('hrp-first').value || '').trim();
  const last = (document.getElementById('hrp-last').value || '').trim();
  const email = (document.getElementById('hrp-email').value || '').trim();
  const phone = (document.getElementById('hrp-phone').value || '').trim();
  const newPwd = (document.getElementById('hrp-password').value || '').trim();
  if (!email) { alert('Email is required'); return; }
  try {
    if (me.employee_id){
      const payload = {
        employee_id: me.employee_id,
        first_name: first || orig.first_name || '',
        last_name: last || orig.last_name || '',
        email: email,
        phone: phone || orig.phone || '',
        department: orig.department || '',
        position: 'hr',
        basic_salary: orig.basic_salary != null ? orig.basic_salary : 0,
        date_hired: orig.date_hired || '',
        status: orig.status || 'active'
      };
      if (newPwd) payload.hr_password = newPwd;
      await axios.post(`${baseApiUrl}/employees.php`, buildFormData({ operation: 'updateEmployee', json: JSON.stringify(payload) }));
    } else {
      // Fallback: update username/password only
      const payload = { username: email, password: newPwd || undefined };
      await axios.post(`${baseApiUrl}/auth.php`, buildFormData({ operation: 'updateProfile', json: JSON.stringify(payload) }));
    }
    modal.classList.add('hidden');
    alert('Profile updated');
    // Refresh header name/avatar
    document.getElementById('profile-name').textContent = email;
    document.getElementById('profile-avatar').textContent = (email || 'H').substring(0,1).toUpperCase();
  } catch {
    alert('Failed to update profile');
  }
}
