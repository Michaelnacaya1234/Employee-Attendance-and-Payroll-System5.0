/**
 * GLOBAL API BASE URL CONFIGURATION
 * Sets up the base URL for all API calls
 * Available globally for all modules
 */
const baseApiUrl = `${location.origin}/intro/api`;
window.baseApiUrl = baseApiUrl;

/**
 * STYLE HEADER NOTIFICATION BUTTON
 * Applies visual styling to notification button and badge
 * Uses amber color scheme for better visibility
 */
function styleHeaderNotif(){
  try {
    const btn = document.getElementById('notif-toggle');
    const badge = document.getElementById('notif-badge');
    if (btn) {
      // Button container: apply tinted bg + ring
      btn.classList.add('bg-amber-50','ring-amber-200','hover:bg-amber-100');
      btn.classList.remove('ring-gray-200','hover:bg-gray-50');
      // Icon tint
      const svg = btn.querySelector('svg');
      if (svg) {
        svg.classList.add('text-amber-600');
        svg.classList.remove('text-gray-600');
      }
    }
    if (badge) {
      // Badge color/pill
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
 * ENSURE SWEETALERT2 ASSETS ARE LOADED
 * Dynamically loads SweetAlert2 CSS and JavaScript
 * Includes Tailwind CSS compatibility fixes
 */
async function ensureSweetAlertAssets(){
  try {
    if (!window.__swalReady){
      await new Promise((resolve) => {
        let pending = 0;
        const done = () => { if (--pending <= 0) resolve(); };
        // Load CSS and wait
        if (!document.getElementById('swal2-css')){
          pending++;
          const link = document.createElement('link');
          link.id = 'swal2-css';
          link.rel = 'stylesheet';
          link.href = 'https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css';
          link.onload = done; link.onerror = done;
          document.head.appendChild(link);
        }
        // Load JS and wait
        if (!window.Swal){
          pending++;
          const s = document.createElement('script');
          s.id = 'swal2-js';
          s.src = 'https://cdn.jsdelivr.net/npm/sweetalert2@11';
          s.onload = done; s.onerror = done;
          document.head.appendChild(s);
        }
        if (pending === 0) resolve();
      });
      // Force visible buttons even with Tailwind preflight
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
      window.__swalReady = true;
    }
  } catch {}
}

/**
 * SHOW SWEETALERT2 TOAST NOTIFICATION
 * Displays temporary notification with customizable message and icon
 * Fallback to console.log if SweetAlert2 unavailable
 */
function showSweetToast(message = 'Done', icon = 'info'){
  try {
    if (!window.Swal){ console.log(message); return; }
    const Toast = Swal.mixin({ toast: true, position: 'top-end', showConfirmButton: false, timer: 1500, timerProgressBar: true });
    Toast.fire({ icon, title: message });
  } catch {}
}

/**
 * FORMAT NOTIFICATION DATE
 * Converts various date formats to readable format
 * Handles timezone and parsing edge cases
 */
function formatNotifDate(val){
  try {
    if (!val) return '';
    const s = String(val);
    let d = new Date(s);
    if (isNaN(d.getTime())) { d = new Date(s.includes('T') ? s : `${s}T00:00:00`); }
    if (isNaN(d.getTime())) return String(val);
    const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    const mon = months[d.getMonth()];
    const day = d.getDate();
    const year = d.getFullYear();
    let h = d.getHours();
    const m = d.getMinutes();
    const ampm = h >= 12 ? 'PM' : 'AM';
    h = h % 12; if (h === 0) h = 12;
    const mm = String(m).padStart(2, '0');
    return `${mon} ${day}, ${year} ${h}:${mm}${ampm}`;
  } catch { return String(val || ''); }
}

/**
 * OPEN ADMIN NOTIFICATION MODAL
 * Displays notifications in SweetAlert2 modal with actions
 * Supports mark as read, delete, and mark all as read
 */
async function openAdminNotifSweetModal(){
  try {
    try { await ensureSweetAlertAssets(); } catch {}
    const resp = await axios.get(`${baseApiUrl}/notifications.php`, { params: { operation: 'getNotifications' }, withCredentials: true });
    const list = (resp && resp.data && (resp.data.notifications || resp.data)) || [];
    const notifications = Array.isArray(list) ? list : [];
    const escapeHtml = (s) => String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));

    const content = notifications.length ? notifications.map(n => {
      const id = n.id || n.notification_id || n.notificationID || '';
      const msg = escapeHtml(n.message || n.text || n.title || 'Notification');
      const whenRaw = n.created_at || n.createdAt || n.created || '';
      const when = escapeHtml(formatNotifDate(whenRaw));
      const unread = !n.read_at && !n.readAt && !n.read;
      return `
        <div class="sw-notif-item ${unread ? 'bg-blue-50' : ''} rounded-lg border border-gray-200 p-3 mb-2 cursor-pointer" data-id="${id}">
          <div class="flex items-start justify-between gap-3">
            <div class="text-sm text-gray-800">${msg}</div>
            <button class="sw-del text-gray-400 hover:text-red-600" title="Delete" data-id="${id}">×</button>
          </div>
          <div class="mt-1 text-xs text-gray-500">${when}</div>
        </div>`;
    }).join('') : '<div class="text-sm text-gray-500">No notifications</div>';

    const result = await Swal.fire({
      title: 'Notifications',
      html: `<div class="text-left max-h-80 overflow-y-auto">${content}</div>`,
      width: 520,
      showCloseButton: true,
      showCancelButton: true,
      showConfirmButton: notifications.some(n => !n.read_at && !n.readAt && !n.read),
      confirmButtonText: 'Mark all read',
      cancelButtonText: 'Close',
      didOpen: () => {
        const html = Swal.getHtmlContainer();
        if (!html) return;
        html.querySelectorAll('.sw-notif-item').forEach(el => {
          el.addEventListener('click', async () => {
            const id = el.getAttribute('data-id');
            if (!id) return;
            try {
              await markNotificationAsRead(id);
              el.classList.remove('bg-blue-50');
              try { await renderHeaderNotifications(); } catch {}
            } catch {}
          });
        });
        html.querySelectorAll('.sw-del').forEach(btn => {
          btn.addEventListener('click', async (ev) => {
            ev.preventDefault(); ev.stopPropagation();
            const id = btn.getAttribute('data-id');
            if (!id) return;
            try {
              await deleteNotification(id);
              const item = btn.closest('.sw-notif-item');
              if (item) item.remove();
              try { await renderHeaderNotifications(); } catch {}
              showSweetToast('Notification deleted', 'success');
            } catch { showSweetToast('Failed to delete notification', 'error'); }
          });
        });
      }
    });

    if (result && result.isConfirmed) {
      try {
        const unread = notifications.filter(n => !n.read_at && !n.readAt && !n.read);
        await Promise.all(unread.map(n => markNotificationAsRead(n.id || n.notification_id || n.notificationID)));
        try { await renderHeaderNotifications(); } catch {}
        showSweetToast('All notifications marked as read', 'success');
      } catch { showSweetToast('Failed to mark all as read', 'error'); }
    }
  } catch {}
}

/**
 * ATTACH SWEETALERT2 TO HEADER NOTIFICATION BUTTON
 * Replaces default dropdown with SweetAlert2 modal
 * Prevents duplicate event listeners
 */
function attachSweetHeaderNotifAdmin(){
  try {
    const btn = document.getElementById('notif-toggle');
    if (!btn) return;
    if (btn.__sweetWired) return;
    btn.__sweetWired = true;
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopImmediatePropagation();
      try { await ensureSweetAlertAssets(); } catch {}
      const dropdown = document.getElementById('notif-dropdown');
      if (dropdown) dropdown.classList.add('hidden');
      try { await openAdminNotifSweetModal(); } catch {}
    }, true);
  } catch {}
}

if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', attachSweetHeaderNotifAdmin); }
else { try { attachSweetHeaderNotifAdmin(); } catch {} }

// Inactivity-based session timeout watchdog (uses Security Settings -> session_timeout_minutes)
(function initInactivityLogout(){
  if (window.__inactivityWatchdog) return;
  window.__inactivityWatchdog = true;
  let timeoutMinutes = 30; // default if settings not loaded
  // Load configured timeout (non-blocking)
  try {
    axios.get(`${baseApiUrl}/security.php`, { params: { operation: 'getSecuritySettings' } })
      .then(res => {
        const cfg = res && res.data ? res.data : {};
        const n = parseInt(cfg.session_timeout_minutes, 10);
        if (Number.isFinite(n)) timeoutMinutes = n;
      })
      .catch(() => {});
  } catch {}

  let lastActivity = Date.now();
  const mark = () => { lastActivity = Date.now(); };
  ['click','keydown','mousemove','scroll','touchstart','touchmove'].forEach(ev => {
    try { window.addEventListener(ev, mark, { passive: true }); } catch { window.addEventListener(ev, mark); }
  });

  setInterval(async () => {
    try {
      if (timeoutMinutes <= 0) return; // disabled
      const elapsedMs = Date.now() - lastActivity;
      if (elapsedMs >= timeoutMinutes * 60 * 1000) {
        // Proactively end session on server and redirect to login
        try { await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'logout' }, withCredentials: true }); } catch {}
        try { showToast('Session expired due to inactivity', 'warning', 3000); } catch {}
        location.href = '/intro/index.html';
      }
    } catch {}
  }, 30000); // check every 30s
})();

// Simple toast notification system
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

// Minimal anime.js loader (used for subtle card animations)
async function ensureAnime(){
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

const routes = {
  dashboard: async () => {
    const app = document.getElementById("app");
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
                <h1 class="text-2xl font-semibold">Welcome, <span id="welcome-name">Admin</span></h1>
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

      <!-- Graphs Section -->
      <section class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div class="bg-white rounded-lg shadow p-4">
          <div class="flex items-center justify-between mb-3">
            <h3 class="font-semibold">Attendance Today</h3>
            <a href="#attendance" class="text-primary-700 text-sm hover:underline">View Details</a>
          </div>
          <div class="h-64">
            <canvas id="attendanceChart"></canvas>
          </div>
        </div>

        <div class="bg-white rounded-lg shadow p-4">
          <div class="flex items-center justify-between mb-3">
            <h3 class="font-semibold">Payroll Expense Trend (Monthly)</h3>
            <a href="#payroll" class="text-primary-700 text-sm hover:underline">View Details</a>
          </div>
          <div class="h-64">
            <canvas id="payrollTrendChart"></canvas>
          </div>
        </div>
      </section>


      
      <!-- Holidays Calendar -->
      <section class="grid grid-cols-1 gap-4 mb-6">
        <div class="bg-white rounded-lg shadow p-4" id="holidays-calendar-card">
          <div class="flex items-center justify-between mb-3">
            <h3 class="font-semibold">Calendar</h3>
            <div class="flex items-center gap-2">
              <button id="cal-prev" class="px-2 py-1 text-xs border rounded">Prev</button>
              <div id="cal-title" class="text-sm font-medium min-w-[8rem] text-center"></div>
              <button id="cal-next" class="px-2 py-1 text-xs border rounded">Next</button>
              <button id="cal-add" class="ml-2 px-2 py-1 text-xs rounded bg-primary-600 text-white">Add Holiday</button>
            </div>
          </div>
          <div id="calendar" class="grid grid-cols-7 gap-px bg-gray-200 rounded overflow-hidden text-xs"></div>
          <div class="text-[10px] text-gray-500 mt-2">Legend: <span class="inline-block w-3 h-3 bg-rose-500 align-middle mr-1"></span> Holiday • <span class="inline-block w-3 h-3 bg-primary-500 align-middle mr-1"></span> Today • <span class="inline-block w-3 h-3 bg-rose-200 align-middle mr-1"></span> Sun • <span class="inline-block w-3 h-3 bg-blue-200 align-middle mr-1"></span> Sat</div>
        </div>
      </section>

      <section class="grid grid-cols-1 gap-4 mb-6">
                <div class="bg-white rounded-lg shadow p-3 text-xs" id="recent-activities">
          <div class="flex items-center justify-between mb-2"><h3 class="font-semibold text-sm">Recent Activities</h3></div>
          <div class="mb-2 flex items-center justify-between gap-2">
            <div class="flex items-center gap-1">
              <div class="relative">
                <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
                <input id="act-search-input" class="w-24 border rounded pl-8 pr-2 py-1 text-xs" placeholder="Search name, department, status" />
              </div>
              <button id="act-search-clear" aria-label="Clear search" class="inline-flex items-center gap-1 border border-gray-300 rounded px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50 active:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1">
                <svg class="w-3 h-3 text-gray-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
                <span>Clear</span>
              </button>
              <input type="date" id="act-date" class="border rounded px-2 py-1 text-xs" />
            </div>
                      </div>
          <ul id="recent-activities-list" class="divide-y divide-gray-200"></ul>
          <div id="recent-activities-pagination" class="mt-2 flex items-center justify-between text-xs text-gray-600"></div>
        </div>
      </section>`;

    await renderSummaryCards();
    await renderAttendanceSnapshot();
        await renderHolidayCalendar();
    await renderRecentActivities();

    // Welcome header content
    try {
      const me = await getCurrentUser();
      const welcomeNameEl = document.getElementById('welcome-name');
      if (welcomeNameEl && me) {
        const displayName = (() => {
          const first = (me.first_name || '').trim();
          const last = (me.last_name || '').trim();
          if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
          const u = (me.username || '').trim();
          if (u.includes('@')) return u.split('@')[0];
          return u || 'Admin';
        })();
        welcomeNameEl.textContent = displayName;
      }
    } catch {}
    const dateEl = document.getElementById('welcome-date');
    if (dateEl) {
      if (window.__welcomeInterval) { try { clearInterval(window.__welcomeInterval); } catch {} }
      const tick = () => {
        const now = new Date();
        dateEl.textContent = now.toLocaleString('en-US');
      };
      tick();
      window.__welcomeInterval = setInterval(tick, 1000);
    }

    // Render key charts on dashboard
    await renderAttendanceChartDaily();
        await renderPayrollTrendChart();

    // Employee view modal (lazy mount on dashboard init)
    mountEmployeeViewModal();

    // Holiday calendar state and handlers
    function monthName(m){ return new Date(2000, m-1, 1).toLocaleString('en-US', { month: 'long' }); }

    async function renderHolidayCalendar(){
      const container = document.getElementById('calendar');
      const title = document.getElementById('cal-title');
      if (!container || !title) return;
      // state
      if (!window.__calState){
        const now = new Date();
        window.__calState = { year: now.getFullYear(), month: now.getMonth()+1 };
      }
      const { year, month } = window.__calState;
      title.textContent = `${monthName(month)} ${year}`;

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

      // dates grid
      const first = new Date(year, month-1, 1);
      const startIdx = first.getDay();
      const daysInMonth = new Date(year, month, 0).getDate();
      const todayStr = new Date().toLocaleDateString('en-CA');

      // fetch holidays this month
      let holidays = [];
      try {
        const res = await axios.get(`${window.baseApiUrl}/holidays.php`, { params: { operation: 'list', month, year } });
        holidays = Array.isArray(res.data) ? res.data : [];
      } catch {}
      const holiMap = new Map((holidays||[]).map(h => [String(h.holiday_date), h]));

      // blanks before first (weekend-aware shading)
      for (let i=0;i<startIdx;i++) {
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
        let todayBadge = isToday ? '<span class="absolute top-1 right-1 text-[10px] px-1 py-0.5 rounded bg-primary-600 text-white">Today</span>' : '';
        if (isToday) { cell.className += ' bg-primary-50 ring-2 ring-primary-300'; }
        const dayNumCls = isSun ? 'text-rose-600' : (isSat ? 'text-blue-600' : 'text-gray-500');
        const topBarClass = hol ? 'bg-rose-500' : (isToday ? 'bg-primary-500' : (isSun ? 'bg-rose-300' : (isSat ? 'bg-blue-300' : 'bg-gray-200')));
        const topBarHtml = `<div class="absolute left-0 right-0 top-0 h-1 ${topBarClass}"></div>`;
        cell.innerHTML = `
          ${topBarHtml}
          <div class="text-[11px] ${dayNumCls}">${d}</div>
          ${hol ? `<div class="mt-1 text-[11px] px-1 py-0.5 rounded bg-rose-500 text-white inline-block" title="${escapeHtml(hol.holiday_name || '')}${hol.description ? ' — ' + escapeHtml(hol.description) : ''}">${escapeHtml(hol.holiday_name || 'Holiday')}</div>` : ''}
          ${todayBadge}`;
        // Click handler: add or edit
        cell.addEventListener('click', () => {
          if (hol) openHolidayForm({ ...hol }); else openHolidayForm({ holiday_date: dateStr });
        });
        container.appendChild(cell);
      }

      // controls
      const prev = document.getElementById('cal-prev');
      const next = document.getElementById('cal-next');
      const add = document.getElementById('cal-add');
      if (prev && !prev.__wired){ prev.__wired = true; prev.addEventListener('click', async () => { let {year, month} = window.__calState; month--; if (month===0){ month=12; year--; } window.__calState = { year, month }; await renderHolidayCalendar(); }); }
      if (next && !next.__wired){ next.__wired = true; next.addEventListener('click', async () => { let {year, month} = window.__calState; month++; if (month===13){ month=1; year++; } window.__calState = { year, month }; await renderHolidayCalendar(); }); }
      if (add && !add.__wired){ add.__wired = true; add.addEventListener('click', () => {
        const { year, month } = window.__calState;
        const dateStr = `${year}-${String(month).padStart(2,'0')}-01`;
        openHolidayForm({ holiday_date: dateStr });
      }); }

      // Minimal calendar cell animation (no opacity)
      try {
        const anime = await ensureAnime();
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
          const titleEl = document.getElementById('cal-title');
          if (titleEl) {
            anime.remove(titleEl);
            anime({ targets: titleEl, translateX: [-6, 0], scale: [0.98, 1], duration: 220, easing: 'easeOutQuad' });
          }
        }
      } catch {}
    }

    function openHolidayForm(row){
      let modal = document.getElementById('holidayFormModal');
      if (!modal){ modal = document.createElement('div'); modal.id='holidayFormModal'; modal.className='fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
      const isEdit = !!(row && row.id);
      modal.innerHTML = `
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-24 w-full max-w-md">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold">${isEdit ? 'Edit Holiday' : 'Add Holiday'}</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
            <div class="p-4 space-y-3 text-sm">
              <div>
                <label class="block text-xs text-gray-600 mb-1">Date</label>
                <input type="date" id="hol-date" class="border rounded w-full px-2 py-1.5" value="${(row.holiday_date||'').slice(0,10)}" />
              </div>
              <div>
                <label class="block text-xs text-gray-600 mb-1">Holiday Name</label>
                <input type="text" id="hol-name" class="border rounded w-full px-2 py-1.5" value="${escapeHtml(row.holiday_name||'')}" />
              </div>
              <div>
                <label class="block text-xs text-gray-600 mb-1">Description</label>
                <textarea id="hol-desc" class="border rounded w-full px-2 py-1.5" rows="3">${escapeHtml(row.description||'')}</textarea>
              </div>
            </div>
            <div class="flex justify-between items-center gap-2 border-t px-4 py-3">
              <div class="text-xs text-gray-500">${isEdit ? `Created: ${row.created_at||''}` : ''}</div>
              <div class="flex items-center gap-2">
                ${isEdit ? '<button id="hol-delete" class="px-3 py-2 text-sm rounded border border-rose-600 text-rose-700">Delete</button>' : ''}
                <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
                <button id="hol-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white">${isEdit ? 'Save Changes' : 'Add Holiday'}</button>
              </div>
            </div>
          </div>
        </div>`;
      modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
      const saveBtn = document.getElementById('hol-save');
      const delBtn = document.getElementById('hol-delete');
      const dateInp = document.getElementById('hol-date');
      const nameInp = document.getElementById('hol-name');
      const descInp = document.getElementById('hol-desc');

      if (saveBtn){
        saveBtn.addEventListener('click', async () => {
          const payload = {
            holiday_date: (dateInp.value||'').slice(0,10),
            holiday_name: (nameInp.value||'').trim(),
            description: (descInp.value||'').trim()
          };
          if (!payload.holiday_date || !payload.holiday_name){
            try { showToast('Date and Holiday Name are required','warning'); } catch {}
            return;
          }
          try {
            if (row && row.id){ payload.id = row.id; await saveHolidayUpdate(payload); }
            else { await saveHolidayCreate(payload); }
            modal.classList.add('hidden');
            await renderHolidayCalendar();
            try { showToast(isEdit ? 'Holiday updated' : 'Holiday added','success'); } catch {}
          } catch (e) {
            try { showToast('Failed to save holiday','error'); } catch {}
          }
        });
      }
      if (delBtn){
        delBtn.addEventListener('click', async () => {
          const confirmed = window.confirm('Delete this holiday? This cannot be undone.');
          if (!confirmed) return;
          try {
            await deleteHolidayRow(row.id);
            modal.classList.add('hidden');
            await renderHolidayCalendar();
            try { showToast('Holiday deleted','success'); } catch {}
          } catch {
            try { showToast('Failed to delete holiday','error'); } catch {}
          }
        });
      }

      modal.classList.remove('hidden');
    }

    async function saveHolidayCreate(payload){
      const fd = new FormData();
      fd.append('operation', 'create');
      fd.append('json', JSON.stringify(payload));
      const res = await axios.post(`${window.baseApiUrl}/holidays.php`, fd);
      return res.data;
    }
    async function saveHolidayUpdate(payload){
      const fd = new FormData();
      fd.append('operation', 'update');
      fd.append('json', JSON.stringify(payload));
      const res = await axios.post(`${window.baseApiUrl}/holidays.php`, fd);
      return res.data;
    }
    async function deleteHolidayRow(id){
      const fd = new FormData();
      fd.append('operation', 'delete');
      fd.append('json', JSON.stringify({ id }));
      const res = await axios.post(`${window.baseApiUrl}/holidays.php`, fd);
      return res.data;
    }

    async function renderSummaryCards(){
      const [summaryRes, payrollRes] = await Promise.all([
        axios.get(`${window.baseApiUrl}/reports.php`, { params: { operation: 'dashboardSummary' } }),
        axios.get(`${window.baseApiUrl}/reports.php`, { params: { operation: 'payrollSummary' } })
      ]);
      const s = summaryRes.data || { total_employees: 0, present_today: 0, pending_leaves: 0 };
      const p = payrollRes.data || { total_net_pay: 0 };

      // Recompute admin top cards excluding inactive employees
      const todayStr = new Date().toLocaleDateString('en-CA');
      const [empRes, attRes] = await Promise.all([
        axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
        axios.get(`${window.baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: todayStr, end_date: todayStr } })
      ]);
      const all = Array.isArray(empRes.data) ? empRes.data : [];
      const activeEmp = all.filter(e => {
        const st = String(e.status || '').trim().toLowerCase();
        return !st || st === 'active';
      });
      const totalActive = activeEmp.length;
      const activeIds = new Set(activeEmp.map(e => String(e.employee_id)));
      const attRows = Array.isArray(attRes.data) ? attRes.data : [];
      const presentActive = attRows.filter(r => {
        if (!activeIds.has(String(r.employee_id))) return false;
        const st = String(r.status || '').toLowerCase();
        const hasTime = !!(r.time_in && r.time_in !== '00:00:00') || !!(r.time_out && r.time_out !== '00:00:00');
        const okStatus = ['present','late','undertime','leave','on time','ontime','present today','present_today'].includes(st);
        return hasTime || okStatus;
      }).length;
      const absentToday = Math.max(0, totalActive - presentActive);
      const peso = (n) => `₱${Number(n || 0).toLocaleString('en-PH', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

      const topCards = [
        { label: 'Total Employees', value: totalActive, color: 'blue', icon: 'users', id: 'total' },
        { label: 'Present Today', value: presentActive, color: 'emerald', icon: 'check', id: 'present' },
        { label: 'Absent Today', value: absentToday, color: 'rose', icon: 'x', id: 'absent' }
      ];
      const bottomCards = [
        { label: 'Pending Leave Requests', value: s.pending_leaves, color: 'amber', icon: 'clock', id: 'pending_leaves' },
        { label: 'Payroll Processed This Month', value: peso(p.total_net_pay), color: 'fuchsia', icon: 'currency', id: 'payroll_processed' }
      ];



      const iconSvg = (name, cls) => {
        if (name === 'users') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M12 12a4 4 0 100-8 4 4 0 000 8z"/><path d="M2 20c0-3.314 4.03-6 10-6s10 2.686 10 6v1H2v-1z"/></svg>`;
        if (name === 'check') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.2l-3.5-3.5a1 1 0 10-1.4 1.4l4.2 4.2a1 1 0 001.4 0l10-10a1 1 0 10-1.4-1.4L9 16.2z"/></svg>`;
        if (name === 'x') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M6.225 4.811a1 1 0 011.414 0L12 9.172l4.361-4.361a1 1 0 111.414 1.414L13.414 10.586l4.361 4.361a1 1 0 01-1.414 1.414L12 12l-4.361 4.361a1 1 0 01-1.414-1.414l4.361-4.361-4.361-4.361a1 1 0 010-1.414z"/></svg>`;
        if (name === 'clock') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M12 8a1 1 0 011 1v3h3a1 1 0 110 2h-4a1 1 0 01-1-1V9a1 1 0 011-1z"/><path fill-rule="evenodd" d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zM4 12a8 8 0 1116 0 8 8 0 01-16 0z" clip-rule="evenodd"/></svg>`;
        if (name === 'currency') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M13 5a3 3 0 013 3h2a5 5 0 00-5-5V1h-2v2a5 5 0 000 10h2a3 3 0 110 6h-2a3 3 0 01-3-3H6a5 5 0 005 5v2h2v-2a5 5 0 000-10h-2a3 3 0 110-6h2z"/></svg>`;
        return '';
      };

      const renderCard = (c) => {
        const palMap = {
          blue: { bg: 'bg-blue-50', text: 'text-blue-600', ring: 'ring-blue-200' },
          emerald: { bg: 'bg-emerald-50', text: 'text-emerald-600', ring: 'ring-emerald-200' },
          rose: { bg: 'bg-rose-50', text: 'text-rose-600', ring: 'ring-rose-200' },
          amber: { bg: 'bg-amber-50', text: 'text-amber-600', ring: 'ring-amber-200' },
          fuchsia: { bg: 'bg-fuchsia-50', text: 'text-fuchsia-600', ring: 'ring-fuchsia-200' }
        };
        const pal = palMap[c.color] || { bg: 'bg-gray-100', text: 'text-gray-600', ring: 'ring-gray-200' };
        return `
          <div class="rounded-lg bg-white shadow ${c.id ? 'cursor-pointer hover:shadow-md' : ''}" data-card-id="${c.id || ''}">
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

      // Minimal dashboard card animations (no opacity)
      try {
        const anime = await ensureAnime();
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

      // Wire Absent Today card to show list of absent employees for today
      async function showAbsentTodayList(){
        try {
          const todayStr = new Date().toLocaleDateString('en-CA');
          const [empRes, attRes, leaveRes] = await Promise.all([
            axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
            axios.get(`${window.baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: todayStr, end_date: todayStr } }),
            axios.get(`${window.baseApiUrl}/leaves.php`, { params: { operation: 'listApproved', start_date: todayStr, end_date: todayStr } })
          ]);
          const employees = Array.isArray(empRes.data) ? empRes.data : [];
          const active = employees.filter(e => String(e.status || '').toLowerCase() === 'active');
          const activeIds = new Set(active.map(e => String(e.employee_id)));
          const attRows = Array.isArray(attRes.data) ? attRes.data : [];
          const leaveRows = Array.isArray(leaveRes.data) ? leaveRes.data : [];

          const union = new Set();
          attRows.forEach(r => {
            const eid = String(r.employee_id || '');
            if (!activeIds.has(eid)) return;
            const d = String(r.attendance_date || r.date || r.created_at || r.time_in || '').slice(0,10);
            const st = String(r.status || '').toLowerCase();
            if (d === todayStr) {
              if (["present","late","undertime","leave"].includes(st)) {
                union.add(eid);
              }
            }
          });
          leaveRows.forEach(lr => {
            const s = String(lr.start_date || lr.date || lr.work_date || '').slice(0,10);
            const e = String(lr.end_date || lr.start_date || lr.date || lr.work_date || '').slice(0,10);
            if (!s || !e) return;
            if (s <= todayStr && todayStr <= e) {
              const eid = String(lr.employee_id || '');
              if (activeIds.has(eid)) union.add(eid);
            }
          });
          const absentees = active.filter(e => !union.has(String(e.employee_id)));

          let modal = document.getElementById('absentListModal');
          if (!modal){
            modal = document.createElement('div');
            modal.id = 'absentListModal';
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
            const wrap = document.getElementById('absent-table-wrap');
            if (!wrap) return;
            const list = getFiltered();
            if (!list.length){
              wrap.innerHTML = '<div class="text-sm text-gray-500">No absent today</div>';
              return;
            }
            const rowsHtml = list.map(e => `
              <tr>
                <td class="px-3 py-2 text-sm text-gray-700 w-8">
                  <input type="checkbox" class="absent-select" data-emp-id="${e.employee_id}" ${selectedIds.has(String(e.employee_id)) ? 'checked' : ''} />
                </td>
                <td class="px-3 py-2 text-sm text-gray-700">${t(`${e.first_name || ''} ${e.last_name || ''}`.trim())}</td>
                <td class="px-3 py-2 text-sm text-gray-700">${t(e.department || '')}</td>
              </tr>`).join('');
            wrap.innerHTML = `
              <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                  <tr>
                    <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600 w-8"><input type="checkbox" id="absent-select-all" /></th>
                    <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
                    <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Department</th>
                  </tr>
                </thead>
                <tbody id="absent-tbody" class="divide-y divide-gray-200 bg-white">${rowsHtml}</tbody>
              </table>`;
            const tbody = document.getElementById('absent-tbody');
            if (tbody){
              tbody.querySelectorAll('.absent-select').forEach(cb => {
                cb.addEventListener('change', () => {
                  const id = String(cb.getAttribute('data-emp-id'));
                  if (cb.checked) selectedIds.add(id); else selectedIds.delete(id);
                  const btn = document.getElementById('absent-mark-btn');
                  if (btn) btn.disabled = selectedIds.size === 0;
                  const selectAll = document.getElementById('absent-select-all');
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
            const selectAll = document.getElementById('absent-select-all');
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
                const tb = document.getElementById('absent-tbody');
                if (tb) tb.querySelectorAll('.absent-select').forEach(cb => { cb.checked = selectAll.checked; });
                const btn = document.getElementById('absent-mark-btn');
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
                      <input id="absent-search" class="w-64 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name or department" />
                    </div>
                    <button id="absent-clear" class="text-xs text-gray-600 border rounded px-2 py-1">Clear</button>
                    <a href="#attendance" class="ml-auto text-primary-700 text-sm hover:underline">Open Attendance</a>
                  </div>
                  <div id="absent-table-wrap" class="overflow-auto max-h-[48vh]"></div>
                </div>
                <div class="flex justify-between items-center gap-2 border-t px-4 py-3">
                  <div class="text-xs text-gray-500">Select employees to mark as absent. These will be recorded in today's attendance.</div>
                  <div class="flex items-center gap-2">
                    <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
                    <button id="absent-mark-btn" class="px-3 py-2 text-sm rounded bg-rose-600 text-white disabled:opacity-50" disabled>Mark selected as Absent</button>
                  </div>
                </div>
              </div>
            </div>`;

          // Wire close buttons with cleanup and day-change watchers
          let __absentModalTimer = null;
          let __absentModalDayKey = todayStr;
          const __absentMaybeRollover = async () => {
            try {
              const d = new Date().toLocaleDateString('en-CA');
              if (d !== __absentModalDayKey) {
                __absentModalDayKey = d;
                // Close and reopen to refresh list for the new day
                try { closeModal(); } catch {}
                await showAbsentTodayList();
              }
            } catch {}
          };
          const onFocus = () => { __absentMaybeRollover(); };
          const onVis = () => { __absentMaybeRollover(); };
          const closeModal = () => {
            modal.classList.add('hidden');
            try { if (__absentModalTimer) { clearInterval(__absentModalTimer); __absentModalTimer = null; } } catch {}
            try { window.removeEventListener('focus', onFocus); } catch {}
            try { document.removeEventListener('visibilitychange', onVis); } catch {}
          };
          modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeModal));

          // Wire search
          const searchInp = document.getElementById('absent-search');
          const clearBtn = document.getElementById('absent-clear');
          if (searchInp){
            searchInp.addEventListener('input', () => { query = (searchInp.value||'').trim(); renderTable(); });
          }
          if (clearBtn){
            clearBtn.addEventListener('click', () => { if (searchInp) searchInp.value=''; query=''; renderTable(); });
          }

          // Wire mark action
          const markBtn = document.getElementById('absent-mark-btn');
          if (markBtn){
            markBtn.addEventListener('click', async () => {
              if (selectedIds.size === 0) return;
              const confirmed = await (async function confirmAbsAll(){
                return new Promise((resolve)=>{
                  let cm = document.getElementById('absentConfirmModal');
                  if (!cm) { cm = document.createElement('div'); cm.id='absentConfirmModal'; cm.className='fixed inset-0 z-50 hidden'; document.body.appendChild(cm); }
                  cm.innerHTML = `
                    <div class="absolute inset-0 bg-black/50" data-close="true"></div>
                    <div class="relative mx-auto mt-32 w-full max-w-md">
                      <div class="bg-white rounded-lg shadow">
                        <div class="px-4 py-3 border-b"><h5 class="font-semibold text-gray-900">Confirm</h5></div>
                        <div class="p-4 text-sm text-gray-700">Are you sure you want to mark all as absent?</div>
                        <div class="px-4 py-3 border-t flex justify-end gap-2">
                          <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
                          <button id="absent-confirm-ok" class="px-3 py-2 text-sm rounded bg-rose-600 text-white">Confirm</button>
                        </div>
                      </div>
                    </div>`;
                  const closeEls = cm.querySelectorAll('[data-close="true"]');
                  closeEls.forEach(el => el.addEventListener('click', () => { cm.classList.add('hidden'); resolve(false); }, { once: true }));
                  const okBtn = cm.querySelector('#absent-confirm-ok');
                  if (okBtn) okBtn.addEventListener('click', () => { cm.classList.add('hidden'); resolve(true); }, { once: true });
                  cm.classList.remove('hidden');
                });
              })();
              if (!confirmed) return;
              const ids = Array.from(selectedIds);
              let ok = 0, fail = 0;
              for (const id of ids){
                try {
                  const payload = { employee_id: id, attendance_date: todayStr, status: 'absent', time_in: null, time_out: null, remarks: 'Marked absent (dashboard)' };
                  const fd = new FormData();
                  fd.append('operation', 'recordAttendance');
                  fd.append('json', JSON.stringify(payload));
                  const res = await axios.post(`${window.baseApiUrl}/attendance.php`, fd);
                  const success = String(res.data) === '1' || res.data === 1 || (res.data && res.data.success === 1);
                  if (success) ok++; else fail++;
                } catch { fail++; }
              }
              try { showToast(`Marked as Absent: ${ok} | Failed: ${fail} (Add Other)`, fail ? 'warning' : 'success'); } catch {}
              // Immediately empty the Absent Today list in the modal
              try {
                selectedIds = new Set();
                const wrap = document.getElementById('absent-table-wrap');
                if (wrap) wrap.innerHTML = '<div class="text-sm text-gray-500">No absentees for today.</div>';
                const title = modal.querySelector('h5');
                if (title) title.textContent = 'Absent Today (0)';
                const markButton = document.getElementById('absent-mark-btn');
                if (markButton) markButton.disabled = true;
                const searchInp2 = document.getElementById('absent-search');
                if (searchInp2) { searchInp2.value = ''; searchInp2.disabled = true; }
                const selectAllCb = document.getElementById('absent-select-all');
                if (selectAllCb) { selectAllCb.checked = false; selectAllCb.indeterminate = false; selectAllCb.disabled = true; }
              } catch {}
              try { await renderAttendanceSnapshot(); } catch {}
            });
          }

          // Initial render
          renderTable();
          modal.classList.remove('hidden');
          // Setup day-change refresh for this modal
          try {
            if (__absentModalTimer) { clearInterval(__absentModalTimer); }
            __absentModalTimer = setInterval(__absentMaybeRollover, 60000);
            window.addEventListener('focus', onFocus);
            document.addEventListener('visibilitychange', onVis);
          } catch {}
        } catch (e) {
          try { alert('Failed to load absent list'); } catch {}
        }
      }
      async function showAllEmployeesList(){
        try {
          const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
          const all = Array.isArray(res.data) ? res.data : [];
          const list = all.filter(e => String(e.status || '').toLowerCase() === 'active');
          let modal = document.getElementById('empAllListModal');
          if (!modal) { modal = document.createElement('div'); modal.id = 'empAllListModal'; modal.className = 'fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
          let query = '';
          const renderTable = () => {
            const rows = (!query ? list : list.filter(e => {
              const name = `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`;
              const dept = String(e.department || '').toLowerCase();
              const pos = String(e.position || '').toLowerCase();
              const st = String(e.status || '').toLowerCase();
              return name.includes(query) || dept.includes(query) || pos.includes(query) || st.includes(query);
            }));
            const wrap = document.getElementById('empall-table-wrap');
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
                      <input id="empall-search" class="w-64 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, department, position, status" />
                    </div>
                    <button id="empall-clear" class="text-xs text-gray-600 border rounded px-2 py-1">Clear</button>
                    <a href="#employees" class="ml-auto text-primary-700 text-sm hover:underline">Open Employees</a>
                  </div>
                  <div id="empall-table-wrap" class="overflow-auto max-h-[48vh]"></div>
                </div>
                <div class="flex justify-end items-center gap-2 border-t px-4 py-3">
                  <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
                </div>
              </div>
            </div>`;
          const closeEls = modal.querySelectorAll('[data-close="true"]');
          closeEls.forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
          const si = document.getElementById('empall-search');
          const sc = document.getElementById('empall-clear');
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
            axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
            axios.get(`${window.baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: todayStr, end_date: todayStr } }),
            axios.get(`${window.baseApiUrl}/leaves.php`, { params: { operation: 'listApproved', start_date: todayStr, end_date: todayStr } })
          ]);
          const employees = Array.isArray(empRes.data) ? empRes.data : [];
          const active = employees.filter(e => String(e.status || '').toLowerCase() === 'active');
          const activeMap = new Map(active.map(e => [String(e.employee_id), e]));
          const attRows = Array.isArray(attRes.data) ? attRes.data : [];
          const leaveRows = Array.isArray(leaveRes.data) ? leaveRes.data : [];

          // Build map of present employees, prefer attendance status if exists; else mark as leave
          const presentMap = new Map();
          attRows.forEach(r => {
            const eid = String(r.employee_id || '');
            if (!activeMap.has(eid)) return;
            const st = String(r.status || '').toLowerCase();
            if (['present','late','undertime','on time','ontime','present today','present_today'].includes(st) || (r.time_in && r.time_in !== '' && r.time_in !== '00:00:00')) {
              presentMap.set(eid, { ...(activeMap.get(eid) || {}), status: st || (r.time_in ? 'present' : ''), time_in: r.time_in || '', time_out: r.time_out || '' });
            }
          });
          leaveRows.forEach(lr => {
            const s = String(lr.start_date || lr.date || lr.work_date || '').slice(0,10);
            const e = String(lr.end_date || lr.start_date || lr.date || lr.work_date || '').slice(0,10);
            if (!s || !e) return;
            if (s <= todayStr && todayStr <= e) {
              const eid = String(lr.employee_id || '');
              if (!activeMap.has(eid)) return;
              if (!presentMap.has(eid)) {
                presentMap.set(eid, { ...(activeMap.get(eid) || {}), status: 'leave', time_in: '', time_out: '' });
              }
            }
          });

          const list = Array.from(presentMap.values());
          let modal = document.getElementById('presentTodayModal');
          if (!modal) { modal = document.createElement('div'); modal.id = 'presentTodayModal'; modal.className = 'fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
          let query = '';
          const renderTable = () => {
            const filtered = (!query ? list : list.filter(e => {
              const name = `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.trim();
              const dept = String(e.department || '').toLowerCase();
              const st = String(e.status || '').toLowerCase();
              return name.includes(query) || dept.includes(query) || st.includes(query);
            }));
            const wrap = document.getElementById('present-table-wrap');
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
                      <input id="present-search" class="w-64 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, department, status" />
                    </div>
                    <button id="present-clear" class="text-xs text-gray-600 border rounded px-2 py-1">Clear</button>
                    <a href="#attendance" class="ml-auto text-primary-700 text-sm hover:underline">Open Attendance</a>
                  </div>
                  <div id="present-table-wrap" class="overflow-auto max-h-[48vh]"></div>
                </div>
                <div class="flex justify-end items-center gap-2 border-t px-4 py-3">
                  <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
                </div>
              </div>
            </div>`;
          modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
          const si = document.getElementById('present-search');
          const sc = document.getElementById('present-clear');
          if (si) si.addEventListener('input', () => { query = (si.value || '').trim().toLowerCase(); renderTable(); });
          if (sc) sc.addEventListener('click', () => { if (si) si.value=''; query=''; renderTable(); });
          renderTable();
          modal.classList.remove('hidden');
        } catch {
          try { alert('Failed to load present list'); } catch {}
        }
      }
      async function showPayrollProcessedList(){
        try {
          const now = new Date();
          const start = new Date(now.getFullYear(), now.getMonth(), 1);
          const end = new Date(now.getFullYear(), now.getMonth() + 1, 0);
          const startStr = start.toLocaleDateString('en-CA');
          const endStr = end.toLocaleDateString('en-CA');

          const tryEndpoints = async () => {
            const endpoints = [
              { url: `${window.baseApiUrl}/reports.php`, params: { operation: 'payrollProcessedList', start_date: startStr, end_date: endStr } },
              { url: `${window.baseApiUrl}/payroll.php`, params: { operation: 'listProcessed', start_date: startStr, end_date: endStr } },
              { url: `${window.baseApiUrl}/payroll.php`, params: { operation: 'list', start_date: startStr, end_date: endStr } },
              { url: `${window.baseApiUrl}/payroll.php`, params: { operation: 'getPayrolls', start_date: startStr, end_date: endStr } }
            ];
            for (const ep of endpoints) {
              try {
                const res = await axios.get(ep.url, { params: ep.params });
                const data = res && res.data;
                if (Array.isArray(data)) return data;
                if (data && Array.isArray(data.rows)) return data.rows;
              } catch {}
            }
            return [];
          };

          const rowsRaw = await tryEndpoints();
          const normalize = (r) => {
            const first = r.first_name || r.emp_first_name || '';
            const last = r.last_name || r.emp_last_name || '';
            const dept = r.department || r.dept || '';
            const ps = r.payroll_period_start || r.period_start || r.start_date || '';
            const pe = r.payroll_period_end || r.period_end || r.end_date || '';
            const status = (r.status || r.pay_status || '').toString().toLowerCase() || 'processed';
            const net = r.net_pay != null ? r.net_pay : (r.total_net_pay != null ? r.total_net_pay : r.net || r.total);
            const netPay = Number(net || 0);
            return {
              payroll_id: r.payroll_id || r.id || r.pay_id || '',
              employee_id: r.employee_id || r.emp_id || '',
              first_name: first,
              last_name: last,
              department: dept,
              period_start: ps,
              period_end: pe,
              status,
              net_pay: netPay
            };
          };
          const rows = rowsRaw.map(normalize).filter(r => !!r.period_start && !!r.period_end);

          let modal = document.getElementById('payrollProcessedModal');
          if (!modal) { modal = document.createElement('div'); modal.id = 'payrollProcessedModal'; modal.className = 'fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
          let query = '';
          const peso = (n) => `₱${Number(n || 0).toLocaleString('en-PH', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
          const renderTable = () => {
            const list = (!query ? rows : rows.filter(e => {
              const name = `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.trim();
              const dept = String(e.department || '').toLowerCase();
              const pid = String(e.payroll_id || '').toLowerCase();
              const period = `${e.period_start || ''} ${e.period_end || ''}`.toLowerCase();
              const st = String(e.status || '').toLowerCase();
              return name.includes(query) || dept.includes(query) || pid.includes(query) || period.includes(query) || st.includes(query);
            }));
            const wrap = document.getElementById('payrollproc-table-wrap');
            if (!wrap) return;
            if (!list.length) { wrap.innerHTML = '<div class="text-sm text-gray-500">No payroll processed this month</div>'; return; }
            const trs = list.map((r, idx) => `
              <tr>
                <td class="px-3 py-2 text-sm text-gray-700">${idx+1}</td>
                <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(`${r.first_name || ''} ${r.last_name || ''}`.trim()) || ('Employee #' + (r.employee_id || ''))}</td>
                <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(r.department || '')}</td>
                <td class="px-3 py-2 text-sm text-gray-700">${r.period_start || ''} → ${r.period_end || ''}</td>
                <td class="px-3 py-2 text-sm text-gray-700">${peso(r.net_pay)}</td>
                <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(r.status || '')}</td>
              </tr>`).join('');
            wrap.innerHTML = `
              <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                  <tr>
                    <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
                    <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
                    <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Department</th>
                    <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Period</th>
                    <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Net Pay</th>
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
                  <h5 class="font-semibold">Payroll Processed This Month (${rows.length})</h5>
                  <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
                </div>
                <div class="p-4">
                  <div class="mb-3 flex items-center gap-2">
                    <div class="relative">
                      <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
                      <input id="payrollproc-search" class="w-72 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, department, payroll ID, period, status" />
                    </div>
                    <button id="payrollproc-clear" class="text-xs text-gray-600 border rounded px-2 py-1">Clear</button>
                    <a href="#payroll" class="ml-auto text-primary-700 text-sm hover:underline">Open Payroll</a>
                  </div>
                  <div id="payrollproc-table-wrap" class="overflow-auto max-h-[48vh]"></div>
                </div>
                <div class="flex justify-end items-center gap-2 border-t px-4 py-3">
                  <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
                </div>
              </div>
            </div>`;
          modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
          const si = document.getElementById('payrollproc-search');
          const sc = document.getElementById('payrollproc-clear');
          if (si) si.addEventListener('input', () => { query = (si.value || '').trim().toLowerCase(); renderTable(); });
          if (sc) sc.addEventListener('click', () => { if (si) si.value=''; query=''; renderTable(); });
          renderTable();
          modal.classList.remove('hidden');
        } catch {
          try { alert('Failed to load payroll list'); } catch {}
        }
      }
      async function showPendingLeavesList(){
        try {
          const res = await axios.get(`${window.baseApiUrl}/leaves.php`, { params: { operation: 'listPending' } });
          const rows = Array.isArray(res.data) ? res.data : [];
          let modal = document.getElementById('pendingLeavesModal');
          if (!modal) { modal = document.createElement('div'); modal.id = 'pendingLeavesModal'; modal.className = 'fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
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
            const wrap = document.getElementById('pendleaves-table-wrap');
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
                      <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
                      <input id="pendleaves-search" class="w-72 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, type, date, reason, status" />
                    </div>
                    <button id="pendleaves-clear" class="text-xs text-gray-600 border rounded px-2 py-1">Clear</button>
                    <a href="#LeaveRequests" class="ml-auto text-primary-700 text-sm hover:underline">Open Leave Management</a>
                  </div>
                  <div id="pendleaves-table-wrap" class="overflow-auto max-h-[48vh]"></div>
                </div>
                <div class="flex justify-end items-center gap-2 border-t px-4 py-3">
                  <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
                </div>
              </div>
            </div>`;
          modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
          const si = document.getElementById('pendleaves-search');
          const sc = document.getElementById('pendleaves-clear');
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
        if (absentEl) {
          absentEl.addEventListener('click', async () => { await showAbsentTodayList(); });
        }
        const totalEl = topWrap && topWrap.querySelector('[data-card-id="total"]');
        if (totalEl) {
          totalEl.addEventListener('click', async () => { await showAllEmployeesList(); });
        }
        const presentEl = topWrap && topWrap.querySelector('[data-card-id="present"]');
        if (presentEl) {
          presentEl.addEventListener('click', async () => { await showPresentTodayList(); });
        }
        const pendingEl = bottomWrap && bottomWrap.querySelector('[data-card-id="pending_leaves"]');
        if (pendingEl) {
          pendingEl.addEventListener('click', async () => { await showPendingLeavesList(); });
        }
        const payrollProcessedEl = bottomWrap && bottomWrap.querySelector('[data-card-id="payroll_processed"]');
        if (payrollProcessedEl) {
          payrollProcessedEl.addEventListener('click', () => { location.hash = '#payroll'; });
        }
      } catch {}
    }

    async function renderAttendanceSnapshot(){
    const wrap = document.getElementById('attendance-table');
    if (!wrap) return;
    const params = { operation: 'getAttendance', start_date: new Date().toLocaleDateString('en-CA'), end_date: new Date().toLocaleDateString('en-CA') };
      const res = await axios.get(`${window.baseApiUrl}/attendance.php`, { params });
      const rows = res.data || [];
      const table = document.createElement('table');
      table.className = 'min-w-full divide-y divide-gray-200';
      table.innerHTML = `
        <thead class="bg-gray-50"><tr>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time In</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time Out</th>
        </tr></thead><tbody class="divide-y divide-gray-200 bg-white"></tbody>`;
      const tbody = table.querySelector('tbody');
      if (!rows.length) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="4" class="px-3 py-6 text-sm text-center text-gray-500">No attendance records</td>`;
        tbody.appendChild(tr);
      } else {
        rows.forEach(r => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td class="px-3 py-2 text-sm">
              <button class="text-primary-700 hover:underline" data-emp-id="${r.employee_id}">${toTitleCase(`${r.first_name} ${r.last_name}`)}</button>
            </td>
            <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(r.status || '')}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${r.time_in || ''}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${r.time_out || ''}</td>`;
          const btn = tr.querySelector('[data-emp-id]');
          if (btn) {
            btn.addEventListener('click', async () => {
              await showEmployeeDetails(r.employee_id);
            });
          }
          tbody.appendChild(tr);
        });
      }
      wrap.innerHTML = '';
      wrap.appendChild(table);
    }

    async function renderRecentActivities(){
      let all = [];
      let query = '';
      let page = 1;
      let pageSize = 5;
      const ul = document.getElementById('recent-activities-list');
      const pager = document.getElementById('recent-activities-pagination');
      const searchInput = document.getElementById('act-search-input');
      const searchClear = document.getElementById('act-search-clear');
      const pageSizeSelect = document.getElementById('act-page-size');
      const dateInput = document.getElementById('act-date');

      const fmtTime = (d, t) => {
        try { return new Date(`${d}T${t}`).toLocaleString(); } catch { return `${d} ${t || ''}`; }
      };

      const load = async () => {
        if (!ul) return;
        ul.innerHTML = '<li class="p-2 text-xs text-gray-500">Loading...</li>';
        try {
          let items = [];
          const dt = (dateInput && dateInput.value) ? dateInput.value : undefined;
          if (dt) {
            const res = await axios.get(`${window.baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: dt, end_date: dt } });
            items = Array.isArray(res.data) ? res.data : [];
          } else {
            const res = await axios.get(`${window.baseApiUrl}/attendance.php`, { params: { operation: 'recentActivities', limit: 200 } });
            items = Array.isArray(res.data) ? res.data : [];
          }
          // Normalize shape to have same keys regardless of endpoint used
          all = items.map(a => ({
            attendance_date: a.attendance_date,
            time_in: a.time_in,
            time_out: a.time_out,
            status: a.status,
            first_name: a.first_name,
            last_name: a.last_name,
            department: a.department
          })).sort((x, y) => (y.attendance_date || '').localeCompare(x.attendance_date || ''));
          page = 1;
          render();
        } catch {
          ul.innerHTML = '<li class="p-2 text-xs text-red-600">Failed to load activities</li>';
          all = [];
          render();
        }
      };

      const getFiltered = () => {
        const q = (query || '').toLowerCase();
        if (!q) return all.slice();
        return all.filter(a => {
          const name = `${a.first_name || ''} ${a.last_name || ''}`.toLowerCase();
          const dept = (a.department || '').toLowerCase();
          const st = (a.status || '').toLowerCase();
          const dt = (a.attendance_date || '').toLowerCase();
          return name.includes(q) || dept.includes(q) || st.includes(q) || dt.includes(q);
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
        if (!pageRows.length) {
          ul.innerHTML = '<li class="p-2 text-xs text-gray-500">No recent activity</li>';
        } else {
          ul.innerHTML = pageRows.map(a => {
            const name = toTitleCase(`${a.first_name || ''} ${a.last_name || ''}`.trim());
            const checkIn = a.time_in ? `<div class='text-xs text-gray-500'>Time in: ${fmtTime(a.attendance_date, a.time_in)}</div>` : '';
            const checkOut = a.time_out ? `<div class='text-xs text-gray-500'>Time out: ${fmtTime(a.attendance_date, a.time_out)}</div>` : '';
            return `<li class="p-2 text-xs">
              <div class="flex items-center justify-between">
                <div>
                  <div class="font-medium">${name || 'Unknown'}</div>
                  <div class="text-xs text-gray-500">${toTitleCase(a.department || '')} • ${toTitleCase(a.status || '')}</div>
                  ${checkIn}${checkOut}
                </div>
                <div class="text-xs text-gray-400">${a.attendance_date || ''}</div>
              </div>
            </li>`;
          }).join('');
        }
        if (pager) {
          const showingFrom = total === 0 ? 0 : (startIdx + 1);
          const showingTo = endIdx;
          pager.innerHTML = `
            <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${total}</span></div>
            <div class="flex items-center gap-2">
              <button id="act-prev" class="px-1.5 py-0.5 text-xs rounded border ${page <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
              <span>Page ${page} of ${totalPages}</span>
              <button id="act-next" class="px-1.5 py-0.5 text-xs rounded border ${page >= totalPages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
            </div>`;
          const prev = document.getElementById('act-prev');
          const next = document.getElementById('act-next');
          if (prev) prev.addEventListener('click', () => { if (page > 1) { page -= 1; render(); } });
          if (next) next.addEventListener('click', () => { if (page < totalPages) { page += 1; render(); } });
        }
      };

      if (searchInput) searchInput.addEventListener('input', () => { query = (searchInput.value || '').trim(); page = 1; render(); });
      if (searchClear) searchClear.addEventListener('click', () => { if (searchInput) searchInput.value=''; query=''; page=1; render(); });
      if (pageSizeSelect) pageSizeSelect.addEventListener('change', () => { const n = Number(pageSizeSelect.value); pageSize = Number.isFinite(n) && n > 0 ? n : 7; page = 1; render(); });
      if (dateInput) dateInput.addEventListener('change', load);

      await load();
    }

    async function renderLeaves(){
      const res = await axios.get(`${window.baseApiUrl}/leaves.php`, { params: { operation: 'listPending' } });
      const rows = Array.isArray(res.data) ? res.data : [];
      const table = document.createElement('table');
      table.className = 'min-w-full divide-y divide-gray-200';

      const daysInclusive = (start, end) => {
        try {
          const parse = (s) => { const [y,m,d] = String(s||'').split('-').map(n=>parseInt(n,10)); return Date.UTC(y||1970,(m||1)-1,d||1); };
          const a = parse(start), b = parse(end || start);
          if (!Number.isFinite(a) || !Number.isFinite(b)) return '';
          const diff = Math.floor((b - a) / 86400000) + 1;
          return diff > 0 ? diff : 1;
        } catch { return ''; }
      };

      table.innerHTML = `
        <thead class="bg-gray-50"><tr>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Type</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Dates</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Days</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Reason</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Submitted</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Approved By</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Actions</th>
        </tr></thead><tbody class="divide-y divide-gray-200 bg-white"></tbody>`;

      const tbody = table.querySelector('tbody');
      rows.forEach((r, idx) => {
        const n = idx + 1;
        const name = toTitleCase(`${r.first_name || ''} ${r.last_name || ''}`.trim());
        const type = toTitleCase(r.leave_type || '');
        const dateRange = `${r.start_date || ''} → ${r.end_date || ''}`;
        const days = daysInclusive(r.start_date, r.end_date);
        const reason = (r.reason || '').toString();
        const status = toTitleCase(r.status || 'pending');
        const submitted = (() => { try { const s = String(r.created_at || ''); return s ? new Date(s).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : ''; } catch { return String(r.created_at || ''); }})();
        const approvedBy = r.approved_by_username || '';
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="px-3 py-2 text-sm text-gray-700">${n}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${name}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${type}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${dateRange}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${days}</td>
          <td class="px-3 py-2 text-sm text-gray-700 truncate max-w-[16rem]" title="${reason.replace(/\"/g,'&quot;')}">${reason}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${status}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${submitted}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(approvedBy || '')}</td>
          <td class="px-3 py-2 text-sm"><button data-view="${r.leave_id}" class="px-2 py-1 text-xs rounded border border-gray-300 text-gray-700 hover:bg-gray-50">View</button></td>`;
        const viewBtn = tr.querySelector('[data-view]');
        if (viewBtn) {
          viewBtn.addEventListener('click', async () => {
            try {
              if (r && r.reason != null) {
                openLeaveView(r);
              } else {
                const res = await axios.get(`${window.baseApiUrl}/leaves.php`, { params: { operation: 'getLeave', leave_id: r.leave_id } });
                const full = res.data || r;
                openLeaveView(full);
              }
            } catch {
              try { openLeaveView(r); } catch {}
            }
          });
        }
        tbody.appendChild(tr);
      });
      const wrap = document.getElementById('leaves-table');
      wrap.innerHTML = '';
      wrap.appendChild(table);
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
      const res = await axios.get(`${window.baseApiUrl}/reports.php`, { params: { operation: 'payrollSummary' } });
      const data = res.data || { total_net_pay: 0, total_deductions: 0, total_overtime_pay: 0 };
      document.getElementById('payroll-summary').innerHTML = `
        <ul class="divide-y divide-gray-200">
          <li class="flex items-center justify-between py-2"><span>Total Net Pay (period)</span><strong>${Number(data.total_net_pay || 0).toFixed(2)}</strong></li>
          <li class="flex items-center justify-between py-2"><span>Total Deductions</span><strong>${Number(data.total_deductions || 0).toFixed(2)}</strong></li>
          <li class="flex items-center justify-between py-2"><span>Total Overtime Pay</span><strong>${Number(data.total_overtime_pay || 0).toFixed(2)}</strong></li>
        </ul>`;
    }

    function setupEmployeeSearch(){
      const input = document.getElementById('emp-search');
      const btn = document.getElementById('emp-search-btn');
      const results = document.getElementById('emp-search-results');
      const search = async () => {
        const q = (input.value || '').toLowerCase();
        if (!q) { results.innerHTML = ''; return; }
        const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
        const employees = (res.data || []).filter(e => (`${e.first_name} ${e.last_name}`.toLowerCase().includes(q)));
        results.innerHTML = employees.slice(0,10).map(e => `
          <div class="flex items-center justify-between py-2 border-b last:border-b-0">
            <div class="text-sm text-gray-700">${toTitleCase(`${e.first_name} ${e.last_name}`)}</div>
            <a href="#employees" class="text-primary-700 text-xs hover:underline">Open</a>
          </div>`).join('');
      };
      btn.addEventListener('click', (e) => { e.preventDefault(); search(); });
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); search(); } });
    }

    async function renderNotifications(){
      const list = document.getElementById('admin-notif-list');
      if (!list) return;
      try {
        const response = await axios.get(`${baseApiUrl}/notifications.php`, {
          params: { operation: 'getNotifications' },
          withCredentials: true
        });
        const notifications = (response.data && response.data.success) ? (response.data.notifications || []) : [];
        if (!notifications.length){
          list.innerHTML = '<li class="text-sm text-gray-500">No notifications</li>';
          return;
        }
        list.innerHTML = notifications.map(n => `
          <li class="text-sm flex items-start justify-between gap-3 py-1 ${n.read_at ? 'opacity-75' : ''}">
            <div class="flex-1">
              <div class="${n.read_at ? 'text-gray-600' : 'text-gray-800 font-medium'}">${escapeHtml(n.message)}</div>
              <div class="text-xs text-gray-400 mt-0.5">${formatTime(n.created_at)}</div>
            </div>
            <div class="flex items-center gap-2 text-xs whitespace-nowrap">
              ${!n.read_at ? `<button data-action="mark-read" data-id="${n.id}" class="px-2 py-1 rounded border border-primary-600 text-primary-700">Mark Read</button>` : ''}
              <button data-action="delete" data-id="${n.id}" class="px-2 py-1 rounded border border-red-600 text-red-700">Delete</button>
            </div>
          </li>
        `).join('');

        list.querySelectorAll('[data-action="mark-read"]').forEach(btn => {
          btn.addEventListener('click', async () => {
            const id = btn.getAttribute('data-id');
            await markNotificationAsRead(id);
            await renderNotifications();
          });
        });
        list.querySelectorAll('[data-action="delete"]').forEach(btn => {
          btn.addEventListener('click', async () => {
            const id = btn.getAttribute('data-id');
            await deleteNotification(id);
            await renderNotifications();
          });
        });
      } catch {
        list.innerHTML = '<li class="text-sm text-red-500">Failed to load notifications</li>';
      }
    }

    function mountEmployeeViewModal(){
      if (document.getElementById('empViewModal')) return;
      const modal = document.createElement('div');
      modal.id = 'empViewModal';
      modal.className = 'fixed inset-0 z-50 hidden';
      modal.innerHTML = `
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-xl">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3">
              <h5 class="font-semibold">Employee Details</h5>
              <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
            </div>
            <div id="empViewBody" class="p-4 text-sm text-gray-700"></div>
            <div class="flex justify-end gap-2 border-t px-4 py-3">
              <a href="#employees" class="px-3 py-2 text-sm rounded border">Open Employees</a>
              <button class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700" data-close="true">Close</button>
            </div>
          </div>
        </div>`;
      document.body.appendChild(modal);
      modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
    }

    async function showEmployeeDetails(employeeId){
      const res = await axios.get(`${window.baseApiUrl}/employees.php`, {
        params: { operation: 'getEmployee', employee_id: employeeId }
      });
      const e = res.data || {};
      const body = document.getElementById('empViewBody');
      const fmtDate = (s) => {
        if (!s || s === '0000-00-00') return '';
        try {
          const d = new Date(s);
          if (isNaN(d.getTime())) return '';
          return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
        } catch { return ''; }
      };
      body.innerHTML = `
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <div class="text-gray-500">Name</div>
            <div class="font-medium">${toTitleCase(`${e.first_name || ''} ${e.last_name || ''}`)}</div>
          </div>
          <div>
            <div class="text-gray-500">Status</div>
            <div class="font-medium">${toTitleCase(e.status || '')}</div>
          </div>
          <div>
            <div class="text-gray-500">Email</div>
            <div class="font-medium">${e.email || ''}</div>
          </div>
          <div>
            <div class="text-gray-500">Phone</div>
            <div class="font-medium">${e.phone || ''}</div>
          </div>
          <div>
            <div class="text-gray-500">Department</div>
            <div class="font-medium">${toTitleCase(e.department || '')}</div>
          </div>
          <div>
            <div class="text-gray-500">Position</div>
            <div class="font-medium">${toTitleCase(e.position || '')}</div>
          </div>
          <div>
            <div class="text-gray-500">Basic Salary</div>
            <div class="font-medium">${e.basic_salary != null ? Number(e.basic_salary).toLocaleString('en-US', { minimumFractionDigits: 0, maximumFractionDigits: 0 }) : ''}</div>
          </div>
          <div>
            <div class="text-gray-500">Date Hired</div>
            <div class="font-medium">${fmtDate(e.date_hired)}</div>
          </div>
        </div>`;
      const modal = document.getElementById('empViewModal');
      modal.classList.remove('hidden');
    }

    // Notifications (header) for admin
    async function renderHeaderNotifications(){
      const badge = document.getElementById('notif-badge');
      const listEl = document.getElementById('admin-notif-dropdown-list');
      if (!badge || !listEl) return;
      try {
        const response = await axios.get(`${baseApiUrl}/notifications.php`, {
          params: { operation: 'getNotifications' },
          withCredentials: true
        });
        
        // Handle different response formats properly
        let notifications = [];
        if (response.data) {
          // Check if it's the new format with success flag
          if (response.data.success === 1 && Array.isArray(response.data.notifications)) {
            notifications = response.data.notifications;
          }
          // Check if it's the old format with tblnotifications
          else if (Array.isArray(response.data.tblnotifications)) {
            notifications = response.data.tblnotifications;
          }
          // Check if response.data is directly an array
          else if (Array.isArray(response.data)) {
            notifications = response.data;
          }
          // Handle case where response.data is an object with notifications property
          else if (response.data.notifications && Array.isArray(response.data.notifications)) {
            notifications = response.data.notifications;
          }
          // Handle direct array response
          else if (Array.isArray(response.data)) {
            notifications = response.data;
          }
        }
        
        const unread = notifications.filter(n => !n.read_at).length;
        try { sessionStorage.setItem('introUnreadNotifCount', String(unread)); } catch {}
        if (unread > 0) {
          badge.textContent = unread;
          badge.classList.remove('hidden');
        } else {
          badge.textContent = '';
          badge.classList.add('hidden');
        }

        if (notifications.length) {
          listEl.innerHTML = notifications.map(n => `
            <div class="px-4 py-2 border-t first:border-t-0 ${n.read_at ? 'opacity-75' : ''}">
              <div class="text-sm ${n.read_at ? 'text-gray-600' : 'text-gray-800 font-medium'}">${escapeHtml(n.message || n.text || 'Notification')}</div>
              <div class="text-xs text-gray-400 mt-0.5">${formatTime(n.created_at || n.createdAt || '')}</div>
              <div class="mt-2 text-xs">
                ${!n.read_at ? `<button data-action="mark-read" data-id="${n.id || n.notification_id || ''}" class="px-2 py-1 rounded border border-primary-600 text-primary-700">Mark read</button>` : ''}
              </div>
            </div>
          `).join('');
          
          listEl.querySelectorAll('[data-action="mark-read"]').forEach(btn => {
            btn.addEventListener('click', async () => {
              const id = btn.getAttribute('data-id');
              if (id) {
                await markNotificationAsRead(id);
                await renderHeaderNotifications();
              }
            });
          });
        } else {
          listEl.innerHTML = '<div class="px-4 py-6 text-sm text-gray-500 text-center">No notifications</div>';
        }
      } catch (error) {
        console.error('Error fetching notifications:', error);
        if (listEl) {
          listEl.innerHTML = '<div class="px-4 py-6 text-sm text-gray-500 text-center">Error loading notifications</div>';
        }
      }
    }

    function initHeaderNotifications(){
      // Check if admin-header.js is already handling notifications
      if (window.__adminNotifHeaderWired || document.querySelector('script[src*="admin-header.js"]')) {
        return;
      }
      
      window.__adminNotifHeaderWired = true;
      const toggle = document.getElementById('notif-toggle');
      const dropdown = document.getElementById('notif-dropdown');
      const closeBtn = document.getElementById('notif-close');
      const markAllBtn = document.getElementById('notif-mark-all');
      if (!toggle || !dropdown) return;
      // Immediately restore stored unread count to avoid badge flicker on navigation
      try {
        const badge = document.getElementById('notif-badge');
        if (badge) {
          const stored = parseInt(sessionStorage.getItem('introUnreadNotifCount') || '0', 10);
          if (Number.isFinite(stored) && stored > 0) {
            badge.textContent = stored;
            badge.classList.remove('hidden');
          } else {
            badge.textContent = '';
            badge.classList.add('hidden');
          }
        }
      } catch {}
      const close = () => dropdown.classList.add('hidden');
      toggle.addEventListener('click', async (e) => {
        e.stopPropagation();
        dropdown.classList.toggle('hidden');
        if (!dropdown.classList.contains('hidden')) {
          await renderHeaderNotifications();
        }
      });
      if (closeBtn) closeBtn.addEventListener('click', (e) => { e.preventDefault(); close(); });
      document.addEventListener('click', (e) => {
        if (!dropdown.contains(e.target) && !toggle.contains(e.target)) close();
      });
      if (markAllBtn) {
        markAllBtn.addEventListener('click', async (e) => {
          e.preventDefault();
          try {
            const response = await axios.get(`${baseApiUrl}/notifications.php`, { params: { operation: 'getNotifications' }, withCredentials: true });
            
            // Handle different response formats properly
            let notifications = [];
            if (response.data) {
              // Check if it's the new format with success flag
              if (response.data.success === 1 && Array.isArray(response.data.notifications)) {
                notifications = response.data.notifications;
              }
              // Check if it's the old format with tblnotifications
              else if (Array.isArray(response.data.tblnotifications)) {
                notifications = response.data.tblnotifications;
              }
              // Check if response.data is directly an array
              else if (Array.isArray(response.data)) {
                notifications = response.data;
              }
              // Handle case where response.data is an object with notifications property
              else if (response.data.notifications && Array.isArray(response.data.notifications)) {
                notifications = response.data.notifications;
              }
              // Handle direct array response
              else if (Array.isArray(response.data)) {
                notifications = response.data;
              }
            }
            
            const unread = notifications.filter(n => !n.read_at);
            await Promise.all(unread.map(n => markNotificationAsRead(n.id || n.notification_id || '')));
            await renderHeaderNotifications();
          } catch {}
        });
      }
    }

    // Wire admin header notifications after initial render
    initHeaderNotifications();
    // Auto refresh badge every 30s
    setInterval(renderHeaderNotifications, 30000);
    // initial load
    renderHeaderNotifications();
  },
  employees: async () => {
    const module = await import('./modules/employees.js');
    await module.render();
  },
  attendance: async () => {
    const module = await import('./modules/attendance.js');
    await module.render();
  },
  payroll: async () => {
    const module = await import('./modules/payroll.js');
    await module.render();
  },
  reports: async () => {
    const module = await import('./modules/reports.js');
    await module.render();
  },
  settings: async () => {
    const module = await import('./modules/settings.js');
    await module.render();
  },
  LeaveRequests: async () => {
    const module = await import('./modules/leaves.js');
    await module.render();
  },
  requestapproval: async () => {
    const app = document.getElementById('app');
    app.innerHTML = `
      <div class="flex items-center justify-between mb-3">
        <h3 class="font-semibold">Request Approval</h3>
        <div class="flex items-center gap-2">
          <button id="admin-btn-file-ot" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Request Overtime</button>
        </div>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <div class="mb-3 flex items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <div class="relative">
              <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
              <input id="req-search-input" class="w-56 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, type, date, reason" />
            </div>
            <select id="req-status-filter" class="border rounded px-2 py-1 text-sm">
              <option value="pending" selected>Pending</option>
              <option value="approved">Approved</option>
              <option value="rejected">Rejected</option>
            </select>
            <select id="req-dept-filter" class="border rounded px-2 py-1 text-sm">
              <option value="">All Departments</option>
            </select>
          </div>
          <div class="flex items-center gap-2 text-sm text-gray-600">
            <span>Rows per page</span>
            <select id="req-page-size" class="border rounded px-2 py-1">
              <option value="5">5</option>
              <option value="10" selected>10</option>
              <option value="20">20</option>
              <option value="50">50</option>
            </select>
          </div>
        </div>
        <div id="req-approval-table" class="overflow-x-auto"></div>
        <div id="req-pagination" class="mt-3 flex items-center justify-between text-sm text-gray-600"></div>
      </div>

      <div id="adminOtModal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-lg">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold">Request Overtime</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
            <div class="p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Employee</label>
                <input id="admin-ot-emp-search" class="w-full border rounded px-3 py-2 mb-2" placeholder="Search employee..." />
                <select id="admin-ot-emp" class="w-full border rounded px-3 py-2"></select>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Date</label>
                <input id="admin-ot-date" type="date" class="w-full border rounded px-3 py-2" />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Time In</label>
                <input id="admin-ot-in" type="time" class="w-full border rounded px-3 py-2" />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Time Out</label>
                <input id="admin-ot-out" type="time" class="w-full border rounded px-3 py-2" />
              </div>
                                          <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Reason</label>
                <textarea id="admin-ot-reason" rows="3" class="w-full border rounded px-3 py-2"></textarea>
              </div>
            </div>
            <div class="flex justify-end gap-2 border-t px-4 py-3">
              <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
              <button id="admin-ot-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Submit</button>
            </div>
          </div>
        </div>
      </div>

      <div id="adminUtModal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-lg">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold">Request Undertime</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
            <div class="p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Employee</label>
                <input id="admin-ut-emp-search" class="w-full border rounded px-3 py-2 mb-2" placeholder="Search employee..." />
                <select id="admin-ut-emp" class="w-full border rounded px-3 py-2"></select>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Date</label>
                <input id="admin-ut-date" type="date" class="w-full border rounded px-3 py-2" />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Hours</label>
                <input id="admin-ut-hours" type="number" step="0.25" min="0.25" class="w-full border rounded px-3 py-2" placeholder="e.g., 1" />
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Reason</label>
                <textarea id="admin-ut-reason" rows="3" class="w-full border rounded px-3 py-2"></textarea>
              </div>
            </div>
            <div class="flex justify-end gap-2 border-t px-4 py-3">
              <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
              <button id="admin-ut-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Submit</button>
            </div>
          </div>
        </div>
      </div>`;
    const wrap = document.getElementById('req-approval-table');
    wrap.innerHTML = '<div class="text-gray-500">Loading...</div>';

    // Admin OT/UT modals wiring
    let _allEmployees = [];
    async function loadEmployeesList(){
      try {
        const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
        _allEmployees = Array.isArray(res.data) ? res.data : [];
      } catch { _allEmployees = []; }
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
        const filtered = !q ? _allEmployees.slice() : _allEmployees.filter(e => `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.includes(q) || String(e.email||'').toLowerCase().includes(q));
        renderEmpOptions(selectId, filtered, selected);
      };
    }

    const otModal = document.getElementById('adminOtModal');
    const utModal = document.getElementById('adminUtModal');
    const openOt = async () => { await loadEmployeesList(); renderEmpOptions('admin-ot-emp', _allEmployees); wireSearchEmp('admin-ot-emp-search', 'admin-ot-emp'); if (otModal) otModal.classList.remove('hidden'); };
    const closeOt = () => { if (otModal) otModal.classList.add('hidden'); };
    const openUt = async () => { await loadEmployeesList(); renderEmpOptions('admin-ut-emp', _allEmployees); wireSearchEmp('admin-ut-emp-search', 'admin-ut-emp'); if (utModal) utModal.classList.remove('hidden'); };
    const closeUt = () => { if (utModal) utModal.classList.add('hidden'); };

    const otBtn = document.getElementById('admin-btn-file-ot');
    const utBtn = document.getElementById('admin-btn-file-ut');
    if (otBtn) otBtn.addEventListener('click', openOt);
    if (utBtn) utBtn.addEventListener('click', openUt);
    if (otModal) otModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeOt));
    if (utModal) utModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeUt));

    const otSave = document.getElementById('admin-ot-save');
    if (otSave) otSave.addEventListener('click', async () => {
      const employee_id = document.getElementById('admin-ot-emp')?.value;
      const work_date = document.getElementById('admin-ot-date')?.value;
      const reason = document.getElementById('admin-ot-reason')?.value || '';
      const tIn = document.getElementById('admin-ot-in')?.value || '';
      const tOut = document.getElementById('admin-ot-out')?.value || '';
      const toMinutes = (t) => { const parts = String(t).split(':').map(n => parseInt(n,10)); if (parts.length < 2 || Number.isNaN(parts[0]) || Number.isNaN(parts[1])) return NaN; return parts[0]*60 + parts[1]; };
      const a = toMinutes(tIn);
      const b = toMinutes(tOut);
      if (!employee_id || !work_date || !Number.isFinite(a) || !Number.isFinite(b)) { alert('Select employee, date and valid time in/out'); return; }
      let diff = b - a; if (diff <= 0) diff += 24*60;
      const hoursVal = Math.round((diff / 60) * 100) / 100;

      const fd = new FormData();
      fd.append('operation', 'requestOvertime');
      fd.append('json', JSON.stringify({ employee_id, work_date, hours: hoursVal, reason }));
      try {
        await axios.post(`${window.baseApiUrl}/overtime.php`, fd);
        closeOt();
        alert('Overtime request submitted');
        await routes.requestapproval();
      } catch {
        alert('Failed to submit overtime');
      }
    });

    const utSave = document.getElementById('admin-ut-save');
    if (utSave) utSave.addEventListener('click', async () => {
      const employee_id = document.getElementById('admin-ut-emp')?.value;
      const work_date = document.getElementById('admin-ut-date')?.value;
      const hours = Number(document.getElementById('admin-ut-hours')?.value || '0');
      const reason = document.getElementById('admin-ut-reason')?.value || '';
      if (!employee_id || !work_date || !Number.isFinite(hours) || hours <= 0) { alert('Select employee, date and valid hours'); return; }
      const fd = new FormData();
      fd.append('operation', 'requestUndertime');
      fd.append('json', JSON.stringify({ employee_id, work_date, hours, reason }));
      try { await axios.post(`${window.baseApiUrl}/undertime.php`, fd); closeUt(); alert('Undertime request submitted'); await routes.requestapproval(); } catch { alert('Failed to submit undertime'); }
    });
    // Table search and pagination
    let allItems = [];
    let query = '';
    let page = 1;
    let pageSize = 10;
    let statusFilter = 'pending';
    let deptFilter = '';

    const searchInput = document.getElementById('req-search-input');
    const pageSizeSelect = document.getElementById('req-page-size');
    const pager = document.getElementById('req-pagination');

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
      if (!Number.isFinite(n) || n <= 0) return '';
      const total = Math.round(n * 60);
      const h = Math.floor(total / 60);
      const m = total % 60;
      return `${h}h ${m}m`;
    };

    const getFiltered = () => {
    const q = (query || '').toLowerCase();
    const s = (statusFilter || 'pending').toLowerCase();
    let base = allItems.slice();
    if (s !== 'all') {
    base = base.filter(it => {
    const st = String(it.status || '').toLowerCase();
    if (s === 'approved' || s === 'approve') return st === 'approved' || st === 'approve';
    if (s === 'rejected' || s === 'reject') return st === 'rejected' || st === 'reject';
    return st === 'pending';
    });
    }
    if (deptFilter) {
    base = base.filter(it => {
    const rowDept = String(it.department || '').toLowerCase();
    if (rowDept) return rowDept === deptFilter;
    const emp = _allEmployees.find(e => String(e.employee_id) === String(it.employee_id));
    const empDept = emp && emp.department ? String(emp.department).toLowerCase() : '';
    return empDept === deptFilter;
    });
    }
    if (!q) return base;
    return base.filter(it => {
    const name = `${it.first_name || ''} ${it.last_name || ''}`.toLowerCase();
    const type = (it.kind || '').toLowerCase();
    const date = (it.work_date || '').toLowerCase();
    const reason = (it.reason || '').toLowerCase();
    const st = (it.status || '').toLowerCase();
    const rowDept = (() => {
    const d = String(it.department || '').toLowerCase();
    if (d) return d;
    const emp = _allEmployees.find(e => String(e.employee_id) === String(it.employee_id));
    return emp && emp.department ? String(emp.department).toLowerCase() : '';
    })();
    return name.includes(q) || type.includes(q) || date.includes(q) || reason.includes(q) || st.includes(q) || rowDept.includes(q);
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

      const formatTime12 = (timeStr) => {
        try {
          const parts = String(timeStr || '').split(':');
          if (parts.length < 2) return String(timeStr || '');
          let h = parseInt(parts[0], 10);
          const m = parseInt(parts[1], 10) || 0;
          if (!Number.isFinite(h)) return String(timeStr || '');
          const ampm = h >= 12 ? 'PM' : 'AM';
          h = h % 12; if (h === 0) h = 12;
          const mm = String(m).padStart(2, '0');
          return `${h}:${mm} ${ampm}`;
        } catch { return String(timeStr || ''); }
      };

      {
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
            const hoursStr = (() => {
              if (it.hours != null) return formatHours(it.hours);
              const dec = calcHoursDecimal(it.start_time, it.end_time);
              if (dec != null) return formatHours(dec);
              return '';
            })();
            const dept = (() => {
              const d = String(it.department || '').trim();
              if (d) return d;
              const emp = _allEmployees.find(e => String(e.employee_id) === String(it.employee_id));
              return emp && emp.department ? emp.department : '';
            })();
            tr.innerHTML = `
              <td class="px-3 py-2 text-sm text-gray-700">${startIdx + idx + 1}</td>
              <td class="px-3 py-2 text-sm text-gray-700">${name}</td>
              <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(dept || '')}</td>
              <td class="px-3 py-2 text-sm text-gray-700">${it.kind}</td>
              <td class="px-3 py-2 text-sm text-gray-700">${formatWorkDate(it.work_date) || ''}</td>
              <td class="px-3 py-2 text-sm text-gray-700">${hoursStr}</td>
              <td class="px-3 py-2 text-sm text-gray-700 truncate max-w-[20rem]" title="${(it.reason||'').replace(/\"/g,'&quot;')}">${it.reason || ''}</td>
              <td class="px-3 py-2 text-sm text-gray-700">${statusBadge(it.status)}</td>
              <td class="px-3 py-2 text-sm text-right">
                <div class="relative inline-block text-left" data-req-menu-container>
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
            const container = tr.querySelector('[data-req-menu-container]');
            const toggle = container?.querySelector('[data-action="menu-toggle"]');
            const menu = container?.querySelector('[data-menu]');
            if (toggle && menu) {
              toggle.addEventListener('click', (ev) => {
                ev.preventDefault(); ev.stopPropagation();
                // Close other menus
                tbody.querySelectorAll('[data-req-menu-container] [data-menu]').forEach(m => { if (m !== menu) m.classList.add('hidden'); });
                const wasHidden = menu.classList.contains('hidden');
                menu.classList.toggle('hidden');
                // When opening, temporarily disable scrollbars on the table wrapper
                const wrap = container.closest('.overflow-x-auto');
                if (wasHidden) {
                  if (wrap) {
                    window.__reqPrevScrollWrap = wrap;
                    window.__reqPrevOverflowX = wrap.style.overflowX;
                    window.__reqPrevOverflowY = wrap.style.overflowY;
                    wrap.style.overflowX = 'visible';
                    wrap.style.overflowY = 'visible';
                  }
                } else {
                  if (window.__reqPrevScrollWrap) {
                    window.__reqPrevScrollWrap.style.overflowX = window.__reqPrevOverflowX || '';
                    window.__reqPrevScrollWrap.style.overflowY = window.__reqPrevOverflowY || '';
                    window.__reqPrevScrollWrap = null;
                    window.__reqPrevOverflowX = null;
                    window.__reqPrevOverflowY = null;
                  }
                }
              });
              menu.querySelectorAll('[data-menu-action]').forEach(btn => {
                btn.addEventListener('click', async () => {
                  const action = btn.getAttribute('data-menu-action');
                  if (action === 'edit') {
                    await openEditRequestModal(it);
                  } else if (action === 'approve') {
                    await submitDecision(it, 'approve');
                    await routes.requestapproval();
                  } else if (action === 'reject') {
                    await submitDecision(it, 'reject');
                    await routes.requestapproval();
                  }
                  menu.classList.add('hidden');
                  // Restore scrollbars if we disabled them when opening
                  if (window.__reqPrevScrollWrap) {
                    window.__reqPrevScrollWrap.style.overflowX = window.__reqPrevOverflowX || '';
                    window.__reqPrevScrollWrap.style.overflowY = window.__reqPrevOverflowY || '';
                    window.__reqPrevScrollWrap = null;
                    window.__reqPrevOverflowX = null;
                    window.__reqPrevOverflowY = null;
                  }
                });
              });
            }
            tbody.appendChild(tr);
          });
          // Wire global click close for request approval menus
          if (!window.__reqMenuGlobalClose) {
            window.__reqMenuGlobalClose = true;
            document.addEventListener('click', () => {
              document.querySelectorAll('[data-req-menu-container] [data-menu]').forEach(m => m.classList.add('hidden'));
              // Restore scroll state for table wrapper if modified
              if (window.__reqPrevScrollWrap) {
                window.__reqPrevScrollWrap.style.overflowX = window.__reqPrevOverflowX || '';
                window.__reqPrevScrollWrap.style.overflowY = window.__reqPrevOverflowY || '';
                window.__reqPrevScrollWrap = null;
                window.__reqPrevOverflowX = null;
                window.__reqPrevOverflowY = null;
              }
            });
          }
        }
        wrap.innerHTML = '';
        wrap.appendChild(table);
      }

      if (pager) {
        const showingFrom = total === 0 ? 0 : (startIdx + 1);
        const showingTo = endIdx;
        pager.innerHTML = `
          <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${total}</span></div>
          <div class="flex items-center gap-2">
            <button id="req-prev" class="px-1.5 py-0.5 text-xs rounded border ${page <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
            <span>Page ${page} of ${totalPages}</span>
            <button id="req-next" class="px-1.5 py-0.5 text-xs rounded border ${page >= totalPages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
          </div>`;
        const prev = document.getElementById('req-prev');
        const next = document.getElementById('req-next');
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
    const statusSelect = document.getElementById('req-status-filter');
    if (statusSelect) statusSelect.addEventListener('change', () => {
      statusFilter = (statusSelect.value || 'pending').toLowerCase();
      page = 1;
      render();
    });
    const deptSelect = document.getElementById('req-dept-filter');
    if (deptSelect) deptSelect.addEventListener('change', () => {
      deptFilter = (deptSelect.value || '').toLowerCase();
      page = 1;
      render();
    });

    // Populate department dropdown
    (async () => {
      try {
        const sel = document.getElementById('req-dept-filter');
        if (sel) {
          const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getDepartments' } });
          const list = Array.isArray(res.data) ? res.data : [];
          sel.innerHTML = '<option value="">All Departments</option>' + list.map(d => `<option value="${d}">${d}</option>`).join('');
        }
      } catch {}
    })();

    // Initial load of items (Overtime only)
    try {
      await loadEmployeesList();
      const otRes = await axios.get(`${window.baseApiUrl}/overtime.php`, { params: { operation: 'listAll' } });
      const ots = (otRes.data || []).map(r => ({ kind: 'Overtime', id: r.ot_id, employee_id: r.employee_id, first_name: r.first_name, last_name: r.last_name, work_date: r.work_date, hours: r.hours, reason: r.reason, status: r.status, start_time: r.start_time, end_time: r.end_time }));
      allItems = ots.sort((a, b) => String(b.work_date || '').localeCompare(String(a.work_date || '')));
      render();
    } catch (e) {
      wrap.innerHTML = '<div class="text-red-600">Failed to load requests</div>';
    }

    async function openEditRequestModal(it) {
      try {
        await ensureSweetAlertAssets();
        
        const isOvertime = it.kind === 'Overtime';
        const title = `Edit ${it.kind} Request`;
        
        // Format date for input
        const workDate = it.work_date ? it.work_date.slice(0, 10) : '';
        
        // Format time for inputs (if available)
        const startTime = it.start_time || '';
        const endTime = it.end_time || '';
        
        // Create custom modal with floating card design
        let modal = document.getElementById('editRequestModal');
        if (!modal) {
          modal = document.createElement('div');
          modal.id = 'editRequestModal';
          modal.className = 'fixed inset-0 z-50 hidden';
          document.body.appendChild(modal);
        }
        
        modal.innerHTML = `
          <div class="absolute inset-0 bg-black/50" data-close="true"></div>
          <div class="relative mx-auto mt-20 w-full max-w-lg">
            <div class="bg-white rounded-lg shadow">
              <div class="flex items-center justify-between border-b px-4 py-3">
                <h5 class="font-semibold">${title}</h5>
                <button class="text-gray-500 text-xl" data-close="true">×</button>
              </div>
              <div class="p-4 space-y-4">
                <div>
                  <label class="block text-sm text-gray-600 mb-1">Work Date</label>
                  <input type="date" id="edit-work-date" class="w-full border rounded px-3 py-2" value="${workDate}">
                </div>
                
                ${isOvertime ? `
                  <div class="grid grid-cols-2 gap-3">
                    <div>
                      <label class="block text-sm text-gray-600 mb-1">Start Time</label>
                      <input type="time" id="edit-start-time" class="w-full border rounded px-3 py-2" value="${startTime}">
                    </div>
                    <div>
                      <label class="block text-sm text-gray-600 mb-1">End Time</label>
                      <input type="time" id="edit-end-time" class="w-full border rounded px-3 py-2" value="${endTime}">
                    </div>
                  </div>
                ` : `
                  <div>
                    <label class="block text-sm text-gray-600 mb-1">Hours</label>
                    <input type="number" id="edit-hours" class="w-full border rounded px-3 py-2" value="${it.hours || ''}" step="0.25" min="0.25" placeholder="e.g., 1">
                  </div>
                `}
                
                <div>
                  <label class="block text-sm text-gray-600 mb-1">Reason</label>
                  <textarea id="edit-reason" rows="3" class="w-full border rounded px-3 py-2">${it.reason || ''}</textarea>
                </div>
              </div>
              <div class="flex justify-end gap-2 border-t px-4 py-3">
                <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
                <button id="edit-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save Changes</button>
              </div>
            </div>
          </div>
        `;
        
        // Add event listeners for close buttons
        modal.querySelectorAll('[data-close="true"]').forEach(el => {
          el.addEventListener('click', () => modal.classList.add('hidden'));
        });
        
        // Add save button event listener
        const saveBtn = document.getElementById('edit-save');
        saveBtn.addEventListener('click', async () => {
          const workDate = document.getElementById('edit-work-date').value;
          const reason = document.getElementById('edit-reason').value.trim();
          
          if (!workDate) {
            showSweetToast('Work date is required', 'warning');
            return;
          }
          
          if (!reason) {
            showSweetToast('Reason is required', 'warning');
            return;
          }
          
          const data = {
            work_date: workDate,
            reason: reason
          };
          
          if (isOvertime) {
            const startTime = document.getElementById('edit-start-time').value;
            const endTime = document.getElementById('edit-end-time').value;
            
            if (!startTime || !endTime) {
              showSweetToast('Start time and end time are required', 'warning');
              return;
            }
            
            data.start_time = startTime;
            data.end_time = endTime;
          } else {
            const hours = parseFloat(document.getElementById('edit-hours').value);
            
            if (!hours || hours <= 0) {
              showSweetToast('Hours must be greater than 0', 'warning');
              return;
            }
            
            data.hours = hours;
          }
          
          try {
            const updateData = { ...data };
            
            if (isOvertime) {
              updateData.ot_id = it.id;
              const fd = new FormData();
              fd.append('operation', 'update');
              fd.append('json', JSON.stringify(updateData));
              await axios.post(`${window.baseApiUrl}/overtime.php`, fd);
            } else {
              updateData.ut_id = it.id;
              const fd = new FormData();
              fd.append('operation', 'update');
              fd.append('json', JSON.stringify(updateData));
              await axios.post(`${window.baseApiUrl}/undertime.php`, fd);
            }
            
            modal.classList.add('hidden');
            showSweetToast(`${it.kind} request updated successfully`, 'success');
            await routes.requestapproval();
          } catch (error) {
            console.error('Error updating request:', error);
            showSweetToast(`Failed to update ${it.kind.toLowerCase()} request`, 'error');
          }
        });
        
        modal.classList.remove('hidden');
      } catch (error) {
        console.error('Error updating request:', error);
        showSweetToast(`Failed to update ${it.kind.toLowerCase()} request`, 'error');
      }
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
  },
  'audit-logs': async () => {
    const module = await import('./modules/audit-logs.js');
    await module.render();
  },
};

function handleRoute() {
  const hash = location.hash.replace('#', '') || 'dashboard';
  const route = routes[hash] || routes.dashboard;
  route();
}

window.addEventListener('hashchange', handleRoute);
// Apply saved theme immediately on load (before DOMContentLoaded handlers finish)
(function applySavedThemeEarly(){
  try {
    const t = localStorage.getItem('introTheme');
    if (t && window.__applyTheme) { window.__applyTheme(t); }
    else if (t) {
      // Minimal inline fallback: set CSS vars for primary shades
      const map = { blue:['#2563eb','#1d4ed8'], emerald:['#059669','#047857'], rose:['#e11d48','#be123c'], violet:['#7c3aed','#6d28d9'], amber:['#d97706','#b45309'], teal:['#0d9488','#0f766e'] };
      const v = map[t] || map.blue;
      const css = `:root { --primary-600:${v[0]}; --primary-700:${v[1]}; }`;
      let el = document.getElementById('theme-overrides');
      if (!el){ el = document.createElement('style'); el.id='theme-overrides'; document.head.appendChild(el); }
      el.textContent = (el.textContent || '') + `\n.bg-primary-600{background-color:var(--primary-600)!important}.bg-primary-700{background-color:var(--primary-700)!important}.text-primary-700{color:var(--primary-700)!important}.text-primary-600{color:var(--primary-600)!important}.border-primary-600{border-color:var(--primary-600)!important}.from-primary-700{--tw-gradient-from:var(--primary-700)!important}.to-primary-600{--tw-gradient-to:var(--primary-600)!important}`;
    }
  } catch {}
})();

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
        location.href = './login.html';
        return;
      }
    } catch {}
  }

  const me = await getCurrentUser();
  // expose current user info for user management self-delete guard
  try { window.__me = me; } catch {}
  if (!me) {
    location.href = '/intro/master/login.html';
    return;
  }
  if (me.role === 'hr') {
    location.href = '/intro/master/hr/hr.html#dashboard';
    return;
  }
  // Redirect managers and employees to their respective dashboards if they land here
  if (me.role === 'manager') {
    location.href = '/intro/master/manager.html#dashboard';
    return;
  }
  if (me.role === 'employee') {
    location.href = '/intro/master/employee.html';
    return;
  }
  await fillProfile();
  await syncHeaderAvatar();
  wireHelp();
  handleRoute();
});

async function isAuthenticated(){
  try {
    const res = await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
    return !!(res.data && res.data.authenticated);
  } catch { return false; }
}

function wireHelp(){
  const btn = document.getElementById('btn-help');
  if (!btn) return;
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

// Header profile dropdown
document.addEventListener('DOMContentLoaded', () => {
  const trigger = document.getElementById('profile-trigger');
  const menu = document.getElementById('profile-menu');
  const headerLogout = document.getElementById('header-logout');
  if (trigger && menu){
    // Wire theme swatches in profile menu
    const wireProfileTheme = () => {
      const sw = menu.querySelectorAll('[data-theme-pick]');
      if (!sw || !sw.length) return;
      sw.forEach(btn => btn.addEventListener('click', (e) => {
        e.preventDefault(); e.stopPropagation();
        const theme = btn.getAttribute('data-theme-pick');
        if (window.__setTheme) window.__setTheme(theme);
      }));
    };
    // Call once and also when menu opens
    wireProfileTheme();

    // Collapse Management submenu when clicking Settings (Employees page)
    const settingsLink = menu.querySelector('a[href="#settings"]');
    if (settingsLink) {
      settingsLink.addEventListener('click', (e) => {
        e.preventDefault(); e.stopPropagation();
        try {
          const sub = document.getElementById('nav-employees-sub');
          const caret = document.getElementById('nav-employees-caret');
          const toggleBtn = document.getElementById('nav-employees-toggle');
          if (sub && !sub.classList.contains('hidden')) sub.classList.add('hidden');
          if (caret) caret.style.transform = 'rotate(0deg)';
          if (toggleBtn) toggleBtn.setAttribute('aria-expanded','false');
        } catch {}
        // hide the profile menu before navigating
        try { if (menu && !menu.classList.contains('hidden')) menu.classList.add('hidden'); } catch {}
        location.hash = '#settings';
      });
    }

    trigger.addEventListener('click', (e) => {
      e.preventDefault();
      menu.classList.toggle('hidden');
      if (!menu.classList.contains('hidden')) wireProfileTheme();
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
        try {
          await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'logout' }, withCredentials: true });
        } catch {}
        try {
          const p = location.pathname || '';
          const idx = p.indexOf('/master/');
          const base = idx >= 0 ? p.slice(0, idx) : '';
          location.href = `${base}/master/login.html`;
        } catch {
          location.href = '../login.html';
        }
      }
    });
  }
  // Re-open profile menu if requested by manage pages (keeps dropdown open after navigating to settings)
  try {
    if (sessionStorage.getItem('introKeepProfileOpen') === '1'){
      if (menu) menu.classList.remove('hidden');
      sessionStorage.removeItem('introKeepProfileOpen');
    }
  } catch {}
});

async function fillProfile(){
  try {
    const res = await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
    const user = res.data && res.data.user ? res.data.user : { username: 'Admin', role: 'admin' };
    const nameEl = document.getElementById('profile-name');
    const roleEl = document.getElementById('profile-role');
    const avatarEl = document.getElementById('profile-avatar');
    const displayName = (() => {
      const first = (user.first_name || '').trim();
      const last = (user.last_name || '').trim();
      if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
      const u = (user.username || '').trim();
      if (u.includes('@')) return u.split('@')[0];
      return u || 'Admin';
    })();
    if (nameEl) nameEl.textContent = displayName;
    if (roleEl) roleEl.textContent = user.role || 'admin';
    if (avatarEl) avatarEl.textContent = (displayName || 'A').substring(0,1).toUpperCase();
  } catch {}
}

async function syncHeaderAvatar(){
  try {
    const img = document.getElementById('profile-avatar-img');
    const fallback = document.getElementById('profile-avatar');
    if (!img || !fallback) return;
    const me = await getCurrentUser();
    if (!me || !me.employee_id) {
      img.classList.add('hidden');
      img.src = '';
      fallback.classList.remove('hidden');
      return;
    }
    let src = '';
    try {
      const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployee', employee_id: me.employee_id } });
      const emp = res.data || {};
      if (emp && emp.profile_image) src = emp.profile_image;
    } catch {}
    if (src) {
      img.src = src;
      img.classList.remove('hidden');
      fallback.classList.add('hidden');
    } else {
      img.src = '';
      img.classList.add('hidden');
      fallback.classList.remove('hidden');
    }
  } catch {}
}

async function getCurrentUser(){
  try {
    const res = await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
    return res.data && res.data.user ? res.data.user : null;
  } catch { return null; }
}

// Chart rendering functions
async function renderAttendanceChart() {
  try {
    // Today's only (updates daily)
    const todayStr = new Date().toLocaleDateString('en-CA');

    const [empRes, attRes, leaveRes] = await Promise.all([
      axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
      axios.get(`${window.baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: todayStr, end_date: todayStr } }),
      axios.get(`${window.baseApiUrl}/leaves.php`, { params: { operation: 'listApproved', start_date: todayStr, end_date: todayStr } })
    ]);

    const empList = Array.isArray(empRes.data) ? empRes.data : [];
    const active = empList.filter(e => String(e.status || '').toLowerCase() === 'active');
    const activeIds = new Set(active.map(e => String(e.employee_id)));

    const attRows = Array.isArray(attRes.data) ? attRes.data : [];
    const leaveRows = Array.isArray(leaveRes.data) ? leaveRes.data : [];

    // Category sets for today
    const presentSet = new Set();
    const lateSet = new Set();
    const leaveSet = new Set();
    const undertimeSet = new Set();

    const isToday = (s) => String(s || '').slice(0,10) === todayStr;

    attRows.forEach(r => {
      const eid = String(r.employee_id || '');
      if (!activeIds.has(eid)) return;
      const st = String(r.status || '').toLowerCase();
      const ds = (r.attendance_date || r.date || r.created_at || r.time_in || '').toString().slice(0,10);
      if (ds !== todayStr) return;
      if (st === 'present') presentSet.add(eid);
      else if (st === 'late') lateSet.add(eid);
      else if (st === 'leave') leaveSet.add(eid);
      else if (st === 'undertime') undertimeSet.add(eid);
    });

    // Add approved leaves that include today
    leaveRows.forEach(lr => {
      const s = String(lr.start_date || lr.date || lr.work_date || '').slice(0,10);
      const e = String(lr.end_date || lr.start_date || lr.date || lr.work_date || '').slice(0,10);
      if (!s || !e) return;
      if (s <= todayStr && todayStr <= e) {
        const eid = String(lr.employee_id || '');
        if (activeIds.has(eid)) leaveSet.add(eid);
      }
    });

    const union = new Set([...presentSet, ...lateSet, ...leaveSet, ...undertimeSet]);
    const totalActive = activeIds.size;
    const absentCount = Math.max(0, totalActive - union.size);

    const labels = ['Present', 'Late', 'Absent', 'On Leave', 'Undertime'];
    const data = [presentSet.size, lateSet.size, absentCount, leaveSet.size, undertimeSet.size];

    const ctx = document.getElementById('attendanceChart');
    if (!ctx) return;

    if (window.__adminAttendanceChart) { try { window.__adminAttendanceChart.destroy(); } catch {} }
    window.__adminAttendanceChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Count',
          data,
          backgroundColor: ['#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#0ea5e9'],
          borderColor: ['#059669', '#d97706', '#dc2626', '#7c3aed', '#0284c7'],
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
        plugins: { legend: { display: false } }
      }
    });
  } catch (error) {
    console.error('Error rendering attendance chart:', error);
  }
}

async function renderStatusLineChart() {
  try {
    // Build series from localStorage history (anchored at Aug 25 of current year)
    let hist = [];
    try { const raw = localStorage.getItem('admin_att_trend_hist'); hist = raw ? JSON.parse(raw) : []; if (!Array.isArray(hist)) hist = []; } catch { hist = []; }
    const year = new Date().getFullYear();
    const anchor = new Date(`${year}-08-25T00:00:00`);
    const today = new Date();
    const start = anchor > today ? today : anchor;
    const labels = [];
    const presentArr = [], lateArr = [], absentArr = [], leaveArr = [], utArr = [];
    for (let d = new Date(start); d <= today; d.setDate(d.getDate() + 1)) {
      const ds = d.toLocaleDateString('en-CA');
      const h = hist.find(x => String(x.date) === ds) || { present: 0, late: 0, absent: 0, onLeave: 0, undertime: 0 };
      labels.push(d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
      presentArr.push(Number(h.present || 0));
      lateArr.push(Number(h.late || 0));
      absentArr.push(Number(h.absent || 0));
      leaveArr.push(Number(h.onLeave || 0));
      utArr.push(Number(h.undertime || 0));
    }

    const ctx = document.getElementById('statusLineChart');
    if (!ctx) return;

    new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          { label: 'Present', data: presentArr, borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.15)', tension: 0.3, fill: false, borderWidth: 2, pointRadius: 2 },
          { label: 'Late', data: lateArr, borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.15)', tension: 0.3, fill: false, borderWidth: 2, pointRadius: 2 },
          { label: 'Absent', data: absentArr, borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.15)', tension: 0.3, fill: false, borderWidth: 2, pointRadius: 2 },
          { label: 'On Leave', data: leaveArr, borderColor: '#8b5cf6', backgroundColor: 'rgba(139,92,246,0.15)', tension: 0.3, fill: false, borderWidth: 2, pointRadius: 2 },
          { label: 'Undertime', data: utArr, borderColor: '#0ea5e9', backgroundColor: 'rgba(14,165,233,0.15)', tension: 0.3, fill: false, borderWidth: 2, pointRadius: 2 }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: { beginAtZero: true, ticks: { stepSize: 1 } }
        },
        plugins: { legend: { position: 'top' } }
      }
    });
  } catch (e) {
    console.error('Error rendering status line chart:', e);
  }
}

async function renderAttendanceChartDaily() {
  try {
    const ctx = document.getElementById('attendanceChart');
    if (!ctx) return;
    const todayStr = new Date().toLocaleDateString('en-CA');
    const [empRes, attRes, leaveRes] = await Promise.all([
      axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
      axios.get(`${window.baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: todayStr, end_date: todayStr } }),
      axios.get(`${window.baseApiUrl}/leaves.php`, { params: { operation: 'listApproved', start_date: todayStr, end_date: todayStr } })
    ]);

    const employees = Array.isArray(empRes.data) ? empRes.data : [];
    const active = employees.filter(e => {
      const st = String(e.status || '').trim().toLowerCase();
      return !st || st === 'active';
    });
    const activeIds = new Set(active.map(e => String(e.employee_id)));
    const attRows = Array.isArray(attRes.data) ? attRes.data : [];
    const leaveRows = Array.isArray(leaveRes.data) ? leaveRes.data : [];

    const present = new Set();
    const late = new Set();
    const undertime = new Set();
    const onleave = new Set();

    attRows.forEach(r => {
      const eid = String(r.employee_id || '');
      if (!activeIds.has(eid)) return;
      const st = String(r.status || '').toLowerCase();
      const hasTime = (r.time_in && r.time_in !== '' && r.time_in !== '00:00:00') || (r.time_out && r.time_out !== '' && r.time_out !== '00:00:00');
      if (st === 'late') { late.add(eid); return; }
      if (st === 'undertime') { undertime.add(eid); return; }
      if (['present','on time','ontime','present today','present_today'].includes(st) || hasTime) { present.add(eid); return; }
    });

    leaveRows.forEach(lr => {
      const s = String(lr.start_date || lr.date || lr.work_date || '').slice(0,10);
      const e = String(lr.end_date || lr.start_date || lr.date || lr.work_date || '').slice(0,10);
      if (!s || !e) return;
      if (s <= todayStr && todayStr <= e) {
        const eid = String(lr.employee_id || '');
        if (!activeIds.has(eid)) return;
        if (!present.has(eid) && !late.has(eid) && !undertime.has(eid)) onleave.add(eid);
      }
    });

    const union = new Set([...present, ...late, ...undertime, ...onleave]);
    const absentCount = Math.max(0, activeIds.size - union.size);

    const counts = {
      present: present.size,
      late: late.size,
      absent: absentCount,
      onleave: onleave.size,
      undertime: undertime.size
    };

    const colors = {
      present: '#22c55e',
      late: '#f59e0b',
      absent: '#ef4444',
      onleave: '#3b82f6',
      undertime: '#a855f7'
    };
    window.__adminAttendanceChartColors = [colors.present, colors.late, colors.absent, colors.onleave, colors.undertime];

    // Insert or update legend above the chart
    try {
      const wrap = ctx.parentElement; // the h-64 container
      if (wrap) {
        let legend = document.getElementById('attendance-legend');
        if (!legend) {
          legend = document.createElement('div');
          legend.id = 'attendance-legend';
          legend.className = 'mb-2 flex flex-wrap items-center gap-3 text-xs';
          wrap.insertBefore(legend, ctx);
        }
        const item = (key, label, color, value) => `<span class="inline-flex items-center gap-1" data-att-item="${key}"><span style="background:${color}" class="inline-block w-3 h-3 rounded-sm" aria-hidden="true"></span><span class="text-gray-700">${label} (${value})</span></span>`;
        legend.innerHTML = [
          item('present','Present', colors.present, counts.present),
          item('late','Late', colors.late, counts.late),
          item('absent','Absent', colors.absent, counts.absent),
          item('onleave','On Leave', colors.onleave, counts.onleave),
          item('undertime','Undertime', colors.undertime, counts.undertime)
        ].join(' ');
        // wire legend hover highlight and click (no permanent color change)
        const keysOrder = ['present','late','absent','onleave','undertime'];
        const hexToRgba = (hex, alpha = 1) => {
          try {
            const h = hex.replace('#','');
            const bigint = parseInt(h, 16);
            const r = (bigint >> 16) & 255;
            const g = (bigint >> 8) & 255;
            const b = bigint & 255;
            return `rgba(${r}, ${g}, ${b}, ${alpha})`;
          } catch { return hex; }
        };
        // hover on whole item (color or text) to highlight its bar
        legend.querySelectorAll('[data-att-item]').forEach(itemEl => {
          const key = itemEl.getAttribute('data-att-item');
          const idx = keysOrder.indexOf(key);
          itemEl.addEventListener('mouseenter', () => {
            const chart = window.__adminAttendanceChart;
            if (!chart) return;
            const orig = window.__adminAttendanceChartColors || [colors.present, colors.late, colors.absent, colors.onleave, colors.undertime];
            const faded = orig.map((c, i) => i === idx ? c : hexToRgba(c, 0.25));
            try { chart.data.datasets[0].backgroundColor = faded; chart.update('none'); } catch {}
          });
          itemEl.addEventListener('mouseleave', () => {
            const chart = window.__adminAttendanceChart;
            if (!chart) return;
            const orig = window.__adminAttendanceChartColors || [colors.present, colors.late, colors.absent, colors.onleave, colors.undertime];
            try { chart.data.datasets[0].backgroundColor = orig; chart.update('none'); } catch {}
          });
        });
        // text labels not clickable per request; removed click handlers
      }
    } catch {}

    if (window.__adminAttendanceChart) { try { window.__adminAttendanceChart.destroy(); } catch {} }

    window.__adminAttendanceChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['Present', 'Late', 'Absent', 'On Leave', 'Undertime'],
        datasets: [{
          label: 'Count',
          data: [counts.present, counts.late, counts.absent, counts.onleave, counts.undertime],
          backgroundColor: [colors.present, colors.late, colors.absent, colors.onleave, colors.undertime],
          borderWidth: 0,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: (ctx) => `${ctx.parsed.y || 0}` } }
        },
        scales: {
          y: { beginAtZero: true, ticks: { precision: 0 } },
          x: { grid: { display: false } }
        }
      }
    });
  } catch {}
}

async function showAttendanceCategoryList(category){
  try {
    const cat = String(category || '').toLowerCase();
    const todayStr = new Date().toLocaleDateString('en-CA');
    const [empRes, attRes, leaveRes] = await Promise.all([
      axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
      axios.get(`${window.baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: todayStr, end_date: todayStr } }),
      axios.get(`${window.baseApiUrl}/leaves.php`, { params: { operation: 'listApproved', start_date: todayStr, end_date: todayStr } })
    ]);
    const employees = Array.isArray(empRes.data) ? empRes.data : [];
    const active = employees.filter(e => {
      const st = String(e.status || '').trim().toLowerCase();
      return !st || st === 'active';
    });
    const activeMap = new Map(active.map(e => [String(e.employee_id), e]));
    const activeIds = new Set(active.map(e => String(e.employee_id)));
    const attRows = Array.isArray(attRes.data) ? attRes.data : [];
    const leaveRows = Array.isArray(leaveRes.data) ? leaveRes.data : [];

    // Build category sets
    const present = new Set();
    const late = new Set();
    const undertime = new Set();
    const onleave = new Set();
    const attByEmp = new Map();

    attRows.forEach(r => {
      const eid = String(r.employee_id || '');
      if (!activeIds.has(eid)) return;
      if (!attByEmp.has(eid)) attByEmp.set(eid, r);
      const st = String(r.status || '').toLowerCase();
      const hasTime = (r.time_in && r.time_in !== '' && r.time_in !== '00:00:00') || (r.time_out && r.time_out !== '' && r.time_out !== '00:00:00');
      if (st === 'late') { late.add(eid); return; }
      if (st === 'undertime') { undertime.add(eid); return; }
      if (['present','on time','ontime','present today','present_today'].includes(st) || hasTime) { present.add(eid); return; }
    });

    leaveRows.forEach(lr => {
      const s = String(lr.start_date || lr.date || lr.work_date || '').slice(0,10);
      const e = String(lr.end_date || lr.start_date || lr.date || lr.work_date || '').slice(0,10);
      if (!s || !e) return;
      if (s <= todayStr && todayStr <= e) {
        const eid = String(lr.employee_id || '');
        if (!activeIds.has(eid)) return;
        if (!present.has(eid) && !late.has(eid) && !undertime.has(eid)) onleave.add(eid);
      }
    });

    const union = new Set([...present, ...late, ...undertime, ...onleave]);
    const absentees = active.filter(e => !union.has(String(e.employee_id)));

    const toRow = (eid, statusOverride) => {
      const base = activeMap.get(String(eid)) || {};
      const att = attByEmp.get(String(eid)) || {};
      return {
        first_name: base.first_name || '',
        last_name: base.last_name || '',
        department: base.department || '',
        status: statusOverride || (att.status || ''),
        time_in: att.time_in || '',
        time_out: att.time_out || ''
      };
    };

    let list = [];
    let title = '';
    if (cat === 'present') { list = Array.from(present).map(eid => toRow(eid, 'present')); title = 'Present'; }
    else if (cat === 'late') { list = Array.from(late).map(eid => toRow(eid, 'late')); title = 'Late'; }
    else if (cat === 'undertime') { list = Array.from(undertime).map(eid => toRow(eid, 'undertime')); title = 'Undertime'; }
    else if (cat === 'onleave') { list = Array.from(onleave).map(eid => ({ ...toRow(eid, 'leave'), time_in: '', time_out: '' })); title = 'On Leave'; }
    else if (cat === 'absent') { list = absentees.map(e => ({ first_name: e.first_name||'', last_name: e.last_name||'', department: e.department||'', status: 'absent', time_in: '', time_out: '' })); title = 'Absent'; }
    else { return; }

    let modal = document.getElementById('attCatModal');
    if (!modal) { modal = document.createElement('div'); modal.id = 'attCatModal'; modal.className = 'fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
    let query = '';
    const renderTable = () => {
      const filtered = (!query ? list : list.filter(e => {
        const name = `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.trim();
        const dept = String(e.department || '').toLowerCase();
        const st = String(e.status || '').toLowerCase();
        return name.includes(query) || dept.includes(query) || st.includes(query);
      }));
      const wrap = document.getElementById('attcat-table-wrap');
      if (!wrap) return;
      if (!filtered.length) { wrap.innerHTML = '<div class="text-sm text-gray-500">No matches</div>'; return; }
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
            <h5 class="font-semibold">${title} Today (${list.length})</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
          </div>
          <div class="p-4">
            <div class="mb-3 flex items-center gap-2">
              <div class="relative">
                <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
                <input id="attcat-search" class="w-64 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, department, status" />
              </div>
              <button id="attcat-clear" class="text-xs text-gray-600 border rounded px-2 py-1">Clear</button>
              <a href="#attendance" class="ml-auto text-primary-700 text-sm hover:underline">Open Attendance</a>
            </div>
            <div id="attcat-table-wrap" class="overflow-auto max-h-[48vh]"></div>
          </div>
          <div class="flex justify-end items-center gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
          </div>
        </div>
      </div>`;
    modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
    const si = document.getElementById('attcat-search');
    const sc = document.getElementById('attcat-clear');
    if (si) si.addEventListener('input', () => { query = (si.value || '').trim().toLowerCase(); renderTable(); });
    if (sc) sc.addEventListener('click', () => { if (si) si.value=''; query=''; renderTable(); });
    renderTable();
    modal.classList.remove('hidden');
  } catch {
    try { alert('Failed to load list'); } catch {}
  }
}

async function renderPayrollTrendChart() {
  try {
    const res = await axios.get(`${window.baseApiUrl}/reports.php`, {
      params: { operation: 'payrollTrend', months: 6 }
    });
    const data = res.data || { labels: [], expenses: [] };

    const ctx = document.getElementById('payrollTrendChart');
    if (!ctx) return;

    new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.labels || ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
        datasets: [{
          label: 'Total Payroll Expenses',
          data: data.expenses || [45000, 48000, 52000, 49000, 55000, 58000],
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
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              callback: function(value) {
                return '$' + value.toLocaleString();
              }
            }
          }
        },
        plugins: {
          legend: {
            position: 'top'
          }
        }
      }
    });
  } catch (error) {
    console.error('Error rendering payroll trend chart:', error);
  }
}

async function renderOvertimeChart() {
  try {
    const res = await axios.get(`${window.baseApiUrl}/reports.php`, {
      params: { operation: 'overtimeDistribution' }
    });
    const data = res.data || { labels: [], hours: [] };

    const ctx = document.getElementById('overtimeChart');
    if (!ctx) return;

    new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: data.labels || ['IT', 'HR', 'Finance', 'Operations', 'Sales'],
        datasets: [{
          data: data.hours || [45, 32, 28, 38, 25],
          backgroundColor: [
            '#3b82f6',
            '#10b981',
            '#f59e0b',
            '#ef4444',
            '#8b5cf6'
          ],
          borderWidth: 2,
          borderColor: '#ffffff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom'
          }
        }
      }
    });
  } catch (error) {
    console.error('Error rendering overtime chart:', error);
  }
}

async function renderLeaveTypeChart() {
  try {
    const res = await axios.get(`${window.baseApiUrl}/reports.php`, {
      params: { operation: 'leaveTypeDistribution' }
    });
    const data = res.data || { labels: [], counts: [] };

    const ctx = document.getElementById('leaveTypeChart');
    if (!ctx) return;

    new Chart(ctx, {
      type: 'pie',
      data: {
        labels: data.labels || ['Vacation', 'Sick Leave', 'Emergency', 'Personal', 'Other'],
        datasets: [{
          data: data.counts || [15, 8, 3, 5, 2],
          backgroundColor: [
            '#10b981',
            '#ef4444',
            '#f59e0b',
            '#3b82f6',
            '#8b5cf6'
          ],
          borderWidth: 2,
          borderColor: '#ffffff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom'
          }
        }
      }
    });
  } catch (error) {
    console.error('Error rendering leave type chart:', error);
  }
}

async function renderDeductionsChart() {
  try {
    const res = await axios.get(`${window.baseApiUrl}/reports.php`, {
      params: { operation: 'deductionsBreakdown' }
    });
    const data = res.data || { labels: [], amounts: [] };

    const ctx = document.getElementById('deductionsChart');
    if (!ctx) return;

    new Chart(ctx, {
      type: 'bar',
      data: {
        labels: data.labels || ['SSS', 'PhilHealth', 'Pag-IBIG', 'Withholding Tax', 'Other'],
        datasets: [{
          label: 'Deduction Amount',
          data: data.amounts || [2500, 1200, 800, 3500, 500],
          backgroundColor: [
            '#3b82f6',
            '#10b981',
            '#f59e0b',
            '#ef4444',
            '#8b5cf6'
          ],
          borderColor: [
            '#2563eb',
            '#059669',
            '#d97706',
            '#dc2626',
            '#7c3aed'
          ],
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              callback: function(value) {
                return '$' + value.toLocaleString();
              }
            }
          }
        },
        plugins: {
          legend: {
            display: false
          }
        }
      }
    });
  } catch (error) {
    console.error('Error rendering deductions chart:', error);
  }
}

async function renderEmployeeCountChart() {
  try {
    const res = await axios.get(`${window.baseApiUrl}/reports.php`, {
      params: { operation: 'employeeCountTrend', months: 12 }
    });
    const data = res.data || { labels: [], counts: [] };

    const ctx = document.getElementById('employeeCountChart');
    if (!ctx) return;

    new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.labels || ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
        datasets: [{
          label: 'Total Employees',
          data: data.counts || [25, 26, 28, 30, 32, 35, 38, 40, 42, 45, 48, 50],
          borderColor: '#10b981',
          backgroundColor: 'rgba(16, 185, 129, 0.1)',
          borderWidth: 3,
          fill: true,
          tension: 0.4,
          pointBackgroundColor: '#10b981',
          pointBorderColor: '#ffffff',
          pointBorderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              stepSize: 5
            }
          }
        },
        plugins: {
          legend: {
            position: 'top'
          }
        }
      }
    });
  } catch (error) {
    console.error('Error rendering employee count chart:', error);
  }
}


function formatTime(iso){
  try { const d = new Date(iso); return d.toLocaleString(); } catch { return ''; }
}

function escapeHtml(text){
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
function toTitleCase(s){
  return String(s || '')
    .toLowerCase()
    .split(/([ -])/)
    .map(part => (/^[ -]$/.test(part) ? part : part.charAt(0).toUpperCase() + part.slice(1)))
    .join('');
}

async function markNotificationAsRead(notificationId){
  try {
    const fd = new FormData();
    fd.append('operation', 'markAsRead');
    fd.append('json', JSON.stringify({ notification_id: notificationId }));
    await axios.post(`${baseApiUrl}/notifications.php`, fd, { withCredentials: true });
    return true;
  } catch {
    return false;
  }
}

async function deleteNotification(notificationId){
  try {
    const fd = new FormData();
    fd.append('operation', 'deleteNotification');
    fd.append('json', JSON.stringify({ notification_id: notificationId }));
    await axios.post(`${baseApiUrl}/notifications.php`, fd, { withCredentials: true });
    return true;
  } catch {
    return false;
  }
}
