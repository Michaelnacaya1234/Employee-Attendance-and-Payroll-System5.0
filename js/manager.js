/**
 * GLOBAL API BASE URL CONFIGURATION
 * Sets up the base URL for all API calls in manager portal
 */
const baseApiUrl = `${location.origin}/intro/api`;

/**
 * STYLE HEADER NOTIFICATION BUTTON FOR MANAGER PORTAL
 * Applies amber color scheme to notification button and badge
 * Matches styling with other portal interfaces
 */
function styleHeaderNotif(){
  try {
    const btn = document.getElementById('notif-toggle');
    const badge = document.getElementById('notif-badge');
    if (btn) {
      btn.classList.add('bg-amber-50','ring-amber-200','hover:bg-amber-100');
      btn.classList.remove('ring-gray-200','hover:bg-gray-50');
      const icon = btn.querySelector('i.fa-bell');
      if (icon) { icon.classList.add('text-amber-600'); icon.classList.remove('text-gray-600'); }
    }
    if (badge) { badge.classList.add('bg-amber-600'); badge.classList.remove('bg-red-600'); }
  } catch {}
}
if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', styleHeaderNotif); }
else { try { styleHeaderNotif(); } catch {} }

/**
 * CONVERT STRING TO TITLE CASE
 * Capitalizes first letter of each word while preserving separators
 * Handles spaces and hyphens correctly
 */
function toTitleCase(s){
  return String(s || '')
    .toLowerCase()
    .split(/([ -])/)
    .map(part => (/^[ -]$/.test(part) ? part : part.charAt(0).toUpperCase() + part.slice(1)))
    .join('');
}

/**
 * ENSURE SWEETALERT2 IS LOADED
 * Dynamically loads SweetAlert2 if not already available
 * Used for modal dialogs and notifications
 */
async function ensureSwal(){
  if (window.Swal) return;
  await new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/npm/sweetalert2@11';
    s.onload = resolve;
    s.onerror = reject;
    document.head.appendChild(s);
  });
}

/**
 * SHOW TOAST NOTIFICATION
 * Displays temporary notification using SweetAlert2
 * Fallback to console/alert if SweetAlert2 unavailable
 */
function showToast(message = 'Done', type = 'info'){
  try {
    if (!window.Swal){ console.log(message); return; }
    const icon = ['success','error','warning','info','question'].includes(String(type)) ? String(type) : 'info';
    const Toast = Swal.mixin({ toast: true, position: 'top-end', showConfirmButton: false, timer: 1500, timerProgressBar: true });
    Toast.fire({ icon, title: message });
  } catch(e){ try { alert(message); } catch {} }
}

/**
 * ENSURE ANIME.JS IS LOADED FOR MANAGER DASHBOARD
 * Dynamically loads animation library for dashboard animations
 * Returns null if loading fails
 */
async function ensureAnimeMgr(){
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
 * ENSURE SWEETALERT2 ASSETS ARE LOADED
 * Loads both CSS and JavaScript for SweetAlert2
 * Required for notification modal functionality
 */
async function ensureSweetAlertAssets(){
  try {
    if (!document.getElementById('swal2-css')){
      const link = document.createElement('link');
      link.id = 'swal2-css';
      link.rel = 'stylesheet';
      link.href = 'https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css';
      document.head.appendChild(link);
    }
    if (!window.Swal){
      await new Promise((resolve) => {
        const s = document.createElement('script');
        s.id = 'swal2-js';
        s.src = 'https://cdn.jsdelivr.net/npm/sweetalert2@11';
        s.onload = resolve; s.onerror = resolve;
        document.head.appendChild(s);
      });
    }
  } catch {}
}

/**
 * FORMAT NOTIFICATION DATE FOR DISPLAY
 * Converts various date formats to readable format
 * Handles timezone and parsing edge cases
 */
function formatNotifDate(val){
  try {
    if (!val) return '';
    const s = String(val);
    let d = new Date(s);
    if (isNaN(d.getTime())) {
      d = new Date(s.includes('T') ? s : `${s}T00:00:00`);
    }
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
 * ATTACH SWEETALERT2 TO HEADER NOTIFICATION BUTTON
 * Replaces default dropdown with SweetAlert2 modal
 * Prevents duplicate event listeners
 */
function attachSweetHeaderNotif(){
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
      await openNotifSweetModal();
    }, true);
  } catch {}
}

/**
 * OPEN NOTIFICATION MODAL WITH SWEETALERT2
 * Displays notifications with delete and mark as read functionality
 * Supports bulk operations for all notifications
 */
async function openNotifSweetModal(){
  try {
    try { await ensureSweetAlertAssets(); } catch {}
    const resp = await axios.get(`${baseApiUrl}/notifications.php`, { params: { operation: 'getNotifications' }, withCredentials: true });
    const items = (resp && resp.data && (resp.data.notifications || resp.data)) || [];
    const notifications = Array.isArray(items) ? items : [];
    const escapeHtml = (s) => String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));
    const content = notifications.length ? notifications.map(n => {
      const id = n.id || n.notification_id || n.notificationID || '';
      const msg = escapeHtml(n.message || n.text || n.title || 'Notification');
      const whenRaw = n.created_at || n.createdAt || n.created || '';
      const when = escapeHtml(formatNotifDate(whenRaw));
      const unread = !n.read_at && !n.readAt && !n.read;
      return `
        <div class="sw-notif-item ${unread ? 'bg-blue-50' : ''} rounded-lg border border-gray-200 p-3 mb-2" data-id="${id}">
          <div class="flex items-start justify-between gap-3">
            <div class="text-sm text-gray-800">${msg}</div>
            <button class="sw-del text-gray-400 hover:text-red-600" title="Delete" data-id="${id}">×</button>
          </div>
          <div class="mt-1 text-xs text-gray-500">${when}</div>
        </div>`;
    }).join('') : '<div class="text-sm text-gray-500">No notifications</div>';

    const hasUnread = notifications.some(n => !n.read_at && !n.readAt && !n.read);
    const result = await Swal.fire({
      title: 'Notifications',
      html: `<div class="text-left max-h-80 overflow-y-auto">${content}</div>`,
      width: 520,
      showCloseButton: true,
      showCancelButton: true,
      showConfirmButton: hasUnread,
      confirmButtonText: 'Mark all read',
      cancelButtonText: 'Close',
      didOpen: () => {
        const html = Swal.getHtmlContainer();
        if (!html) return;
        html.querySelectorAll('.sw-del').forEach(btn => {
          btn.addEventListener('click', async (ev) => {
            ev.preventDefault();
            ev.stopPropagation();
            const id = btn.getAttribute('data-id');
            if (!id) return;
            try {
              const fd = new FormData();
              fd.append('operation', 'deleteNotification');
              fd.append('json', JSON.stringify({ notification_id: id }));
              await axios.post(`${baseApiUrl}/notifications.php`, fd, { withCredentials: true });
              const item = btn.closest('.sw-notif-item');
              if (item) item.remove();
              await renderNotifications();
              showToast('Notification deleted', 'success');
            } catch {
              showToast('Failed to delete notification', 'error');
            }
          });
        });
      }
    });
    if (result && result.isConfirmed) {
      try {
        await markAllManagerNotifsAsRead();
        await renderNotifications();
        showToast('All notifications marked as read', 'success');
      } catch {
        showToast('Failed to mark all as read', 'error');
      }
    }
  } catch {}
}

const routes = {
  dashboard: async () => {
    const app = document.getElementById('app');
    app.innerHTML = `
      <section class="mb-6">
        <div class="sticky top-0 z-10 relative overflow-hidden rounded-xl bg-gradient-to-r from-primary-700 to-primary-600 text-white shadow">
          <div class="absolute -right-16 -top-16 w-64 h-64 rounded-full bg-white/10"></div>
          <div class="p-6 flex items-center justify-between relative">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 rounded-full bg-white/20 flex items-center justify-center relative overflow-hidden">
                <img id="welcome-avatar-img" alt="Profile" class="w-full h-full object-cover hidden"/>
                <svg id="welcome-avatar-ph" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-6 h-6 text-white">
                  <path d="M12 12c2.21 0 4-1.79 4-4S14.21 4 12 4 8 5.79 8 8s1.79 4 4 4zm0 2c-3.33 0-8 1.67-8 5v1h16v-1c0-3.33-4.67-5-8-5z"/>
                </svg>
              </div>
              <div>
                <h1 class="text-2xl font-semibold">Welcome, <span id="welcome-name">Manager</span></h1>
                <div class="mt-1 text-white/90 text-sm flex items-center gap-2">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-4 h-4"><path d="M12 8a1 1 0 011 1v3h3a1 1 0 110 2h-4a1 1 0 01-1-1V9a1 1 0 011-1z"/><path fill-rule="evenodd" d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zm0-18a8 8 0 100 16 8 8 0 000-16z" clip-rule="evenodd"/></svg>
                  <span id="welcome-date"></span>
                </div>
                <div class="mt-1 text-white/90 text-sm">Department: <span id="welcome-dept">Not set</span></div>
              </div>
            </div>
          </div>
        </div>
      </section>
      <section class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-4" id="mgr-cards"></section>

      <section class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div class="bg-white rounded-lg shadow p-4">
          <div class="flex items-center justify-between mb-3">
            <h3 class="font-semibold">Attendance Trend (Dept)</h3>
          </div>
          <div class="h-64"><canvas id="mgrAttendanceTrend"></canvas></div>
        </div>
        <div class="bg-white rounded-lg shadow p-4">
          <div class="flex items-center justify-between mb-3">
            <h3 class="font-semibold">Leave Breakdown (Dept)</h3>
          </div>
          <div class="h-64"><canvas id="mgrLeaveBreakdown"></canvas></div>
        </div>
      </section>

      
      <!-- Holidays Calendar (Read-only) -->
      <section class="grid grid-cols-1 gap-4 mb-6">
        <div class="bg-white rounded-lg shadow p-4" id="mgr-holidays-card">
          <div class="flex items-center justify-between mb-3">
            <h3 class="font-semibold">Calendar</h3>
            <div class="flex items-center gap-2">
              <button id="mgr-cal-prev" class="px-2 py-1 text-xs border rounded">Prev</button>
              <div id="mgr-cal-title" class="text-sm font-medium min-w-[8rem] text-center"></div>
              <button id="mgr-cal-next" class="px-2 py-1 text-xs border rounded">Next</button>
            </div>
          </div>
          <div id="mgr-calendar" class="grid grid-cols-7 gap-px bg-gray-200 rounded overflow-hidden text-xs"></div>
          <div class="text-[10px] text-gray-500 mt-2">Legend: <span class="inline-block w-3 h-3 bg-rose-500 align-middle mr-1"></span> Holiday • <span class="inline-block w-3 h-3 bg-primary-500 align-middle mr-1"></span> Today • <span class="inline-block w-3 h-3 bg-rose-200 align-middle mr-1"></span> Sun • <span class="inline-block w-3 h-3 bg-blue-200 align-middle mr-1"></span> Sat</div>
        </div>
      </section>

      `;

    const me = await currentUser();
    if (!me || me.role !== 'manager') {
      location.href = './login.html';
      return;
    }
    fillProfile(me);
    wireHeader();

    // Update welcome section with user info and profile image
    await updateWelcomeSection(me);

    const dept = (me.department || '').trim();
    await renderCards(dept, me);

    // Anime.js card animations (match admin dashboard)
    try {
      const anime = await ensureAnimeMgr();
      if (anime) {
        const cardsWrap = document.getElementById('mgr-cards');
        const cards = cardsWrap ? Array.from(cardsWrap.children) : [];
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
            card.addEventListener('mouseenter', () => { anime.remove(card); anime({ targets: card, scale: 1.02, duration: 140, easing: 'easeOutQuad' }); });
            card.addEventListener('mouseleave', () => { anime.remove(card); anime({ targets: card, scale: 1.0, duration: 160, easing: 'easeOutQuad' }); });
          });
        }
      }
    } catch {}

    await renderAttendanceTrend(dept);
    await renderLeaveBreakdown(dept);
    await renderHolidayCalendarMgr();

    function monthNameMgr(m){ return new Date(2000, m-1, 1).toLocaleString('en-US', { month: 'long' }); }
    async function renderHolidayCalendarMgr(){
      const container = document.getElementById('mgr-calendar');
      const title = document.getElementById('mgr-cal-title');
      if (!container || !title) return;
      if (!window.__mgrCalState){ const now = new Date(); window.__mgrCalState = { year: now.getFullYear(), month: now.getMonth()+1 }; }
      const { year, month } = window.__mgrCalState;
      title.textContent = `${monthNameMgr(month)} ${year}`;
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
      let holidays = [];
      try {
        const res = await axios.get(`${baseApiUrl}/holidays.php`, { params: { operation: 'list', month, year } });
        holidays = Array.isArray(res.data) ? res.data : [];
      } catch {}
      const holiMap = new Map((holidays||[]).map(h => [String(h.holiday_date), h]));
      for (let i=0;i<startIdx;i++){
        const dayIdx = i % 7; // 0=Sun ... 6=Sat
        const isSun = dayIdx === 0;
        const isSat = dayIdx === 6;
        const cell = document.createElement('div');
        cell.className = `p-2 h-20 ${isSun ? 'bg-rose-50' : isSat ? 'bg-blue-50' : 'bg-white'}`;
        container.appendChild(cell);
      }
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
          ${hol ? `<div class=\"mt-1 text-[11px] px-1 py-0.5 rounded bg-rose-500 text-white inline-block\" title=\"${(hol.holiday_name||'').replace(/\"/g,'&quot;')}${hol.description ? ' — ' + String(hol.description).replace(/\"/g,'&quot;') : ''}\">${(hol.holiday_name||'').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>` : ''}
          ${todayBadge}`;
        if (hol) { cell.addEventListener('click', () => openHolidayViewMgr(hol)); }
        container.appendChild(cell);
      }
      // Minimal calendar cell animation (match admin)
      try {
        const anime = await ensureAnimeMgr();
        if (anime) {
          const dayCells = Array.from(container.querySelectorAll('[data-date]'));
          if (dayCells.length) {
            dayCells.forEach(c => { c.style.transformOrigin = '50% 50%'; });
            anime({ targets: dayCells, translateY: [4, 0], scale: [0.99, 1], easing: 'easeOutQuad', duration: 280, delay: anime.stagger(8) });
            dayCells.forEach(cell => {
              cell.addEventListener('mouseenter', () => { anime.remove(cell); anime({ targets: cell, scale: 1.02, duration: 120, easing: 'easeOutQuad' }); });
              cell.addEventListener('mouseleave', () => { anime.remove(cell); anime({ targets: cell, scale: 1.0, duration: 140, easing: 'easeOutQuad' }); });
            });
          }
          if (title) { anime.remove(title); anime({ targets: title, translateX: [-6, 0], scale: [0.98, 1], duration: 220, easing: 'easeOutQuad' }); }
        }
      } catch {}

      const prev = document.getElementById('mgr-cal-prev');
      const next = document.getElementById('mgr-cal-next');
      if (prev && !prev.__wired){ prev.__wired = true; prev.addEventListener('click', async () => { let {year, month} = window.__mgrCalState; month--; if (month===0){ month=12; year--; } window.__mgrCalState = { year, month }; await renderHolidayCalendarMgr(); }); }
      if (next && !next.__wired){ next.__wired = true; next.addEventListener('click', async () => { let {year, month} = window.__mgrCalState; month++; if (month===13){ month=1; year++; } window.__mgrCalState = { year, month }; await renderHolidayCalendarMgr(); }); }
    }
    function openHolidayViewMgr(row){
      try {
        let modal = document.getElementById('mgrHolidayViewModal');
        if (!modal){ modal = document.createElement('div'); modal.id='mgrHolidayViewModal'; modal.className='fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
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

    
    // Welcome name/date
    try {
      const welcomeNameEl = document.getElementById('welcome-name');
      if (welcomeNameEl) {
        const displayName = (() => {
          const first = (me.first_name || '').trim();
          const last = (me.last_name || '').trim();
          if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
          const u = (me.username || '').trim();
          if (u.includes('@')) return u.split('@')[0];
          return u || 'Manager';
        })();
        welcomeNameEl.textContent = displayName;
      }
    } catch {}
    const deptEl = document.getElementById('welcome-dept');
    if (deptEl) { deptEl.textContent = me && me.department ? me.department : 'Not set'; }
    const dateEl = document.getElementById('welcome-date');
    if (dateEl) {
      if (window.__mgrWelcomeInterval) { try { clearInterval(window.__mgrWelcomeInterval); } catch {} }
      const tick = () => { dateEl.textContent = new Date().toLocaleString('en-US'); };
      tick();
      window.__mgrWelcomeInterval = setInterval(tick, 1000);
    }
  },
  attendance: async () => {
    await renderDeptAttendanceTableV2();
  },
  employee: async () => {
    const module = await import('./modules/employees.js');
    await module.render();
  },
  leaves: async () => {
    const module = await import('./modules/manager-leaves.js');
    await module.render();
  },
  reports: async () => {
    await renderDeptReports();
  },
  requestapproval: async () => {
    const app = document.getElementById('app');
    app.innerHTML = `
      <div class="flex items-center justify-between mb-3">
        <h4 class="text-xl font-semibold">Overtime Management</h4>
        <div class="flex items-center gap-2">
          <button id="mgr-btn-file-ot" class="inline-flex items-center px-3 py-2 text-sm font-medium rounded bg-primary-600 text-white hover:bg-primary-700">Request Overtime</button>
        </div>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <div class="mb-3 flex items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <div class="relative">
              <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
              <input id="mgr-req-search-input" class="w-56 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, type, date, reason" />
            </div>
            <select id="mgr-req-status-filter" class="border rounded px-2 py-1 text-sm">
              <option value="approve">Approve</option>
              <option value="peding" selected>Peding</option>
              <option value="reject">Reject</option>
            </select>
          </div>
          <div class="flex items-center gap-2 text-sm text-gray-600">
            <span>Rows per page</span>
            <select id="mgr-req-page-size" class="border rounded px-2 py-1">
              <option value="5">5</option>
              <option value="10" selected>10</option>
              <option value="20">20</option>
              <option value="50">50</option>
            </select>
          </div>
        </div>
        <div id="mgr-req-approval-table"></div>
        <div id="mgr-req-pagination" class="mt-3 flex items-center justify-between text-sm text-gray-600"></div>
      </div>

      <div id="mgrOtModal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-lg">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold">Request Overtime</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
            <div class="p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Employee</label>
                <input id="mgr-ot-emp-search" class="w-full border rounded px-3 py-2 mb-2" placeholder="Search employee..." />
                <select id="mgr-ot-emp" class="w-full border rounded px-3 py-2"></select>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Date</label>
                <input id="mgr-ot-date" type="date" class="w-full border rounded px-3 py-2" />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Time In</label>
                <input id="mgr-ot-in" type="time" class="w-full border rounded px-3 py-2" />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Time Out</label>
                <input id="mgr-ot-out" type="time" class="w-full border rounded px-3 py-2" />
              </div>
                            <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Reason</label>
                <textarea id="mgr-ot-reason" rows="3" class="w-full border rounded px-3 py-2"></textarea>
              </div>
            </div>
            <div class="flex justify-end gap-2 border-t px-4 py-3">
              <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
              <button id="mgr-ot-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Submit</button>
            </div>
          </div>
        </div>
      </div>

      <div id="mgrUtModal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-lg">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold">Request Undertime</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
            <div class="p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Employee</label>
                <input id="mgr-ut-emp-search" class="w-full border rounded px-3 py-2 mb-2" placeholder="Search employee..." />
                <select id="mgr-ut-emp" class="w-full border rounded px-3 py-2"></select>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Date</label>
                <input id="mgr-ut-date" type="date" class="w-full border rounded px-3 py-2" />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Hours</label>
                <input id="mgr-ut-hours" type="number" step="0.25" min="0.25" class="w-full border rounded px-3 py-2" placeholder="e.g., 1" />
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Reason</label>
                <textarea id="mgr-ut-reason" rows="3" class="w-full border rounded px-3 py-2"></textarea>
              </div>
            </div>
            <div class="flex justify-end gap-2 border-t px-4 py-3">
              <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
              <button id="mgr-ut-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Submit</button>
            </div>
          </div>
        </div>
      </div>`;

    const wrap = document.getElementById('mgr-req-approval-table');
    wrap.innerHTML = '<div class="text-gray-500">Loading...</div>';

    // Load employees for OT/UT
    let _mgrEmployees = [];
    async function loadEmployeesList(){
      try {
        const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
        const list = Array.isArray(res.data) ? res.data : [];
        const me = await currentUser();
        const meId = me && me.employee_id ? String(me.employee_id) : '';
        const deptLc = (me && me.department ? String(me.department) : '').toLowerCase().trim();
        // Restrict to current manager's department employees only and exclude the current manager
        _mgrEmployees = list.filter(e => {
          const d = String(e.department || '').toLowerCase().trim();
          const sameDept = deptLc && d === deptLc;
          const notMe = meId ? String(e.employee_id) !== meId : true;
          return sameDept && notMe;
        });
      } catch { _mgrEmployees = []; }
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
        const filtered = !q ? _mgrEmployees.slice() : _mgrEmployees.filter(e => `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.includes(q) || String(e.email||'').toLowerCase().includes(q));
        renderEmpOptions(selectId, filtered, selected);
      };
    }

    // Modal controls
    const otModal = document.getElementById('mgrOtModal');
    let editContext = null;
    function setOtModalMode(isEdit){
      const title = otModal?.querySelector('h5');
      const save = document.getElementById('mgr-ot-save');
      if (title) title.textContent = isEdit ? 'Edit Overtime' : 'Request Overtime';
      if (save) save.textContent = isEdit ? 'Update' : 'Submit';
    }
        function resetOtForm(){
      const f = {
        emp: document.getElementById('mgr-ot-emp'),
        date: document.getElementById('mgr-ot-date'),
        reason: document.getElementById('mgr-ot-reason'),
        search: document.getElementById('mgr-ot-emp-search')
      };
      if (f.date) f.date.value = '';
      if (f.reason) f.reason.value = '';
      if (f.search) f.search.value = '';
    }
        const openOt = async () => {
      await loadEmployeesList();
      renderEmpOptions('mgr-ot-emp', _mgrEmployees);
      wireSearchEmp('mgr-ot-emp-search', 'mgr-ot-emp');
      setOtModalMode(!!(editContext && editContext.type==='ot'));
      if (otModal) otModal.classList.remove('hidden');
    };
    const closeOt = () => { if (otModal) otModal.classList.add('hidden'); editContext = null; setOtModalMode(false); };

    const otBtn = document.getElementById('mgr-btn-file-ot');
    if (otBtn) otBtn.addEventListener('click', async () => { editContext = null; resetOtForm(); setOtModalMode(false); await openOt(); });
    if (otModal) otModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeOt));

    const otSave = document.getElementById('mgr-ot-save');
    if (otSave) otSave.addEventListener('click', async () => {
      const employee_id = document.getElementById('mgr-ot-emp')?.value;
      const work_date = document.getElementById('mgr-ot-date')?.value;
      const reason = document.getElementById('mgr-ot-reason')?.value || '';
      const tIn = document.getElementById('mgr-ot-in')?.value || '';
      const tOut = document.getElementById('mgr-ot-out')?.value || '';
      const toMinutes = (t) => { const parts = String(t).split(':').map(n => parseInt(n,10)); if (parts.length < 2 || Number.isNaN(parts[0]) || Number.isNaN(parts[1])) return NaN; return parts[0]*60 + parts[1]; };
      const a = toMinutes(tIn);
      const b = toMinutes(tOut);
      if (!employee_id || !work_date || !Number.isFinite(a) || !Number.isFinite(b)) { showToast('Select employee, date and valid time in/out', 'warning'); return; }
      let diff = b - a; if (diff <= 0) diff += 24*60;
      const hoursVal = Math.round((diff / 60) * 100) / 100;
      const fd = new FormData();
      if (editContext && editContext.type === 'ot' && editContext.id) {
        fd.append('operation', 'updateOvertime');
        fd.append('json', JSON.stringify({ ot_id: editContext.id, employee_id, work_date, reason }));
        try { await axios.post(`${baseApiUrl}/overtime.php`, fd); closeOt(); showToast('Overtime request updated', 'success'); await routes.requestapproval(); } catch { showToast('Failed to update overtime', 'error'); }
      } else {
        fd.append('operation', 'requestOvertime');
        fd.append('json', JSON.stringify({ employee_id, work_date, hours: hoursVal, reason }));
        try { await axios.post(`${baseApiUrl}/overtime.php`, fd); closeOt(); showToast('Overtime request submitted', 'success'); await routes.requestapproval(); } catch { showToast('Failed to submit overtime', 'error'); }
      }
    });


    // Search & pagination state
    let allItems = [];
    let query = '';
    let page = 1;
    let pageSize = 10;
    let statusFilter = 'pending';

    const searchInput = document.getElementById('mgr-req-search-input');
    const pageSizeSelect = document.getElementById('mgr-req-page-size');
    const pager = document.getElementById('mgr-req-pagination');

    const getFiltered = () => {
      const q = (query || '').toLowerCase();
      const s = (statusFilter || 'all').toLowerCase();
      let base = allItems.slice();
      if (s !== 'all') {
        base = base.filter(it => {
          const st = String(it.status || '').toLowerCase();
          if (s === 'approved') return st === 'approved' || st === 'approve';
          if (s === 'rejected') return st === 'rejected' || st === 'reject';
          return st === 'pending';
        });
      }
      if (!q) return base;
      return base.filter(it => {
        const name = `${it.first_name || ''} ${it.last_name || ''}`.toLowerCase();
        const type = (it.kind || '').toLowerCase();
        const date = (it.work_date || '').toLowerCase();
        const reason = (it.reason || '').toLowerCase();
        const status = (it.status || '').toLowerCase();
        return name.includes(q) || type.includes(q) || date.includes(q) || reason.includes(q) || status.includes(q);
      });
    };

    const statusBadge = (st) => {
      const s = String(st || '').toLowerCase();
      let cls = 'inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full ring-1';
      let label = 'Pending';
      if (s === 'approved' || s === 'approve') {
        cls += ' bg-green-50 text-green-700 ring-green-200';
        label = 'Approved';
      } else if (s === 'rejected' || s === 'reject') {
        cls += ' bg-red-50 text-red-700 ring-red-200';
        label = 'Rejected';
      } else {
        cls += ' bg-yellow-50 text-yellow-700 ring-yellow-200';
        label = 'Pending';
      }
      return `<span class="${cls}">${label}</span>`;
    };

    const calcDurationStr = (start, end) => {
      try {
        const toMinutes = (t) => {
          const parts = String(t).split(':').map(n => parseInt(n,10));
          const h = parts[0] || 0, m = parts[1] || 0, s = parts[2] || 0;
          return h*60 + m + Math.round(s/60);
        };
        let a = toMinutes(start), b = toMinutes(end);
        if (!Number.isFinite(a) || !Number.isFinite(b)) return '';
        if (b < a) b += 24*60;
        const diff = b - a;
        if (!Number.isFinite(diff) || diff < 0) return '';
        const h = Math.floor(diff / 60);
        const m = diff % 60;
        return `${h}h ${m}m`;
      } catch { return ''; }
    };

    const formatHoursMinutesFromHours = (hrs) => {
      const n = Number(hrs);
      if (!Number.isFinite(n) || n < 0) return '';
      const totalMinutes = Math.round(n * 60);
      const h = Math.floor(totalMinutes / 60);
      const m = totalMinutes % 60;
      return `${h}h ${m}m`;
    };

    const formatWorkDate = (s) => {
      if (!s) return '';
      try {
        const d = new Date(String(s).includes('T') ? s : `${s}T00:00:00`);
        if (isNaN(d.getTime())) return s;
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
      } catch { return s; }
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
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Work Date</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Type</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Overtime Hours</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Reason</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
          <th class="px-3 py-2 text-right text-xs font-semibold text-gray-600">Actions</th>
        </tr></thead>
        <tbody class="divide-y divide-gray-200 bg-white"></tbody>`;
      const tbody = table.querySelector('tbody');
      if (!pageRows.length) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="8" class="px-3 py-6 text-sm text-center text-gray-500">No requests found</td>`;
        tbody.appendChild(tr);
      } else {
        pageRows.forEach((it, idx) => {
          const tr = document.createElement('tr');
          const name = toTitleCase(`${it.first_name || ''} ${it.last_name || ''}`.trim());
          const timeIn = it.start_time || '';
          const timeOut = it.end_time || '';
          const hoursStr = (() => {
            if (it.hours != null) return formatHoursMinutesFromHours(it.hours);
            const d = calcDurationStr(timeIn, timeOut);
            return d || '-';
          })();
          const typeLabel = it.kind || 'Overtime';
          tr.innerHTML = `
            <td class="px-3 py-2 text-sm text-gray-700">${startIdx + idx + 1}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${name}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${formatWorkDate(it.work_date) || ''}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${typeLabel}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${hoursStr}</td>
            <td class="px-3 py-2 text-sm text-gray-700 truncate max-w-[20rem]" title="${(it.reason||'').replace(/\"/g,'&quot;')}">${it.reason || ''}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${statusBadge(it.status)}</td>
            <td class="px-3 py-2 text-sm text-right">
              <button class="px-2 py-1 text-xs rounded border hover:bg-gray-50 inline-flex items-center gap-1.5" data-action="edit" aria-label="Edit">
                <svg class="w-4 h-4 text-blue-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536M4 20h4l10.606-10.606a2 2 0 10-2.828-2.828L5.172 17.172A4 4 0 004 20z" />
                </svg>
                <span>Edit</span>
              </button>
            </td>`;
          const editBtn = tr.querySelector('[data-action="edit"]');
          if (editBtn) editBtn.addEventListener('click', async () => {
            if (it.kind === 'Overtime') {
              editContext = { type: 'ot', id: it.id, start_time: it.start_time, end_time: it.end_time };
              await openOt();
              setOtModalMode(true);
              const sel = document.getElementById('mgr-ot-emp'); if (sel) sel.value = String(it.employee_id || '');
              const d = document.getElementById('mgr-ot-date'); if (d) d.value = it.work_date || '';
              const r = document.getElementById('mgr-ot-reason'); if (r) r.value = it.reason || '';
            }
          });

                    tbody.appendChild(tr);
        });
      }
      wrap.innerHTML = '';
      wrap.appendChild(table);

      // Animate overtime request rows using anime.js (align with Employees/Attendance pages)
      try {
        ensureAnimeMgr().then(anime => {
          if (!anime) return;
          const rows = Array.from(wrap.querySelectorAll('tbody tr'));
          if (!rows.length) return;
          rows.forEach(r => { r.style.transformOrigin = '50% 50%'; r.style.opacity = '0'; });
          anime({
            targets: rows,
            translateY: [6, 0],
            scale: [0.99, 1],
            opacity: [0, 1],
            easing: 'easeOutQuad',
            duration: 260,
            delay: anime.stagger(20)
          });
        });
      } catch {}

      if (pager) {
        const showingFrom = total === 0 ? 0 : (startIdx + 1);
        const showingTo = endIdx;
        pager.innerHTML = `
          <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${total}</span></div>
          <div class="flex items-center gap-2">
            <button id="mgr-req-prev" class="px-1.5 py-0.5 text-xs rounded border ${page <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
            <span>Page ${page} of ${totalPages}</span>
            <button id="mgr-req-next" class="px-1.5 py-0.5 text-xs rounded border ${page >= totalPages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
          </div>`;
        const prev = document.getElementById('mgr-req-prev');
        const next = document.getElementById('mgr-req-next');
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
    const statusSelect = document.getElementById('mgr-req-status-filter');
    if (statusSelect) statusSelect.addEventListener('change', () => {
      statusFilter = (statusSelect.value || 'pending').toLowerCase();
      page = 1;
      render();
    });
    // Removed three-dots menu; global close handler no longer needed

    // Load OT/UT pending items
    try {
      const [empRes, otRes] = await Promise.all([
        axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
        axios.get(`${baseApiUrl}/overtime.php`, { params: { operation: 'listAll' } })
      ]);
      const me = await currentUser();
      const deptLc = (me && me.department ? String(me.department) : '').toLowerCase().trim();
      const deptIds = new Set((empRes.data || [])
        .filter(e => String(e.department || '').toLowerCase().trim() === deptLc)
        .map(e => String(e.employee_id)));
      const ots = (otRes.data || [])
        .filter(r => deptIds.has(String(r.employee_id)))
        .map(r => ({ kind: 'Overtime', id: r.ot_id, employee_id: r.employee_id, first_name: r.first_name, last_name: r.last_name, work_date: r.work_date, hours: r.hours, reason: r.reason, status: r.status, start_time: r.start_time, end_time: r.end_time }));
            allItems = [...ots].sort((a, b) => String(b.work_date || '').localeCompare(String(a.work_date || '')));
      render();
    } catch (e) {
      wrap.innerHTML = '<div class="text-red-600">Failed to load requests</div>';
    }

    async function submitDecision(it, op){
      const fd = new FormData();
      fd.append('operation', op === 'approve' ? 'approve' : 'reject');
      if (it.kind === 'Overtime') {
        fd.append('json', JSON.stringify({ ot_id: it.id }));
        await axios.post(`${baseApiUrl}/overtime.php`, fd);
      } else {
        fd.append('json', JSON.stringify({ ut_id: it.id }));
        await axios.post(`${baseApiUrl}/undertime.php`, fd);
      }
      // Refresh manager notifications/badge immediately after decision
      try { await renderNotifications(); } catch {}
    }
  },
  requestundertime: async () => {
    const app = document.getElementById('app');
    app.innerHTML = `
      <div class="flex items-center justify-between mb-3">
        <h4 class="text-xl font-semibold">Request Undertime</h4>
        <div class="flex items-center gap-2">
          <button id="mgr-btn-file-ut" class="inline-flex items-center px-3 py-2 text-sm font-medium rounded bg-primary-600 text-white hover:bg-primary-700">Request Undertime</button>
        </div>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <div class="mb-3 flex items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <div class="relative">
              <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
              <input id="mgr-ut-search-input" class="w-56 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, department, date, reason, status" />
            </div>
            <select id="mgr-ut-status-filter" class="border rounded px-2 py-1 text-sm">
              <option value="approve">Approve</option>
              <option value="peding" selected>Peding</option>
              <option value="reject">Reject</option>
            </select>
          </div>
          <div class="flex items-center gap-2 text-sm text-gray-600">
            <span>Rows per page</span>
            <select id="mgr-ut-page-size" class="border rounded px-2 py-1">
              <option value="5">5</option>
              <option value="10" selected>10</option>
              <option value="20">20</option>
              <option value="50">50</option>
            </select>
          </div>
        </div>
        <div id="mgr-ut-table" class="overflow-x-auto"></div>
        <div id="mgr-ut-pagination" class="mt-3 flex items-center justify-between text-sm text-gray-600"></div>
      </div>

      <div id="mgrUtModal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-lg">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold">Request Undertime</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
            <div class="p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Employee</label>
                <input id="mgr-ut-emp-search" class="w-full border rounded px-3 py-2 mb-2" placeholder="Search employee..." />
                <select id="mgr-ut-emp" class="w-full border rounded px-3 py-2"></select>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Date</label>
                <input id="mgr-ut-date" type="date" class="w-full border rounded px-3 py-2" />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Hours</label>
                <input id="mgr-ut-hours" type="number" step="0.25" min="0.25" class="w-full border rounded px-3 py-2" placeholder="e.g., 1" />
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Reason</label>
                <textarea id="mgr-ut-reason" rows="3" class="w-full border rounded px-3 py-2"></textarea>
              </div>
            </div>
            <div class="flex justify-end gap-2 border-t px-4 py-3">
              <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
              <button id="mgr-ut-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Submit</button>
            </div>
          </div>
        </div>
      </div>`;

    // Load employees list in the manager's department (Warehouse Department only, excluding self)
    let _mgrEmployees = [];
    async function loadEmployeesList(){
      try {
        const [empRes, meRes] = await Promise.all([
          axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
          axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true })
        ]);
        const me = meRes.data && meRes.data.user ? meRes.data.user : null;
        const meId = me && me.employee_id ? String(me.employee_id) : '';
        const list = Array.isArray(empRes.data) ? empRes.data : [];
        const deptLc = (me && me.department ? String(me.department) : '').toLowerCase().trim();
        _mgrEmployees = list.filter(e => {
          const d = String(e.department || '').toLowerCase().trim();
          const sameDept = deptLc && d === deptLc;
          const notMe = meId ? String(e.employee_id) !== meId : true;
          return sameDept && notMe;
        });
      } catch { _mgrEmployees = []; }
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
        const filtered = !q ? _mgrEmployees.slice() : _mgrEmployees.filter(e => `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.includes(q) || String(e.email||'').toLowerCase().includes(q));
        renderEmpOptions(selectId, filtered, selected);
      };
    }

    // Modal controls
    const utModal = document.getElementById('mgrUtModal');
    let utEditContext = null;
    const openUt = async () => {
      await loadEmployeesList();
      renderEmpOptions('mgr-ut-emp', _mgrEmployees);
      wireSearchEmp('mgr-ut-emp-search', 'mgr-ut-emp');
      // Transform Hours input into Time Out (type=time)
      try {
        const hoursInput = utModal?.querySelector('#mgr-ut-hours');
        if (hoursInput) {
          const label = hoursInput.parentElement?.querySelector('label');
          if (label) label.textContent = 'Time Out';
          hoursInput.type = 'time';
          hoursInput.id = 'mgr-ut-end';
          hoursInput.placeholder = '';
          hoursInput.removeAttribute('step');
          hoursInput.removeAttribute('min');
        }
      } catch {}
      if (utModal) utModal.classList.remove('hidden');
    };
    const closeUt = () => { if (utModal) utModal.classList.add('hidden'); utEditContext = null; };

    const utBtn = document.getElementById('mgr-btn-file-ut');
    if (utBtn) utBtn.addEventListener('click', async () => { await openUt(); });

    if (utModal) utModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeUt));

    const utSave = document.getElementById('mgr-ut-save');
    if (utSave) utSave.addEventListener('click', async () => {
      const employee_id = document.getElementById('mgr-ut-emp')?.value;
      const work_date = document.getElementById('mgr-ut-date')?.value;
      const end_time = document.getElementById('mgr-ut-end')?.value || '';
      const reason = document.getElementById('mgr-ut-reason')?.value || '';
      const toMinutes = (t) => { const parts = String(t).split(':').map(n => parseInt(n,10)); const h = parts[0]||0, m = parts[1]||0; return h*60 + m; };
      const SHIFT_END = '20:00';
      let hours = 0;
      if (end_time) {
        const se = toMinutes(SHIFT_END);
        const b = toMinutes(end_time);
        const diff = se - b;
        hours = diff > 0 ? (diff / 60) : 0;
      }
      if (!employee_id || !work_date || !end_time || !Number.isFinite(hours) || hours <= 0) { showToast('Select employee, date, and a valid time out', 'warning'); return; }
      const fd = new FormData();
      if (utEditContext && utEditContext.id) {
        fd.append('operation', 'updateUndertime');
        fd.append('json', JSON.stringify({ ut_id: utEditContext.id, employee_id, work_date, hours, end_time, reason }));
      } else {
        fd.append('operation', 'requestUndertime');
        fd.append('json', JSON.stringify({ employee_id, work_date, hours, start_time: null, end_time, reason }));
      }
      try { await axios.post(`${baseApiUrl}/undertime.php`, fd); closeUt(); showToast(utEditContext ? 'Undertime request updated' : 'Undertime request submitted', 'success'); await loadUndertime(); } catch { showToast('Failed to submit undertime', 'error'); }
    });

    // Table state and rendering (Undertime list)
    let utItems = [];
    let query = '';
    let page = 1;
    let pageSize = 10;
    let statusFilter = 'pending';

    const searchInput = document.getElementById('mgr-ut-search-input');
    const pageSizeSelect = document.getElementById('mgr-ut-page-size');
    const pager = document.getElementById('mgr-ut-pagination');
    const statusSelect = document.getElementById('mgr-ut-status-filter');

    const statusBadge = (st) => {
      const s = String(st || '').toLowerCase();
      let cls = 'inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full ring-1 ';
      let label = 'Pending';
      if (s === 'approved' || s === 'approve') { cls += 'bg-green-50 text-green-700 ring-green-200'; label = 'Approved'; }
      else if (s === 'rejected' || s === 'reject') { cls += 'bg-red-50 text-red-700 ring-red-200'; label = 'Rejected'; }
      else { cls += 'bg-yellow-50 text-yellow-700 ring-yellow-200'; label = 'Pending'; }
      return `<span class="${cls}">${label}</span>`;
    };

    async function loadUndertime(){
      const tableDiv = document.getElementById('mgr-ut-table');
      if (tableDiv) tableDiv.innerHTML = '<div class="text-gray-500">Loading...</div>';
      try {
        const [empRes, utRes, meRes] = await Promise.all([
          axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
          axios.get(`${baseApiUrl}/undertime.php`, { params: { operation: 'listAll' } }),
          axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true })
        ]);
        const empList = Array.isArray(empRes.data) ? empRes.data : [];
        const deptOf = new Map(empList.map(e => [String(e.employee_id), String(e.department || '')]));
        const me = meRes.data && meRes.data.user ? meRes.data.user : null;
        const meDept = (me && me.department ? String(me.department) : '').toLowerCase();
        utItems = (utRes.data || [])
          .filter(r => String(deptOf.get(String(r.employee_id) || ''))?.toLowerCase() === meDept)
          .map(r => ({ id: r.ut_id, employee_id: r.employee_id, first_name: r.first_name, last_name: r.last_name, department: deptOf.get(String(r.employee_id)) || '', work_date: r.work_date, end_time: r.end_time, hours: r.hours, reason: r.reason, status: r.status }));
        page = 1;
        renderTable();
      } catch {
        const tableDiv = document.getElementById('mgr-ut-table');
        if (tableDiv) tableDiv.innerHTML = '<div class="text-red-600">Failed to load undertime requests</div>';
        utItems = [];
        renderTable();
      }
    }

    function getFiltered(){
      const q = (query || '').toLowerCase();
      const s = (statusFilter || 'pending').toLowerCase();
      let base = utItems.slice();
      if (s !== 'all') {
        base = base.filter(it => {
          const st = String(it.status || '').toLowerCase();
          if (s === 'approved' || s === 'approve') return st === 'approved' || st === 'approve';
          if (s === 'rejected' || s === 'reject') return st === 'rejected' || st === 'reject';
          return st === 'pending';
        });
      }
      if (!q) return base;
      return base.filter(it => {
        const name = `${it.first_name || ''} ${it.last_name || ''}`.toLowerCase();
        const dept = (it.department || '').toLowerCase();
        const date = (it.work_date || '').toLowerCase();
        const reason = (it.reason || '').toLowerCase();
        const st = (it.status || '').toLowerCase();
        return name.includes(q) || dept.includes(q) || date.includes(q) || reason.includes(q) || st.includes(q);
      });
    }

    function renderTable(){
      const tableWrap = document.getElementById('mgr-ut-table');
      if (!tableWrap) return;
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

      const table = document.createElement('table');
      table.className = 'min-w-full divide-y divide-gray-200';
      table.innerHTML = `
        <thead class="bg-gray-50"><tr>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Date</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time out</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Reason</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Actions</th>
        </tr></thead>
        <tbody class="divide-y divide-gray-200 bg-white"></tbody>`;
      const tbody = table.querySelector('tbody');
      if (!pageRows.length) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="7" class="px-3 py-6 text-sm text-center text-gray-500">No undertime requests</td>`;
        tbody.appendChild(tr);
      } else {
        pageRows.forEach((it, idx) => {
          const tr = document.createElement('tr');
          const name = toTitleCase(`${it.first_name || ''} ${it.last_name || ''}`.trim());
          tr.innerHTML = `
            <td class="px-3 py-2 text-sm text-gray-700">${startIdx + idx + 1}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${name}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${it.work_date || ''}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${formatTime12(it.end_time) || ''}</td>
            <td class="px-3 py-2 text-sm text-gray-700 truncate max-w-[20rem]" title="${(it.reason||'').replace(/\"/g,'&quot;')}">${it.reason || ''}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${statusBadge(it.status)}</td>
            <td class="px-3 py-2 text-sm text-gray-700">
              <button class="px-2 py-1 text-xs rounded border hover:bg-gray-50 inline-flex items-center gap-1.5" data-action="edit" aria-label="Edit">
                <svg class="w-4 h-4 text-blue-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536M4 20h4l10.606-10.606a2 2 0 10-2.828-2.828L5.172 17.172A4 4 0 004 20z" />
                </svg>
                <span>Edit</span>
              </button>
            </td>`;
                    const editBtn = tr.querySelector('[data-action="edit"]');
          if (editBtn) editBtn.addEventListener('click', async () => {
            utEditContext = { id: it.id };
            await openUt();
            const sel = document.getElementById('mgr-ut-emp'); if (sel) sel.value = String(it.employee_id || '');
            const d = document.getElementById('mgr-ut-date'); if (d) d.value = it.work_date || '';
            const e = document.getElementById('mgr-ut-end'); if (e) e.value = it.end_time || '';
            const r = document.getElementById('mgr-ut-reason'); if (r) r.value = it.reason || '';
          });
          tbody.appendChild(tr);
        });
      }
      tableWrap.innerHTML = '';
      tableWrap.appendChild(table);

      // Animate undertime request rows using anime.js (align with other pages)
      try {
        ensureAnimeMgr().then(anime => {
          if (!anime) return;
          const rows = Array.from(tableWrap.querySelectorAll('tbody tr'));
          if (!rows.length) return;
          rows.forEach(r => { r.style.transformOrigin = '50% 50%'; r.style.opacity = '0'; });
          anime({
            targets: rows,
            translateY: [6, 0],
            scale: [0.99, 1],
            opacity: [0, 1],
            easing: 'easeOutQuad',
            duration: 260,
            delay: anime.stagger(20)
          });
        });
      } catch {}

      if (pager) {
        const showingFrom = total === 0 ? 0 : (startIdx + 1);
        const showingTo = endIdx;
        pager.innerHTML = `
          <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${total}</span></div>
          <div class="flex items-center gap-2">
            <button id="mgr-ut-prev" class="px-1.5 py-0.5 text-xs rounded border ${page <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
            <span>Page ${page} of ${totalPages}</span>
            <button id="mgr-ut-next" class="px-1.5 py-0.5 text-xs rounded border ${page >= totalPages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
          </div>`;
        const prev = document.getElementById('mgr-ut-prev');
        const next = document.getElementById('mgr-ut-next');
        if (prev) prev.addEventListener('click', () => { if (page > 1) { page -= 1; renderTable(); } });
        if (next) next.addEventListener('click', () => { if (page < totalPages) { page += 1; renderTable(); } });
      }
    }

    if (searchInput) searchInput.addEventListener('input', () => { query = (searchInput.value || '').trim(); page = 1; renderTable(); });
    if (pageSizeSelect) pageSizeSelect.addEventListener('change', () => { const n = Number(pageSizeSelect.value); pageSize = Number.isFinite(n) && n > 0 ? n : 10; page = 1; renderTable(); });
    if (statusSelect) statusSelect.addEventListener('change', () => { statusFilter = (statusSelect.value || 'pending').toLowerCase(); page = 1; renderTable(); });

    await loadUndertime();
  }
};

function renderDeptAttendanceTableV2(){
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h4 class="text-xl font-semibold">Department Attendance</h4>
    </div>
    <div class="bg-white rounded-lg shadow p-4">
      <div class="mb-3 flex items-center justify-between gap-3">
        <div class="flex items-center gap-2">
          <div class="relative">
            <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
            <input id="att-search-input" class="w-56 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search by name, status, date" />
          </div>
          <button id="att-search-clear" aria-label="Clear search" class="inline-flex items-center gap-1.5 border border-gray-300 rounded px-2.5 py-1 text-sm text-gray-700 hover:bg-gray-50 active:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1">
            <svg class="w-4 h-4 text-gray-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
            <span>Clear</span>
          </button>
          <input type="date" id="att-date" class="border rounded px-2.5 py-1 text-sm" />
          <select id="att-status-filter" class="border rounded px-2 py-1 text-sm">
            <option value="all" selected>All Status</option>
            <option value="present">Present</option>
            <option value="absent">Absent</option>
            <option value="leave">On Leave</option>
            <option value="undertime">Undertime</option>
          </select>
        </div>
        <div class="flex items-center gap-3">
          <span class="text-sm text-gray-600">Rows per page</span>
          <select id="att-page-size" class="border rounded px-2 py-1">
            <option value="10" selected>10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </div>
      </div>
      <div id="attendance-table"></div>
      <div id="attendance-pagination" class="mt-3 flex items-center justify-between text-sm text-gray-600"></div>
    </div>`;

  let allAttendance = [];
  let leavesCache = [];
  let currentQuery = '';
  let currentPage = 1;
  let pageSize = 10;

  // Setup anime.js animation on attendance table render
  try {
    const container = document.getElementById('attendance-table');
    if (container && !container.__animeWired) {
      container.__animeWired = true;
      const observer = new MutationObserver(() => {
        ensureAnimeMgr().then(anime => {
          if (!anime) return;
          const rows = Array.from(container.querySelectorAll('tbody tr'));
          if (!rows.length) return;
          rows.forEach(r => { r.style.transformOrigin = '50% 50%'; r.style.opacity = '0'; });
          anime({
            targets: rows,
            translateY: [6, 0],
            scale: [0.99, 1],
            opacity: [0, 1],
            easing: 'easeOutQuad',
            duration: 260,
            delay: anime.stagger(20)
          });
        });
      });
      observer.observe(container, { childList: true, subtree: true });
    }
  } catch {}

  function today(){
    const d = new Date();
    const y = d.getFullYear();
    const m = String(d.getMonth()+1).padStart(2,'0');
    const day = String(d.getDate()).padStart(2,'0');
    return `${y}-${m}-${day}`;
  }

  function capitalizeWords(str){
    if (!str) return '';
    return String(str).split(' ').map(w => w ? (w[0].toUpperCase() + w.slice(1).toLowerCase()) : '').join(' ');
  }

  function formatDate(dateStr){
    if (!dateStr) return '';
    try {
      const date = new Date(dateStr);
      if (isNaN(date.getTime())) return dateStr;
      return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch { return dateStr; }
  }

  function formatTimeOfDay(timeStr){
    if (!timeStr) return '';
    try {
      const parts = String(timeStr).split(':');
      if (parts.length < 2) return timeStr;
      let h = parseInt(parts[0], 10);
      const m = parseInt(parts[1], 10) || 0;
      if (!Number.isFinite(h)) return timeStr;
      const ampm = h >= 12 ? 'PM' : 'AM';
      h = h % 12; if (h === 0) h = 12;
      const mm = String(m).padStart(2,'0');
      return `${h}:${mm} ${ampm}`;
    } catch { return timeStr; }
  }

  function statusBadge(status){
    const s = String(status || '').toLowerCase();
    const map = {
      present: { cls: 'bg-green-50 text-green-700 ring-green-200', label: 'Present' },
      late: { cls: 'bg-amber-50 text-amber-700 ring-amber-200', label: 'Late' },
      absent: { cls: 'bg-red-50 text-red-700 ring-red-200', label: 'Absent' },
      leave: { cls: 'bg-indigo-50 text-indigo-700 ring-indigo-200', label: 'On Leave' },
      undertime: { cls: 'bg-blue-50 text-blue-700 ring-blue-200', label: 'Undertime' }
    };
    const m = map[s] || { cls: 'bg-gray-50 text-gray-700 ring-gray-200', label: capitalizeWords(s) };
    return `<span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ring-1 ${m.cls}">${m.label}</span>`;
  }

  function consolidateLeaveRows(rows){
    try {
      const leaveRows = rows.filter(r => String(r.status || '').toLowerCase() === 'leave');
      const byEmp = new Map();
      for (const r of leaveRows){
        const k = String(r.employee_id);
        if (!byEmp.has(k)) byEmp.set(k, []);
        byEmp.get(k).push(r);
      }
      const toDate = (s) => { const [y,m,d] = String(s||'').split('-').map(n=>parseInt(n,10)); return new Date(y,(m||1)-1,d||1); };
      const addDays = (dt, n) => new Date(dt.getFullYear(), dt.getMonth(), dt.getDate()+n);
      const fmtYmd = (dt) => `${dt.getFullYear()}-${String(dt.getMonth()+1).padStart(2,'0')}-${String(dt.getDate()).padStart(2,'0')}`;
      const result = [];
      for (const [empId, list] of byEmp.entries()){
        const uniqueDates = Array.from(new Set(list.map(r => r.attendance_date))).filter(Boolean).sort();
        let i = 0;
        while (i < uniqueDates.length){
          const start = uniqueDates[i];
          let end = start;
          let j = i + 1;
          while (j < uniqueDates.length){
            const prev = toDate(end);
            const next = toDate(uniqueDates[j]);
            const expected = addDays(prev, 1);
            if (fmtYmd(expected) === fmtYmd(next)) { end = uniqueDates[j]; j++; } else { break; }
          }
          const sample = list.find(r => r.attendance_date === start) || list[0];
          result.push({
            attendance_id: null,
            employee_id: empId,
            first_name: sample.first_name,
            last_name: sample.last_name,
            position: sample.position,
            attendance_date: start,
            range_start: start,
            range_end: end,
            status: 'leave',
            time_in: null,
            time_out: null,
            remarks: ''
          });
          i = j;
        }
      }
      return result.sort((a,b) =>
        String(a.last_name||'').localeCompare(String(b.last_name||'')) ||
        String(a.first_name||'').localeCompare(String(b.first_name||'')) ||
        String(a.range_start||'').localeCompare(String(b.range_start||''))
      );
    } catch { return rows; }
  }

  function getFilteredAttendance(){
    const q = (currentQuery || '').toLowerCase();
    const statusEl = document.getElementById('att-status-filter');
    const statusFilter = statusEl ? (statusEl.value || 'all').toLowerCase() : 'all';
    const base = allAttendance.slice();
    const filteredBySearch = !q ? base : base.filter(r => {
      const name = `${r.first_name || ''} ${r.last_name || ''}`.toLowerCase();
      const status = (r.status || '').toLowerCase();
      const date = (r.attendance_date || '').toLowerCase();
      return name.includes(q) || status.includes(q) || date.includes(q);
    });
    if (statusFilter === 'all') return filteredBySearch;
    if (statusFilter === 'present') return filteredBySearch.filter(r => {
      const st = String(r.status || '').toLowerCase();
      return st === 'present' || st === 'late';
    });
    return filteredBySearch.filter(r => (String(r.status || '').toLowerCase() === statusFilter));
  }

  function calcTotalHours(attDate, tIn, tOut){
    try {
      if (!tIn) return '';
      const inStr = `${attDate || ''}T${tIn}`;
      const dIn = new Date(inStr);
      let dOut = tOut ? new Date(`${attDate || ''}T${tOut}`) : new Date();
      if (dOut.getTime() < dIn.getTime()) dOut = new Date(dOut.getTime() + 24*60*60*1000);
      const ms = dOut.getTime() - dIn.getTime();
      if (!Number.isFinite(ms) || ms <= 0) return '';
      const totalMinutes = Math.round(ms / (1000*60));
      const h = Math.floor(totalMinutes / 60);
      const m = totalMinutes % 60;
      return m ? `${h}h ${m}m` : `${h}h`;
    } catch { return ''; }
  }

  function renderAttendanceTable(){
    const container = document.getElementById('attendance-table');
    if (!container) return;
    let rows;
    const statusEl = document.getElementById('att-status-filter');
    const statusFilter = statusEl ? (statusEl.value || 'all').toLowerCase() : 'all';
    if (statusFilter === 'leave'){
      const dateEl = document.getElementById('att-date');
      const onDate = dateEl ? (dateEl.value || '').trim() : '';
      const q = (currentQuery || '').toLowerCase();
      const base = Array.isArray(leavesCache) ? leavesCache : [];
      rows = base
        .filter(l => String(l.status || '').toLowerCase() === 'approved')
        .filter(l => !onDate || (String(l.start_date || '') <= onDate && String(l.end_date || '') >= onDate))
        .map(l => ({
          employee_id: l.employee_id,
          first_name: l.first_name,
          last_name: l.last_name,
          position: l.position,
          attendance_date: l.start_date,
          range_start: l.start_date,
          range_end: l.end_date,
          status: 'leave',
          time_in: null,
          time_out: null,
          remarks: l.reason || ''
        }))
        .filter(r => !q || (`${r.first_name || ''} ${r.last_name || ''}`.toLowerCase().includes(q)));
      rows.sort((a,b) => String(b.range_start||'').localeCompare(String(a.range_start||''))
        || String(a.last_name||'').localeCompare(String(b.last_name||''))
        || String(a.first_name||'').localeCompare(String(b.first_name||'')));
    } else {
      rows = getFilteredAttendance();
      try {
        const dateEl = document.getElementById('att-date');
        const selectedDate = dateEl ? (dateEl.value || '').trim() : '';
        if (selectedDate && Array.isArray(rows) && rows.length){
          const baseLeaves = Array.isArray(leavesCache) ? leavesCache : [];
          const byEmpLeaves = new Map();
          for (const l of baseLeaves){
            if (String(l.status || '').toLowerCase() !== 'approved') continue;
            const s = String(l.start_date || '');
            const e = String(l.end_date || '');
            if (!(s && e)) continue;
            if (!(s <= selectedDate && e >= selectedDate)) continue;
            const k = String(l.employee_id);
            const prev = byEmpLeaves.get(k);
            if (!prev) byEmpLeaves.set(k, l); else if (String(l.end_date).localeCompare(String(prev.end_date)) > 0) byEmpLeaves.set(k, l);
          }
          rows = rows.map(r => {
            if (String(r.status || '').toLowerCase() === 'leave'){
              const hit = byEmpLeaves.get(String(r.employee_id));
              if (hit) return { ...r, range_start: hit.start_date, range_end: hit.end_date };
            }
            return r;
          });
        }
        if (!selectedDate && Array.isArray(rows) && rows.length){
          const nonLeave = rows.filter(r => String(r.status || '').toLowerCase() !== 'leave');
          const consolidatedLeave = consolidateLeaveRows(rows);
          rows = nonLeave.concat(consolidatedLeave);
          rows.sort((a,b) => String(b.range_start || b.attendance_date || '').localeCompare(String(a.range_start || a.attendance_date || '')));
        }
      } catch {}
    }

    const total = rows.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (currentPage > totalPages) currentPage = totalPages;
    const startIdx = (currentPage - 1) * pageSize;
    const endIdx = Math.min(startIdx + pageSize, total);
    const pageRows = rows.slice(startIdx, endIdx);

    const table = document.createElement('table');
    table.className = 'min-w-full divide-y divide-gray-200';
    table.innerHTML = `
      <thead class="bg-gray-50">
        <tr>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Date</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time In</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time Out</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Total Hours</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-200 bg-white"></tbody>`;

    const tbody = table.querySelector('tbody');
    if (!pageRows.length){
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="7" class="px-3 py-6 text-sm text-center text-gray-500">No attendance records</td>`;
      tbody.appendChild(tr);
    } else {
      pageRows.forEach((r, i) => {
        const tr = document.createElement('tr');
        const name = capitalizeWords(`${r.first_name || ''} ${r.last_name || ''}`.trim());
        const idx = startIdx + i + 1;
        const statusHtml = statusBadge(r.status || '');
        tr.innerHTML = `
          <td class="px-3 py-2 text-sm text-gray-700">${idx}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${name}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${r.range_start ? (formatDate(r.range_start) + ' → ' + formatDate(r.range_end)) : formatDate(r.attendance_date)}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${statusHtml}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${formatTimeOfDay(r.time_in) || ''}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${formatTimeOfDay(r.time_out) || ''}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${calcTotalHours(r.attendance_date, r.time_in, r.time_out)}</td>`;
        tbody.appendChild(tr);
      });
    }

    container.innerHTML = '';
    container.appendChild(table);

    const footer = document.getElementById('attendance-pagination');
    if (footer){
      const showingFrom = total === 0 ? 0 : (startIdx + 1);
      const showingTo = endIdx;
      footer.innerHTML = `
        <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${total}</span></div>
        <div class="flex items-center gap-2">
          <button id="att-prev" class="px-2 py-1 text-xs rounded border ${currentPage <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
          <span>Page ${currentPage} of ${totalPages}</span>
          <button id="att-next" class="px-2 py-1 text-xs rounded border ${currentPage >= totalPages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
        </div>`;
      const prev = document.getElementById('att-prev');
      const next = document.getElementById('att-next');
      if (prev) prev.addEventListener('click', () => { if (currentPage > 1){ currentPage -= 1; renderAttendanceTable(); } });
      if (next) next.addEventListener('click', () => { if (currentPage < totalPages){ currentPage += 1; renderAttendanceTable(); } });
    }
  }

  async function loadAttendance(){
    const tableDiv = document.getElementById('attendance-table');
    if (tableDiv) tableDiv.innerHTML = '<div class="text-gray-500">Loading...</div>';
    const selEl = document.getElementById('att-date');
    const effectiveDate = (selEl && selEl.value) ? selEl.value : today();
    try {
      const me = await currentUser();
      const [attRes, empRes] = await Promise.all([
        axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: effectiveDate, end_date: effectiveDate } }),
        axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } })
      ]);
      const empList = Array.isArray(empRes.data) ? empRes.data : [];
      const deptOf = new Map(empList.map(e => [String(e.employee_id), String(e.department || '')]));
      const myDeptLc = String(me && me.department ? me.department : '').toLowerCase();
      let rows = Array.isArray(attRes.data) ? attRes.data : [];
      const myId = me && me.employee_id ? String(me.employee_id) : '';
      rows = rows
        .filter(r => String(deptOf.get(String(r.employee_id) || '')).toLowerCase() === myDeptLc)
        .filter(r => !myId || String(r.employee_id) !== myId);

      // Deduplicate leave entries per employee per date
      try {
        const unique = [];
        const seenLeave = new Set();
        for (const r of rows){
          const st = String(r.status || '').toLowerCase();
          if (st === 'leave'){
            const key = `${r.employee_id}|${r.attendance_date}`;
            if (seenLeave.has(key)) continue;
            seenLeave.add(key);
          }
          unique.push(r);
        }
        rows = unique;
      } catch {}

      allAttendance = rows;
      try {
        const lr = await axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listApproved' } });
        leavesCache = Array.isArray(lr.data) ? lr.data : [];
      } catch { leavesCache = []; }
      currentPage = 1;
      renderAttendanceTable();
    } catch {
      if (tableDiv) tableDiv.innerHTML = '<div class="text-red-600">Failed to load attendance</div>';
      allAttendance = [];
      renderAttendanceTable();
    }
  }

  // Wire inputs
  const attSearchInput = document.getElementById('att-search-input');
  const attSearchClear = document.getElementById('att-search-clear');
  const attPageSizeSelect = document.getElementById('att-page-size');
  const attDate = document.getElementById('att-date');
  const attStatus = document.getElementById('att-status-filter');

  if (attSearchInput){
    attSearchInput.addEventListener('input', () => {
      currentQuery = (attSearchInput.value || '').trim().toLowerCase();
      currentPage = 1;
      renderAttendanceTable();
    });
  }
  if (attSearchClear){
    attSearchClear.addEventListener('click', () => {
      if (attSearchInput) attSearchInput.value = '';
      currentQuery = '';
      currentPage = 1;
      renderAttendanceTable();
    });
  }
  if (attPageSizeSelect){
    attPageSizeSelect.addEventListener('change', () => {
      const num = Number(attPageSizeSelect.value);
      pageSize = Number.isFinite(num) && num > 0 ? num : 10;
      currentPage = 1;
      renderAttendanceTable();
    });
  }

  if (attDate){ try { attDate.value = today(); } catch {} }
  if (attStatus){ try { attStatus.value = 'all'; } catch {} }

  if (attDate){
    attDate.addEventListener('change', () => { if (!attDate.value) { try { attDate.value = today(); } catch {} } currentPage = 1; loadAttendance(); });
    attDate.addEventListener('input', () => { if (!attDate.value) { try { attDate.value = today(); } catch {} } currentPage = 1; loadAttendance(); });
  }
  if (attStatus){ attStatus.addEventListener('change', () => { currentPage = 1; renderAttendanceTable(); }); }

  let __attDayKey = today();
  function resetForNewDay(){
    try {
      if (attSearchInput) attSearchInput.value = '';
      currentQuery = '';
      if (attStatus) attStatus.value = 'all';
      if (attDate) attDate.value = today();
      currentPage = 1;
    } catch {}
    loadAttendance();
  }
  function maybeRollover(){
    const nowDay = today();
    if (nowDay !== __attDayKey){ __attDayKey = nowDay; resetForNewDay(); }
  }
  try { setInterval(maybeRollover, 60000); window.addEventListener('focus', maybeRollover); document.addEventListener('visibilitychange', maybeRollover); } catch {}

  loadAttendance();
}

function handleRoute(){
  const hash = location.hash.replace('#','') || 'dashboard';
  (routes[hash] || routes.dashboard)();
}

window.addEventListener('hashchange', handleRoute);

document.addEventListener('DOMContentLoaded', async () => {
  const me = await currentUser();
  if (!me || me.role !== 'manager') {
    location.href = './login.html';
    return;
  }
  fillProfile(me);
  wireHelp();
  wireProfileMenu();
  // Ensure notification header is always wired regardless of the initial route
  wireHeader();
  try { await ensureSwal(); } catch {}
  try { attachSweetHeaderNotif(); } catch {}
  handleRoute();
});

async function currentUser(){
  try {
    const res = await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
    return res.data && res.data.user ? res.data.user : null;
  } catch { return null; }
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
    return u || 'Manager';
  })();
  if (nameEl) nameEl.textContent = displayName;
  if (roleEl) roleEl.textContent = user.role || 'manager';
  if (avatarEl) avatarEl.textContent = (displayName || 'M').substring(0,1).toUpperCase();
  
  // Initialize header avatar
  syncManagerHeaderAvatar(user);
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

function wireProfileMenu(){
  const trigger = document.getElementById('profile-trigger');
  const menu = document.getElementById('profile-menu');
  const headerLogout = document.getElementById('header-logout');
  if (trigger && menu){
    trigger.addEventListener('click', (e) => { e.preventDefault(); menu.classList.toggle('hidden'); });
    document.addEventListener('click', (e) => {
      if (!menu.classList.contains('hidden')){
        const within = trigger.contains(e.target) || menu.contains(e.target);
        if (!within) menu.classList.add('hidden');
      }
    });
  }
  const mgrProfileBtn = document.getElementById('mgr-profile');
  if (mgrProfileBtn){
    mgrProfileBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      if (menu) menu.classList.add('hidden');
      try { const me = await currentUser(); if (me) await openManagerProfile(me); } catch {}
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
        location.href = './login.html';
      }
    });
  }
}

// Manager Profile Modal + Password Reset (mirrors employee profile behavior)
function mgrProfileImgKey(empId){ return `intro_emp_profile_img_${empId}`; }
function mgrLoadProfileImg(empId){ try { return localStorage.getItem(mgrProfileImgKey(empId)) || ''; } catch { return ''; } }
function mgrSaveProfileImg(empId, data){ try { if (empId) localStorage.setItem(mgrProfileImgKey(empId), data || ''); } catch {} }
function mgrClearProfileImg(empId){ try { if (empId) localStorage.removeItem(mgrProfileImgKey(empId)); } catch {} }

function ensureMgrProfileModal(){
  if (document.getElementById('mgrProfileModal')) return;
  const html = `
    <div id="mgrProfileModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto my-12 w-full max-w-3xl px-4">
        <div class="bg-white rounded-lg shadow max-h-[85vh] overflow-y-auto">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">My Profile</h5>
            <button class="text-gray-500 text-xl" data-close="true">×</button>
          </div>
          <div class="p-5">
            <div class="flex flex-col sm:flex-row gap-5">
              <div class="flex flex-col items-center sm:w-56">
                <div class="w-32 h-32 rounded-full bg-gray-100 border overflow-hidden flex items-center justify-center">
                  <img id="mgr-prof-avatar" alt="Profile" class="w-full h-full object-cover hidden"/>
                  <svg id="mgr-prof-avatar-ph" class="w-16 h-16 text-gray-400" viewBox="0 0 24 24" fill="currentColor"><path d="M12 12a5 5 0 100-10 5 5 0 000 10z"/><path d="M4 20a8 8 0 1116 0v1H4v-1z"/></svg>
                </div>
                <label class="mt-3 inline-flex items-center gap-2 px-3 py-1.5 text-sm rounded border bg-white cursor-pointer">
                  <svg class="w-4 h-4 text-gray-600" viewBox="0 0 20 20" fill="currentColor"><path d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V9.414a2 2 0 00-.586-1.414l-3.414-3.414A2 2 0 0012.586 4H12V3a1 1 0 10-2 0v1H7a1 1 0 00-1 1v1h8V5h1.586L19 8.414V15H1V5a2 2 0 012-2h1z"/></svg>
                  <span>Upload Image</span>
                  <input id="mgr-prof-file" type="file" accept="image/*" class="hidden" />
                </label>
                <div class="flex items-center gap-3 mt-2">
                  <button id="mgr-prof-save" class="px-3 py-1.5 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
                  <button id="mgr-prof-remove" class="px-3 py-1.5 text-sm rounded border">Remove</button>
                  <a href="#" id="mgr-prof-reset-link" class="text-sm text-blue-600 hover:text-blue-800 underline ml-2">Reset password</a>
                </div>
              </div>
              <div class="flex-1 text-sm space-y-6">
                <div>
                  <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Personal Information</div>
                  <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-2">
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Name</div>
                      <div id="mgr-prof-name" class="font-semibold text-gray-900"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Gender</div>
                      <div id="mgr-prof-gender" class="font-semibold text-gray-900"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Date of Birth</div>
                      <div id="mgr-prof-dob" class="font-semibold text-gray-900"></div>
                    </div>
                  </div>
                </div>
                <div>
                  <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Contact Information</div>
                  <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-2">
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Email</div>
                      <div id="mgr-prof-email" class="font-semibold text-gray-900 break-words"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Phone</div>
                      <div id="mgr-prof-phone" class="font-semibold text-gray-900"></div>
                    </div>
                    <div class="sm:col-span-2">
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Address</div>
                      <div id="mgr-prof-address" class="font-semibold text-gray-900"></div>
                    </div>
                  </div>
                </div>
                <div>
                  <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Employment Information</div>
                  <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-2">
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Employee ID</div>
                      <div id="mgr-prof-eid" class="font-semibold text-gray-900"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Status</div>
                      <div id="mgr-prof-status" class="font-semibold text-gray-900"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Department</div>
                      <div id="mgr-prof-dept" class="font-semibold text-gray-900"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Position</div>
                      <div id="mgr-prof-pos" class="font-semibold text-gray-900"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Date Hired</div>
                      <div id="mgr-prof-hired" class="font-semibold text-gray-900"></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
          </div>
        </div>
      </div>
    </div>`;
  document.body.insertAdjacentHTML('beforeend', html);
  const modal = document.getElementById('mgrProfileModal');
  modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
}

function ensureMgrResetPwdModal(){
  if (document.getElementById('mgrResetPwdModal')) return;
  const html = `
    <div id="mgrResetPwdModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-28 w-full max-w-md px-4">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">Reset Password</h5>
            <button class="text-gray-500 text-xl" data-close="true">×</button>
          </div>
          <div class="p-4 grid gap-3">
            <div>
              <label class="block text-sm text-gray-600 mb-1">New Password</label>
              <input id="mgr-newpwd" type="password" class="w-full border rounded px-3 py-2" />
            </div>
            <div>
              <label class="block text-sm text-gray-600 mb-1">Confirm Password</label>
              <input id="mgr-newpwd-confirm" type="password" class="w-full border rounded px-3 py-2" />
            </div>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
            <button id="mgr-resetpwd-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Update Password</button>
          </div>
        </div>
      </div>
    </div>`;
  document.body.insertAdjacentHTML('beforeend', html);
  const modal = document.getElementById('mgrResetPwdModal');
  modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
}

function syncManagerHeaderAvatarFrom(src, displayName){
  try {
    const img = document.getElementById('profile-avatar-img');
    const ph = document.getElementById('profile-avatar');
    if (src){
      if (img){ img.src = src; img.classList.remove('hidden'); }
      if (ph){ ph.classList.add('hidden'); }
    } else {
      if (img){ img.src = ''; img.classList.add('hidden'); }
      if (ph){ ph.textContent = (displayName || 'M').substring(0,1).toUpperCase(); ph.classList.remove('hidden'); }
    }
  } catch {}
}

// Sync header avatar by fetching from DB first, fallback to localStorage
async function syncManagerHeaderAvatar(user){
  try {
    const img = document.getElementById('profile-avatar-img');
    const ph = document.getElementById('profile-avatar');
    if (!img || !ph || !user || !user.employee_id) return;
    
    const displayName = (() => {
      const first = (user.first_name || '').trim();
      const last = (user.last_name || '').trim();
      if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
      const u = (user.username || '').trim();
      if (u.includes('@')) return u.split('@')[0];
      return u || 'Manager';
    })();
    
    let src = '';
    // Try to get from database first
    try {
      const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployee', employee_id: user.employee_id } });
      const emp = res.data || {};
      if (emp && emp.profile_image) src = emp.profile_image;
    } catch {}
    
    // Fallback to localStorage
    if (!src) {
      src = mgrLoadProfileImg(user.employee_id);
    }
    
    if (src) {
      img.src = src;
      img.classList.remove('hidden');
      ph.classList.add('hidden');
    } else {
      img.src = '';
      img.classList.add('hidden');
      ph.textContent = (displayName || 'M').substring(0,1).toUpperCase();
      ph.classList.remove('hidden');
    }
  } catch {}
}

// Update welcome section with user profile image and information
async function updateWelcomeSection(user){
  try {
    // Update welcome name
    const welcomeNameEl = document.getElementById('welcome-name');
    const welcomeDeptEl = document.getElementById('welcome-dept');
    const welcomeDateEl = document.getElementById('welcome-date');
    const welcomeImg = document.getElementById('welcome-avatar-img');
    const welcomePh = document.getElementById('welcome-avatar-ph');
    
    const displayName = (() => {
      const first = (user.first_name || '').trim();
      const last = (user.last_name || '').trim();
      if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
      const u = (user.username || '').trim();
      if (u.includes('@')) return u.split('@')[0];
      return u || 'Manager';
    })();
    
    if (welcomeNameEl) welcomeNameEl.textContent = displayName;
    if (welcomeDeptEl) welcomeDeptEl.textContent = user.department || 'Not set';
    
    // Update date with real-time clock
    const updateTime = () => {
      if (welcomeDateEl) welcomeDateEl.textContent = new Date().toLocaleString('en-US');
    };
    updateTime();
    if (window.__welcomeInterval) clearInterval(window.__welcomeInterval);
    window.__welcomeInterval = setInterval(updateTime, 1000);
    
    // Update profile image
    if (welcomeImg && welcomePh && user.employee_id) {
      let src = '';
      // Try to get from database first
      try {
        const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployee', employee_id: user.employee_id } });
        const emp = res.data || {};
        if (emp && emp.profile_image) src = emp.profile_image;
      } catch {}
      
      // Fallback to localStorage
      if (!src) {
        src = mgrLoadProfileImg(user.employee_id);
      }
      
      if (src) {
        welcomeImg.src = src;
        welcomeImg.classList.remove('hidden');
        welcomePh.classList.add('hidden');
      } else {
        welcomeImg.src = '';
        welcomeImg.classList.add('hidden');
        welcomePh.classList.remove('hidden');
      }
    }
  } catch {}
}

async function openManagerProfile(user){
  ensureMgrProfileModal();
  ensureMgrResetPwdModal();
  const modal = document.getElementById('mgrProfileModal');
  if (!modal) return;

  // Ensure a "Download QR" button is present next to the footer Close button and wire its click handler
  try {
    const closeBtns = modal ? modal.querySelectorAll('button[data-close="true"]') : [];
    let footerClose = null;
    if (closeBtns && closeBtns.length) {
      closeBtns.forEach(b => { if (String(b.textContent||'').trim() === 'Close') footerClose = b; });
    }
    if (footerClose && !document.getElementById('mgr-prof-download-qr')) {
      const qrBtn = document.createElement('button');
      qrBtn.id = 'mgr-prof-download-qr';
      qrBtn.className = 'px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700';
      qrBtn.textContent = 'Download QR';
      try { footerClose.parentNode.insertBefore(qrBtn, footerClose); } catch {}
    }
  } catch {}
  // Click handler to generate and download the manager QR code
  try {
    const dlBtn = document.getElementById('mgr-prof-download-qr');
    if (dlBtn) {
      dlBtn.onclick = async () => {
        try {
          // Resolve user/employee info
          let me = null;
          try { const s = sessionStorage.getItem('currentUser'); if (s) me = JSON.parse(s); } catch {}
          if (!me || !me.employee_id) me = (typeof user !== 'undefined' && user) ? user : me;
          const id = me && me.employee_id ? me.employee_id : null;
          if (!id) { showToast('Employee information unavailable', 'error'); return; }
          // Fetch latest employee info for accurate name
          let empRec = null; try { const r = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployee', employee_id: id } }); empRec = r && r.data ? r.data : null; } catch {}
          const first = (empRec && empRec.first_name) ? empRec.first_name : (me.first_name || '');
          const last = (empRec && empRec.last_name) ? empRec.last_name : (me.last_name || '');
          const fullName = (function toTitleCaseName(s){ return String(s||'').split(' ').map(w => w? w[0].toUpperCase()+w.slice(1).toLowerCase() : '').join(' '); })(`${first} ${last}`.trim());
          const pad3 = (n) => String(Number(n)||0).toString().padStart(3, '0');
          const year = new Date().getFullYear();
          const code = `EMP${year}-${pad3(id)}`;
          const payload = JSON.stringify({ type: 'manager', employee_id: id, name: fullName, code, role: 'manager' });
          // Load QR library if needed
          if (!window.QRCode) {
            await new Promise((resolve) => {
              const s = document.createElement('script');
              s.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';
              s.onload = resolve; s.onerror = resolve;
              document.head.appendChild(s);
            });
          }
          // Build QR offscreen
          const temp = document.createElement('div');
          temp.style.position = 'fixed'; temp.style.left = '-9999px'; temp.style.top = '0';
          document.body.appendChild(temp);
          try { new (window.QRCode || function(){}) (temp, { text: payload, width: 256, height: 256, correctLevel: window.QRCode && window.QRCode.CorrectLevel ? window.QRCode.CorrectLevel.M : 1 }); } catch {}
          await new Promise(r => setTimeout(r, 80));
          const img = temp.querySelector('img');
          const canvas = temp.querySelector('canvas');
          // Convert QR to a framed image like admin QR
          function createFramedFromSource(qrImg, qrCanvas, opts) {
            let srcCanvas = null;
            let size = 256;
            if (qrCanvas) {
              srcCanvas = qrCanvas;
              size = qrCanvas.width || 256;
            } else if (qrImg && qrImg.src) {
              const tempC = document.createElement('canvas');
              const tctx = tempC.getContext('2d');
              tempC.width = qrImg.naturalWidth || 256;
              tempC.height = qrImg.naturalHeight || 256;
              try { tctx.drawImage(qrImg, 0, 0, tempC.width, tempC.height); } catch {}
              srcCanvas = tempC;
              size = tempC.width;
            } else {
              return '';
            }
            const borderWidth = Number.isFinite(opts.borderWidth) ? opts.borderWidth : 8;
            const margin = Number.isFinite(opts.margin) ? opts.margin : 16;
            const borderColor = opts.borderColor || '#ffffff';
            const bgColor = opts.bgColor || '#ffffff';
            const radius = Number.isFinite(opts.radius) ? opts.radius : 12;
            const outSize = size + 2 * (borderWidth + margin);
            const out = document.createElement('canvas');
            out.width = outSize; out.height = outSize;
            const ctx = out.getContext('2d');
            if (ctx) {
              ctx.imageSmoothingEnabled = false;
              const drawRoundedRect = (c, x, y, w, h, r) => {
                const rr = Math.max(0, Math.min(r, Math.min(w, h) / 2));
                c.beginPath();
                c.moveTo(x + rr, y);
                c.arcTo(x + w, y, x + w, y + h, rr);
                c.arcTo(x + w, y + h, x, y + h, rr);
                c.arcTo(x, y + h, x, y, rr);
                c.arcTo(x, y, x + w, y, rr);
                c.closePath();
              };
              // Background
              ctx.fillStyle = bgColor;
              drawRoundedRect(ctx, 0, 0, out.width, out.height, radius);
              ctx.fill();
              // Border
              const bx = margin;
              const by = margin;
              const bw = out.width - 2 * margin;
              const bh = out.height - 2 * margin;
              ctx.strokeStyle = borderColor;
              ctx.lineWidth = borderWidth;
              drawRoundedRect(ctx, bx + borderWidth / 2, by + borderWidth / 2, bw - borderWidth, bh - borderWidth, Math.max(0, radius - margin / 2));
              ctx.stroke();
              // Draw QR
              const offset = margin + borderWidth;
              ctx.drawImage(srcCanvas, offset, offset, size, size);
            }
            return out.toDataURL('image/png');
          }
          const framed = createFramedFromSource(img, canvas, { borderWidth: 8, margin: 16, borderColor: '#ffffff', bgColor: '#ffffff', radius: 12 });
          try { document.body.removeChild(temp); } catch {}
          if (!framed) { showToast('Failed to generate QR code', 'error'); return; }
          const a = document.createElement('a');
          a.href = framed;
          a.download = `manager-${code}.png`;
          document.body.appendChild(a);
          a.click();
          a.remove();
        } catch {
          showToast('Failed to generate QR code', 'error');
        }
      };
    }
  } catch {}

  // Load latest employee data for image and complete profile information
  let emp = null;
  try {
    const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployee', employee_id: user.employee_id } });
    emp = res.data || null;
  } catch {}

  const displayName = (() => {
    const first = (user.first_name || '').trim();
    const last = (user.last_name || '').trim();
    if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
    const u = (user.username || '').trim();
    if (u.includes('@')) return u.split('@')[0];
    return u || 'Manager';
  })();

  // Helper functions for formatting
  const fmtDate = (s) => { try { const d = new Date(s); return isNaN(d.getTime()) ? '' : d.toLocaleDateString('en-US', { year:'numeric', month:'short', day:'numeric' }); } catch { return ''; } };
  const formatEmployeeCode = (id) => { const year = new Date().getFullYear(); const n = Number(id)||0; return `EMP${year}-${String(n).padStart(3,'0')}`; };
  const genderStr = toTitleCase(emp?.gender || '');
  const fullName = toTitleCase(`${emp?.first_name || user.first_name || ''} ${emp?.last_name || user.last_name || ''}`.trim());

  // Populate personal information fields
  const eidEl = document.getElementById('mgr-prof-eid');
  const statusEl = document.getElementById('mgr-prof-status');
  const nameEl = document.getElementById('mgr-prof-name');
  const genderEl = document.getElementById('mgr-prof-gender');
  const addrEl = document.getElementById('mgr-prof-address');
  const emailEl = document.getElementById('mgr-prof-email');
  const phoneEl = document.getElementById('mgr-prof-phone');
  const deptEl = document.getElementById('mgr-prof-dept');
  const posEl = document.getElementById('mgr-prof-pos');
  const dobEl = document.getElementById('mgr-prof-dob');
  const hiredEl = document.getElementById('mgr-prof-hired');

  if (eidEl) eidEl.textContent = emp?.employee_id ? formatEmployeeCode(emp.employee_id) : String(user.employee_id || '');
  if (statusEl) statusEl.textContent = toTitleCase(emp?.status || 'Active');
  if (nameEl) nameEl.textContent = fullName;
  if (genderEl) genderEl.textContent = genderStr || '-';
  if (addrEl) addrEl.textContent = emp?.address || '-';
  if (emailEl) emailEl.textContent = user.username || emp?.email || '-';
  if (phoneEl) phoneEl.textContent = emp?.phone || '-';
  if (deptEl) deptEl.textContent = toTitleCase(emp?.department || user.department || '-');
  if (posEl) posEl.textContent = toTitleCase(emp?.position || '-');
  if (dobEl) dobEl.textContent = fmtDate(emp?.date_of_birth || '');
  if (hiredEl) hiredEl.textContent = fmtDate(emp?.date_hired || '');

  // Handle profile image
  const imgEl = document.getElementById('mgr-prof-avatar');
  const phEl = document.getElementById('mgr-prof-avatar-ph');
  const dbImg = emp && emp.profile_image ? emp.profile_image : '';
  const stored = mgrLoadProfileImg(user.employee_id);
  const src = dbImg || stored || '';
  if (src){ if (imgEl){ imgEl.src = src; imgEl.classList.remove('hidden'); } if (phEl){ phEl.classList.add('hidden'); } }
  else { if (imgEl){ imgEl.src=''; imgEl.classList.add('hidden'); } if (phEl){ phEl.classList.remove('hidden'); } }

  let pendingDataUrl = '';
  const fileInput = document.getElementById('mgr-prof-file');
  const btnRemove = document.getElementById('mgr-prof-remove');
  const btnSave = document.getElementById('mgr-prof-save');
  const resetLink = document.getElementById('mgr-prof-reset-link');

  if (fileInput){
    fileInput.onchange = () => {
      const f = fileInput.files && fileInput.files[0];
      if (!f) return;
      const reader = new FileReader();
      reader.onload = (e) => {
        pendingDataUrl = String(e.target && e.target.result || '');
        if (imgEl){ imgEl.src = pendingDataUrl; imgEl.classList.remove('hidden'); }
        if (phEl){ phEl.classList.add('hidden'); }
      };
      reader.readAsDataURL(f);
    };
  }

  if (btnRemove){
    btnRemove.onclick = async () => {
      try {
        const fd = new FormData();
        fd.append('operation', 'updateProfileImage');
        fd.append('json', JSON.stringify({ employee_id: user.employee_id, profile_image: '' }));
        const res = await axios.post(`${baseApiUrl}/employees.php`, fd);
        const ok = res && res.data && (res.data.success === 1 || res.data === 1);
        if (ok){
          mgrClearProfileImg(user.employee_id);
          if (imgEl){ imgEl.src=''; imgEl.classList.add('hidden'); }
          if (phEl){ phEl.textContent = displayName.substring(0,1).toUpperCase(); phEl.classList.remove('hidden'); }
          // Update header avatar to show removed image
          await syncManagerHeaderAvatar(user);
          // Update welcome section avatar if on dashboard
          await updateWelcomeSection(user);
          showToast('Profile image removed', 'success');
        } else { showToast('Failed to remove image', 'error'); }
      } catch { showToast('Failed to remove image', 'error'); }
    };
  }

  if (btnSave){
    btnSave.onclick = async () => {
      try {
        const dataUrl = pendingDataUrl || imgEl && !imgEl.classList.contains('hidden') ? imgEl.src : '';
        if (!dataUrl){ showToast('Select an image to upload', 'warning'); return; }
        const fd = new FormData();
        fd.append('operation', 'updateProfileImage');
        fd.append('json', JSON.stringify({ employee_id: user.employee_id, profile_image: dataUrl }));
        const res = await axios.post(`${baseApiUrl}/employees.php`, fd);
        const ok = res && res.data && (res.data.success === 1 || res.data === 1);
        if (ok){
          mgrSaveProfileImg(user.employee_id, dataUrl);
          // Update header avatar with new image
          await syncManagerHeaderAvatar(user);
          // Update welcome section avatar if on dashboard
          await updateWelcomeSection(user);
          showToast('Profile image saved', 'success');
        } else { showToast('Failed to save image', 'error'); }
      } catch { showToast('Failed to save image', 'error'); }
    };
  }

  if (resetLink){
    resetLink.onclick = (e) => {
      e.preventDefault();
      const rm = document.getElementById('mgrResetPwdModal');
      if (rm) rm.classList.remove('hidden');
      const savePwdBtn = document.getElementById('mgr-resetpwd-save');
      if (savePwdBtn){
        savePwdBtn.onclick = async () => {
          try {
            const pwd = (document.getElementById('mgr-newpwd')?.value || '').trim();
            const cpwd = (document.getElementById('mgr-newpwd-confirm')?.value || '').trim();
            if (pwd.length < 6){ showToast('Password must be at least 6 characters', 'warning'); return; }
            if (pwd !== cpwd){ showToast('Passwords do not match', 'error'); return; }
            const fd = new FormData();
            fd.append('operation', 'updateEmployee');
            fd.append('json', JSON.stringify({ employee_id: user.employee_id, hr_password: pwd }));
            const res = await axios.post(`${baseApiUrl}/employees.php`, fd);
            const ok = res && res.data && (res.data.success === 1 || res.data === 1 || res.data.success === true);
            if (ok){ showToast('Password updated successfully', 'success'); document.getElementById('mgrResetPwdModal')?.classList.add('hidden'); }
            else { showToast(res?.data?.message || 'Failed to update password', 'error'); }
          } catch (err){ showToast('An error occurred while updating password', 'error'); }
        };
      }
    };
  }

  modal.classList.remove('hidden');
}

function wireHeader(){
  // Prevent duplicate event bindings when navigating between routes
  if (window.__mgrNotifHeaderWired) return;
  window.__mgrNotifHeaderWired = true;

  const toggle = document.getElementById('notif-toggle');
  const dropdown = document.getElementById('notif-dropdown');
  const closeBtn = document.getElementById('notif-close');
  const markAllBtn = document.getElementById('notif-mark-all');
    if (!toggle || !dropdown) return;

  const close = () => dropdown.classList.add('hidden');

  const refreshNotifications = async () => {
    try { await renderNotifications(); } catch {}
  };

  toggle.addEventListener('click', async (e) => {
    e.stopPropagation();
    dropdown.classList.toggle('hidden');
    if (!dropdown.classList.contains('hidden')) {
      await refreshNotifications();
    }
  });

  try {
    if (window.__mgrNotifInterval) { clearInterval(window.__mgrNotifInterval); }
  } catch {}
  try {
    window.__mgrNotifInterval = setInterval(refreshNotifications, 5000);
    if (!window.__mgrNotifVisibilityHooked) {
      window.__mgrNotifVisibilityHooked = true;
      try {
        document.addEventListener('visibilitychange', () => {
          if (!document.hidden) { refreshNotifications(); }
        });
        window.addEventListener('focus', refreshNotifications);
      } catch {}
    }
  } catch {}

  if (closeBtn) closeBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    try { await markAllManagerNotifsAsRead(); await refreshNotifications(); } catch {}
    close();
  });

  if (markAllBtn) markAllBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    try { await markAllManagerNotifsAsRead(); await refreshNotifications(); } catch {}
  });

  document.addEventListener('click', (e) => {
    if (!dropdown.contains(e.target) && !toggle.contains(e.target)) close();
  });

  // Immediate fetch so badge/count appear without waiting for interval
  refreshNotifications();
}

async function renderCards(dept, me){
  try {
    // Fetch base counts
    const [empRes, attRes, leavesRes] = await Promise.all([
      axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
      axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: new Date().toISOString().slice(0,10), end_date: new Date().toISOString().slice(0,10) } }),
      axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listPending' } })
    ]);
    const meId = me && me.employee_id ? String(me.employee_id) : '';
    const employees = (empRes.data || []).filter(e => (e.department || '').toLowerCase() === (dept || '').toLowerCase() && (meId ? String(e.employee_id) !== meId : true));
    const today = (attRes.data || []).filter(r => (r.department || '').toLowerCase() === (dept || '').toLowerCase() && (meId ? String(r.employee_id) !== meId : true));
    const presentToday = today.filter(r => ['present','late','undertime','leave'].includes(String(r.status || '').toLowerCase())).length;
    const absentToday = Math.max(0, employees.length - presentToday);
    const pendingLeaves = (leavesRes.data || []).filter(l => (l.status || '').toLowerCase() === 'pending').filter(l => {
      const emp = employees.find(e => String(e.employee_id) === String(l.employee_id));
      return !!emp;
    }).length;

    const cards = [
      { label: 'Employees Under Department', value: employees.length, icon: 'users', id: 'emp_under_dept' },
      { label: 'Present Today', value: presentToday, icon: 'check', id: 'present' },
      { label: 'Absent Today', value: absentToday, icon: 'x', id: 'absent' },
      { label: 'Pending Leave Requests', value: pendingLeaves, icon: 'clock', id: 'pending_leaves' }
    ];
    const iconSvg = (name, cls = 'text-gray-600') => {
      if (name === 'users') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M12 12a4 4 0 100-8 4 4 0 000 8z"/><path d="M2 20c0-3.314 4.03-6 10-6s10 2.686 10 6v1H2v-1z"/></svg>`;
      if (name === 'check') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.2l-3.5-3.5a1 1 0 10-1.4 1.4l4.2 4.2a1 1 0 001.4 0l10-10a1 1 0 10-1.4-1.4L9 16.2z"/></svg>`;
      if (name === 'x') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M6.225 4.811a1 1 0 011.414 0L12 9.172l4.361-4.361a1 1 0 111.414 1.414L13.414 10.586l4.361 4.361a1 1 0 01-1.414 1.414L12 12l-4.361 4.361a1 1 0 01-1.414-1.414l4.361-4.361-4.361-4.361a1 1 0 010-1.414z"/></svg>`;
      if (name === 'clock') return `<svg class="w-5 h-5 ${cls}" viewBox="0 0 24 24" fill="currentColor"><path d="M12 8a1 1 0 011 1v3h3a1 1 0 110 2h-4a1 1 0 01-1-1V9a1 1 0 011-1z"/><path fill-rule="evenodd" d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zM4 12a8 8 0 1116 0 8 8 0 01-16 0z" clip-rule="evenodd"/></svg>`;
      return '';
    };
    const renderCard = (c) => {
      const palMap = {
        blue: { bg: 'bg-blue-50', text: 'text-blue-600', ring: 'ring-blue-200' },
        emerald: { bg: 'bg-emerald-50', text: 'text-emerald-600', ring: 'ring-emerald-200' },
        rose: { bg: 'bg-rose-50', text: 'text-rose-600', ring: 'ring-rose-200' },
        amber: { bg: 'bg-amber-50', text: 'text-amber-600', ring: 'ring-amber-200' }
      };
      const color = c.id === 'emp_under_dept' ? 'blue' : (c.id === 'present' ? 'emerald' : (c.id === 'absent' ? 'rose' : (c.id === 'pending_leaves' ? 'amber' : 'gray')));
      const pal = palMap[color] || { bg: 'bg-gray-100', text: 'text-gray-600', ring: 'ring-gray-200' };
      return `
      <div class="rounded-lg bg-white shadow ${(c.id === 'absent' || c.id === 'emp_under_dept' || c.id === 'present' || c.id === 'pending_leaves') ? 'cursor-pointer hover:shadow-md' : ''}" data-card-id="${c.id || ''}">
        <div class="p-4 flex items-center gap-3">
          <div class="w-10 h-10 rounded-full ${pal.bg} ${pal.ring} ring-1 flex items-center justify-center">${iconSvg(c.icon, pal.text)}</div>
          <div>
            <div class="text-xs uppercase tracking-wide text-gray-500">${c.label}</div>
            <div class="text-2xl font-semibold">${c.value}</div>
          </div>
        </div>
      </div>`;
    };
    const wrap = document.getElementById('mgr-cards');
    if (wrap) wrap.innerHTML = cards.map(renderCard).join('');
      async function showEmployeesUnderDeptList(){
        try {
          const [empRes, meRes] = await Promise.all([
            axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
            axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true })
          ]);
          const me = meRes.data && meRes.data.user ? meRes.data.user : await currentUser();
          const deptLc = (me && me.department ? String(me.department) : '').toLowerCase().trim();
          const myId = me && me.employee_id ? String(me.employee_id) : '';
          const all = Array.isArray(empRes.data) ? empRes.data : [];
          const list = all.filter(e => {
            const d = String(e.department || '').toLowerCase().trim();
            const notMe = myId ? String(e.employee_id) !== myId : true;
            return d === deptLc && notMe;
          });
          let modal = document.getElementById('mgrEmpUnderDeptModal');
          if (!modal) { modal = document.createElement('div'); modal.id='mgrEmpUnderDeptModal'; modal.className='fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
          let query = '';
          const renderTable = () => {
            const rows = (!query ? list : list.filter(e => {
              const name = `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`;
              const dept = String(e.department || '').toLowerCase();
              const pos = String(e.position || '').toLowerCase();
              const st = String(e.status || '').toLowerCase();
              return name.includes(query) || dept.includes(query) || pos.includes(query) || st.includes(query);
            }));
            const wrap = document.getElementById('mgr-empdept-table-wrap');
            if (!wrap) return;
            if (!rows.length) { wrap.innerHTML = '<div class="text-sm text-gray-500">No employees in your department</div>'; return; }
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
                  <h5 class="font-semibold">Employees Under Department (${list.length})</h5>
                  <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
                </div>
                <div class="p-4">
                  <div class="mb-3 flex items-center gap-2">
                    <div class="relative">
                      <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
                      <input id="mgr-empdept-search" class="w-64 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, department, position, status" />
                    </div>
                    <button id="mgr-empdept-clear" class="text-xs text-gray-600 border rounded px-2 py-1">Clear</button>
                    <a href="#employee" class="ml-auto text-primary-700 text-sm hover:underline">Open Employees</a>
                  </div>
                  <div id="mgr-empdept-table-wrap" class="overflow-auto max-h-[48vh]"></div>
                </div>
                <div class="flex justify-end items-center gap-2 border-t px-4 py-3">
                  <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
                </div>
              </div>
            </div>`;
          modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
          const si = document.getElementById('mgr-empdept-search');
          const sc = document.getElementById('mgr-empdept-clear');
          if (si) si.addEventListener('input', () => { query = (si.value || '').trim().toLowerCase(); renderTable(); });
          if (sc) sc.addEventListener('click', () => { if (si) si.value=''; query=''; renderTable(); });
          renderTable();
          modal.classList.remove('hidden');
        } catch {
          try { alert('Failed to load employees'); } catch {}
        }
      }
      // Wire Absent Today card to show read-only list for managers
      async function showPresentTodayList(){
        try {
          const todayStr = new Date().toLocaleDateString('en-CA');
          const [empRes, attRes, leaveRes, meRes] = await Promise.all([
            axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
            axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: todayStr, end_date: todayStr } }),
            axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listApproved', start_date: todayStr, end_date: todayStr } }),
            axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true })
          ]);
          const me = meRes.data && meRes.data.user ? meRes.data.user : await currentUser();
          const deptLc = (me && me.department ? String(me.department) : '').toLowerCase().trim();
          const myId = me && me.employee_id ? String(me.employee_id) : '';
          const all = Array.isArray(empRes.data) ? empRes.data : [];
          const allowed = all.filter(e => {
            const d = String(e.department || '').toLowerCase().trim();
            const notMe = myId ? String(e.employee_id) !== myId : true;
            return d === deptLc && notMe;
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
          let modal = document.getElementById('mgrPresentTodayModal');
          if (!modal) { modal = document.createElement('div'); modal.id = 'mgrPresentTodayModal'; modal.className = 'fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
          let query = '';
          const renderTable = () => {
            const filtered = (!query ? list : list.filter(e => {
              const name = `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.trim();
              const dept = String(e.department || '').toLowerCase();
              const st = String(e.status || '').toLowerCase();
              return name.includes(query) || dept.includes(query) || st.includes(query);
            }));
            const wrap = document.getElementById('mgr-present-table-wrap');
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
                      <input id="mgr-present-search" class="w-64 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, department, status" />
                    </div>
                    <button id="mgr-present-clear" class="text-xs text-gray-600 border rounded px-2 py-1">Clear</button>
                    <a href="#attendance" class="ml-auto text-primary-700 text-sm hover:underline">Open Attendance</a>
                  </div>
                  <div id="mgr-present-table-wrap" class="overflow-auto max-h-[48vh]"></div>
                </div>
                <div class="flex justify-end items-center gap-2 border-t px-4 py-3">
                  <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
                </div>
              </div>
            </div>`;
          modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
          const si = document.getElementById('mgr-present-search');
          const sc = document.getElementById('mgr-present-clear');
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
          const [resLeaves, resEmp, meRes] = await Promise.all([
            axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listPending' } }),
            axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
            axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true })
          ]);
          const me = meRes.data && meRes.data.user ? meRes.data.user : await currentUser();
          const dept = (me && me.department ? String(me.department) : '').toLowerCase();
          const emap = new Map((resEmp.data || []).filter(e => String(e.department || '').toLowerCase() === dept).map(e => [String(e.employee_id), e]));
          const rows = (resLeaves.data || []).filter(l => emap.has(String(l.employee_id)));
          const daysInclusive = (start, end) => {
            try {
              const parse = (s) => { const [y,m,d] = String(s||'').split('-').map(n=>parseInt(n,10)); return Date.UTC(y||1970,(m||1)-1,d||1); };
              const a = parse(start), b = parse(end || start);
              if (!Number.isFinite(a) || !Number.isFinite(b)) return '';
              const diff = Math.floor((b - a) / 86400000) + 1;
              return diff > 0 ? diff : 1;
            } catch { return ''; }
          };
          let modal = document.getElementById('mgrPendingLeavesModal');
          if (!modal) { modal = document.createElement('div'); modal.id = 'mgrPendingLeavesModal'; modal.className = 'fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
          let query = '';
          const renderTable = () => {
            const list = (!query ? rows : rows.filter(r => {
              const e = emap.get(String(r.employee_id)) || {};
              const name = `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.trim();
              const type = String(r.leave_type || '').toLowerCase();
              const dates = `${String(r.start_date||'')} ${String(r.end_date||'')}`.toLowerCase();
              const reason = String(r.reason || '').toLowerCase();
              const status = String(r.status || '').toLowerCase();
              return name.includes(query) || type.includes(query) || dates.includes(query) || reason.includes(query) || status.includes(query);
            }));
            const wrap = document.getElementById('mgr-pendleaves-table-wrap');
            if (!wrap) return;
            if (!list.length) { wrap.innerHTML = '<div class="text-sm text-gray-500">No pending leaves.</div>'; return; }
            const trs = list.map((r, idx) => {
              const e = emap.get(String(r.employee_id)) || {};
              const name = toTitleCase(`${e.first_name || ''} ${e.last_name || ''}`.trim());
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
                      <input id="mgr-pendleaves-search" class="w-72 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search name, type, date, reason, status" />
                    </div>
                    <button id="mgr-pendleaves-clear" class="text-xs text-gray-600 border rounded px-2 py-1">Clear</button>
                    <a href="#leaves" class="ml-auto text-primary-700 text-sm hover:underline">Open Leave Management</a>
                  </div>
                  <div id="mgr-pendleaves-table-wrap" class="overflow-auto max-h-[48vh]"></div>
                </div>
                <div class="flex justify-end items-center gap-2 border-t px-4 py-3">
                  <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
                </div>
              </div>
            </div>`;
          modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
          const si = document.getElementById('mgr-pendleaves-search');
          const sc = document.getElementById('mgr-pendleaves-clear');
          if (si) si.addEventListener('input', () => { query = (si.value || '').trim().toLowerCase(); renderTable(); });
          if (sc) sc.addEventListener('click', () => { if (si) si.value=''; query=''; renderTable(); });
          renderTable();
          modal.classList.remove('hidden');
        } catch {
          try { alert('Failed to load pending leaves'); } catch {}
        }
      }
      async function showAbsentTodayList(){
        try {
          const todayStr = new Date().toLocaleDateString('en-CA');
          const [empRes, attRes, leaveRes] = await Promise.all([
            axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
            axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: todayStr, end_date: todayStr } }),
            axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listApproved', start_date: todayStr, end_date: todayStr } })
          ]);
          const emps = Array.isArray(empRes.data) ? empRes.data : [];
          const allowed = emps.filter(e => (String(e.department || '').toLowerCase() === String(dept || '').toLowerCase()) && (me && me.employee_id ? String(e.employee_id) !== String(me.employee_id) : true));
          const allowedIds = new Set(allowed.map(e => String(e.employee_id)));
          const attRows = Array.isArray(attRes.data) ? attRes.data : [];
          const leaveRows = Array.isArray(leaveRes.data) ? leaveRes.data : [];
          const union = new Set();
          attRows.forEach(r => {
            const eid = String(r.employee_id || '');
            if (!allowedIds.has(eid)) return;
            const d = String(r.attendance_date || r.date || r.created_at || r.time_in || '').slice(0,10);
            const st = String(r.status || '').toLowerCase();
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

          let modal = document.getElementById('mgrAbsentListModal');
          if (!modal){
            modal = document.createElement('div');
            modal.id = 'mgrAbsentListModal';
            modal.className = 'fixed inset-0 z-50 hidden';
            document.body.appendChild(modal);
          }

          let query = '';
          const t = (s) => { try { return toTitleCase(String(s||'')); } catch { return String(s||''); } };
          const getFiltered = () => {
            const q = (query || '').toLowerCase();
            if (!q) return absentees.slice();
            return absentees.filter(e => {
              const name = `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.trim();
              const deptLc = String(e.department || '').toLowerCase();
              return name.includes(q) || deptLc.includes(q);
            });
          };
          const renderTable = () => {
            const wrapTbl = document.getElementById('mgr-absent-table-wrap');
            if (!wrapTbl) return;
            const list = getFiltered();
            if (!list.length){
              wrapTbl.innerHTML = '<div class="text-sm text-gray-500">No matches</div>';
              return;
            }
            const rowsHtml = list.map(e => `
              <tr>
                <td class=\"px-3 py-2 text-sm text-gray-700\">${t(`${e.first_name || ''} ${e.last_name || ''}`.trim())}</td>
                <td class=\"px-3 py-2 text-sm text-gray-700\">${t(e.department || '')}</td>
              </tr>`).join('');
            wrapTbl.innerHTML = `
              <table class=\"min-w-full divide-y divide-gray-200\">
                <thead class=\"bg-gray-50\">
                  <tr>
                    <th class=\"px-3 py-2 text-left text-xs font-semibold text-gray-600\">Employee</th>
                    <th class=\"px-3 py-2 text-left text-xs font-semibold text-gray-600\">Department</th>
                  </tr>
                </thead>
                <tbody class=\"divide-y divide-gray-200 bg-white\">${rowsHtml}</tbody>
              </table>`;
          };

          modal.innerHTML = `
            <div class=\"absolute inset-0 bg-black/50\" data-close=\"true\"></div>
            <div class=\"relative mx-auto mt-20 w-full max-w-2xl\">
              <div class=\"bg-white rounded-lg shadow max-h-[80vh] flex flex-col\">
                <div class=\"flex items-center justify-between border-b px-4 py-3\">
                  <h5 class=\"font-semibold\">Absent Today (${absentees.length})</h5>
                  <button class=\"text-gray-500 hover:text-gray-700 text-xl leading-none\" data-close=\"true\">×</button>
                </div>
                <div class=\"p-4\">
                  <div class=\"mb-3 flex items-center gap-2\">
                    <div class=\"relative\">
                      <svg class=\"pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400\" xmlns=\"http://www.w3.org/2000/svg\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z\"/></svg>
                      <input id=\"mgr-absent-search\" class=\"w-64 border rounded pl-9 pr-3 py-1.5 text-sm\" placeholder=\"Search name or department\" />
                    </div>
                    <button id=\"mgr-absent-clear\" class=\"text-xs text-gray-600 border rounded px-2 py-1\">Clear</button>
                    <a href=\"#attendance\" class=\"ml-auto text-primary-700 text-sm hover:underline\">Open Attendance</a>
                  </div>
                  <div id=\"mgr-absent-table-wrap\" class=\"overflow-auto max-h-[48vh]\"></div>
                </div>
                <div class=\"flex justify-between items-center gap-2 border-t px-4 py-3\">
                  <div class=\"text-xs text-gray-500\">Managers have view-only access to absentees.</div>
                  <div class=\"flex items-center gap-2\">
                    <button class=\"px-3 py-2 text-sm rounded border\" data-close=\"true\">Close</button>
                    <button id=\"mgr-absent-mark-btn\" class=\"px-3 py-2 text-sm rounded bg-rose-600 text-white opacity-50 cursor-not-allowed\" disabled title=\"Only Admin/HR can mark absences\">Mark selected as Absent</button>
                  </div>
                </div>
              </div>
            </div>`;

          modal.querySelectorAll('[data-close=\"true\"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
          const searchInp = document.getElementById('mgr-absent-search');
          const clearBtn = document.getElementById('mgr-absent-clear');
          if (searchInp) searchInp.addEventListener('input', () => { query = (searchInp.value || '').trim(); renderTable(); });
          if (clearBtn) clearBtn.addEventListener('click', () => { if (searchInp) searchInp.value = ''; query = ''; renderTable(); });

          renderTable();
          modal.classList.remove('hidden');
        } catch {
          try { showToast('Failed to load absent list', 'error'); } catch {}
        }
      }
      try {
        const empUnderEl = wrap && wrap.querySelector('[data-card-id="emp_under_dept"]');
        if (empUnderEl) empUnderEl.addEventListener('click', async () => { await showEmployeesUnderDeptList(); });
        const presentEl = wrap && wrap.querySelector('[data-card-id="present"]');
        if (presentEl) presentEl.addEventListener('click', async () => { await showPresentTodayList(); });
        const pendingEl = wrap && wrap.querySelector('[data-card-id="pending_leaves"]');
        if (pendingEl) pendingEl.addEventListener('click', async () => { await showPendingLeavesList(); });
        const absentEl = wrap && wrap.querySelector('[data-card-id="absent"]');
        if (absentEl) absentEl.addEventListener('click', async () => { await showAbsentTodayList(); });
      } catch {}
  } catch {}
}

async function renderAttendanceTrend(dept){
  try {
    // Get last 14 days attendance and filter by dept
    const end = new Date();
    const start = new Date();
    start.setDate(end.getDate() - 13);
    const params = { operation: 'getAttendance', start_date: start.toISOString().slice(0,10), end_date: end.toISOString().slice(0,10) };
    const res = await axios.get(`${baseApiUrl}/attendance.php`, { params });
    const rows = res.data || [];
    const dLc = (dept || '').toLowerCase();
    const byDate = new Map();
    rows.filter(r => (r.department || '').toLowerCase() === dLc).forEach(r => {
      const d = String(r.attendance_date || '').slice(0,10);
      if (!byDate.has(d)) byDate.set(d, { present: 0, total: 0 });
      const rec = byDate.get(d);
      rec.total += 1;
      if (['present','late','undertime','leave'].includes(String(r.status || '').toLowerCase())) rec.present += 1;
    });
    const dates = [];
    for (let i=0;i<14;i++){
      const d = new Date(start);
      d.setDate(start.getDate() + i);
      dates.push(d.toISOString().slice(0,10));
    }
    const labels = dates.map(s => new Date(s).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    const rate = dates.map(s => {
      const rec = byDate.get(s) || { present:0, total:0 };
      return rec.total > 0 ? Math.round((rec.present/rec.total)*100) : 0;
    });
    const ctx = document.getElementById('mgrAttendanceTrend');
    if (!ctx) return;
    new Chart(ctx, { type: 'bar', data: { labels, datasets: [{ label: 'Attendance %', data: rate, backgroundColor: 'rgba(59,130,246,0.6)', borderColor: '#2563eb', borderWidth: 1 }] }, options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, max: 100, ticks: { callback: (v)=>`${v}%` } } }, plugins: { legend: { position: 'top' } } } });
  } catch {}
}

async function renderLeaveBreakdown(dept){
  try {
    // Pull last 60 days leaves and filter by dept
    const resLeaves = await axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listRecent' } });
    const leaves = (resLeaves.data || [])
      .filter(l => String(l.status || '').toLowerCase() === 'approved')
      .filter(l => (l.leave_type || '').length > 0);
    // Need mapping of employee->department
    const resEmp = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
    const dLc = (dept || '').toLowerCase();
    const emap = new Map((resEmp.data || []).filter(e => (e.department || '').toLowerCase() === dLc).map(e => [String(e.employee_id), e]));
    const counts = new Map();
    leaves.forEach(l => {
      const emp = emap.get(String(l.employee_id));
      if (!emp) return;
      const typ = String(l.leave_type || 'other').toLowerCase();
      counts.set(typ, (counts.get(typ) || 0) + 1);
    });
    const labels = Array.from(counts.keys()).map(s => toTitleCase(s));
    const data = Array.from(counts.values());
    const ctx = document.getElementById('mgrLeaveBreakdown');
    if (!ctx) return;
    new Chart(ctx, { type: 'pie', data: { labels, datasets: [{ data, backgroundColor: ['#10b981', '#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#14b8a6', '#f97316', '#6366f1'] }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } } });
  } catch {}
}

async function renderOvertime(dept){
  try {
    // Use payroll list and sum overtime by department
    const resPayroll = await axios.get(`${baseApiUrl}/payroll.php`, { params: { operation: 'listPayroll' } });
    const rows = resPayroll.data || [];
    const dLc = (dept || '').toLowerCase();
    // Need employees mapping
    const resEmp = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
    const emap = new Map((resEmp.data || []).filter(e => (e.department || '').toLowerCase() === dLc).map(e => [String(e.employee_id), e]));
    const byEmp = new Map();
    rows.forEach(p => {
      const emp = emap.get(String(p.employee_id));
      if (!emp) return;
      const name = toTitleCase(`${emp.first_name || ''} ${emp.last_name || ''}`.trim());
      byEmp.set(name, (byEmp.get(name) || 0) + Number(p.total_overtime_hours || 0));
    });
    const labels = Array.from(byEmp.keys());
    const hours = Array.from(byEmp.values());
    const ctx = document.getElementById('mgrOvertime');
    if (!ctx) return;
    new Chart(ctx, { type: 'bar', data: { labels, datasets: [{ label: 'OT Hours', data: hours, backgroundColor: '#3b82f6', borderColor: '#2563eb', borderWidth: 1 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'top' } }, scales: { y: { beginAtZero: true } } } });
  } catch {}
}

async function renderNotifications(deptParam){
  const list = document.getElementById('mgr-notif-list') || document.getElementById('notif-list');
  const dropList = document.getElementById('mgr-notif-dropdown-list') || document.getElementById('notif-list');
  const badge = document.getElementById('notif-badge');
  const toArray = (input) => {
    if (Array.isArray(input)) return input;
    if (!input) return [];
    if (typeof input === 'string') {
      try {
        const parsed = JSON.parse(input);
        return Array.isArray(parsed) ? parsed : [];
      } catch { return []; }
    }
    if (typeof input === 'object') {
      if (Array.isArray(input.data)) return input.data;
      if (Array.isArray(input.records)) return input.records;
      if (Array.isArray(input.rows)) return input.rows;
    }
    return [];
  };
  const getEmployeeId = (row) => {
    if (!row || typeof row !== 'object') return '';
    const candidates = [row.employee_id, row.EmployeeID, row.EmployeeId, row.emp_id, row.EmpID];
    for (const candidate of candidates) {
      if (candidate !== undefined && candidate !== null && candidate !== '') {
        return String(candidate);
      }
    }
    return '';
  };
  const normalizeDept = (val) => {
    if (typeof val === 'string' && val.trim() !== '') return val.trim().toLowerCase();
    return '';
  };
  const getDeptFromRow = (row) => normalizeDept(row?.department ?? row?.Department ?? row?.dept ?? row?.Dept ?? '');
  const getFirstName = (row) => {
    if (!row) return '';
    return String(row.first_name ?? row.FirstName ?? row.firstname ?? '').trim();
  };
  const getLastName = (row) => {
    if (!row) return '';
    return String(row.last_name ?? row.LastName ?? row.lastname ?? '').trim();
  };
  const resolveName = (primary, fallback) => {
    const first = getFirstName(primary) || getFirstName(fallback);
    const last = getLastName(primary) || getLastName(fallback);
    const full = `${first} ${last}`.trim();
    return full ? toTitleCase(full) : 'Team member';
  };
  try {
    // Determine department
    const me = await currentUser();
    let dept = (deptParam || (me && me.department ? me.department : '')).toString().trim().toLowerCase();

    // Fetch data for the three categories
    const today = new Date().toISOString().slice(0,10);
    const [empRes, leavesRes, otRes, utRes, attRes, notifRes] = await Promise.all([
      axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
      axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listPending' } }),
      axios.get(`${baseApiUrl}/overtime.php`, { params: { operation: 'listPending' } }),
      axios.get(`${baseApiUrl}/undertime.php`, { params: { operation: 'listPending' } }),
      axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: today, end_date: today } }),
      axios.get(`${baseApiUrl}/notifications.php`, { params: { operation: 'getNotifications' }, withCredentials: true })
    ]);

    const employees = toArray(empRes?.data).filter(e => getEmployeeId(e));
    let deptFilterActive = false;
    let scopedEmployees = employees;
    if (dept) {
      const byDept = employees.filter(e => getDeptFromRow(e) === dept);
      if (byDept.length) {
        scopedEmployees = byDept;
        deptFilterActive = true;
      }
    }
    if (!scopedEmployees.length) {
      scopedEmployees = employees;
      deptFilterActive = false;
    }
    const emap = new Map(scopedEmployees.map(e => [getEmployeeId(e), e]));
    const includeByDept = (record) => {
      if (!deptFilterActive) return true;
      const id = getEmployeeId(record);
      if (id && emap.has(id)) return true;
      const rowDept = getDeptFromRow(record);
      return rowDept !== '' && rowDept === dept;
    };

    // 1) Leave requests from team members (pending)
    const pendingLeaves = toArray(leavesRes?.data);
    const leaveItems = pendingLeaves
      .filter(l => includeByDept(l))
      .map(l => {
        const emp = emap.get(getEmployeeId(l)) || {};
        const name = resolveName(emp, l);
        return {
          type: 'leave',
          created_at: l.created_at || `${l.start_date || today}T00:00:00`,
          text: `Leave request — ${name} (${l.start_date} → ${l.end_date})`
        };
      });

    // 2) Overtime/Undertime requests from team members (pending)
    const pendingOt = toArray(otRes?.data);
    const otItems = pendingOt
      .filter(r => includeByDept(r))
      .map(r => {
        const emp = emap.get(getEmployeeId(r)) || {};
        const name = resolveName(emp, r);
        const hours = (r.hours != null) ? Number(r.hours).toFixed(2) : (r.start_time && r.end_time ? `${r.start_time}–${r.end_time}` : '');
        return {
          type: 'overtime',
          created_at: r.created_at || `${r.work_date || today}T00:00:00`,
          text: `Overtime request — ${name} (${r.work_date}${hours ? `, ${hours}h` : ''})`
        };
      });

    const pendingUt = toArray(utRes?.data);
    const utItems = pendingUt
      .filter(r => includeByDept(r))
      .map(r => {
        const emp = emap.get(getEmployeeId(r)) || {};
        const name = resolveName(emp, r);
        const hours = (r.hours != null) ? Number(r.hours).toFixed(2) : '';
        return {
          type: 'undertime',
          created_at: r.created_at || `${r.work_date || today}T00:00:00`,
          text: `Undertime request — ${name} (${r.work_date}${hours ? `, ${hours}h` : ''})`
        };
      });

    // 3) Attendance issues (late, absent, undertime) for today
    const todaysAttendance = toArray(attRes?.data);
    const attIssues = todaysAttendance
      .filter(a => includeByDept(a))
      .filter(a => /^(late|absent|undertime)$/i.test(String(a.status || '')))
      .map(a => {
        const emp = emap.get(getEmployeeId(a)) || {};
        const name = resolveName(emp, a);
        const st = toTitleCase(String(a.status || ''));
        return {
          type: 'attendance',
          created_at: `${a.attendance_date || today}T${a.time_in || '00:00:00'}`,
          text: `Attendance issue — ${name}: ${st} (${a.attendance_date})`
        };
      });

    // 4) System notifications for manager (only leave cancellations)
    let notifData = notifRes?.data;
    if (typeof notifData === 'string') {
      try { notifData = JSON.parse(notifData); } catch { notifData = {}; }
    }
    const notifItems = ((notifData && notifData.success) ? toArray(notifData.notifications) : [])
      .filter(n => String(n.type || '') === 'leave_cancelled')
      .map(n => ({ type: 'system', created_at: n.created_at || '', text: n.message || '', read_at: n.read_at || null }));

    // Combine and sort newest first (normalize timestamps to avoid ' ' vs 'T' issues)
    const parseTs = (s) => {
      try {
        const str = String(s || '').replace(' ', 'T');
        const d = new Date(str);
        const t = d.getTime();
        return Number.isFinite(t) ? t : 0;
      } catch { return 0; }
    };
    let items = [...leaveItems, ...otItems, ...utItems, ...attIssues, ...notifItems]
      .map(it => ({ ...it, ts: parseTs(it.created_at) }))
      .sort((a,b) => b.ts - a.ts);

    // Badge shows unread count from DB notifications (align with employee behavior)
    const dbNotifs = (notifData && notifData.success) ? toArray(notifData.notifications) : [];
    const unreadCount = dbNotifs.filter(n => !(n.read_at || n.readAt || n.read)).length;
    if (badge) {
      if (unreadCount > 0) {
        badge.textContent = unreadCount;
        badge.classList.remove('hidden');
        badge.classList.add('animate-zoom-pulse');
      } else {
        badge.classList.add('hidden');
        badge.classList.remove('animate-zoom-pulse');
      }
    }

    // Render card list (fade read notifications like employee UI)
    if (list) {
      list.innerHTML = items.length ? items.map(n => `
        <li class="py-2 ${n.read_at ? 'opacity-75' : ''}">
          <div class="flex items-start justify-between gap-3">
            <div>
              <div class="${n.read_at ? 'text-gray-600' : 'text-gray-800 font-medium'}">${escapeHtml(n.text)}</div>
              <div class="text-xs text-gray-400 mt-0.5">${formatTime(n.created_at)}</div>
            </div>
          </div>
        </li>`).join('') : '<li class="py-2 text-gray-500">No notifications</li>';
    }

    // Render header dropdown list (fade read notifications like employee UI)
    if (dropList) {
      dropList.innerHTML = items.length ? items.map(n => `
        <div class="px-4 py-2 border-t first:border-t-0 ${n.read_at ? 'opacity-75' : ''}">
          <div class="text-sm ${n.read_at ? 'text-gray-600' : 'text-gray-800 font-medium'}">${escapeHtml(n.text)}</div>
          <div class="text-xs text-gray-400 mt-0.5">${formatTime(n.created_at)}</div>
        </div>`).join('') : '<div class="px-4 py-6 text-sm text-gray-500 text-center">No notifications</div>';
    }
  } catch {
    if (list) list.innerHTML = '<li class="py-2 text-red-600">Failed to load notifications</li>';
    const dropListEl = document.getElementById('mgr-notif-dropdown-list') || document.getElementById('notif-list');
    if (dropListEl) dropListEl.innerHTML = '<div class="px-4 py-6 text-sm text-red-600 text-center">Failed to load notifications</div>';
  }
}

async function renderRecent(dept){
  const ul = document.getElementById('mgr-recent-activities');
  if (!ul) return;
  try {
    const res = await axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'recentActivities', limit: 50 } });
    const dLc = (dept || '').toLowerCase();
    const items = (res.data || []).filter(a => (a.department || '').toLowerCase() === dLc);
    if (!items.length){ ul.innerHTML = '<li class="py-2 text-gray-500">No recent activity</li>'; return; }
    ul.innerHTML = items.slice(0, 10).map(a => {
      const name = toTitleCase(`${a.first_name || ''} ${a.last_name || ''}`.trim());
      const ts = (() => { try { return new Date(`${a.attendance_date}T${a.time_in || a.time_out || '00:00:00'}`).toLocaleString(); } catch { return a.attendance_date; } })();
      return `<li class="py-2">
        <div class="flex items-center justify-between">
          <div>
            <div class="font-medium">${name}</div>
            <div class="text-xs text-gray-500">${toTitleCase(a.status || '')}</div>
          </div>
          <div class="text-xs text-gray-400">${ts}</div>
        </div>
      </li>`;
    }).join('');
  } catch {
    ul.innerHTML = '<li class="py-2 text-red-600">Failed to load recent activities</li>';
  }
}

async function renderDeptAttendanceTable(){
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h4 class="text-xl font-semibold">Department Attendance</h4>
    </div>
    <div class="bg-white rounded-lg shadow p-4">
      <div class="mb-3 flex items-center justify-between gap-3">
        <div class="flex items-center gap-2">
          <div class="relative">
            <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
            <input id="att-search-input" class="w-56 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search by name, status" />
          </div>
          <button id="att-search-clear" aria-label="Clear search" class="inline-flex items-center gap-1.5 border border-gray-300 rounded px-2.5 py-1 text-sm text-gray-700 hover:bg-gray-50 active:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1">
            <svg class="w-4 h-4 text-gray-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
            <span>Clear</span>
          </button>
          <input type="date" id="att-date" class="border rounded px-2.5 py-1 text-sm" />
          <select id="att-status-filter" class="border rounded px-2 py-1 text-sm">
            <option value="all" selected>All Status</option>
            <option value="present">Present</option>
            <option value="late">Late</option>
            <option value="absent">Absent</option>
            <option value="leave">On Leave</option>
          </select>
        </div>
        <div class="flex items-center gap-3">
          <span class="text-sm text-gray-600">Rows per page</span>
          <select id="att-page-size" class="border rounded px-2 py-1">
            <option value="10" selected>10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </div>
      </div>
      <div id="attendance-table"></div>
      <div id="attendance-pagination" class="mt-3 flex items-center justify-between text-sm text-gray-600"></div>
    </div>`;

  let allAttendance = [];
  let currentQuery = '';
  let currentPage = 1;
  let pageSize = 10;

  function formatDate(dateStr) {
    if (!dateStr) return '';
    try {
      const date = new Date(dateStr);
      if (isNaN(date.getTime())) return dateStr;
      return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch { return dateStr; }
  }
  function formatTimeOfDay(timeStr) {
    if (!timeStr) return '';
    try {
      const parts = String(timeStr).split(':');
      if (parts.length < 2) return timeStr;
      let h = parseInt(parts[0], 10);
      const m = parseInt(parts[1], 10) || 0;
      if (!Number.isFinite(h)) return timeStr;
      const ampm = h >= 12 ? 'PM' : 'AM';
      h = h % 12; if (h === 0) h = 12;
      const mm = String(m).padStart(2, '0');
      return `${h}:${mm} ${ampm}`;
    } catch { return timeStr; }
  }
  function calcTotalHours(attDate, tIn, tOut) {
    try {
      if (!tIn) return '';
      const inStr = `${attDate || ''}T${tIn}`;
      const dIn = new Date(inStr);
      let dOut = tOut ? new Date(`${attDate || ''}T${tOut}`) : new Date();
      if (Number.isNaN(dIn.getTime())) {
        const partsIn = String(tIn).split(':').map(Number);
        const partsOut = String(tOut || '').split(':').map(Number);
        if (!tOut || partsOut.length < 2 || partsIn.length < 2) return '';
        const hi = partsIn[0] || 0, mi = partsIn[1] || 0, si = partsIn[2] || 0;
        const ho = partsOut[0] || 0, mo = partsOut[1] || 0, so = partsOut[2] || 0;
        let inMinutes = hi * 60 + mi + si / 60;
        let outMinutes = ho * 60 + mo + so / 60;
        if (outMinutes < inMinutes) outMinutes += 24 * 60; // overnight
        const diffMinutes = outMinutes - inMinutes;
        if (!Number.isFinite(diffMinutes) || diffMinutes <= 0) return '';
        const totalMinutes = Math.round(diffMinutes);
        const h = Math.floor(totalMinutes / 60);
        const m = totalMinutes % 60;
        return m ? `${h}h ${m}m` : `${h}h`;
      }
      if (dOut.getTime() < dIn.getTime()) {
        dOut = new Date(dOut.getTime() + 24 * 60 * 60 * 1000);
      }
      const ms = dOut.getTime() - dIn.getTime();
      if (!Number.isFinite(ms) || ms <= 0) return '';
      const totalMinutes = Math.round(ms / (1000 * 60));
      const h = Math.floor(totalMinutes / 60);
      const m = totalMinutes % 60;
      return m ? `${h}h ${m}m` : `${h}h`;
    } catch { return ''; }
  }

  async function loadAttendance(){
    const tableDiv = document.getElementById('attendance-table');
    if (tableDiv) tableDiv.innerHTML = '<div class="text-gray-500">Loading...</div>';
    try {
      const me = await currentUser();
      const dept = (me && me.department) ? me.department : '';
      const selEl = document.getElementById('att-date');
      const effectiveDate = (selEl && selEl.value) ? selEl.value : new Date().toISOString().slice(0,10);
      const params = {
        operation: 'getAttendance',
        start_date: effectiveDate,
        end_date: effectiveDate
      };
      const [empRes, res] = await Promise.all([
        axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
        axios.get(`${baseApiUrl}/attendance.php`, { params })
      ]);
      const employees = Array.isArray(empRes.data) ? empRes.data : [];
      const roleById = new Map(employees.map(e => [String(e.employee_id), String(e.user_role || e.role || '').toLowerCase()]));
      const rows = (res.data || [])
        .filter(r => (r.department || '').toLowerCase() === (dept || '').toLowerCase())
        .filter(r => (roleById.get(String(r.employee_id)) || 'employee') !== 'manager');
      allAttendance = rows;
      currentPage = 1;
      renderAttendanceTable();
    } catch {
      if (tableDiv) tableDiv.innerHTML = '<div class="text-red-600">Failed to load attendance</div>';
    }
  }

  function getFilteredAttendance(){
    const q = (currentQuery || '').toLowerCase();
    const statusFilterEl = document.getElementById('att-status-filter');
    const statusFilter = statusFilterEl ? (statusFilterEl.value || 'all').toLowerCase() : 'all';
    const base = allAttendance.slice();
    const filteredBySearch = !q ? base : base.filter(r => {
      const name = `${r.first_name || ''} ${r.last_name || ''}`.toLowerCase();
      const status = (r.status || '').toLowerCase();
      const date = (r.attendance_date || '').toLowerCase();
      return name.includes(q) || status.includes(q) || date.includes(q);
    });
    if (statusFilter === 'all') return filteredBySearch;
    if (statusFilter === 'present') return filteredBySearch.filter(r => ['present','late','undertime','leave'].includes(String(r.status || '').toLowerCase()));
    return filteredBySearch.filter(r => (String(r.status || '').toLowerCase() === statusFilter));
  }

  function renderAttendanceTable(){
    const container = document.getElementById('attendance-table');
    if (!container) return;
    const rows = getFilteredAttendance();
    const total = rows.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (currentPage > totalPages) currentPage = totalPages;
    const startIdx = (currentPage - 1) * pageSize;
    const endIdx = Math.min(startIdx + pageSize, total);
    const pageRows = rows.slice(startIdx, endIdx);

    const table = document.createElement('table');
    table.className = 'min-w-full divide-y divide-gray-200';
    table.innerHTML = `
      <thead class="bg-gray-50">
        <tr>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Date</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time In</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time Out</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Total Hours</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-200 bg-white"></tbody>`;

    const tbody = table.querySelector('tbody');
    if (!pageRows.length) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="7" class="px-3 py-6 text-sm text-center text-gray-500">No attendance records</td>`;
      tbody.appendChild(tr);
    } else {
    pageRows.forEach((r, i) => {
      const tr = document.createElement('tr');
      const name = toTitleCase(`${r.first_name} ${r.last_name}`);
      const displayIndex = startIdx + i + 1;
      const statusText = toTitleCase(r.status || '');
      const stRaw = String(r.status || '').toLowerCase();
      const stBadge = (() => {
        const base = 'inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full ring-1 ';
        if (stRaw === 'present') return `<span class="${base}bg-green-50 text-green-700 ring-green-200">Present</span>`;
        if (stRaw === 'late') return `<span class="${base}bg-yellow-50 text-yellow-700 ring-yellow-200">Late</span>`;
        if (stRaw === 'absent') return `<span class="${base}bg-red-50 text-red-700 ring-red-200">Absent</span>`;
        if (stRaw === 'leave' || stRaw === 'on leave') return `<span class="${base}bg-blue-50 text-blue-700 ring-blue-200">OnLeave</span>`;
        if (stRaw === 'undertime') return `<span class="${base}bg-orange-50 text-orange-700 ring-orange-200">Undertime</span>`;
        return `<span class="${base}bg-gray-50 text-gray-700 ring-gray-200">${statusText || '—'}</span>`;
      })();
      tr.innerHTML = `
        <td class="px-3 py-2 text-sm text-gray-700">${displayIndex}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${name}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${formatDate(r.attendance_date)}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${stBadge}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${formatTimeOfDay(r.time_in) || ''}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${formatTimeOfDay(r.time_out) || ''}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${calcTotalHours(r.attendance_date, r.time_in, r.time_out)}</td>`;
      tbody.appendChild(tr);
    });
    }

    container.innerHTML = '';
    container.appendChild(table);

    const footer = document.getElementById('attendance-pagination');
    if (footer) {
      const showingFrom = total === 0 ? 0 : (startIdx + 1);
      const showingTo = endIdx;
      const totalPagesSafe = Math.max(1, Math.ceil(total / pageSize));
      footer.innerHTML = `
        <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${total}</span></div>
        <div class="flex items-center gap-2">
          <button id="att-prev" class="px-2 py-1 text-xs rounded border ${currentPage <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
          <span>Page ${currentPage} of ${totalPagesSafe}</span>
          <button id="att-next" class="px-2 py-1 text-xs rounded border ${currentPage >= totalPagesSafe ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
        </div>`;
      const prev = document.getElementById('att-prev');
      const next = document.getElementById('att-next');
      if (prev) prev.addEventListener('click', () => { if (currentPage > 1) { currentPage -= 1; renderAttendanceTable(); } });
      if (next) next.addEventListener('click', () => { if (currentPage < totalPagesSafe) { currentPage += 1; renderAttendanceTable(); } });
    }
  }

  // Wire controls
  const attSearchInput = document.getElementById('att-search-input');
  const attSearchClear = document.getElementById('att-search-clear');
  const attPageSizeSelect = document.getElementById('att-page-size');
  if (attSearchInput) {
    attSearchInput.addEventListener('input', () => { currentQuery = (attSearchInput.value || '').trim().toLowerCase(); currentPage = 1; renderAttendanceTable(); });
  }
  if (attSearchClear) {
    attSearchClear.addEventListener('click', () => { if (attSearchInput) attSearchInput.value = ''; currentQuery = ''; currentPage = 1; renderAttendanceTable(); });
  }
  if (attPageSizeSelect) {
    attPageSizeSelect.addEventListener('change', () => { const num = Number(attPageSizeSelect.value); pageSize = Number.isFinite(num) && num > 0 ? num : 10; currentPage = 1; renderAttendanceTable(); });
  }
  const attDate = document.getElementById('att-date');
  const attStatus = document.getElementById('att-status-filter');
  // Default date to today on initial load
  if (attDate) { try { attDate.value = new Date().toISOString().slice(0,10); } catch {} }
  // Listen to changes; if cleared, revert to today and reload
  if (attDate) {
    attDate.addEventListener('change', () => {
      if (!attDate.value) { try { attDate.value = new Date().toISOString().slice(0,10); } catch {} }
      currentPage = 1;
      loadAttendance();
    });
    attDate.addEventListener('input', () => {
      if (!attDate.value) { try { attDate.value = new Date().toISOString().slice(0,10); } catch {} }
      currentPage = 1;
      loadAttendance();
    });
  }
  if (attStatus) attStatus.addEventListener('change', () => { currentPage = 1; renderAttendanceTable(); });

  // Auto rollover daily: when the day changes, reset filters and show today's list
  function todayYmd(){ const d=new Date(); const y=d.getFullYear(); const m=String(d.getMonth()+1).padStart(2,'0'); const day=String(d.getDate()).padStart(2,'0'); return `${y}-${m}-${day}`; }
  let __mgrAttDayKey = todayYmd();
  function __mgrResetForNewDay(){
    try {
      const attSearchInputEl = document.getElementById('att-search-input');
      if (attSearchInputEl) attSearchInputEl.value = '';
      currentQuery = '';
      if (attStatus) attStatus.value = 'all';
      if (attDate) attDate.value = todayYmd();
      currentPage = 1;
    } catch {}
    loadAttendance();
  }
  function __mgrMaybeRollover(){
    const nowDay = todayYmd();
    if (nowDay !== __mgrAttDayKey) { __mgrAttDayKey = nowDay; __mgrResetForNewDay(); }
  }
  try {
    setInterval(__mgrMaybeRollover, 60000);
    window.addEventListener('focus', __mgrMaybeRollover);
    document.addEventListener('visibilitychange', __mgrMaybeRollover);
  } catch {}

  await loadAttendance();
}

async function renderDeptPendingLeaves(){
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h4 class="text-xl font-semibold">Leave Approvals</h4>
          </div>
    <div class="bg-white rounded-lg shadow p-4">
      <div class="mb-3 flex items-center justify-between gap-3">
        <div class="flex items-center gap-2">
          <div class="relative">
            <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
            <input id="leave-search" class="w-56 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search by employee, type, reason" />
          </div>
                              <select id="leave-type-filter" class="border rounded px-2 py-1 text-sm">
            <option value="">All Types</option>
          </select>
        </div>
        <div class="flex items-center gap-2">
          <span class="text-sm text-gray-600">Rows per page</span>
          <select id="leave-page-size" class="border rounded px-2 py-1">
            <option value="10" selected>10</option>
            <option value="25">25</option>
            <option value="50">50</option>
          </select>
        </div>
      </div>
      <div id="leaves-table"></div>
      <div id="leaves-pagination" class="mt-3 flex items-center justify-between text-sm text-gray-600"></div>
    </div>

    <div id="leaveDecisionModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-24 w-full max-w-md">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 id="leaveDecisionTitle" class="font-semibold">Confirm Decision</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
          </div>
          <div class="p-4">
            <div id="leaveDecisionInfo" class="text-sm text-gray-700 mb-3"></div>
            <label class="block text-sm text-gray-600 mb-1">Manager Note (optional)</label>
            <textarea id="leaveDecisionNote" rows="3" class="w-full border rounded px-3 py-2 text-sm" placeholder="Add a note for this decision..."></textarea>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
            <button id="leaveDecisionConfirm" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Confirm</button>
          </div>
        </div>
      </div>
    </div>
  `;

  // Inject "File Leave" button (same behavior as admin) and modal for managers
  try {
    const header = app.querySelector('.flex.items-center.justify-between.mb-4');
    if (header && !document.getElementById('mgr-btn-file-leave')) {
      const wrap = document.createElement('div');
      wrap.className = 'flex items-center gap-2';
      const btn = document.createElement('button');
      btn.id = 'mgr-btn-file-leave';
      btn.className = 'inline-flex items-center px-3 py-2 text-sm font-medium rounded bg-primary-600 text-white hover:bg-primary-700';
      btn.textContent = 'File Leave';
      wrap.appendChild(btn);
      header.appendChild(wrap);
    }
  } catch {}

  // Append modal container to the page once
  if (!document.getElementById('mgrLeaveModal')) {
    app.insertAdjacentHTML('beforeend', `
      <div id="mgrLeaveModal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-lg">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3">
              <h5 class="font-semibold">File Leave</h5>
              <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
            </div>
            <div class="p-4">
              <form class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div class="md:col-span-2">
                  <div class="relative">
                    <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M12.9 14.32a8 8 0 111.414-1.414l4.387 4.387a1 1 0 01-1.414 1.414l-4.387-4.387zM8 14a6 6 0 100-12 6 6 0 000 12z" clip-rule="evenodd"/></svg>
                    <input id="mgr-emp-search" class="w-full border rounded pl-8 pr-3 py-2" placeholder="Search employee..." />
                  </div>
                </div>
                <div class="md:col-span-2">
                  <label class="block text-sm text-gray-600 mb-1">Employee</label>
                  <select id="mgr-employee-id" class="w-full border rounded px-3 py-2" required></select>
                </div>
                <div>
                  <label class="block text-sm text-gray-600 mb-1">Start date</label>
                  <input type="date" id="mgr-lv-start" class="w-full border rounded px-3 py-2" required />
                </div>
                <div>
                  <label class="block text-sm text-gray-600 mb-1">End date</label>
                  <input type="date" id="mgr-lv-end" class="w-full border rounded px-3 py-2" required />
                </div>
                <div>
                  <label class="block text-sm text-gray-600 mb-1">Leave Type</label>
                  <select id="mgr-lv-type" class="w-full border rounded px-3 py-2"></select>
                </div>
                <div class="md:col-span-2">
                  <label class="block text-sm text-gray-600 mb-1">Reason</label>
                  <textarea id="mgr-lv-reason" rows="3" class="w-full border rounded px-3 py-2"></textarea>
                </div>
              </form>
            </div>
            <div class="flex justify-end gap-2 border-t px-4 py-3">
              <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
              <button id="mgr-save-leave" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
            </div>
          </div>
        </div>
      </div>
    `);
  }

  // Modal/controller wiring for File Leave
  const mgrLvModal = document.getElementById('mgrLeaveModal');
  if (mgrLvModal) mgrLvModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => mgrLvModal.classList.add('hidden')));

  // Employees list limited to manager's department (excluding self)
  let __mgrLvEmployees = [];
  async function mgrLoadEmployees(){
    try {
      const [empRes, meRes] = await Promise.all([
        axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
        axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true })
      ]);
      const me = meRes.data && meRes.data.user ? meRes.data.user : null;
      const meId = me && me.employee_id ? String(me.employee_id) : '';
      const meDept = (me && me.department ? String(me.department) : '').toLowerCase().trim();
      const list = Array.isArray(empRes.data) ? empRes.data : [];
      __mgrLvEmployees = list.filter(e => String(e.department || '').toLowerCase().trim() === meDept && (!meId || String(e.employee_id) !== meId));
    } catch { __mgrLvEmployees = []; }
  }
  function mgrRenderEmpOptions(list, selected){
    const sel = document.getElementById('mgr-employee-id');
    if (!sel) return;
    const cur = selected != null ? String(selected) : String(sel.value || '');
    sel.innerHTML = '';
    list.forEach(e => {
      const opt = document.createElement('option');
      opt.value = e.employee_id;
      opt.textContent = toTitleCase(`${e.first_name || ''} ${e.last_name || ''}`.trim());
      if (cur && String(cur) === String(e.employee_id)) opt.selected = true;
      sel.appendChild(opt);
    });
  }
  function mgrWireEmpSearch(){
    const input = document.getElementById('mgr-emp-search');
    if (!input) return;
    input.oninput = () => {
      const q = (input.value || '').toLowerCase().trim();
      const selected = document.getElementById('mgr-employee-id')?.value || '';
      const filtered = !q ? __mgrLvEmployees.slice() : __mgrLvEmployees.filter(e => `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.includes(q) || String(e.email||'').toLowerCase().includes(q));
      mgrRenderEmpOptions(filtered, selected);
    };
  }

  async function mgrFetchActiveLeaveTypes(){
    try {
      const res = await axios.get(`${baseApiUrl}/leave-types.php`, { params: { operation: 'listActive' } });
      return Array.isArray(res.data) ? res.data : [];
    } catch { return []; }
  }
  async function mgrLoadLeaveTypesOptions(selectId, current){
    const select = document.getElementById(selectId);
    if (!select) return;
    select.innerHTML = '';
    const ph = document.createElement('option'); ph.value = ''; ph.textContent = 'Select leave type'; ph.disabled = true; ph.selected = true; select.appendChild(ph);
    const types = await mgrFetchActiveLeaveTypes();
    if (!types.length){
      const defaults = ['vacation','sick leave','birthday leave','deductible against pay','maternity','paternity'].sort((a,b)=>a.localeCompare(b,undefined,{sensitivity:'base'}));
      defaults.forEach(n => { const o = document.createElement('option'); o.value = n.toLowerCase(); o.textContent = n.replace(/\b\w/g,c=>c.toUpperCase()); select.appendChild(o); });
    } else {
      types.slice().sort((a,b)=>String(a.name||'').localeCompare(String(b.name||''),undefined,{sensitivity:'base'})).forEach(t => {
        const name = String(t.name||'').trim(); if (!name) return; const o = document.createElement('option'); o.value = name.toLowerCase(); o.textContent = name; select.appendChild(o);
      });
    }
    const val = String(current || '').toLowerCase();
    if (val && Array.from(select.options).some(o => String(o.value).toLowerCase() === val)) select.value = val; else if (!select.value && select.options.length) select.selectedIndex = 0;
  }
  function mgrResetLeaveForm(){
    const f = { emp: document.getElementById('mgr-employee-id'), s: document.getElementById('mgr-lv-start'), e: document.getElementById('mgr-lv-end'), t: document.getElementById('mgr-lv-type'), r: document.getElementById('mgr-lv-reason'), q: document.getElementById('mgr-emp-search') };
    if (f.s) f.s.value = ''; if (f.e) f.e.value=''; if (f.t) f.t.value=''; if (f.r) f.r.value=''; if (f.q) f.q.value='';
  }

  const mgrBtnFileLeave = document.getElementById('mgr-btn-file-leave');
  if (mgrBtnFileLeave) mgrBtnFileLeave.addEventListener('click', async () => {
    await mgrLoadEmployees();
    mgrRenderEmpOptions(__mgrLvEmployees);
    mgrWireEmpSearch();
    await mgrLoadLeaveTypesOptions('mgr-lv-type', '');
    mgrResetLeaveForm();
    const m = document.getElementById('mgrLeaveModal'); if (m) m.classList.remove('hidden');
  });

  const mgrSaveLeave = document.getElementById('mgr-save-leave');
  if (mgrSaveLeave) mgrSaveLeave.addEventListener('click', async () => {
    const employee_id = document.getElementById('mgr-employee-id')?.value;
    const start_date = document.getElementById('mgr-lv-start')?.value;
    const end_date = document.getElementById('mgr-lv-end')?.value;
    const leave_type = (document.getElementById('mgr-lv-type')?.value || '');
    const reason = document.getElementById('mgr-lv-reason')?.value || '';
    if (!employee_id || !start_date || !end_date || !leave_type) { alert('Fill employee, dates and leave type'); return; }
    try {
      const fd = new FormData();
      fd.append('operation', 'requestLeave');
      fd.append('json', JSON.stringify({ employee_id, start_date, end_date, leave_type, reason }));
      await axios.post(`${baseApiUrl}/leaves.php`, fd);
      const m = document.getElementById('mgrLeaveModal'); if (m) m.classList.add('hidden');
      alert('Leave request submitted');
      await loadLeaves();
    } catch { alert('Failed to submit leave'); }
  });

  const tableDiv = document.getElementById('leaves-table');
  const paginationDiv = document.getElementById('leaves-pagination');
  const searchInput = document.getElementById('leave-search');
  const startInput = null;
  const endInput = null;
  const typeFilter = document.getElementById('leave-type-filter');
  const pageSizeSelect = document.getElementById('leave-page-size');
    const bulkApproveBtn = document.getElementById('bulk-approve');
  const bulkRejectBtn = document.getElementById('bulk-reject');

  let allLeaves = [];
  let currentQuery = '';
  let currentPage = 1;
  let pageSize = 10;
  let selected = new Set();

  function diffDays(a, b){
    try { const d1 = new Date(a); const d2 = new Date(b); if (isNaN(d1)||isNaN(d2)) return ''; const ms = (d2 - d1) + 24*60*60*1000; const days = Math.max(1, Math.round(ms / (24*60*60*1000))); return `${days} day${days>1?'s':''}`; } catch { return ''; }
  }
  function formatDate(dateStr) {
    if (!dateStr) return '';
    try { const date = new Date(dateStr); if (isNaN(date.getTime())) return dateStr; return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }); } catch { return dateStr; }
  }
  function updateBulkState(){
    const any = selected.size > 0;
    if (bulkApproveBtn) { bulkApproveBtn.disabled = !any; }
    if (bulkRejectBtn) { bulkRejectBtn.disabled = !any; }
  }

  async function loadLeaves(){
    if (tableDiv) tableDiv.innerHTML = '<div class="text-gray-500">Loading...</div>';
    try {
      const me = await currentUser();
      const dept = (me && me.department) ? me.department : '';
      const [resLeaves, resEmp] = await Promise.all([
        axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listPending' } }),
        axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } })
      ]);
      const emap = new Map((resEmp.data || []).filter(e => (e.department || '').toLowerCase() === (dept || '').toLowerCase()).map(e => [String(e.employee_id), e]));
      const rows = (resLeaves.data || []).filter(l => emap.has(String(l.employee_id)));
      // Map enriched rows
      allLeaves = rows.map(r => {
        const emp = emap.get(String(r.employee_id));
        const name = emp ? toTitleCase(`${emp.first_name || ''} ${emp.last_name || ''}`.trim()) : toTitleCase(`${r.first_name || ''} ${r.last_name || ''}`.trim());
        return { ...r, __emp: emp, __name: name };
      });
      // Populate type filter options
      const types = Array.from(new Set(allLeaves.map(l => (l.leave_type || '').toString().trim()).filter(Boolean)));
      const prev = typeFilter.value || '';
      typeFilter.innerHTML = '<option value="">All Types</option>' + types.map(t => `<option value="${t}">${toTitleCase(t)}</option>`).join('');
      typeFilter.value = prev || '';
      selected = new Set();
      updateBulkState();
      currentPage = 1;
      renderTable();
    } catch {
      if (tableDiv) tableDiv.innerHTML = '<div class="text-red-600">Failed to load leaves</div>';
    }
  }

  function getFiltered(){
    const q = (currentQuery || '').toLowerCase();
    const s = (startInput && startInput.value) ? startInput.value : '';
    const e = (endInput && endInput.value) ? endInput.value : '';
    const t = (typeFilter && typeFilter.value) ? typeFilter.value.toLowerCase() : '';
    return allLeaves.filter(r => {
      const name = (r.__name || '').toLowerCase();
      const type = (r.leave_type || '').toLowerCase();
      const reason = (r.reason || r.leave_reason || '').toLowerCase();
      const matchesQ = !q || name.includes(q) || type.includes(q) || reason.includes(q);
      const matchesT = !t || type === t;
      const matchesStart = !s || String(r.start_date || '') >= s;
      const matchesEnd = !e || String(r.end_date || '') <= e;
      return matchesQ && matchesT && matchesStart && matchesEnd;
    });
  }

  function renderTable(){
    const rows = getFiltered();
    const total = rows.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (currentPage > totalPages) currentPage = totalPages;
    const startIdx = (currentPage - 1) * pageSize;
    const endIdx = Math.min(startIdx + pageSize, total);
    const pageRows = rows.slice(startIdx, endIdx);

    const table = document.createElement('table');
    table.className = 'min-w-full divide-y divide-gray-200';
    table.innerHTML = `
      <thead class="bg-gray-50">
        <tr>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Type</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Dates</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Days</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Reason</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Submitted</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Actions</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-200 bg-white"></tbody>`;

    const tbody = table.querySelector('tbody');
    if (!pageRows.length) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="8" class="px-3 py-6 text-sm text-center text-gray-500">No leave requests</td>`;
      tbody.appendChild(tr);
    } else {
    pageRows.forEach((r, idx) => {
      const tr = document.createElement('tr');
      const name = r.__name || '';
      const type = toTitleCase(r.leave_type || '');
      const reason = (r.reason || r.leave_reason || '').toString();
      const submitted = formatDate(r.created_at || r.submitted_at || '');
      tr.innerHTML = `
        <td class="px-3 py-2 text-sm text-gray-700">${startIdx + idx + 1}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${name}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${type || '-'}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${r.start_date} → ${r.end_date}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${diffDays(r.start_date, r.end_date)}</td>
        <td class="px-3 py-2 text-sm text-gray-700 max-w-[240px]"><div class="truncate" title="${reason.replace(/"/g,'&quot;')}">${reason || '-'}</div></td>
        <td class="px-3 py-2 text-sm text-gray-700">${submitted || '-'}</td>
        <td class="px-3 py-2 text-sm">
          <button data-approve="${r.leave_id}" class="px-2 py-1 text-xs rounded border border-green-600 text-green-700 hover:bg-green-50">Approve</button>
          <button data-reject="${r.leave_id}" class="ml-2 px-2 py-1 text-xs rounded border border-red-600 text-red-700 hover:bg-red-50">Reject</button>
        </td>`;
      tbody.appendChild(tr);
    });
    }

    if (tableDiv) { tableDiv.innerHTML = ''; tableDiv.appendChild(table); }

    // Wire row checkbox and master checkbox
    const master = document.getElementById('leave-check-all');
    const rowChecks = Array.from(table.querySelectorAll('.row-check'));
    if (master) master.addEventListener('change', () => {
      rowChecks.forEach(cb => { cb.checked = master.checked; const id = cb.getAttribute('data-id'); if (cb.checked) selected.add(id); else selected.delete(id); });
      updateBulkState();
    });
    rowChecks.forEach(cb => cb.addEventListener('change', () => {
      const id = cb.getAttribute('data-id'); if (cb.checked) selected.add(id); else selected.delete(id);
      updateBulkState();
      if (!cb.checked && master) master.checked = false;
    }));

    // Wire single approve/reject
    tbody.querySelectorAll('[data-approve]').forEach(btn => btn.addEventListener('click', (e) => {
      const id = e.currentTarget.getAttribute('data-approve');
      openDecisionModal('approve', [id]);
    }));
    tbody.querySelectorAll('[data-reject]').forEach(btn => btn.addEventListener('click', (e) => {
      const id = e.currentTarget.getAttribute('data-reject');
      openDecisionModal('reject', [id]);
    }));

    // Pagination footer
    if (paginationDiv) {
      const showingFrom = total === 0 ? 0 : (startIdx + 1);
      const showingTo = endIdx;
      paginationDiv.innerHTML = `
        <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${total}</span></div>
        <div class="flex items-center gap-2">
          <button id="leaves-prev" class="px-2 py-1 text-xs rounded border ${currentPage <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
          <span>Page ${currentPage} of ${totalPages}</span>
          <button id="leaves-next" class="px-2 py-1 text-xs rounded border ${currentPage >= totalPages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
        </div>`;
      const prev = document.getElementById('leaves-prev');
      const next = document.getElementById('leaves-next');
      if (prev) prev.addEventListener('click', () => { if (currentPage > 1) { currentPage -= 1; renderTable(); } });
      if (next) next.addEventListener('click', () => { if (currentPage < totalPages) { currentPage += 1; renderTable(); } });
    }
  }

  async function decide(action, ids, note){
    const op = action === 'approve' ? 'approve' : 'reject';
    for (const id of ids) {
      const fd = new FormData();
      fd.append('operation', op);
      fd.append('json', JSON.stringify({ leave_id: id, note: note || '' }));
      try { await axios.post(`${baseApiUrl}/leaves.php`, fd, { withCredentials: true }); } catch {} finally { try { const me = await currentUser(); const pie = document.getElementById('mgrLeaveBreakdown'); if (pie && me && me.department) await renderLeaveBreakdown(me.department); } catch {} }
    }
    // Refresh manager notifications/badge immediately after decision
    try { await renderNotifications(); } catch {}
    await loadLeaves();
  }

  function openDecisionModal(action, ids){
    const modal = document.getElementById('leaveDecisionModal');
    const title = document.getElementById('leaveDecisionTitle');
    const info = document.getElementById('leaveDecisionInfo');
    const note = document.getElementById('leaveDecisionNote');
    const confirmBtn = document.getElementById('leaveDecisionConfirm');
    if (!modal || !title || !info || !note || !confirmBtn) return;
    const label = action === 'approve' ? 'Approve' : 'Reject';
    title.textContent = `${label} Leave${ids.length > 1 ? ' Requests' : ''}`;
    info.textContent = `You are about to ${label.toLowerCase()} ${ids.length} request${ids.length>1?'s':''}.`;
    note.value = '';
    modal.classList.remove('hidden');
    const closeEls = modal.querySelectorAll('[data-close="true"]');
    const closeModal = () => { modal.classList.add('hidden'); confirmBtn.onclick = null; };
    closeEls.forEach(el => el.addEventListener('click', closeModal, { once: true }));
    confirmBtn.onclick = async () => { confirmBtn.disabled = true; try { await decide(action, ids, note.value); } finally { confirmBtn.disabled = false; closeModal(); } };
  }

  // Wire controls
  if (searchInput) searchInput.addEventListener('input', () => { currentQuery = (searchInput.value || '').trim().toLowerCase(); currentPage = 1; renderTable(); });
      if (typeFilter) typeFilter.addEventListener('change', () => { currentPage = 1; renderTable(); });
  if (pageSizeSelect) pageSizeSelect.addEventListener('change', () => { const num = Number(pageSizeSelect.value); pageSize = Number.isFinite(num) && num > 0 ? num : 10; currentPage = 1; renderTable(); });
  if (bulkApproveBtn) bulkApproveBtn.addEventListener('click', () => { if (selected.size) openDecisionModal('approve', Array.from(selected)); });
  if (bulkRejectBtn) bulkRejectBtn.addEventListener('click', () => { if (selected.size) openDecisionModal('reject', Array.from(selected)); });

  await loadLeaves();
}

async function renderDeptReports(){
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h4 class="text-xl font-semibold">Reports</h4>
    </div>
    <div class="bg-white rounded-lg shadow">
      <div class="border-b px-3 pt-3">
        <nav class="-mb-px flex gap-3 text-sm" id="mgr-rep-tabs">
          <button data-tab="payroll" class="px-3 py-2 border-b-2 border-primary-600 text-primary-700">Payroll</button>
          <button data-tab="attendance" class="px-3 py-2 border-b-2 border-transparent hover:border-primary-600">Attendance</button>
        </nav>
      </div>
      <div class="p-4">
        <div id="mgr-filter-wrap" class="mb-3 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3"></div>
        <div class="flex items-center gap-2 mb-4">
          <button id="mgr-rep-generate" class="px-3 py-2 text-sm rounded bg-primary-600 text-white">Generate Report</button>
          <button id="mgr-rep-export-pdf" class="px-3 py-2 text-sm rounded border" disabled>Export to PDF</button>
          <button id="mgr-rep-export-excel" class="px-3 py-2 text-sm rounded border" disabled>Export to Excel</button>
        </div>
        <div id="mgr-summary-widgets" class="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4"></div>
        <div id="mgr-rep-output" class="overflow-x-auto"></div>
        <div id="mgr-pager" class="mt-3 flex items-center justify-between text-sm text-gray-600"></div>
      </div>
    </div>`;

  // State
  let activeTab = 'payroll';
  let page = 1, limit = 20, total = 0, items = [];

  const btn = document.getElementById('mgr-rep-generate');
  const pdfBtn = document.getElementById('mgr-rep-export-pdf');
  const excelBtn = document.getElementById('mgr-rep-export-excel');
  if (pdfBtn) pdfBtn.disabled = true;
  if (excelBtn) excelBtn.disabled = true;

  // Build filters per tab
  function filterSchema(tab) {
    const common = [
      { key: 'start_date', label: 'Start Date', type: 'date', show: ['payroll','attendance'].includes(tab) },
      { key: 'end_date', label: 'End Date', type: 'date', show: ['payroll','attendance'].includes(tab) },
    ];
    return common.filter(x => x.show);
  }

  function getFiltersFromUI() {
    const wrap = document.getElementById('mgr-filter-wrap');
    const obj = {};
    wrap.querySelectorAll('[data-key]').forEach(el => { const k = el.getAttribute('data-key'); obj[k] = el.value || ''; });
    // Normalize empty to undefined
    Object.keys(obj).forEach(k => { if (obj[k] === '') delete obj[k]; });
    return obj;
  }

  function setActiveTab(tab) {
    activeTab = tab;
    // Tabs visual
    document.querySelectorAll('#mgr-rep-tabs [data-tab]').forEach(btn => {
      btn.classList.remove('border-primary-600', 'text-primary-700');
      if (btn.getAttribute('data-tab') === tab) btn.classList.add('border-primary-600', 'text-primary-700');
    });
    // Filters
    const schema = filterSchema(tab);
    const wrap = document.getElementById('mgr-filter-wrap');
    wrap.innerHTML = schema.map(f => {
      if (f.type === 'date') {
        return `<div><label class="block text-sm text-gray-600 mb-1">${f.label}</label><input type="date" data-key="${f.key}" class="w-full border rounded px-3 py-2" /></div>`;
      }
      return '';
    }).join('');

    // Reset page but do NOT auto-load reports
    page = 1;
    
    // Clear any existing report content
    const out = document.getElementById('mgr-rep-output');
    if (out) {
      out.innerHTML = '<div class="text-center text-gray-500 py-8">No data.</div>';
    }
  }

  async function ensureXLSXForMgr(){
    if (window.XLSX) return;
    await new Promise((resolve)=>{ const s=document.createElement('script'); s.src='https://cdn.sheetjs.com/xlsx-latest/package/dist/xlsx.full.min.js'; s.onload=resolve; s.onerror=resolve; document.head.appendChild(s); });
  }
  async function ensureHtml2PdfForMgr(){
    if (window.html2pdf) return;
    await new Promise((resolve)=>{ const s=document.createElement('script'); s.src='https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js'; s.onload=resolve; s.onerror=resolve; document.head.appendChild(s); });
  }
  function enableMgrExportsIfReady(){
    try {
      const out = document.getElementById('mgr-rep-output');
      const hasTable = !!(out && out.querySelector && out.querySelector('table'));
      if (pdfBtn) pdfBtn.disabled = !hasTable;
      if (excelBtn) excelBtn.disabled = !hasTable;
    } catch {}
  }
  (function observeMgrRepOutput(){
    try {
      const out = document.getElementById('mgr-rep-output');
      if (!out) return;
      const mo = new MutationObserver(()=> enableMgrExportsIfReady());
      mo.observe(out, { childList: true, subtree: true, characterData: true });
    } catch {}
  })();
  async function mgrExportExcelFromDom(){
    try {
      await ensureXLSXForMgr();
      const out = document.getElementById('mgr-rep-output');
      if (!out) { alert('Generate a report first'); return; }
      const table = out.querySelector('table');
      if (!table) { alert('Generate a report first'); return; }
      
      const aoa = [];
      const ths = table.querySelectorAll('thead tr th');
      if (ths && ths.length){ aoa.push(Array.from(ths).map(th=>String(th.textContent||'').trim())); }
      
      const bodyRows = table.querySelectorAll('tbody tr');
      if (bodyRows && bodyRows.length){
        bodyRows.forEach(tr => { aoa.push(Array.from(tr.children).map(td => String(td.textContent||'').trim())); });
      } else {
        // Fallback: all rows
        const rows = table.querySelectorAll('tr');
        rows.forEach((tr, idx) => { if (idx===0 && aoa.length) return; aoa.push(Array.from(tr.children).map(td => String(td.textContent||'').trim())); });
      }
      
      // Add totals row if it exists
      const totalsRow = table.querySelector('tfoot tr');
      if (totalsRow) {
        aoa.push(Array.from(totalsRow.children).map(td => String(td.textContent||'').trim()));
      }
      
      const ws = XLSX.utils.aoa_to_sheet(aoa);
      const colCount = (aoa[0]||[]).length;
      ws['!cols'] = new Array(colCount).fill(0).map((_,ci)=>({ wch: Math.max(12, Math.min(60, Math.max(...aoa.map(r => (r && r[ci] ? String(r[ci]).length : 0))) + 2)) }));
      
      // Get department and report type for filename
      const me = await currentUser();
      const dept = (me && me.department) ? me.department.toLowerCase().replace(/\s+/g, '_') : 'department';
      const reportType = activeTab || 'report';
      
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, `${reportType.charAt(0).toUpperCase() + reportType.slice(1)} Report`);
      const ts = new Date().toISOString().replace(/[-:TZ]/g,'').slice(0,14);
      XLSX.writeFile(wb, `${dept}_${reportType}_report_${ts}.xlsx`);
    } catch { try { alert('Excel export failed'); } catch {} }
  }
  async function mgrExportPdfFromDom(){
    try {
      await ensureHtml2PdfForMgr();
      const out = document.getElementById('mgr-rep-output');
      if (!out) { alert('Generate a report first'); return; }
      const table = out.querySelector('table');
      if (!table) { alert('Generate a report first'); return; }
      
      // Get department name and report type from current user
      const me = await currentUser();
      const dept = (me && me.department) ? me.department : 'Department';
      const reportType = activeTab ? activeTab.charAt(0).toUpperCase() + activeTab.slice(1) : 'Report';
      
      // Extract only the table HTML for PDF export (exclude summary widgets)
      const tableHtml = table.outerHTML;
      
      const container = document.createElement('div');
      container.innerHTML = `
        <div style="font-family: Arial, sans-serif; color:#111827;">
          <div style="display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #e5e7eb;padding-bottom:8px;margin-bottom:8px;">
            <div style="display:flex;align-items:center;gap:10px;">
              <img src="../images/unitop.png" onerror="this.style.display='none'" style="height:40px;" />
              <div><div style="font-size:18px;font-weight:700;">Unitop</div></div>
            </div>
            <div style="text-align:right;color:#374151;font-size:12px;">Generated on: <strong>${new Date().toLocaleString('en-US')}</strong></div>
          </div>
          <div style="text-align:center;font-size:18px;font-weight:700;margin:6px 0 8px;">${dept} ${reportType} Report</div>
          <style>table, th, td{ border:1px solid #000 !important; border-collapse:collapse; } th, td{ padding:8px; font-size:12px; }</style>
          <div>${tableHtml}</div>
        </div>`;
      const opt = { margin: 10, filename: `${dept.toLowerCase().replace(/\s+/g, '_')}_${activeTab}_report_${new Date().toISOString().slice(0,10)}.pdf`, image: { type: 'jpeg', quality: 0.98 }, html2canvas: { scale: 2 }, jsPDF: { unit: 'mm', format: 'a4', orientation: 'landscape' } };
      await window.html2pdf().from(container).set(opt).save();
    } catch { try { alert('PDF export failed'); } catch {} }
  }
  async function loadReports() {
    const out = document.getElementById('mgr-rep-output');
    try {
      out.innerHTML = 'Loading reports...';
      const filters = getFiltersFromUI();
      const me = await currentUser();
      const dept = (me && me.department) ? me.department : '';
      
      if (activeTab === 'payroll') {
        await loadPayrollReport(filters, dept, out);
      } else if (activeTab === 'attendance') {
        await loadAttendanceReport(filters, dept, out);
      }
      
      enableMgrExportsIfReady();
    } catch (error) {
      console.error('Failed to load reports:', error);
      out.innerHTML = `
        <div class="text-center py-8">
          <div class="text-red-600 mb-2">Failed to load report automatically</div>
          <div class="text-gray-500 text-sm mb-4">Click "Generate Report" to load manually</div>
          <button onclick="window.mgrLoadReports && window.mgrLoadReports()" class="px-4 py-2 bg-primary-600 text-white rounded hover:bg-primary-700">Retry</button>
        </div>`;
    }
  }

  async function loadPayrollReport(filters, dept, out) {
    const start = filters.start_date;
    const end = filters.end_date;
    
    const [payRes, empRes] = await Promise.all([
      axios.get(`${baseApiUrl}/payroll.php`, { params: { operation: 'listPayroll', start_date: start, end_date: end } }),
      axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } })
    ]);
    
    const dLc = (dept || '').toLowerCase();
    const emap = new Map((empRes.data || []).filter(e => (e.department || '').toLowerCase() === dLc).map(e => [String(e.employee_id), e]));
    const pays = (payRes.data || []).filter(p => emap.has(String(p.employee_id)));
    
    // Create payroll summary statistics (include all employees for totals)
    let totalBasicSalary = 0;
    let totalDeductions = 0;
    let totalNetPay = 0;
    let totalOvertimePay = 0;
    
    const allPayrollData = pays.map((pay, index) => {
      const emp = emap.get(String(pay.employee_id));
      const basic = Number(pay.basic_salary || 0);
      const deductions = Number(pay.total_deductions || pay.deductions || 0);
      const netPay = Number(pay.net_pay || 0);
      const overtimePay = Number(pay.overtime_pay || 0);
      
      // Include all employees in totals calculation
      totalBasicSalary += basic;
      totalDeductions += deductions;
      totalNetPay += netPay;
      totalOvertimePay += overtimePay;
      
      return {
        index: index + 1,
        employee_id: pay.employee_id,
        name: `${emp.first_name || ''} ${emp.last_name || ''}`.trim(),
        department: emp.department || '',
        position: emp.position || '',
        period_start: pay.payroll_period_start || pay.period_start || '',
        period_end: pay.payroll_period_end || pay.period_end || '',
        basic_salary: basic,
        deductions,
        net_pay: netPay,
        overtime_pay: overtimePay,
        status: pay.status || 'processed',
        created_at: pay.created_at || '',
        user_role: emp.user_role || null
      };
    });
    
    // Filter out managers from table display only
    const employeeOnlyData = allPayrollData.filter(pay => pay.user_role !== 'manager');
    
    // Re-index the filtered data for display
    const payrollData = employeeOnlyData.map((pay, index) => ({
      ...pay,
      index: index + 1
    }));
    
    // Recalculate totals for display (employees only, excluding managers)
    let displayTotalBasicSalary = 0;
    let displayTotalDeductions = 0;
    let displayTotalNetPay = 0;
    let displayTotalOvertimePay = 0;
    
    payrollData.forEach(pay => {
      displayTotalBasicSalary += pay.basic_salary;
      displayTotalDeductions += pay.deductions;
      displayTotalNetPay += pay.net_pay;
      displayTotalOvertimePay += pay.overtime_pay;
    });
    
    // Generate table HTML
    const tableRows = payrollData.map(pay => `
      <tr>
        <td class="px-3 py-2 text-sm text-gray-700">${pay.index}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${pay.name}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${pay.position}</td>
        <td class="px-3 py-2 text-sm text-gray-700 text-center">${pay.period_start} → ${pay.period_end}</td>
        <td class="px-3 py-2 text-sm text-gray-700 text-center">₱${pay.basic_salary.toFixed(2)}</td>
        <td class="px-3 py-2 text-sm text-gray-700 text-center">₱${pay.overtime_pay.toFixed(2)}</td>
        <td class="px-3 py-2 text-sm text-gray-700 text-center">₱${pay.deductions.toFixed(2)}</td>
        <td class="px-3 py-2 text-sm text-gray-700 text-center">₱${pay.net_pay.toFixed(2)}</td>
        <td class="px-3 py-2 text-sm text-gray-700 text-center">
          <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
            pay.status === 'paid' ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'
          }">${pay.status === 'paid' ? 'Paid' : 'Processed'}</span>
        </td>
      </tr>`).join('');
    
    out.innerHTML = `
      <div class="mb-4">
        <h4 class="font-semibold mb-3">Payroll Summary (${dept})</h4>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-2 mb-4 p-3 bg-gray-50 rounded text-center">
          <div><div class="text-base font-semibold text-blue-600">₱${totalBasicSalary.toFixed(2)}</div><div class="text-xs text-gray-600">Total Basic Salary (All)</div></div>
          <div><div class="text-base font-semibold text-green-600">₱${totalOvertimePay.toFixed(2)}</div><div class="text-xs text-gray-600">Total Overtime Pay (All)</div></div>
          <div><div class="text-base font-semibold text-red-600">₱${totalDeductions.toFixed(2)}</div><div class="text-xs text-gray-600">Total Deductions (All)</div></div>
          <div><div class="text-base font-semibold text-purple-600">₱${totalNetPay.toFixed(2)}</div><div class="text-xs text-gray-600">Total Net Pay (All)</div></div>
        </div>
      </div>
      <div class="overflow-x-auto w-full">
        <table id="reportTable" class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr>
              <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
              <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee Name</th>
              <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Position</th>
              <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">Pay Period</th>
              <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">Basic Salary</th>
              <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">Overtime Pay</th>
              <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">Deductions</th>
              <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">Net Pay</th>
              <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">Status</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200 bg-white">
            ${tableRows}
          </tbody>
          <tfoot class="bg-gray-50">
            <tr>
              <td colspan="4" class="px-3 py-2 text-sm font-semibold text-gray-700 text-right">Totals</td>
              <td class="px-3 py-2 text-sm font-semibold text-gray-700 text-center">₱${displayTotalBasicSalary.toFixed(2)}</td>
              <td class="px-3 py-2 text-sm font-semibold text-gray-700 text-center">₱${displayTotalOvertimePay.toFixed(2)}</td>
              <td class="px-3 py-2 text-sm font-semibold text-gray-700 text-center">₱${displayTotalDeductions.toFixed(2)}</td>
              <td class="px-3 py-2 text-sm font-semibold text-gray-700 text-center">₱${displayTotalNetPay.toFixed(2)}</td>
              <td class="px-3 py-2 text-sm font-semibold text-gray-700 text-center">-</td>
            </tr>
          </tfoot>
        </table>
      </div>`;
  }

  async function loadAttendanceReport(filters, dept, out) {
    const start = filters.start_date;
    const end = filters.end_date;
    
    const [attRes, empRes] = await Promise.all([
      axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: start, end_date: end } }),
      axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } })
    ]);
    
    const dLc = (dept || '').toLowerCase();
    const emap = new Map((empRes.data || []).filter(e => (e.department || '').toLowerCase() === dLc).map(e => [String(e.employee_id), e]));
    const att = (attRes.data || []).filter(r => emap.has(String(r.employee_id)));
    
    // Group attendance by employee (include user_role for filtering)
    const allEmployeeAttendance = new Map();
    
    Array.from(emap.values()).forEach(emp => {
      const empId = String(emp.employee_id);
      const empAtt = att.filter(a => String(a.employee_id) === empId);
      
      const present = empAtt.filter(a => (a.status || '').toLowerCase() === 'present').length;
      const late = empAtt.filter(a => (a.status || '').toLowerCase() === 'late').length;
      const absent = empAtt.filter(a => (a.status || '').toLowerCase() === 'absent').length;
      const onLeave = empAtt.filter(a => (a.status || '').toLowerCase() === 'leave').length;
      const totalDays = empAtt.length;
      
      // Calculate hours worked (simplified calculation)
      const hoursWorked = empAtt.reduce((total, record) => {
        if ((record.status || '').toLowerCase() === 'present') {
          return total + 8; // Assuming 8 hours per day
        } else if ((record.status || '').toLowerCase() === 'late') {
          return total + 7; // Assuming 1 hour deduction for late
        }
        return total;
      }, 0);
      
      allEmployeeAttendance.set(empId, {
        employee_id: empId,
        name: `${emp.first_name || ''} ${emp.last_name || ''}`.trim(),
        position: emp.position || '',
        totalDays,
        present,
        late,
        absent,
        onLeave,
        hoursWorked,
        attendanceRate: totalDays > 0 ? ((present + late) / totalDays * 100).toFixed(1) : '0.0',
        user_role: emp.user_role || null
      });
    });
    
    // Calculate summary stats for ALL employees (including managers)
    const allAttendanceArray = Array.from(allEmployeeAttendance.values());
    const totalEmployees = allAttendanceArray.length;
    const totalPresent = allAttendanceArray.reduce((s, e) => s + e.present, 0);
    const totalLate = allAttendanceArray.reduce((s, e) => s + e.late, 0);
    const totalAbsent = allAttendanceArray.reduce((s, e) => s + e.absent, 0);
    const totalOnLeave = allAttendanceArray.reduce((s, e) => s + e.onLeave, 0);
    const totalHours = allAttendanceArray.reduce((s, e) => s + e.hoursWorked, 0);
    
    // Filter out managers for table display only
    const employeeOnlyAttendance = allAttendanceArray.filter(emp => emp.user_role !== 'manager');
    
    // Re-index the filtered data for display
    const attendanceArray = employeeOnlyAttendance.map((emp, index) => ({
      ...emp,
      index: index + 1
    }));
    
    // Recalculate totals for display (employees only, excluding managers)
    const displayTotalPresent = employeeOnlyAttendance.reduce((s, e) => s + e.present, 0);
    const displayTotalLate = employeeOnlyAttendance.reduce((s, e) => s + e.late, 0);
    const displayTotalAbsent = employeeOnlyAttendance.reduce((s, e) => s + e.absent, 0);
    const displayTotalOnLeave = employeeOnlyAttendance.reduce((s, e) => s + e.onLeave, 0);
    const displayTotalHours = employeeOnlyAttendance.reduce((s, e) => s + e.hoursWorked, 0);
    
    // Generate table HTML
    const tableRows = attendanceArray.map((emp) => `
      <tr>
        <td class="px-3 py-2 text-sm text-gray-700">${emp.index}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${emp.name}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${emp.position}</td>
        <td class="px-3 py-2 text-sm text-gray-700 text-center">${emp.totalDays}</td>
        <td class="px-3 py-2 text-sm text-gray-700 text-center">${emp.present}</td>
        <td class="px-3 py-2 text-sm text-gray-700 text-center">${emp.late}</td>
        <td class="px-3 py-2 text-sm text-gray-700 text-center">${emp.absent}</td>
        <td class="px-3 py-2 text-sm text-gray-700 text-center">${emp.onLeave}</td>
        <td class="px-3 py-2 text-sm text-gray-700 text-center">${emp.hoursWorked}</td>
        <td class="px-3 py-2 text-sm text-gray-700 text-center">${emp.attendanceRate}%</td>
      </tr>`).join('');
    
    out.innerHTML = `
      <div class="mb-4">
        <h4 class="font-semibold mb-3">Attendance Summary (${dept})</h4>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-2 mb-4 p-3 bg-gray-50 rounded text-center">
          <div><div class="text-base font-semibold text-green-600">${totalPresent}</div><div class="text-xs text-gray-600">Total Present Days (All)</div></div>
          <div><div class="text-base font-semibold text-yellow-600">${totalLate}</div><div class="text-xs text-gray-600">Total Late Days (All)</div></div>
          <div><div class="text-base font-semibold text-red-600">${totalAbsent}</div><div class="text-xs text-gray-600">Total Absent Days (All)</div></div>
          <div><div class="text-base font-semibold text-blue-600">${totalHours}</div><div class="text-xs text-gray-600">Total Hours Worked (All)</div></div>
        </div>
      </div>
      <div class="overflow-x-auto w-full">
        <table id="reportTable" class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr>
              <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
              <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee Name</th>
              <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Position</th>
              <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">Total Days</th>
              <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">Present</th>
              <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">Late</th>
              <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">Absent</th>
              <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">On Leave</th>
              <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">Hours Worked</th>
              <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">Attendance Rate</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200 bg-white">
            ${tableRows}
          </tbody>
          <tfoot class="bg-gray-50">
            <tr>
              <td colspan="4" class="px-3 py-2 text-sm font-semibold text-gray-700 text-right">Totals</td>
              <td class="px-3 py-2 text-sm font-semibold text-gray-700 text-center">${displayTotalPresent}</td>
              <td class="px-3 py-2 text-sm font-semibold text-gray-700 text-center">${displayTotalLate}</td>
              <td class="px-3 py-2 text-sm font-semibold text-gray-700 text-center">${displayTotalAbsent}</td>
              <td class="px-3 py-2 text-sm font-semibold text-gray-700 text-center">${displayTotalOnLeave}</td>
              <td class="px-3 py-2 text-sm font-semibold text-gray-700 text-center">${displayTotalHours}</td>
              <td class="px-3 py-2 text-sm font-semibold text-gray-700 text-center">-</td>
            </tr>
          </tfoot>
        </table>
      </div>`;
  }

  // Event handlers
  document.querySelectorAll('#mgr-rep-tabs [data-tab]').forEach(btn => {
    btn.addEventListener('click', () => setActiveTab(btn.getAttribute('data-tab')));
  });
  
  if (btn) btn.addEventListener('click', loadReports);
  if (pdfBtn) pdfBtn.addEventListener('click', mgrExportPdfFromDom);
  if (excelBtn) excelBtn.addEventListener('click', mgrExportExcelFromDom);

  // Make loadReports available globally for retry functionality
  window.mgrLoadReports = loadReports;

  // Initialize with payroll tab but do NOT auto-load reports
  setActiveTab('payroll');
}

async function markAllManagerNotifsAsRead(){
  try {
    const response = await axios.get(`${baseApiUrl}/notifications.php`, { params: { operation: 'getNotifications' }, withCredentials: true });
    let payload = response?.data;
    if (typeof payload === 'string') {
      try { payload = JSON.parse(payload); } catch { payload = {}; }
    }
    const notifications = (payload && payload.success && Array.isArray(payload.notifications)) ? payload.notifications : [];
    const unread = notifications.filter(n => !n.read_at);
    await Promise.all(unread.map(n => markNotificationAsRead(n.id)));
  } catch {}
}
function getMgrNotifClearKey(userId){ return `intro_mgr_notif_cleared_${userId}`; }
function getMgrNotifClearedAt(userId){
  try { return userId ? (localStorage.getItem(getMgrNotifClearKey(String(userId))) || '') : ''; } catch { return ''; }
}
function setMgrNotifClearedNow(userId){
  try { if (userId) localStorage.setItem(getMgrNotifClearKey(String(userId)), new Date().toISOString()); } catch {}
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
function formatTime(iso){ try { const d = new Date(iso); return d.toLocaleString(); } catch { return ''; } }
function escapeHtml(s){ return String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#039;'}[c])); }
