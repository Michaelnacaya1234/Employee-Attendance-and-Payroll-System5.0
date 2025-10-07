/**
 * GLOBAL API BASE URL CONFIGURATION
 * Sets up the base URL for all API calls in employee portal
 */
const baseApiUrl = `${location.origin}/intro/api`;
let __payslipsView = 'active';

/**
 * STYLE HEADER NOTIFICATION BUTTON FOR EMPLOYEE PORTAL
 * Applies amber color scheme to notification button and badge
 * Consistent styling across all portal interfaces
 */
function styleHeaderNotif(){
  try {
    const btn = document.getElementById('notif-toggle');
    const badge = document.getElementById('notif-badge');
    if (btn) {
      btn.classList.add('bg-amber-50','ring-amber-200','hover:bg-amber-100');
      btn.classList.remove('ring-gray-200','hover:bg-gray-50');
      const faIcon = btn.querySelector('i.fa-bell');
      if (faIcon) { faIcon.classList.add('text-amber-600'); faIcon.classList.remove('text-gray-600'); }
    }
    if (badge) { badge.classList.add('bg-amber-600'); badge.classList.remove('bg-red-600'); }
  } catch {}
}
if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', styleHeaderNotif); }
else { try { styleHeaderNotif(); } catch {} }

// Route all alert dialogs through SweetAlert2 toasts
window.alert = function(msg){
  try { ensureSweetAlertAssets(); } catch {}
  const s = String(msg || '');
  const lower = s.toLowerCase();
  let icon = 'info';
  if (lower.includes('failed') || lower.includes('error')) icon = 'error';
  else if (lower.includes('success') || lower.includes('updated') || lower.includes('submitted') || lower.includes('saved')) icon = 'success';
  else if (lower.includes('please') || lower.includes('select') || lower.includes('enter') || lower.includes('required')) icon = 'warning';
  showSweetToast(s, icon);
};

// Removed Flowbite dependencies - using SweetAlert2 for notifications

/**
 * ENSURE SWEETALERT2 ASSETS ARE LOADED
 * Dynamically loads SweetAlert2 CSS and JavaScript
 * Includes Tailwind CSS compatibility fixes for buttons
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
    const Toast = Swal.mixin({
      toast: true,
      position: 'top-end',
      showConfirmButton: false,
      timer: 1500,
      timerProgressBar: true
    });
    Toast.fire({ icon, title: message });
  } catch {}
}
if (typeof window.showToast !== 'function') {
  window.showToast = (msg, type = 'info') => {
    try { showSweetToast(msg, type); } catch {}
  };
}

/**
 * ENSURE ANIME.JS IS LOADED FOR ANIMATIONS
 * Dynamically loads animation library for card animations
 * Returns null if loading fails
 */
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

/**
 * ANIMATE EMPLOYEE DASHBOARD CARDS
 * Applies entrance animations and hover effects to dashboard cards
 * Uses staggered timing for smooth visual flow
 */
async function animateEmpCards(rootEl){
  try {
    const anime = await ensureAnime();
    if (!anime) return;
    const root = rootEl || document;
    const cards = Array.from(root.querySelectorAll('.bg-white.rounded-xl, .bg-white.rounded-lg')).filter(el => el.classList.contains('shadow') || el.classList.contains('shadow-sm') || el.classList.contains('shadow-md'));
    if (!cards.length) return;
    cards.forEach(c => { c.style.transformOrigin = '50% 50%'; });
    anime({
      targets: cards,
      translateY: [2, 0],
      scale: [0.995, 1],
      easing: 'easeOutQuad',
      duration: 200,
      delay: anime.stagger(20)
    });
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
 * Prevents duplicate event listeners with flag check
 */
function attachSweetHeaderNotif(user){
  try {
    const btn = document.getElementById('notif-toggle');
    if (!btn) return;
    if (btn.__sweetWired) return; // prevent duplicate
    btn.__sweetWired = true;
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopImmediatePropagation();
      try { await ensureSweetAlertAssets(); } catch {}
      const dropdown = document.getElementById('notif-dropdown');
      if (dropdown) dropdown.classList.add('hidden');
      try { await openNotifSweetModal(user); } catch {}
    }, true);
  } catch {}
}

/**
 * OPEN NOTIFICATION MODAL WITH SWEETALERT2
 * Displays employee notifications with delete and mark as read functionality
 * Supports individual and bulk notification management
 */
async function openNotifSweetModal(user){
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
          el.addEventListener('click', async (ev) => {
            const id = el.getAttribute('data-id');
            if (!id) return;
            try {
              await markNotificationAsRead(id);
              el.classList.remove('bg-blue-50');
              await renderHeaderNotifications(user);
            } catch {}
          });
        });
        html.querySelectorAll('.sw-del').forEach(btn => {
          btn.addEventListener('click', async (ev) => {
            ev.preventDefault();
            ev.stopPropagation();
            const id = btn.getAttribute('data-id');
            if (!id) return;
            try {
              await deleteNotification(id);
              const item = btn.closest('.sw-notif-item');
              if (item) item.remove();
              await renderHeaderNotifications(user);
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
        await renderHeaderNotifications(user);
        showSweetToast('All notifications marked as read', 'success');
      } catch { showSweetToast('Failed to mark all as read', 'error'); }
    }
  } catch {}
}






// Override header avatar sync to fetch from DB and fallback to local cache
window.syncHeaderAvatar = async function(user){
  try {
    const img = document.getElementById('emp-prof-avatar-header');
    const ph = document.getElementById('emp-prof-avatar-header-ph');
    if (!img || !ph) return;

    let src = '';
    // Prefer DB image
    if (user && user.employee_id){
      try {
        const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployee', employee_id: user.employee_id } });
        const emp = res.data || {};
        if (emp && emp.profile_image) src = emp.profile_image;
      } catch {}
    }
    // Fallback to local cache for immediate UX
    if (!src && user && user.employee_id){
      try { src = localStorage.getItem(`intro_emp_profile_img_${user.employee_id}`) || ''; } catch {}
    }

    if (src){
      img.src = src;
      img.classList.remove('hidden');
      ph.classList.add('hidden');
    } else {
      img.src = '';
      img.classList.add('hidden');
      ph.classList.remove('hidden');
    }
  } catch {}
};

// Update employee welcome section with user profile image and information
async function updateEmployeeWelcomeSection(user){
  try {
    // Update welcome name
    const welcomeNameEl = document.getElementById('emp-welcome-name');
    const welcomeDateEl = document.getElementById('emp-welcome-date');
    const welcomeImg = document.getElementById('emp-welcome-avatar-img');
    const welcomePh = document.getElementById('emp-welcome-avatar-ph');
    
    const displayName = (() => {
      const first = (user.first_name || '').trim();
      const last = (user.last_name || '').trim();
      if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
      const u = (user.username || '').trim();
      if (u.includes('@')) return u.split('@')[0];
      return u || 'Employee';
    })();
    
    if (welcomeNameEl) welcomeNameEl.textContent = displayName;
    
    // Update date with real-time clock
    const updateTime = () => {
      if (welcomeDateEl) welcomeDateEl.textContent = new Date().toLocaleString('en-US');
    };
    updateTime();
    if (window.__empWelcomeInterval) clearInterval(window.__empWelcomeInterval);
    window.__empWelcomeInterval = setInterval(updateTime, 1000);
    
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
        src = loadProfileImg(user.employee_id);
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

document.addEventListener('DOMContentLoaded', async () => {
  try { await ensureSweetAlertAssets(); } catch {}
  // Ensure employee logged in
  const me = await currentUser();
  if (!me || (me.role !== 'employee' && me.role !== 'manager')) {
    location.href = './login.html';
    return;
  }

  // Refresh user data to ensure we have the latest information
  const refreshedUser = await refreshUserData(me);

  handleEmpRoute(refreshedUser);
  window.addEventListener('hashchange', () => handleEmpRoute(refreshedUser));
  wireHelp();
  wireEmpProfileMenu();
  wireNewLeaveButtonDelegation();
});

async function currentUser(){
  try {
    // Check session storage first for updated user information
    const storedUser = sessionStorage.getItem('currentUser');
    if (storedUser) {
      try {
        const parsedUser = JSON.parse(storedUser);
        if (parsedUser && parsedUser.user_id) {
          return parsedUser;
        }
      } catch (e) {
        console.log('Could not parse stored user data');
      }
    }

    // Fallback to API call
    const res = await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
    const user = res.data && res.data.user ? res.data.user : null;

    // Store the user in session storage for future use
    if (user) {
      try {
        sessionStorage.setItem('currentUser', JSON.stringify(user));
      } catch (e) {
        console.log('Could not store user in session storage');
      }
    }

    return user;
  } catch { return null; }
}

async function refreshUserData(user) {
  try {
    // Get fresh user data from the server
    const res = await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
    const freshUser = res.data && res.data.user ? res.data.user : null;

    if (freshUser) {
      // Merge with any stored updates
      const storedUser = sessionStorage.getItem('currentUser');
      if (storedUser) {
        try {
          const parsedStored = JSON.parse(storedUser);
          Object.assign(freshUser, parsedStored);
        } catch (e) {
          console.log('Could not merge stored user data');
        }
      }

      // Update session storage
      try {
        sessionStorage.setItem('currentUser', JSON.stringify(freshUser));
      } catch (e) {
        console.log('Could not update session storage');
      }

      return freshUser;
    }

    return user;
  } catch (error) {
    console.error('Failed to refresh user data:', error);
    return user;
  }
}

function wireHelp(){
  const btn = document.getElementById('btn-help');
  if (btn){
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
}

// Manager-like dropdown profile wiring for employee header
function wireEmpProfileMenu(){
  if (window.__empProfileMenuWired) return;
  window.__empProfileMenuWired = true;
  const trigger = document.getElementById('emp-profile-toggle');
  const menu = document.getElementById('profile-dropdown');
  const headerLogout = document.getElementById('header-logout');
  if (trigger && menu){
    trigger.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); menu.classList.toggle('hidden'); });
    document.addEventListener('click', (e) => {
      if (!menu.classList.contains('hidden')){
        const within = trigger.contains(e.target) || menu.contains(e.target);
        if (!within) menu.classList.add('hidden');
      }
    });
  }
  if (headerLogout){
    headerLogout.addEventListener('click', async (e) => {
      e.preventDefault();
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
        try { sessionStorage.removeItem('currentUser'); } catch {}
        location.href = './login.html';
      }
    });
  }
}

// Delegated wiring for the 'File new leave' button to survive re-renders
function wireNewLeaveButtonDelegation(){
  if (window.__newLeaveBtnDelegated) return;
  window.__newLeaveBtnDelegated = true;
  document.addEventListener('click', (e) => {
    const btn = e.target && e.target.closest ? e.target.closest('#btn-new-leave') : null;
    if (btn) {
      const modal = document.getElementById('leave-modal');
      if (modal) modal.classList.remove('hidden');
    }
  });
}

async function render(user){
  const app = document.getElementById('emp-app');
  app.innerHTML = `
    <section class="mb-6">
      <div class="sticky top-0 z-10 relative overflow-hidden rounded-xl bg-gradient-to-r from-primary-700 to-primary-600 text-white shadow">
        <div class="absolute -right-16 -top-16 w-64 h-64 rounded-full bg-white/10"></div>
        <div class="p-6 flex items-center justify-between relative">
          <div class="flex items-center gap-4">
            <div class="w-12 h-12 rounded-full bg-white/20 flex items-center justify-center relative overflow-hidden">
              <img id="emp-welcome-avatar-img" alt="Profile" class="w-full h-full object-cover hidden"/>
              <svg id="emp-welcome-avatar-ph" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-6 h-6 text-white">
                <path d="M12 12c2.21 0 4-1.79 4-4S14.21 4 12 4 8 5.79 8 8s1.79 4 4 4zm0 2c-3.33 0-8 1.67-8 5v1h16v-1c0-3.33-4.67-5-8-5z"/>
              </svg>
            </div>
            <div>
              <h1 class="text-2xl font-semibold">Welcome, <span id="emp-welcome-name">Employee</span></h1>
              <div class="mt-1 text-white/90 text-sm flex items-center gap-2">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-4 h-4"><path d="M12 8a1 1 0 011 1v3h3a1 1 0 110 2h-4a1 1 0 01-1-1V9a1 1 0 011-1z"/><path fill-rule="evenodd" d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zm0-18a8 8 0 100 16 8 8 0 000-16z" clip-rule="evenodd"/></svg>
                <span id="emp-welcome-date"></span>
              </div>
              <div class="mt-1 text-white/90 text-sm">Department: ${user.department || 'Not set'}</div>
            </div>
          </div>
        </div>
      </div>
    </section>
        <section class="grid grid-cols-1 gap-4">
      <div class="bg-white rounded-xl shadow-sm hover:shadow-md transition-shadow border border-gray-100 p-4">
        <h3 class="font-semibold text-gray-900 tracking-tight mb-2">Today's Attendance</h3>
        <div id="today-att"></div>
      </div>
    </section>
    <section class="grid grid-cols-1 gap-4 mt-4">
      <div class="bg-white rounded-xl shadow-sm hover:shadow-md transition-shadow border border-gray-100 p-4" id="emp-holidays-card">
        <div class="flex items-center justify-between mb-2">
          <h3 class="font-semibold text-gray-900 tracking-tight">Calendar</h3>
          <div class="flex items-center gap-2">
            <button id="emp-cal-prev" class="px-2 py-1 text-xs border rounded">Prev</button>
            <div id="emp-cal-title" class="text-sm font-medium min-w-[8rem] text-center"></div>
            <button id="emp-cal-next" class="px-2 py-1 text-xs border rounded">Next</button>
          </div>
        </div>
        <div id="emp-calendar" class="grid grid-cols-7 gap-px bg-gray-200 rounded overflow-hidden text-xs"></div>
        <div class="text-[10px] text-gray-500 mt-2">Legend: <span class="inline-block w-3 h-3 bg-rose-500 align-middle mr-1"></span> Holiday • <span class="inline-block w-3 h-3 bg-primary-500 align-middle mr-1"></span> Today • <span class="inline-block w-3 h-3 bg-rose-200 align-middle mr-1"></span> Sun • <span class="inline-block w-3 h-3 bg-blue-200 align-middle mr-1"></span> Sat</div>
      </div>
    </section>`;

  try { await animateEmpCards(app); } catch {}
  
  // Update welcome section with user info and profile image
  await updateEmployeeWelcomeSection(user);
  
  await Promise.all([
    renderTodayAttendance(user),
    renderHeaderNotifications(user)
  ]);

  // Employee Holiday Calendar (read-only, same behavior as HR)
  function monthNameEmp(m){ return new Date(2000, m-1, 1).toLocaleString('en-US', { month: 'long' }); }
  async function renderHolidayCalendarEmp(){
    const container = document.getElementById('emp-calendar');
    const title = document.getElementById('emp-cal-title');
    if (!container || !title) return;
    if (!window.__empCalState){ const now = new Date(); window.__empCalState = { year: now.getFullYear(), month: now.getMonth()+1 }; }
    const { year, month } = window.__empCalState;
    title.textContent = `${monthNameEmp(month)} ${year}`;
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
      let cellCls = 'relative p-2 h-24 hover:bg-gray-50 bg-white';
      if (hol) cellCls += ' cursor-pointer';
      if (isSun) cellCls = cellCls.replace('bg-white','bg-rose-50');
      else if (isSat) cellCls = cellCls.replace('bg-white','bg-blue-50');
      if (hol) cellCls += ' border-l-4 border-rose-400';
      cell.className = cellCls;
      cell.setAttribute('data-date', dateStr);
      const todayBadge = isToday ? '<span class="absolute top-1 right-1 text-[10px] px-1 py-0.5 rounded bg-primary-600 text-white">Today</span>' : '';
      if (isToday) { cell.className += ' bg-primary-50 ring-2 ring-primary-300'; }
      const dayNumCls = isSun ? 'text-rose-600' : (isSat ? 'text-blue-600' : 'text-gray-500');
      const escape = (s) => String(s||'').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
      const topBarClass = hol ? 'bg-rose-500' : (isToday ? 'bg-primary-500' : (isSun ? 'bg-rose-300' : (isSat ? 'bg-blue-300' : 'bg-gray-200')));
      const topBarHtml = `<div class="absolute left-0 right-0 top-0 h-1 ${topBarClass}"></div>`;
      cell.innerHTML = `
        ${topBarHtml}
        <div class="text-[11px] ${dayNumCls}">${d}</div>
        ${hol ? `<div class=\"mt-1 text-[11px] px-1 py-0.5 rounded bg-rose-500 text-white inline-block\" title=\"${escape(hol.holiday_name)}${hol.description ? ' — ' + escape(hol.description) : ''}\">${escape(hol.holiday_name)}</div>` : ''}
        ${todayBadge}`;
      if (hol) { cell.addEventListener('click', () => openHolidayViewEmp(hol)); }
      container.appendChild(cell);
    }
    const prev = document.getElementById('emp-cal-prev');
    const next = document.getElementById('emp-cal-next');
    if (prev && !prev.__wired){ prev.__wired = true; prev.addEventListener('click', async () => { let {year, month} = window.__empCalState; month--; if (month===0){ month=12; year--; } window.__empCalState = { year, month }; await renderHolidayCalendarEmp(); }); }
    if (next && !next.__wired){ next.__wired = true; next.addEventListener('click', async () => { let {year, month} = window.__empCalState; month++; if (month===13){ month=1; year++; } window.__empCalState = { year, month }; await renderHolidayCalendarEmp(); }); }

    // Minimal calendar cell animation (align with admin calendar, no opacity changes)
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
        const titleEl = document.getElementById('emp-cal-title');
        if (titleEl) {
          anime.remove(titleEl);
          anime({ targets: titleEl, translateX: [-6, 0], scale: [0.98, 1], duration: 220, easing: 'easeOutQuad' });
        }
      }
    } catch {}
  }
  function openHolidayViewEmp(row){
    try {
      let modal = document.getElementById('empHolidayViewModal');
      if (!modal){ modal = document.createElement('div'); modal.id='empHolidayViewModal'; modal.className='fixed inset-0 z-50 hidden'; document.body.appendChild(modal); }
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

  await renderHolidayCalendarEmp();



  // Set up auto-refresh for header notifications every 30 seconds (reset any existing interval)
  if (window.__empNotifInterval){ try { clearInterval(window.__empNotifInterval); } catch {} }
  window.__empNotifInterval = setInterval(async () => {
    await renderHeaderNotifications(user);
  }, 30000);

  // Wire leave search
  const lvSearchInput = document.getElementById('lv-search');
  if (lvSearchInput) lvSearchInput.addEventListener('input', async () => { await renderLeaves(user); });

  // Wire leave modal (if present on this view)
  const modal = document.getElementById('leave-modal');
  if (modal) {
    const open = () => modal.classList.remove('hidden');
    const close = () => modal.classList.add('hidden');
    const newLeaveBtn = document.getElementById('btn-new-leave');
    if (newLeaveBtn) newLeaveBtn.addEventListener('click', open);
    modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', close));
  }
  // Overtime/Undertime request modals
  const otModal = document.getElementById('overtime-modal');
  const utModal = document.getElementById('undertime-modal');
  const openOt = () => { if (otModal) otModal.classList.remove('hidden'); };
  const closeOt = () => { if (otModal) otModal.classList.add('hidden'); };
  const openUt = () => { if (utModal) utModal.classList.remove('hidden'); };
  const closeUt = () => { if (utModal) utModal.classList.add('hidden'); };
  const otBtn = document.getElementById('btn-request-ot');
  if (otBtn) otBtn.addEventListener('click', openOt);
  if (otModal) otModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeOt));
  const utBtn = document.getElementById('btn-request-ut');
  if (utBtn) utBtn.addEventListener('click', openUt);
  if (utModal) utModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeUt));
  const otSave = document.getElementById('ot-save');
  if (otSave) otSave.addEventListener('click', async () => {
    const date = (document.getElementById('ot-date')?.value || '').trim();
    const reason = (document.getElementById('ot-reason')?.value || '').trim();
    // Default overtime window 8:30 PM → 10:00 PM
    const start_time = '20:30';
    const end_time = '22:00';
    const hours = 1.5; // 90 minutes
    if (!date) { showToast('Select a valid date for overtime', 'warning'); return; }
    try {
      const fd = new FormData();
      fd.append('operation', 'requestOvertime');
      fd.append('json', JSON.stringify({ employee_id: user.employee_id, work_date: date, start_time, end_time, hours, reason }));
      const res = await axios.post(`${baseApiUrl}/overtime.php`, fd);
      const ok = res && res.data && (res.data.success === 1 || res.data === 1);
      if (ok) { closeOt(); showToast('Overtime request submitted', 'success'); await renderLeaves(user); }
      else { showToast('Failed to submit overtime request', 'error'); }
    } catch {
      showToast('Failed to submit overtime request', 'error');
    }
  });
  const utSave = document.getElementById('ut-save');
  if (utSave) utSave.addEventListener('click', async () => {
    const date = (document.getElementById('ut-date')?.value || '').trim();
    const hours = Number((document.getElementById('ut-hours')?.value || '').trim());
    const reason = (document.getElementById('ut-reason')?.value || '').trim();
    if (!date || !Number.isFinite(hours) || hours <= 0) { showToast('Enter a valid date and hours for undertime', 'warning'); return; }
    try {
      const fd = new FormData();
      fd.append('operation', 'requestUndertime');
      fd.append('json', JSON.stringify({ employee_id: user.employee_id, work_date: date, hours, reason }));
      const res = await axios.post(`${baseApiUrl}/undertime.php`, fd);
      const ok = res && res.data && (res.data.success === 1 || res.data === 1);
      if (ok) { closeUt(); showToast('Undertime request submitted', 'success'); await renderLeaves(user); }
      else { showToast('Failed to submit undertime request', 'error'); }
    } catch {
      showToast('Failed to submit undertime request', 'error');
    }
  });
  const lvSaveBtn = document.getElementById('lv-save');
  if (lvSaveBtn && modal) lvSaveBtn.addEventListener('click', async () => {
    const start = (document.getElementById('lv-start').value||'').trim();
    const end = (document.getElementById('lv-end').value||'').trim();
    const reason = (document.getElementById('lv-reason').value||'').trim();
    const typeRaw = (document.getElementById('lv-type')?.value || '');
    const type = typeRaw.toLowerCase();
    if (!start || !end) { showToast('Please select start and end dates', 'warning'); return; }
    if (!typeRaw) { showToast('Please select a leave type', 'warning'); return; }
    // Validate leave balance before submitting
    const daysReq = (() => {
      try {
        const s = new Date(start);
        const e = new Date(end || start);
        const ms = 24*60*60*1000;
        const sUTC = Date.UTC(s.getFullYear(), s.getMonth(), s.getDate());
        const eUTC = Date.UTC(e.getFullYear(), e.getMonth(), e.getDate());
        const diff = Math.round((eUTC - sUTC) / ms);
        return Math.max(1, diff + 1);
      } catch { return 0; }
    })();
    const bal = window.__leaveBalances || { remainingVacation: 0, remainingSick: 0 };
    if (type.includes('vacation')) {
      if (bal.remainingVacation <= 0 || daysReq > bal.remainingVacation) {
        showToast('Not enough vacation balance', 'warning');
        return;
      }
    } else if (type.includes('sick')) {
      if (bal.remainingSick <= 0 || daysReq > bal.remainingSick) {
        showToast('Not enough sick leave balance', 'warning');
        return;
      }
    } else if (type.includes('birthday')) {
      if ((bal.remainingBirthday || 0) <= 0 || daysReq > (bal.remainingBirthday || 0)) {
        showToast('Not enough sick leave balance', 'warning');
        return;
      }
    }
    try {
      try { await ensureSweetAlertAssets(); } catch {}
      const result = await Swal.fire({
        title: 'Submit leave request?',
        text: `${start} to ${end} (${typeRaw || 'Leave'})`,
        icon: 'question',
        showCancelButton: true,
        confirmButtonText: 'Submit',
        cancelButtonText: 'Cancel'
      });
      if (!result.isConfirmed) return;
      const fd = new FormData();
      fd.append('operation', 'requestLeave');
      fd.append('json', JSON.stringify({ employee_id: user.employee_id, start_date: start, end_date: end, reason, leave_type: typeRaw }));
      await axios.post(`${baseApiUrl}/leaves.php`, fd);
      if (modal) modal.classList.add('hidden');
      await renderLeaves(user);
      showToast('Leave request submitted', 'success');
    } catch { showToast('Failed to submit', 'error'); }
  });

  // Wire update personal details modal
  const detailsModal = document.getElementById('details-modal');
  const openDetails = () => { if (detailsModal) detailsModal.classList.remove('hidden'); };
  const closeDetails = () => { if (detailsModal) detailsModal.classList.add('hidden'); };
  if (detailsModal) detailsModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeDetails));
  const updateBtn = document.getElementById('btn-update-details');
  if (updateBtn) {
    updateBtn.addEventListener('click', async () => {
      try {
        const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployee', employee_id: user.employee_id } });
        const e = res.data || {};
        detailsModal.dataset.original = JSON.stringify(e || {});
        const f = (id) => document.getElementById(id);
        if (f('pd-first')) f('pd-first').value = e.first_name || '';
        if (f('pd-last')) f('pd-last').value = e.last_name || '';
        if (f('pd-email')) f('pd-email').value = e.email || '';
        if (f('pd-phone')) f('pd-phone').value = e.phone || '';
        if (f('pd-password')) f('pd-password').value = '';
        openDetails();
      } catch {
        alert('Unable to load your details');
      }
    });
  }
  const saveDetailsBtn = document.getElementById('details-save');
  if (saveDetailsBtn) {
    saveDetailsBtn.addEventListener('click', async () => {
      try {
        const orig = (() => { try { return JSON.parse(detailsModal.dataset.original || '{}'); } catch { return {}; } })();
        const first = (document.getElementById('pd-first').value || '').trim();
        const last = (document.getElementById('pd-last').value || '').trim();
        const email = (document.getElementById('pd-email').value || '').trim();
        const phone = (document.getElementById('pd-phone').value || '').trim();
        const newPwd = (document.getElementById('pd-password').value || '').trim();
        if (!first || !last || !email) { alert('First name, last name and email are required'); return; }
        const payload = {
          employee_id: user.employee_id,
          first_name: first,
          last_name: last,
          email: email,
          phone: phone,
          department: orig.department || '',
          position: orig.position || 'employee',
          basic_salary: orig.basic_salary != null ? orig.basic_salary : 0,
          date_hired: orig.date_hired || '',
          status: orig.status || 'active'
        };
        if (newPwd) payload.hr_password = newPwd;
        const fd = new FormData();
        fd.append('operation', 'updateEmployee');
        fd.append('json', JSON.stringify(payload));
        const response = await axios.post(`${baseApiUrl}/employees.php`, fd);

        // Close modal and show success message
        closeDetails();
        alert('Your details have been updated');

        // Update the user object with new information from the response
        if (response.data && response.data.success) {
          // Sync user object with updated information from API
          if (response.data.updated_user) {
            user.user_id = response.data.updated_user.user_id;
            user.username = response.data.updated_user.username;
            user.role = response.data.updated_user.role;
            user.employee_id = response.data.updated_user.employee_id;
          }

          // Sync employee information
          if (response.data.updated_employee) {
            user.first_name = response.data.updated_employee.first_name;
            user.last_name = response.data.updated_employee.last_name;
            user.email = response.data.updated_employee.email;
            user.phone = response.data.updated_employee.phone;
            user.department = response.data.updated_employee.department;
            user.position = response.data.updated_employee.position;
          }

          // Update session storage to persist the changes
          try {
            sessionStorage.setItem('currentUser', JSON.stringify(user));
          } catch (e) {
            console.log('Could not update session storage');
          }
        }

        // Automatically refresh the dashboard to show updated information
        await render(user);

        // Add background notification about profile update
        addEmployeeNotification(user, 'Profile updated successfully - Your personal details have been updated');

        // Show toast notification
        showToast('Profile updated successfully!', 'success');

      } catch (error) {
        console.error('Update failed:', error);
        alert('Failed to update details');
      }
    });
  }



  // Header notifications setup
  initHeaderNotifications(user);

  // Wire profile dropdown, header profile text, header logout, and sync header avatar
  window.syncHeaderAvatar(user);

  // Fill header profile name/role like manager dashboard
  try {
    const nameEl = document.getElementById('profile-name');
    const roleEl = document.getElementById('profile-role');
    const displayName = (() => {
      const first = (user.first_name || '').trim();
      const last = (user.last_name || '').trim();
      if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
      const u = (user.username || '').trim();
      if (u.includes('@')) return u.split('@')[0];
      return u || 'Employee';
    })();
    if (nameEl) nameEl.textContent = displayName;
    if (roleEl) roleEl.textContent = user.role || 'employee';
  } catch {}

  // Fill employee welcome name/date like manager dashboard hero
  try {
    const empWelcomeNameEl = document.getElementById('emp-welcome-name');
    if (empWelcomeNameEl) {
      const displayName = (() => {
        const first = (user.first_name || '').trim();
        const last = (user.last_name || '').trim();
        if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
        const u = (user.username || '').trim();
        if (u.includes('@')) return u.split('@')[0];
        return u || 'Employee';
      })();
      empWelcomeNameEl.textContent = displayName;
    }
    const dateEl = document.getElementById('emp-welcome-date');
    if (dateEl) {
      if (window.__empWelcomeInterval) { try { clearInterval(window.__empWelcomeInterval); } catch {} }
      const tick = () => { dateEl.textContent = new Date().toLocaleString('en-US'); };
      tick();
      window.__empWelcomeInterval = setInterval(tick, 1000);
    }
  } catch {}

  wireEmpProfileMenu();
  const profSettings = document.getElementById('emp-profile');
  const profDropdown = document.getElementById('profile-dropdown');
  if (profSettings) {
    profSettings.addEventListener('click', async (e) => {
      e.preventDefault();
      if (profDropdown) profDropdown.classList.add('hidden');
      await openEmployeeProfile(user);
    });
  }
}

function handleEmpRoute(user){
  const hash = (location.hash || '').replace('#','').trim().toLowerCase();
  if (hash === 'payslips') { renderPayslipsOnly(user); }
  else if (hash === 'requests') { renderLeaveRequestsOnly(user); }
  else if (hash === 'attendance') { renderAttendanceOnly(user); }
  else { render(user); }
}

async function renderPayslipsOnly(user){
  const app = document.getElementById('emp-app');
  app.innerHTML = `
    <section class="grid grid-cols-1 gap-4">
      <div class="bg-white rounded-xl shadow-sm hover:shadow-md transition-shadow border border-gray-100 p-4">
        <h3 class="font-semibold text-gray-900 tracking-tight mb-2 flex items-center justify-between"><span>Payslips</span><div class="flex items-center gap-2"><button id="ps-active-btn" class="px-2 py-1 text-xs rounded border bg-primary-600 text-white">Active</button><button id="ps-history-btn" class="px-2 py-1 text-xs rounded border">History</button></div></h3>
        <div id="payslips" class="text-sm"></div>
      </div>
    </section>`;
  try { await animateEmpCards(app); } catch {}
  await renderPayslips(user);


  // Ensure header UI components remain interactive
  initHeaderNotifications(user);
  await renderHeaderNotifications(user);
  window.syncHeaderAvatar(user);

  // Fill header profile text
  try {
    const nameEl = document.getElementById('profile-name');
    const roleEl = document.getElementById('profile-role');
    const displayName = (() => {
      const first = (user.first_name || '').trim();
      const last = (user.last_name || '').trim();
      if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
      const u = (user.username || '').trim();
      if (u.includes('@')) return u.split('@')[0];
      return u || 'Employee';
    })();
    if (nameEl) nameEl.textContent = displayName;
    if (roleEl) roleEl.textContent = user.role || 'employee';
  } catch {}

  // Wire profile dropdown and actions
  wireEmpProfileMenu();
  const profSettings = document.getElementById('emp-profile');
  const profDropdown = document.getElementById('profile-dropdown');
  if (profSettings) {
    profSettings.addEventListener('click', async (e) => {
      e.preventDefault();
      if (profDropdown) profDropdown.classList.add('hidden');
      await openEmployeeProfile(user);
    });
  }
}

async function renderAttendanceOnly(user){
  const app = document.getElementById('emp-app');
  app.innerHTML = `
    <section class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div class="bg-white rounded-xl shadow-sm hover:shadow-md transition-shadow border border-gray-100 p-4">
        <h3 class="font-semibold text-gray-900 tracking-tight mb-2">Today's Attendance</h3>
        <ul id="today-att-details" class="text-sm space-y-1"></ul>
      </div>
      <div class="bg-white rounded-xl shadow-sm hover:shadow-md transition-shadow border border-gray-100 p-4">
        <h3 class="font-semibold text-gray-900 tracking-tight mb-2">This Week</h3>
        <ul id="week-att-summary" class="text-sm space-y-1"></ul>
      </div>
    </section>
    <section class="mt-4">
      <div class="bg-white rounded-xl shadow-sm hover:shadow-md transition-shadow border border-gray-100 p-4">
        <div class="flex items-center justify-between mb-2">
          <h3 class="font-semibold text-gray-900 tracking-tight">Attendance Log</h3>
          <div class="flex items-center gap-2 text-sm">
            <input type="date" id="emp-att-start" class="border rounded px-2 py-1" />
            <span class="text-gray-400">→</span>
            <input type="date" id="emp-att-end" class="border rounded px-2 py-1" />
            <button id="emp-att-apply" class="px-3 py-1.5 rounded border hover:bg-gray-50">Apply</button>
          </div>
        </div>
        <div id="emp-log-table" class="overflow-x-auto"></div>
        <div id="emp-log-pagination" class="mt-3 text-sm text-gray-600"></div>
      </div>
    </section>`;

  try { await animateEmpCards(app); } catch {}
  // Helpers

  const fmtDate = (s) => { try { const d = new Date(String(s).includes('T') ? s : `${s}T00:00:00`); return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }); } catch { return String(s||''); } };

  const fmtTime = (t) => { try { const [hh, mm] = String(t||'').split(':').map(n=>parseInt(n,10)); if (!Number.isFinite(hh)) return ''; const ampm = hh>=12?'PM':'AM'; const h = ((hh%12)||12); return `${h}:${String(mm||0).padStart(2,'0')} ${ampm}`; } catch { return String(t||''); } };
  const toMinutes = (t) => { try { const [hh, mm] = String(t||'').split(':').map(n=>parseInt(n,10)); return (hh*60 + (mm||0)); } catch { return NaN; } };
  const inRange = (d, a, b) => { const x = new Date(d).setHours(0,0,0,0); return x >= new Date(a).setHours(0,0,0,0) && x <= new Date(b).setHours(0,0,0,0); };
const weekRange = (base = new Date()) => { const d = new Date(base); const day = d.getDay(); const diffToMon = (day+6)%7; const start = new Date(d); start.setDate(d.getDate()-diffToMon); const end = new Date(start); end.setDate(start.getDate()+6); return { start: start.toISOString().slice(0,10), end: end.toISOString().slice(0,10) }; };

  // Load data
  const today = new Date().toISOString().slice(0,10);
  const { start: wkStart, end: wkEnd } = weekRange(new Date());

  const [attTodayRes, attWeekRes, otRes, utRes, lvRes] = await Promise.all([
    axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: today, end_date: today } }),
    axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: wkStart, end_date: wkEnd } }),
    axios.get(`${baseApiUrl}/overtime.php`, { params: { operation: 'listByEmployee', employee_id: user.employee_id } }),
    axios.get(`${baseApiUrl}/undertime.php`, { params: { operation: 'listByEmployee', employee_id: user.employee_id } }),
    axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listByEmployee', employee_id: user.employee_id } })
  ]).catch(()=>[{}, {}, {}, {}, {}]);

  const todayRec = (Array.isArray(attTodayRes?.data) ? attTodayRes.data : []).find(r => String(r.employee_id) === String(user.employee_id)) || null;
  const weekAtt = (Array.isArray(attWeekRes?.data) ? attWeekRes.data : []).filter(r => String(r.employee_id) === String(user.employee_id));
  const otList = Array.isArray(otRes?.data) ? otRes.data : [];
  const utList = Array.isArray(utRes?.data) ? utRes.data : [];
  const lvList = Array.isArray(lvRes?.data) ? lvRes.data : [];

  // Today details
  const SHIFT_START = '08:00';
  const tDate = fmtDate(today);
  const tIn = todayRec?.time_in || '';
  const tOut = todayRec?.time_out || '';
  const tStatusRaw = String(todayRec?.status || '').toLowerCase();
  const isPresent = ['present','late','undertime','leave'].includes(tStatusRaw);
  let lateMins = 0;
  if (tIn && Number.isFinite(toMinutes(tIn)) && Number.isFinite(toMinutes(SHIFT_START))) {
    lateMins = Math.max(0, toMinutes(tIn) - toMinutes(SHIFT_START));
  }
  const statusText = (() => {
    if (tStatusRaw === 'late' || (isPresent && lateMins>0)) return `Present (Late by ${lateMins} mins)`;
    if (tStatusRaw === 'undertime') return 'Present (Undertime)';
    if (tStatusRaw === 'leave') return 'On Leave';
    if (tStatusRaw === 'absent') return 'Absent';
    return isPresent ? 'Present' : (tStatusRaw ? tStatusRaw : 'No record');
  })();
  const otToday = (otList || []).find(o => String(o.work_date) === today);
  const utToday = (utList || []).find(u => String(u.work_date) === today);
  const otTodayText = (() => {
    if (!otToday) return 'None';
    const h = (otToday.hours != null) ? Number(otToday.hours) : NaN;
    if (Number.isFinite(h) && h>0) return `${h} hrs`;
    if (otToday.start_time && otToday.end_time) return `${otToday.start_time} – ${otToday.end_time}`;
    return 'None';
  })();
  const utTodayText = (() => {
    if (!utToday) return 'None';
    const h = (utToday.hours != null) ? Number(utToday.hours) : NaN;
    if (Number.isFinite(h) && h>0) return `${h} hrs`;
    if (utToday.end_time) return `Time Out: ${fmtTime(utToday.end_time)}`;
    return 'None';
  })();

  const todayList = document.getElementById('today-att-details');
  if (todayList) {
    todayList.innerHTML = `
      <li>Date: <strong>${tDate}</strong></li>
      <li>Time In: <strong>${tIn ? fmtTime(tIn) : '—'}</strong></li>
      <li>Time Out: <strong>${tOut ? fmtTime(tOut) : '—'}</strong></li>
      <li>Status: <strong>${statusText}</strong></li>
      <li>Overtime: <strong>${otTodayText}</strong></li>
      <li>Undertime: <strong>${utTodayText}</strong></li>`;
  }

  // This week summary
  const workedDays = weekAtt.filter(r => ['present','late','undertime'].includes(String(r.status||'').toLowerCase())).length;
  const absents = weekAtt.filter(r => String(r.status||'').toLowerCase() === 'absent').length;
  const otHoursWeek = (otList || []).filter(o => inRange(o.work_date, wkStart, wkEnd)).reduce((sum,o)=>sum + (Number(o.hours)||0), 0);
  const fmtHoursHM = (hours) => {
    const total = Math.round(Number(hours || 0) * 60);
    const h = Math.floor(total / 60);
    const m = total % 60;
    const parts = [];
    if (h > 0) parts.push(`${h}h`);
    if (m > 0) parts.push(`${m}mins`);
    return parts.length ? parts.join(' ') : '0';
  };

  // Approved leave days overlapping the week
  const overlapDays = (s, e) => {
    try {
      const start = new Date(String(s).includes('T')?s:`${s}T00:00:00`);
      const end = new Date(String(e||s).includes('T')? (e||s) : `${e||s}T00:00:00`);
      const ws = new Date(`${wkStart}T00:00:00`), we = new Date(`${wkEnd}T00:00:00`);
      const from = new Date(Math.max(start, ws));
      const to = new Date(Math.min(end, we));
      if (to < from) return 0;
      const msPerDay = 24*60*60*1000;
      const days = Math.round((Date.UTC(to.getFullYear(), to.getMonth(), to.getDate()) - Date.UTC(from.getFullYear(), from.getMonth(), from.getDate()))/msPerDay) + 1;
      return Math.max(0, days);
    } catch { return 0; }
  };
  const approvedLeaves = (lvList || []).filter(l => String(l.status||'').toLowerCase() === 'approved');
  const totalLeaveDaysWeek = approvedLeaves.reduce((sum,l)=> sum + overlapDays(l.start_date, l.end_date), 0);
  const firstApprovedType = approvedLeaves.find(l => overlapDays(l.start_date, l.end_date) > 0)?.leave_type || '';

  const wk = document.getElementById('week-att-summary');
  if (wk) {
    const leaveLabel = totalLeaveDaysWeek > 0 ? `${totalLeaveDaysWeek} ${totalLeaveDaysWeek===1?'day':'days'} (Approved${firstApprovedType?` – ${firstApprovedType}`:''})` : '0 day';
    wk.innerHTML = `
      <li>Worked Days: <strong>${workedDays}</strong></li>
      <li>Absent: <strong>${absents}</strong></li>
      <li>Overtime: <strong>${fmtHoursHM(otHoursWeek)}</strong></li>
      <li>Leave: <strong>${leaveLabel}</strong></li>`;
  }

  // Attendance Log (Employee View)
  try {
    const startInput = document.getElementById('emp-att-start');
    const endInput = document.getElementById('emp-att-end');
    const applyBtn = document.getElementById('emp-att-apply');
    const tableDiv = document.getElementById('emp-log-table');

    const toYMD = (d) => { const y=d.getFullYear(); const m=String(d.getMonth()+1).padStart(2,'0'); const day=String(d.getDate()).padStart(2,'0'); return `${y}-${m}-${day}`; };
    const defaultRange = () => {
      const d = new Date();
      const end = new Date(d);
      const start = new Date(d);
      start.setDate(d.getDate()-6); // last 7 days
      return { start: toYMD(start), end: toYMD(end) };
    };
    const { start: defStart, end: defEnd } = defaultRange();
    if (startInput && !startInput.value) startInput.value = defStart;
    if (endInput && !endInput.value) endInput.value = defEnd;

    const SHIFT_END = '17:00';

    const dayList = (s,e) => { const out=[]; try { const a=new Date(`${s}T00:00:00`); const b=new Date(`${e}T00:00:00`); for(let dt=new Date(a); dt<=b; dt.setDate(dt.getDate()+1)){ out.push(toYMD(dt)); } } catch {} return out; };
    const diffHours = (d, tin, tout) => {
      try {
        if (!tin || !tout) return '';
        const a = new Date(`${d}T${tin}`);
        const b = new Date(`${d}T${tout}`);
        let ms = b - a;
        if (!Number.isFinite(ms) || ms<0) return '';
        const mins = Math.round(ms/60000);
        const h = Math.floor(mins/60), m = mins%60;
        const hStr = h>0 ? `${h} hr${h!==1?'s':''}` : '';
        const mStr = m>0 ? `${m} min` : '';
        return [hStr, mStr].filter(Boolean).join(' ');
      } catch { return ''; }
    };
    const findApprovedOT = (date) => (otList || []).filter(o => String(o.work_date)===date && String(o.status||'').toLowerCase()==='approved');
    const findApprovedUT = (date) => (utList || []).filter(u => String(u.work_date)===date && String(u.status||'').toLowerCase()==='approved');
    const isOnApprovedLeave = (date) => {
      const d0 = new Date(`${date}T00:00:00`);
      return (lvList || []).some(l => String(l.status||'').toLowerCase()==='approved' && inRange(date, l.start_date, l.end_date || l.start_date));
    };

    async function loadLog(){
      if (!tableDiv) return;
      tableDiv.innerHTML = '<div class="text-gray-500">Loading...</div>';
      const start = (startInput && startInput.value) ? startInput.value : defStart;
      const end = (endInput && endInput.value) ? endInput.value : defEnd;
      try {
        const res = await axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: start, end_date: end } });
        const rows = (Array.isArray(res.data) ? res.data : []).filter(r => String(r.employee_id)===String(user.employee_id));
        const byDate = new Map();
        rows.forEach(r => { const d = String(r.attendance_date||'').slice(0,10); if (!d) return; byDate.set(d, r); });
        const dates = dayList(start, end);
        const data = dates.map(d => {
          const r = byDate.get(d) || null;
          const approvedLeave = isOnApprovedLeave(d);
          const statusRaw = String(r?.status || '').toLowerCase();
          let status = r ? (statusRaw || 'present') : (approvedLeave ? 'leave' : 'absent');
          let remarks = r?.remarks || '';
          // Late remark
          const tin = r?.time_in || '';
          if (!remarks && tin && Number.isFinite(toMinutes(tin)) && Number.isFinite(toMinutes(SHIFT_START)) && toMinutes(tin) > toMinutes(SHIFT_START)) {
            const lateM = toMinutes(tin) - toMinutes(SHIFT_START);
            remarks = `Late by ${lateM} mins`;
            if (status !== 'leave' && status !== 'absent') status = 'late';
          }
          // Undertime remark
          const tout = r?.time_out || '';
          if (!remarks && (status === 'undertime' || (tout && Number.isFinite(toMinutes(SHIFT_END)) && Number.isFinite(toMinutes(tout)) && toMinutes(tout) < toMinutes(SHIFT_END)))) {
            const utApproved = findApprovedUT(d);
            remarks = utApproved.length ? 'Approved — Left early' : (remarks || 'Left early');
            status = 'undertime';
          }
          // Leave remark
          if (!r && approvedLeave) {
            const lt = (lvList || []).find(l => String(l.status||'').toLowerCase()==='approved' && inRange(d, l.start_date, l.end_date || l.start_date))?.leave_type || '';
            remarks = lt ? lt : 'On leave';
            status = 'leave';
          }
          if (!r && !approvedLeave) {
            remarks = 'No log recorded';
          }
          const otHours = findApprovedOT(d).reduce((sum,o)=>sum + (Number(o.hours)||0), 0);
          const utHours = findApprovedUT(d).reduce((sum,u)=>sum + (Number(u.hours)||0), 0);
          return {
            date: d,
            time_in: r?.time_in || '',
            time_out: r?.time_out || '',
            hours: r ? diffHours(d, r.time_in, r.time_out) : '',
            status: status,
            overtime: otHours > 0 ? fmtHoursHM(otHours) : 'None',
            undertime: utHours > 0 ? fmtHoursHM(utHours) : 'None',
            remarks
          };
        });

        // Render table
        const table = document.createElement('table');
        table.className = 'min-w-full border border-gray-200 rounded';
        table.innerHTML = `
          <thead class="bg-gray-50">
            <tr>
              <th class="px-3 py-2 text-left text-sm font-semibold text-gray-700">Date</th>
              <th class="px-3 py-2 text-left text-sm font-semibold text-gray-700">Time In</th>
              <th class="px-3 py-2 text-left text-sm font-semibold text-gray-700">Time Out</th>
              <th class="px-3 py-2 text-left text-sm font-semibold text-gray-700">Hours Worked</th>
              <th class="px-3 py-2 text-left text-sm font-semibold text-gray-700">Status</th>
              <th class="px-3 py-2 text-left text-sm font-semibold text-gray-700">Overtime</th>
              <th class="px-3 py-2 text-left text-sm font-semibold text-gray-700">Undertime</th>
              <th class="px-3 py-2 text-left text-sm font-semibold text-gray-700">Remarks</th>
            </tr>
          </thead>
          <tbody></tbody>
        `;
        const tbody = table.querySelector('tbody');
        if (!data.length) {
          const tr = document.createElement('tr');
          tr.innerHTML = `<td colspan="8" class="px-3 py-6 text-sm text-center text-gray-500">No logs</td>`;
          tbody.appendChild(tr);
        } else {
          data.forEach(r => {
            const statusText = (() => {
              const s = String(r.status||'').toLowerCase();
              if (s === 'leave') return 'Leave';
              if (s === 'absent') return 'Absent';
              if (s === 'late') return 'Present (Late)';
              if (s === 'undertime') return 'Present (Undertime)';
              return s ? s.charAt(0).toUpperCase()+s.slice(1) : 'Present';
            })();
            const tr = document.createElement('tr');
            tr.className = 'border-t';
            tr.innerHTML = `
              <td class="px-3 py-2 text-sm text-gray-700">${fmtDate(r.date)}</td>
              <td class="px-3 py-2 text-sm text-gray-700">${r.time_in ? fmtTime(r.time_in) : '—'}</td>
              <td class="px-3 py-2 text-sm text-gray-700">${r.time_out ? fmtTime(r.time_out) : '—'}</td>
              <td class="px-3 py-2 text-sm text-gray-700">${r.hours || '—'}</td>
              <td class="px-3 py-2 text-sm text-gray-700">${statusText}</td>
              <td class="px-3 py-2 text-sm text-gray-700">${r.overtime}</td>
              <td class="px-3 py-2 text-sm text-gray-700">${r.undertime}</td>
              <td class="px-3 py-2 text-sm text-gray-700">${r.remarks || '—'}</td>
            `;
            tbody.appendChild(tr);
          });
        }
        tableDiv.innerHTML = '';
        tableDiv.appendChild(table);
      } catch {
        tableDiv.innerHTML = '<div class="text-red-600">Failed to load attendance log</div>';
      }
    }

    if (applyBtn) applyBtn.addEventListener('click', loadLog);
    await loadLog();
  
  } catch {}

  // Notifications auto-refresh (single interval)

  if (window.__empNotifInterval){ try { clearInterval(window.__empNotifInterval); } catch {} }

  window.__empNotifInterval = setInterval(async () => {
    await renderHeaderNotifications(user);
  }, 30000);

  // Header UI
  initHeaderNotifications(user);
  await renderHeaderNotifications(user);
  window.syncHeaderAvatar(user);
  try {
    const nameEl = document.getElementById('profile-name');
    const roleEl = document.getElementById('profile-role');
    const displayName = (() => {
      const first = (user.first_name || '').trim();
      const last = (user.last_name || '').trim();
      if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
      const u = (user.username || '').trim();
      if (u.includes('@')) return u.split('@')[0];
      return u || 'Employee';
    })();
    if (nameEl) nameEl.textContent = displayName;
    if (roleEl) roleEl.textContent = user.role || 'employee';
  } catch {}
  wireEmpProfileMenu();
  const profSettings = document.getElementById('emp-profile');
  const profDropdown = document.getElementById('profile-dropdown');
  if (profSettings) {
    profSettings.addEventListener('click', async (e) => {
      e.preventDefault();
      if (profDropdown) profDropdown.classList.add('hidden');
      await openEmployeeProfile(user);
    });
  }
}

async function renderLeaveRequestsOnly(user){
  const app = document.getElementById('emp-app');
  app.innerHTML = `
    <section class="grid grid-cols-1 gap-4">
      <div id="leave-balances" class="mb-2"></div>
      <div class="bg-white rounded-xl shadow-sm hover:shadow-md transition-shadow border border-gray-100 p-4">
        <h3 class="font-semibold text-gray-900 tracking-tight mb-2">Leave Requests</h3>
        <div class="mb-3">
          <input id="lv-search" type="text" class="w-full max-w-xs border rounded px-3 py-2 text-sm" placeholder="Search leave requests..." />
        </div>
        <div id="leave-list" class="text-sm max-h-64 overflow-y-auto pr-1"></div>
      </div>
    </section>
    <div id="leave-modal" class="fixed inset-0 hidden z-50">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-24 w-full max-w-md">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold">New Leave Request</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
          <div class="p-4 grid gap-3">
            <div>
              <label class="block text-sm text-gray-600 mb-1">Start date</label>
              <input id="lv-start" type="date" class="w-full border rounded px-3 py-2" />
            </div>
            <div>
              <label class="block text-sm text-gray-600 mb-1">End date</label>
              <input id="lv-end" type="date" class="w-full border rounded px-3 py-2" />
            </div>
            <div>
              <label class="block text-sm text-gray-600 mb-1">Leave Type</label>
              <select id="lv-type" class="w-full border rounded px-3 py-2">
                <option value="" selected disabled>Select leave type</option>
              </select>
            </div>
            <div>
              <label class="block text-sm text-gray-600 mb-1">Reason</label>
              <textarea id="lv-reason" rows="3" class="w-full border rounded px-3 py-2"></textarea>
            </div>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
            <button id="lv-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Submit</button>
          </div>
        </div>
      </div>
    </div>`;

  try { await animateEmpCards(app); } catch {}
  await renderLeaves(user);

  // Dynamic Leave Types loader (employee modal)
  async function fetchActiveLeaveTypesEmp(){
    try {
      const res = await axios.get(`${baseApiUrl}/leave-types.php`, { params: { operation: 'listActive' } });
      return Array.isArray(res.data) ? res.data : [];
    } catch { return []; }
  }
  async function loadLeaveTypesOptionsEmp(selectId, current){
    const select = document.getElementById(selectId);
    if (!select) return;
    const currentVal = current ? String(current).toLowerCase() : '';
    select.innerHTML = '';
    const ph = document.createElement('option');
    ph.value = '';
    ph.textContent = 'Select leave type';
    ph.disabled = true;
    ph.selected = true;
    select.appendChild(ph);
    let types = await fetchActiveLeaveTypesEmp();
    if (!types.length){
      const defaults = ['vacation','sick leave','birthday leave','deductible against pay','maternity','paternity']
        .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
      defaults.forEach(n => {
        const opt = document.createElement('option');
        opt.value = n.toLowerCase();
        opt.textContent = n.replace(/\b\w/g, c => c.toUpperCase());
        select.appendChild(opt);
      });
    } else {
      types
        .slice()
        .sort((a, b) => String(a.name || '').localeCompare(String(b.name || ''), undefined, { sensitivity: 'base' }))
        .forEach(t => {
          const name = String(t.name || '').trim();
          if (!name) return;
          const opt = document.createElement('option');
          opt.value = name.toLowerCase();
          opt.textContent = name;
          select.appendChild(opt);
        });
    }
    if (currentVal){
      const found = Array.from(select.options).find(o => String(o.value).toLowerCase() === currentVal);
      if (found) found.selected = true;
    }
  }

  // Wire leave search
  const lvSearchInput = document.getElementById('lv-search');
  if (lvSearchInput) {
    lvSearchInput.addEventListener('input', async () => {
      await renderLeaves(user);
    });
  }


  // Notifications auto-refresh (single interval)
  if (window.__empNotifInterval){ try { clearInterval(window.__empNotifInterval); } catch {} }
  window.__empNotifInterval = setInterval(async () => {
    await renderHeaderNotifications(user);
  }, 30000);

  // Header UI
  initHeaderNotifications(user);
  await renderHeaderNotifications(user);
  window.syncHeaderAvatar(user);
  try {
    const nameEl = document.getElementById('profile-name');
    const roleEl = document.getElementById('profile-role');
    const displayName = (() => {
      const first = (user.first_name || '').trim();
      const last = (user.last_name || '').trim();
      if (first || last) return `${first}${first && last ? ' ' : ''}${last}`.trim();
      const u = (user.username || '').trim();
      if (u.includes('@')) return u.split('@')[0];
      return u || 'Employee';
    })();
    if (nameEl) nameEl.textContent = displayName;
    if (roleEl) roleEl.textContent = user.role || 'employee';
  } catch {}

  wireEmpProfileMenu();
  const profSettings = document.getElementById('emp-profile');
  const profDropdown = document.getElementById('profile-dropdown');
  if (profSettings) {
    profSettings.addEventListener('click', async (e) => {
      e.preventDefault();
      if (profDropdown) profDropdown.classList.add('hidden');
      await openEmployeeProfile(user);
    });
  }

  // Leave modal wiring
  const modal = document.getElementById('leave-modal');
  const open = async () => { await loadLeaveTypesOptionsEmp('lv-type', ''); modal.classList.remove('hidden'); };
  const close = () => modal.classList.add('hidden');
  const newLeaveBtn = document.getElementById('btn-new-leave');
  const saveBtn = document.getElementById('lv-save');

  if (newLeaveBtn) {
    newLeaveBtn.addEventListener('click', open);
  }

  if (modal) {
    modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', close));
  }

  if (saveBtn) {
    saveBtn.addEventListener('click', async () => {
      const start = (document.getElementById('lv-start').value||'').trim();
      const end = (document.getElementById('lv-end').value||'').trim();
      const reason = (document.getElementById('lv-reason').value||'').trim();
      const typeRaw = (document.getElementById('lv-type')?.value || '');
      const type = typeRaw.toLowerCase();
      if (!start || !end) { showToast('Please select start and end dates', 'warning'); return; }
      if (!typeRaw) { showToast('Please select a leave type', 'warning'); return; }
      const daysReq = (() => {
        try {
          const s = new Date(start);
          const e = new Date(end || start);
          const ms = 24*60*60*1000;
          const sUTC = Date.UTC(s.getFullYear(), s.getMonth(), s.getDate());
          const eUTC = Date.UTC(e.getFullYear(), e.getMonth(), e.getDate());
          const diff = Math.round((eUTC - sUTC) / ms);
          return Math.max(1, diff + 1);
        } catch { return 0; }
      })();
      const bal = window.__leaveBalances || { remainingVacation: 0, remainingSick: 0 };
      if (type.includes('vacation')) {
        if (bal.remainingVacation <= 0 || daysReq > bal.remainingVacation) { showToast('Not enough vacation balance', 'warning'); return; }
      } else if (type.includes('sick')) {
        if (bal.remainingSick <= 0 || daysReq > bal.remainingSick) { showToast('Not enough sick leave balance', 'warning'); return; }
      } else if (type.includes('birthday')) {
        if ((bal.remainingBirthday || 0) <= 0 || daysReq > (bal.remainingBirthday || 0)) { showToast('Not enough sick leave balance', 'warning'); return; }
      }
      try {
        try { await ensureSweetAlertAssets(); } catch {}
        const result = await Swal.fire({
          title: 'Submit leave request?',
          text: `${start} to ${end} (${typeRaw || 'Leave'})`,
          icon: 'question',
          showCancelButton: true,
          confirmButtonText: 'Submit',
          cancelButtonText: 'Cancel'
        });
        if (!result.isConfirmed) return;
        const fd = new FormData();
        fd.append('operation', 'requestLeave');
        fd.append('json', JSON.stringify({ employee_id: user.employee_id, start_date: start, end_date: end, reason, leave_type: typeRaw }));
        await axios.post(`${baseApiUrl}/leaves.php`, fd);
        close();
        await renderLeaves(user);
        showToast('Leave request submitted', 'success');
      } catch { showToast('Failed to submit', 'error'); }
    });
  }
}

async function renderTodayAttendance(user){
  const el = document.getElementById('today-att');
  try {
    const today = new Date().toISOString().slice(0,10);
    const res = await axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: today, end_date: today } });
    const rows = (res.data || []).filter(r => String(r.employee_id) === String(user.employee_id));
    if (!rows.length){ el.textContent = 'No record today'; return; }
    const r = rows[0];
    el.textContent = `Status: ${r.status} ${r.time_in ? `— Clocked in at ${r.time_in}` : ''}`;
  } catch { el.textContent = 'Unable to load'; }
}

async function renderAttendanceSummary(user){
  const el = document.getElementById('att-summary');
  try {
    const now = new Date();
    const start = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().slice(0,10);
    const end = new Date(now.getFullYear(), now.getMonth()+1, 0).toISOString().slice(0,10);
    const res = await axios.get(`${baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: start, end_date: end } });
    const rows = (res.data || []).filter(r => String(r.employee_id) === String(user.employee_id));
    const stats = { present: 0, absent: 0, leave: 0 };
    rows.forEach(r => {
      const st = String(r.status || '').toLowerCase();
      if (st === 'present' || st === 'late') {
        stats.present += 1; // Count 'late' as present
      } else if (st === 'absent') {
        stats.absent += 1;
      } else if (st === 'leave' || st === 'on leave') {
        stats.leave += 1;
      }
    });
    el.innerHTML = `
      <li>Days Present: <strong>${stats.present||0}</strong></li>
      <li>Days Absent: <strong>${stats.absent||0}</strong></li>
      <li>On Leave: <strong>${stats.leave||0}</strong></li>`;
  } catch { el.innerHTML = '<li>Error loading summary</li>'; }
}

async function renderPayslips(user){
  const el = document.getElementById('payslips');
  const view = getPayslipsView();
  try {
    let rows = [];

    if (view === 'history') {
      // Load archived payslips from database
      const res = await axios.get(`${baseApiUrl}/payroll.php`, { params: { operation: 'listPayslipHistory', employee_id: user.employee_id } });
      rows = res.data || [];
      if (!rows.length){
        el.innerHTML = '<div class="text-sm text-gray-500">No payslip history</div>';
      } else {
        el.innerHTML = `<div class="divide-y max-h-72 overflow-y-auto">${rows.map(p => {
          const paid = String(p.status || '') === 'paid';
          const badge = `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${paid ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'}">${paid ? 'Paid' : 'Processed'}</span>`;
          const paidAtStr = paid && p.paid_at ? formatTime(p.paid_at) : '';
          const archivedAt = p.generated_at ? formatTime(p.generated_at) : '';
          return `
          <div class="flex items-center justify-between py-2">
            <div class="flex items-center gap-2">
              ${badge}
            </div>
            <div class="flex items-center gap-3">
              <span class="text-sm text-gray-600">${paid ? (paidAtStr ? `Paid: ${paidAtStr}` : 'Paid') : 'Processed'}</span>
              ${archivedAt ? `<span class="text-xs text-gray-500">Archived: ${archivedAt}</span>` : ''}
              <a class="text-primary-700 hover:underline" href="#" data-action="view" data-id="${p.payroll_id}">View</a>
              <span class="text-gray-300">|</span>
              ${paid ? `<a class="text-primary-700 hover:underline" href="#" data-action="download" data-id="${p.payroll_id}">Download</a>` : `<span class="text-gray-400 cursor-not-allowed" title="Payslip not yet paid">Download</span>`}
              <span class="text-gray-300">|</span>
              <a class="text-red-700 hover:underline" href="#" data-action="restore" data-id="${p.payroll_id}">Restore</a>
            </div>
          </div>`;
        }).join('')}</div>`;
      }
    } else {
      // Active view: fetch current payrolls and exclude archived ones
      const [activeRes, histRes] = await Promise.all([
        axios.get(`${baseApiUrl}/payroll.php`, { params: { operation: 'getPayrolls', employee_id: user.employee_id } }),
        axios.get(`${baseApiUrl}/payroll.php`, { params: { operation: 'listPayslipHistory', employee_id: user.employee_id } })
      ]);
      const all = activeRes.data || [];
      const archived = new Set((histRes.data || []).map(h => String(h.payroll_id)));
      rows = all.filter(p => !archived.has(String(p.payroll_id)));

      if (!rows.length){
        el.innerHTML = '<div class="text-sm text-gray-500">No active payslips. Switch to History to view archived payslips.</div>';
      } else {
        el.innerHTML = `<div class="divide-y max-h-72 overflow-y-auto">${rows.map(p => {
          const paid = String(p.status) === 'paid';
          const badge = `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${paid ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'}">${paid ? 'Paid' : 'Processed'}</span>`;
          const paidAtStr = paid && p.paid_at ? formatTime(p.paid_at) : '';
          return `
          <div class="flex items-center justify-between py-2">
            <div class="flex items-center gap-2">
              ${badge}
            </div>
            <div class="flex items-center gap-3">
              <span class="text-sm text-gray-600">${paid ? (paidAtStr ? `Paid: ${paidAtStr}` : 'Paid') : 'Processed'}</span>
              <a class="text-primary-700 hover:underline" href="#" data-action="view" data-id="${p.payroll_id}">View</a>
              <span class="text-gray-300">|</span>
              ${paid ? `<a class="text-primary-700 hover:underline" href="#" data-action="download" data-id="${p.payroll_id}">Download</a>` : `<span class="text-gray-400 cursor-not-allowed" title="Payslip not yet paid">Download</span>`}
              <span class="text-gray-300">|</span>
              ${paid ? `<a class="text-red-700 hover:underline" href="#" data-action="done" data-id="${p.payroll_id}">Done</a>` : `<span class="text-gray-400 cursor-not-allowed" title="Payslip not yet paid">Done</span>`}
            </div>
          </div>`;
        }).join('')}</div>`;
      }
    }

    // Wire download links
    el.querySelectorAll('[data-action="download"]').forEach(a => {
      a.addEventListener('click', async (ev) => {
        ev.preventDefault();
        const id = a.getAttribute('data-id');
        const rec = (rows || []).find(r => String(r.payroll_id) === String(id));
        if (!rec) return;
        if (String(rec.status || '') !== 'paid') return;
        await downloadEmployeePayslip(rec, user);
      });
    });

    // Wire view links
    el.querySelectorAll('[data-action="view"]').forEach(a => {
      a.addEventListener('click', async (ev) => {
        ev.preventDefault();
        const id = a.getAttribute('data-id');
        const rec = (rows || []).find(r => String(r.payroll_id) === String(id));
        if (!rec) return;
        await viewEmployeePayslip(rec, user);
      });
    });

    // Wire done/restore
    if (view === 'active'){
      el.querySelectorAll('[data-action="done"]').forEach(btn => {
        btn.addEventListener('click', async (ev) => {
          ev.preventDefault();
          const id = btn.getAttribute('data-id');
          const rec = (rows || []).find(r => String(r.payroll_id) === String(id));
          if (!rec) return;
          await archiveEmployeePayslip(user, rec);
          await renderPayslips(user);
        });
      });
    } else {
      el.querySelectorAll('[data-action="restore"]').forEach(btn => {
        btn.addEventListener('click', async (ev) => {
          ev.preventDefault();
          const id = btn.getAttribute('data-id');
          await restoreEmployeePayslip(user, id);
          await renderPayslips(user);
        });
      });
    }

    // Wire view toggle buttons and update styles
    const actBtn = document.getElementById('ps-active-btn');
    const histBtn = document.getElementById('ps-history-btn');
    if (actBtn && histBtn){
      actBtn.onclick = async (e) => { e.preventDefault(); setPayslipsView('active'); updatePayslipViewButtons(); await renderPayslips(user); };
      histBtn.onclick = async (e) => { e.preventDefault(); setPayslipsView('history'); updatePayslipViewButtons(); await renderPayslips(user); };
      updatePayslipViewButtons();
    }
  } catch { el.textContent = 'Unable to load'; }
}

async function archiveEmployeePayslip(user, payroll){
  if (!payroll || String(payroll.status) !== 'paid') { showToast('Payslip must be paid before archiving', 'warning'); return; }
  try {
    const fd = new FormData();
    fd.append('operation', 'archivePayslip');
    fd.append('json', JSON.stringify({ payroll_id: payroll.payroll_id, employee_id: user.employee_id, generated_by: user.user_id || null }));
    const res = await axios.post(`${baseApiUrl}/payroll.php`, fd);
    if (res.data && res.data.success) {
      showToast('Payslip archived to history', 'success');
    } else {
      const errorMsg = res.data && res.data.message ? res.data.message : 'Failed to archive payslip';
      console.error('Archive payslip failed:', res.data);
      showToast(`Failed to archive payslip: ${errorMsg}`, 'error');
    }
  } catch (e) {
    console.error('archivePayslip error', e);
    const errorMsg = e.response && e.response.data && e.response.data.message ? e.response.data.message : e.message;
    showToast(`Failed to archive payslip: ${errorMsg}`, 'error');
  }
}

async function restoreEmployeePayslip(user, payrollId){
  try {
    const fd = new FormData();
    fd.append('operation', 'deletePayslipHistory');
    fd.append('json', JSON.stringify({ payroll_id: payrollId, employee_id: user.employee_id }));
    const res = await axios.post(`${baseApiUrl}/payroll.php`, fd);
    if (res.data && res.data.success) {
      showToast('Payslip restored to active', 'success');
    } else {
      const errorMsg = res.data && res.data.message ? res.data.message : 'Failed to restore payslip';
      console.error('Restore payslip failed:', res.data);
      showToast(`Failed to restore payslip: ${errorMsg}`, 'error');
    }
  } catch (e) {
    console.error('restorePayslip error', e);
    const errorMsg = e.response && e.response.data && e.response.data.message ? e.response.data.message : e.message;
    showToast(`Failed to restore payslip: ${errorMsg}`, 'error');
  }
}

async function downloadEmployeePayslip(p, user){
  try {
    // Prepare canvas with Unitop branding and same format as admin module
    const logoUrl = 'images/unitop.png';
    let logoImg = null;
    try {
      logoImg = await new Promise((resolve) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = () => resolve(null);
        img.src = logoUrl;
      });
    } catch {}

    const width = 1000, height = 1400, margin = 60;
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');

    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);

    ctx.strokeStyle = '#e5e7eb';
    ctx.lineWidth = 2;
    ctx.strokeRect(margin/2, margin/2, width - margin, height - margin);

    const company = 'Unitop';
    const title = 'PAYSLIP';
    ctx.fillStyle = '#111827';
    ctx.font = '700 36px Arial';
    let compX = margin;
    if (logoImg) {
      const logoH = 48;
      const aspect = (logoImg.width && logoImg.height) ? (logoImg.width / logoImg.height) : 1;
      const logoW = Math.round(logoH * aspect);
      ctx.drawImage(logoImg, margin, margin - 24, logoW, logoH);
      compX = margin + logoW + 16;
    }
    ctx.fillText(company, compX, margin + 10);
    ctx.font = '700 28px Arial';
    ctx.textAlign = 'right';
    ctx.fillText(title, width - margin, margin + 10);
    ctx.textAlign = 'left';

    // Custom formatted pay period: 'august 1 -> August 30, 2025'
    const period = (() => {
      const s = p.payroll_period_start || '';
      const e = p.payroll_period_end || '';
      try {
        const sd = new Date(s);
        const ed = new Date(e);
        if (!isNaN(sd) && !isNaN(ed)) {
          const months = ['January','February','March','April','May','June','July','August','September','October','November','December'];
          const sm = months[sd.getMonth()].toLowerCase();
          const em = months[ed.getMonth()];
          const sdNum = sd.getDate();
          const edNum = ed.getDate();
          const year = ed.getFullYear();
          return `${sm} ${sdNum} → ${em} ${edNum}, ${year}`;
        }
      } catch {}
      return `${s} -> ${e}`;
    })();
    ctx.font = '400 18px Arial';
    ctx.fillStyle = '#374151';
    ctx.fillText(`Pay Period: ${period}`, margin, margin + 50);

    let y = margin + 100;
    const lineGap = 34;
    const name = `${p.first_name || user.first_name || ''} ${p.last_name || user.last_name || ''}`.trim();
    const periodDate = p.payroll_period_end || p.payroll_period_start || p.created_at || '';
    let year;
    try { const d = new Date(periodDate); year = isNaN(d.getTime()) ? String(new Date().getFullYear()) : String(d.getFullYear()); } catch { year = String(new Date().getFullYear()); }
    const paddedId = String(user.employee_id || p.employee_id || '').padStart(3, '0');
    const displayEmpId = `EMP${year}-${paddedId}`;
    const fmtProcessed = (() => {
      const s = p.created_at || '';
      try {
        const d = new Date(s);
        if (isNaN(d)) return s;
        const months = ['January','February','March','April','May','June','July','August','September','October','November','December'];
        const mon = months[d.getMonth()];
        const day = d.getDate();
        const year = d.getFullYear();
        let hh = d.getHours();
        const mm = String(d.getMinutes()).padStart(2,'0');
        const ampm = hh >= 12 ? 'pm' : 'am';
        hh = hh % 12; if (hh === 0) hh = 12;
        const hhStr = String(hh).padStart(2,'0');
        return `${mon} ${day}, ${year} ${hhStr}:${mm}${ampm}`;
      } catch { return s; }
    })();
    const info = [
      ['Employee Name', name],
      ['Employee ID', displayEmpId],
      ['Payroll ID', `PR-${String(p.payroll_id || 0).toString().padStart(3,'0')}`],
      ['Processed Date', fmtProcessed]
    ];
    ctx.font = '600 18px Arial';
    ctx.fillStyle = '#111827';
    ctx.fillText('Employee Information', margin, y);
    y += 20;
    ctx.font = '400 18px Arial';
    info.forEach(([label, value]) => {
      y += lineGap;
      ctx.fillStyle = '#6b7280';
      ctx.fillText(`${label}:`, margin, y);
      ctx.fillStyle = '#111827';
      ctx.fillText(`${value}`, margin + 220, y);
    });

    y += 20;
    ctx.strokeStyle = '#e5e7eb';
    ctx.beginPath();
    ctx.moveTo(margin, y);
    ctx.lineTo(width - margin, y);
    ctx.stroke();

    y += 40;
    const colLeftX = margin;
    const colRightX = width / 2 + 20;

    ctx.fillStyle = '#111827';
    ctx.font = '600 20px Arial';
    ctx.fillText('Earnings', colLeftX, y);
    ctx.fillText('Deductions', colRightX, y);
    y += 30;
    ctx.font = '400 18px Arial';
    ctx.fillStyle = '#111827';

    let leftY = y;
    const earnings = [
      ['Basic Salary', Number(p.basic_salary || 0)],
      ['Overtime Pay', Number(p.overtime_pay || 0)]
    ];
    earnings.forEach(([label, amt]) => {
      ctx.fillText(label, colLeftX, leftY);
      ctx.textAlign = 'right';
      ctx.fillText(Number(amt || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }), colRightX - 40, leftY);
      ctx.textAlign = 'left';
      leftY += lineGap;
      });

    let rightY = y;
    const otherDed = Number((p.deductions || 0) - (p.sss_deduction || 0) - (p.philhealth_deduction || 0) - (p.pagibig_deduction || 0) - (p.tax_deduction || 0));
    const deductions = [
      ['SSS', Number(p.sss_deduction || 0)],
      ['PhilHealth', Number(p.philhealth_deduction || 0)],
      ['Pag-IBIG', Number(p.pagibig_deduction || 0)],
      ['Withholding Tax', Number(p.tax_deduction || 0)],
      ['Other Deductions', otherDed]
    ];
    deductions.forEach(([label, amt]) => {
    ctx.fillText(label, colRightX, rightY);
    ctx.textAlign = 'right';
    ctx.fillText(Number(amt || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }), width - margin, rightY);
    ctx.textAlign = 'left';
    rightY += lineGap;
    });

    let totalsY = Math.max(leftY, rightY) + 20;
    ctx.strokeStyle = '#e5e7eb';
    ctx.beginPath();
    ctx.moveTo(margin, totalsY);
    ctx.lineTo(width - margin, totalsY);
    ctx.stroke();

    totalsY += 40;
    const gross = Number(p.net_pay || 0) + Number(p.deductions || 0);
    const totalDeductions = Number(p.deductions || 0);
    const net = Number(p.net_pay || 0);

    ctx.font = '600 20px Arial';
    ctx.fillStyle = '#111827';
    const labelX = colLeftX;
    const valueX = width - margin;

    const drawRow = (label, amount) => {
    ctx.fillText(label, labelX, totalsY);
    ctx.textAlign = 'right';
    ctx.fillText(Number(amount || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }), valueX, totalsY);
    ctx.textAlign = 'left';
    totalsY += lineGap;
    };
    drawRow('Gross Pay', gross);
    drawRow('Total Deductions', totalDeductions);
    totalsY += 10;
    ctx.strokeStyle = '#e5e7eb';
    ctx.beginPath();
    ctx.moveTo(margin, totalsY);
    ctx.lineTo(width - margin, totalsY);
    ctx.stroke();
    totalsY += 40;
    ctx.font = '700 26px Arial';
    ctx.fillStyle = '#065f46';
    ctx.fillText('NET PAY', labelX, totalsY);
    ctx.textAlign = 'right';
    ctx.fillText(Number(net || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }), valueX, totalsY);
    ctx.textAlign = 'left';

    let footY = totalsY + 80;
    ctx.font = '400 16px Arial';
    ctx.fillStyle = '#6b7280';
    ctx.fillText('This payslip is a system-generated document.', margin, footY);

    const dataUrl = canvas.toDataURL('image/png');
    const a = document.createElement('a');
    const sanitize = (s) => String(s || '').replace(/[^a-z0-9]+/gi, '_').replace(/^_+|_+$/g, '').toLowerCase();
    const fname = `payslip_${sanitize(user.last_name || 'employee')}_${sanitize(p.payroll_period_end || 'period')}.png`;
    a.href = dataUrl;
    a.download = fname;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { try { document.body.removeChild(a); } catch {} }, 200);
  } catch (e) {
    console.error('Failed to download payslip:', e);
  }
}

function ensurePayslipModal(){
  let modal = document.getElementById('payslip-modal');
  if (modal) return;
  const html = `
    <div id="payslip-modal" class="fixed inset-0 hidden z-50">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto my-16 w-full max-w-3xl px-4">
        <div class="bg-white rounded-lg shadow max-h-[85vh] overflow-y-auto">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">Payslip</h5>
            <button class="text-gray-500 text-xl" data-close="true">×</button>
          </div>
          <div class="p-4">
            <img id="pslip-img" alt="Payslip" class="w-full h-auto block" />
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
          </div>
        </div>
      </div>
    </div>`;
  document.body.insertAdjacentHTML('beforeend', html);
  modal = document.getElementById('payslip-modal');
  modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
}

function openPayslipModal(dataUrl, filename){
  ensurePayslipModal();
  const modal = document.getElementById('payslip-modal');
  const img = document.getElementById('pslip-img');
  if (img) img.src = dataUrl;
  if (modal) modal.classList.remove('hidden');
}

async function viewEmployeePayslip(p, user){
  try {
    const logoUrl = 'images/unitop.png';
    let logoImg = null;
    try {
      logoImg = await new Promise((resolve) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = () => resolve(null);
        img.src = logoUrl;
      });
    } catch {}

    const width = 1000, height = 1400, margin = 60;
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');

    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);

    ctx.strokeStyle = '#e5e7eb';
    ctx.lineWidth = 2;
    ctx.strokeRect(margin/2, margin/2, width - margin, height - margin);

    const company = 'Unitop';
    const title = 'PAYSLIP';
    ctx.fillStyle = '#111827';
    ctx.font = '700 36px Arial';
    let compX = margin;
    if (logoImg) {
      const logoH = 48;
      const aspect = (logoImg.width && logoImg.height) ? (logoImg.width / logoImg.height) : 1;
      const logoW = Math.round(logoH * aspect);
      ctx.drawImage(logoImg, margin, margin - 24, logoW, logoH);
      compX = margin + logoW + 16;
    }
    ctx.fillText(company, compX, margin + 10);
    ctx.font = '700 28px Arial';
    ctx.textAlign = 'right';
    ctx.fillText(title, width - margin, margin + 10);
    ctx.textAlign = 'left';

    const period = `${p.payroll_period_start || ''} to ${p.payroll_period_end || ''}`;
    ctx.font = '400 18px Arial';
    ctx.fillStyle = '#374151';
    ctx.fillText(`Pay Period: ${period}`, margin, margin + 50);

    let y = margin + 100;
    const lineGap = 34;
    const name = `${p.first_name || user.first_name || ''} ${p.last_name || user.last_name || ''}`.trim();
    const periodDate = p.payroll_period_end || p.payroll_period_start || p.created_at || '';
    let year;
    try { const d = new Date(periodDate); year = isNaN(d.getTime()) ? String(new Date().getFullYear()) : String(d.getFullYear()); } catch { year = String(new Date().getFullYear()); }
    const paddedId = String(user.employee_id || p.employee_id || '').padStart(3, '0');
    const displayEmpId = `EMP${year}-${paddedId}`;
    const info = [
      ['Employee Name', name],
      ['Employee ID', displayEmpId],
      ['Processed Date', (p.created_at || '')]
    ];
    ctx.font = '600 18px Arial';
    ctx.fillStyle = '#111827';
    ctx.fillText('Employee Information', margin, y);
    y += 20;
    ctx.font = '400 18px Arial';
    info.forEach(([label, value]) => {
      y += lineGap;
      ctx.fillStyle = '#6b7280';
      ctx.fillText(`${label}:`, margin, y);
      ctx.fillStyle = '#111827';
      ctx.fillText(`${value}`, margin + 220, y);
    });

    y += 20;
    ctx.strokeStyle = '#e5e7eb';
    ctx.beginPath();
    ctx.moveTo(margin, y);
    ctx.lineTo(width - margin, y);
    ctx.stroke();

    y += 40;
    const colLeftX = margin;
    const colRightX = width / 2 + 20;

    ctx.fillStyle = '#111827';
    ctx.font = '600 20px Arial';
    ctx.fillText('Earnings', colLeftX, y);
    ctx.fillText('Deductions', colRightX, y);
    y += 30;
    ctx.font = '400 18px Arial';
    ctx.fillStyle = '#111827';

    let leftY = y;
    const earnings = [
      ['Basic Salary', Number(p.basic_salary || 0)],
      ['Overtime Pay', Number(p.overtime_pay || 0)]
    ];
    earnings.forEach(([label, amt]) => {
      ctx.fillText(label, colLeftX, leftY);
      ctx.textAlign = 'right';
      ctx.fillText(amt.toFixed(2), colRightX - 40, leftY);
      ctx.textAlign = 'left';
      leftY += lineGap;
    });

    let rightY = y;
    const otherDed = Number((p.deductions || 0) - (p.sss_deduction || 0) - (p.philhealth_deduction || 0) - (p.pagibig_deduction || 0) - (p.tax_deduction || 0));
    const deductions = [
      ['SSS', Number(p.sss_deduction || 0)],
      ['PhilHealth', Number(p.philhealth_deduction || 0)],
      ['Pag-IBIG', Number(p.pagibig_deduction || 0)],
      ['Withholding Tax', Number(p.tax_deduction || 0)],
      ['Other Deductions', otherDed]
    ];
    deductions.forEach(([label, amt]) => {
      ctx.fillText(label, colRightX, rightY);
      ctx.textAlign = 'right';
      ctx.fillText(amt.toFixed(2), width - margin, rightY);
      ctx.textAlign = 'left';
      rightY += lineGap;
    });

    let totalsY = Math.max(leftY, rightY) + 20;
    ctx.strokeStyle = '#e5e7eb';
    ctx.beginPath();
    ctx.moveTo(margin, totalsY);
    ctx.lineTo(width - margin, totalsY);
    ctx.stroke();

    totalsY += 40;
    const gross = Number(p.net_pay || 0) + Number(p.deductions || 0);
    const totalDeductions = Number(p.deductions || 0);
    const net = Number(p.net_pay || 0);

    ctx.font = '600 20px Arial';
    ctx.fillStyle = '#111827';
    const labelX = colLeftX;
    const valueX = width - margin;

    const drawRow = (label, amount) => {
      ctx.fillText(label, labelX, totalsY);
      ctx.textAlign = 'right';
      ctx.fillText(amount.toFixed(2), valueX, totalsY);
      ctx.textAlign = 'left';
      totalsY += lineGap;
    };
    drawRow('Gross Pay', gross);
    drawRow('Total Deductions', totalDeductions);
    totalsY += 10;
    ctx.strokeStyle = '#e5e7eb';
    ctx.beginPath();
    ctx.moveTo(margin, totalsY);
    ctx.lineTo(width - margin, totalsY);
    ctx.stroke();
    totalsY += 40;
    ctx.font = '700 26px Arial';
    ctx.fillStyle = '#065f46';
    ctx.fillText('NET PAY', labelX, totalsY);
    ctx.textAlign = 'right';
    ctx.fillText(net.toFixed(2), valueX, totalsY);
    ctx.textAlign = 'left';

    const dataUrl = canvas.toDataURL('image/png');
    const sanitize = (s) => String(s || '').replace(/[^a-z0-9]+/gi, '_').replace(/^_+|_+$/g, '').toLowerCase();
    const fname = `payslip_${sanitize(user.last_name || 'employee')}_${sanitize(p.payroll_period_end || 'period')}.png`;
    openPayslipModal(dataUrl, fname);
  } catch (e) { console.error('Failed to view payslip:', e); }
}

async function renderLeaves(user){
  const el = document.getElementById('leave-list');
  try {
    const res = await axios.get(`${baseApiUrl}/leaves.php`, { params: { operation: 'listByEmployee', employee_id: user.employee_id } });
    let rows = res.data || [];
    // Remove cancelled or self-cancelled (stored as rejected without manager) from the Leave Requests card
    rows = (rows || []).filter(l => {
      const st = String(l.status || '').toLowerCase();
      const rejectedBy = ((l && (l.rejected_by_username || l.rejected_by)) ? String(l.rejected_by_username || l.rejected_by) : '').trim();
      if (st === 'cancelled') return false;
      if (st === 'rejected' && rejectedBy === '') return false; // self-cancelled stored as rejected
      return true;
    });
    const q = (document.getElementById('lv-search')?.value || '').toLowerCase().trim();
    if (q) {
      rows = rows.filter(l => {
        const fields = [l.start_date||'', l.end_date||'', l.status||'', l.reason||'', l.leave_type||''].join(' ').toLowerCase();
        return fields.includes(q);
      });
    }
    // Compute leave balances with base allocation (Vacation: 5, Sick: 5, Birthday: 1)
    const BASE_VACATION = 5;
    const BASE_SICK = 5;
    const BASE_BIRTHDAY = 1;
    const toDaysInclusive = (start, end) => {
      try {
        const s = new Date(start);
        const e = new Date(end || start);
        if (isNaN(s.getTime()) || isNaN(e.getTime())) return 0;
        const msPerDay = 24*60*60*1000;
        const sUTC = Date.UTC(s.getFullYear(), s.getMonth(), s.getDate());
        const eUTC = Date.UTC(e.getFullYear(), e.getMonth(), e.getDate());
        const diff = Math.round((eUTC - sUTC) / msPerDay);
        return Math.max(1, diff + 1);
      } catch { return 0; }
    };
    let usedVacation = 0;
    let usedSick = 0;
    let usedBirthday = 0;
    (rows || []).forEach(l => {
      const st = String(l.status || '').toLowerCase();
      // Count both approved and pending so filing immediately reduces balance
      if (!(st === 'approved' || st === 'pending')) return;
      const type = String(l.leave_type || '').toLowerCase();
      const days = toDaysInclusive(l.start_date, l.end_date);
      if (type === 'vacation') usedVacation += days;
      else if (type === 'sick leave' || type === 'sick') usedSick += days;
      else if (type === 'birthday leave' || type === 'birthday') usedBirthday += days;
    });
    const remainingVacation = Math.max(0, BASE_VACATION - usedVacation);
    const remainingSick = Math.max(0, BASE_SICK - usedSick);
    const remainingBirthday = Math.max(0, BASE_BIRTHDAY - usedBirthday);
    // expose balances for validation on submit
    window.__leaveBalances = { remainingVacation, remainingSick, remainingBirthday };
    const balEl = document.createElement('div');
    balEl.className = 'mb-3';
    balEl.innerHTML = `
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div class="rounded-xl border border-gray-200 bg-white p-5 shadow hover:shadow-md transition-shadow">
          <div class="text-[11px] uppercase tracking-wider text-gray-500">Vacation</div>
          <div class="mt-1 text-2xl font-bold text-gray-900">${remainingVacation}</div>
          <div class="text-xs text-gray-500">Base: ${BASE_VACATION} days</div>
        </div>
        <div class="rounded-xl border border-gray-200 bg-white p-5 shadow hover:shadow-md transition-shadow">
          <div class="text-[11px] uppercase tracking-wider text-gray-500">Sick</div>
          <div class="mt-1 text-2xl font-bold text-gray-900">${remainingSick}</div>
          <div class="text-xs text-gray-500">Base: ${BASE_SICK} days</div>
        </div>
        <div class="rounded-xl border border-gray-200 bg-white p-5 shadow hover:shadow-md transition-shadow">
        <div class="text-[11px] uppercase tracking-wider text-gray-500">Birthday</div>
        <div class="mt-1 text-2xl font-bold text-gray-900">${remainingBirthday}</div>
        <div class="text-xs text-gray-500">Base: ${BASE_BIRTHDAY} day</div>
        </div>
          <div class="sm:col-span-3 flex justify-end">
          <button id="btn-new-leave" class="inline-flex items-center px-3 py-2 text-sm font-medium rounded bg-primary-600 text-white hover:bg-primary-700">File new leave</button>
          </div>
      </div>
    `;
    // Fetch and include Overtime and Undertime requests in the same list
    let otRows = [];
    let utRows = [];
    try {
      const [otRes, utRes] = await Promise.all([
        axios.get(`${baseApiUrl}/overtime.php`, { params: { operation: 'listByEmployee', employee_id: user.employee_id } }),
        axios.get(`${baseApiUrl}/undertime.php`, { params: { operation: 'listByEmployee', employee_id: user.employee_id } })
      ]);
      otRows = otRes.data || [];
      utRows = utRes.data || [];
    } catch {}

    // Apply the same search filter (q) to OT/UT
    if (q) {
      const match = (s) => String(s || '').toLowerCase().includes(q);
      otRows = otRows.filter(o => match(o.work_date) || match(o.status) || match(o.reason) || match(o.hours) || match(o.start_time) || match(o.end_time));
      utRows = utRows.filter(u => match(u.work_date) || match(u.status) || match(u.reason) || match(u.hours));
    }

    // Combine Leaves + OT + UT into a single timeline list
    const items = [];
    (rows || []).forEach(l => items.push({
      kind: 'Leave',
      created_at: l.created_at || '',
      status: l.status,
      start_date: l.start_date,
      end_date: l.end_date,
      approved_by_username: l.approved_by_username,
      rejected_by_username: l.rejected_by_username,
      leave_id: l.leave_id
    }));
    (otRows || []).forEach(o => items.push({
      kind: 'Overtime',
      created_at: o.created_at || '',
      status: o.status,
      work_date: o.work_date,
      hours: (o.hours != null ? Number(o.hours).toFixed(2) : (o.start_time && o.end_time ? `${o.start_time} - ${o.end_time}` : '')),
      approved_by_username: o.approved_by_username,
      rejected_by_username: o.rejected_by_username
    }));
    (utRows || []).forEach(u => items.push({
      kind: 'Undertime',
      created_at: u.created_at || '',
      status: u.status,
      work_date: u.work_date,
      hours: (u.hours != null ? Number(u.hours).toFixed(2) : ''),
      approved_by_username: u.approved_by_username,
      rejected_by_username: u.rejected_by_username
    }));

    items.sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));

    const list = document.createElement('div');
    list.innerHTML = items.length ? items.map(it => {
      if (it.kind === 'Leave') {
        return `
        <div class="flex items-center justify-between py-2 border-b last:border-b-0">
          <div>
            <div><span class="text-xs text-gray-500 mr-2">[Leave]</span>${it.start_date} → ${it.end_date}</div>
            ${it.status === 'approved' && it.approved_by_username ? `<div class=\"text-xs text-green-700\">Approved by ${it.approved_by_username}</div>` : ''}
            ${it.status === 'rejected' ? (it.rejected_by_username ? `<div class=\"text-xs text-red-700\">Rejected by ${it.rejected_by_username}</div>` : '') : (it.status === 'cancelled' ? `<div class=\"text-xs text-gray-600\">Cancelled by you</div>` : '')}
          </div>
          <div class="text-sm flex items-center gap-2">
            <span class="capitalize">${it.status === 'cancelled' ? 'cancelled' : it.status}</span>
            ${it.status === 'pending' ? `<button data-action=\"cancel\" data-id=\"${it.leave_id}\" class=\"px-2 py-1 text-xs rounded border border-red-600 text-red-700 hover:bg-red-50\">Cancel</button>` : ''}
          </div>
        </div>`;
      }
      // Overtime/Undertime rendering
      const kindTag = it.kind === 'Overtime' ? '[Overtime]' : '[Undertime]';
      const detail = it.hours ? `${it.work_date} — ${it.hours}h` : it.work_date;
      const approverInfo = it.status === 'approved' && it.approved_by_username ? `<div class=\"text-xs text-green-700\">Approved by ${it.approved_by_username}</div>` : (it.status === 'rejected' && it.rejected_by_username ? `<div class=\"text-xs text-red-700\">Rejected by ${it.rejected_by_username}</div>` : '');
      return `
      <div class="flex items-center justify-between py-2 border-b last:border-b-0">
        <div>
          <div><span class="text-xs text-gray-500 mr-2">${kindTag}</span>${detail}</div>
          ${approverInfo}
        </div>
        <div class="text-sm flex items-center gap-2">
          <span class="capitalize">${it.status}</span>
        </div>
      </div>`;
    }).join('') : '<div class="text-sm text-gray-500">No requests</div>';

    const balWrap = document.getElementById('leave-balances');
    if (balWrap) { balWrap.innerHTML = balEl.innerHTML; } else { el.appendChild(balEl); }
    el.innerHTML = '';
    el.appendChild(list);
    // Wire cancel buttons for pending leave requests
    list.querySelectorAll('[data-action="cancel"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        if (!id) return;
        const res = await openLeaveCancelModal();
        if (!res || !res.confirmed) return;
        const reason = (res.reason || '').trim();
        try {
          const fd = new FormData();
          fd.append('operation', 'cancel');
          fd.append('json', JSON.stringify({ leave_id: id, reason }));
          const res = await axios.post(`${baseApiUrl}/leaves.php`, fd);
          const ok = res && res.data && ((res.data.success === 1) || (res.data === 1));
          if (ok) { showToast('Leave request cancelled', 'success'); }
          else { showToast('Failed to cancel leave request', 'error'); }
        } catch {
          showToast('Failed to cancel leave request', 'error');
        }
        await Promise.all([
          renderLeaves(user),
          renderNotifications(user),
          renderHeaderNotifications(user)
        ]);
      });
    });
  } catch { el.textContent = 'Unable to load'; }
}

async function renderNotifications(user){
  const el = document.getElementById('emp-notifs');
  if (!el) return;

  try {
    // Fetch notifications from database
    const response = await axios.get(`${baseApiUrl}/notifications.php`, {
      params: { operation: 'getNotifications' },
      withCredentials: true
    });

    let notifications = [];
    if (response.data && response.data.success) {
      notifications = response.data.notifications || [];
    }

    // If no notifications, show helpful tips
    if (notifications.length === 0) {
      el.innerHTML = `
        <li class="text-sm text-gray-500 italic">No notifications yet</li>
        <li class="text-sm text-gray-500 italic">• Reminder: Please clock in before 9:00 AM</li>
        <li class="text-sm text-gray-500 italic">• Tip: You can file a leave request from the dashboard</li>
      `;
      return;
    }

    el.innerHTML = notifications.map(n => `
      <li class="flex items-start justify-between gap-3 py-1 ${n.read_at ? 'opacity-75' : ''}">
        <div class="flex-1">
          <span class="${n.read_at ? 'text-gray-500' : 'text-gray-800 font-medium'}">${escapeHtml(n.message)}</span>
          <div class="text-xs text-gray-400">${formatNotifDate(n.created_at)}</div>
          ${n.type ? `<div class="text-xs text-blue-600">${n.type}</div>` : ''}
        </div>
        <div class="flex items-center gap-2 text-xs">
          ${!n.read_at ?
            `<button class="px-2 py-1 rounded border border-primary-600 text-primary-700" data-action="mark-read" data-id="${n.id}">Mark Read</button>` :
            `<button class="px-2 py-1 rounded border text-gray-600" data-action="mark-unread" data-id="${n.id}">Mark Unread</button>`
          }
          <button class="px-2 py-1 rounded border border-red-600 text-red-700" data-action="delete" data-id="${n.id}">Delete</button>
        </div>
      </li>`).join('');

    // Wire item actions
    el.querySelectorAll('[data-action="mark-read"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        await markNotificationAsRead(id);
        await renderNotifications(user);
      });
    });

    el.querySelectorAll('[data-action="mark-unread"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        await markNotificationAsUnread(id);
        await renderNotifications(user);
      });
    });

    el.querySelectorAll('[data-action="delete"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        await deleteNotification(id);
        await renderNotifications(user);
      });
    });


  } catch (error) {
    console.error('Failed to load notifications:', error);
    el.innerHTML = '<li class="text-sm text-red-500">Failed to load notifications</li>';
  }
}

async function renderHeaderNotifications(user){
  const badge = document.getElementById('notif-badge');
  // Legacy dropdown list removed
  if (!badge) return;
  try {
    const response = await axios.get(`${baseApiUrl}/notifications.php`, {
      params: { operation: 'getNotifications' },
      withCredentials: true
    });
    const notifications = (response.data && response.data.success) ? (response.data.notifications || []) : [];
    const unread = notifications.filter(n => !n.read_at).length;
    if (unread > 0) {
      badge.textContent = unread;
      badge.classList.remove('hidden');
      // Keep zoom pulse animation running continuously for unread notifications
      badge.classList.add('animate-zoom-pulse');
    } else {
      badge.classList.add('hidden');
      badge.classList.remove('animate-zoom-pulse');
    }

    listEl.innerHTML = notifications.length ? notifications.map(n => `
      <div class="px-4 py-2 border-t first:border-t-0 ${n.read_at ? 'opacity-75' : ''}">
        <div class="text-sm ${n.read_at ? 'text-gray-600' : 'text-gray-800 font-medium'}">${escapeHtml(n.message)}</div>
        <div class="text-xs text-gray-400 mt-0.5">${formatNotifDate(n.created_at)}</div>
        <div class="mt-2 text-xs">
          ${!n.read_at ? `<button data-action="mark-read" data-id="${n.id}" class="px-2 py-1 rounded border border-primary-600 text-primary-700">Mark read</button>` : ''}
        </div>
      </div>
    `).join('') : '<div class="px-4 py-6 text-sm text-gray-500 text-center">No notifications</div>';

    listEl.querySelectorAll('[data-action="mark-read"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        await markNotificationAsRead(id);
        await renderHeaderNotifications(user);
        await renderNotifications(user);
      });
    });
  } catch (e) {
    // silently ignore for header
  }
}

function initHeaderNotifications(user){
  if (window.__notifHeaderWired) return;
  window.__notifHeaderWired = true;
  try { attachSweetHeaderNotif(user); } catch {}
  return;
  window.__notifHeaderWired = true;
  try { attachSweetHeaderNotif(user); } catch {}
  const toggle = document.getElementById('notif-toggle');
  const dropdown = document.getElementById('notif-dropdown');
  const closeBtn = document.getElementById('notif-close');
  const markAllBtn = document.getElementById('notif-mark-all');
  if (!toggle || !dropdown) return;
  const close = () => dropdown.classList.add('hidden');
  toggle.addEventListener('click', async (e) => {
    e.stopPropagation();
    dropdown.classList.toggle('hidden');
    if (!dropdown.classList.contains('hidden')) {
      await renderHeaderNotifications(user);
    }
  });
  if (closeBtn) closeBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      const response = await axios.get(`${baseApiUrl}/notifications.php`, { params: { operation: 'getNotifications' }, withCredentials: true });
      const notifications = (response.data && response.data.success) ? (response.data.notifications || []) : [];
      const unread = notifications.filter(n => !n.read_at);
      await Promise.all(unread.map(n => markNotificationAsRead(n.id)));
      await Promise.all([
        renderHeaderNotifications(user),
        renderNotifications(user)
      ]);
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
      await Promise.all([
        renderHeaderNotifications(user),
        renderNotifications(user)
      ]);
    } catch {}
  });
  document.addEventListener('click', (e) => {
    if (!dropdown.contains(e.target) && !toggle.contains(e.target)) close();
  });
  }

function addEmployeeNotification(user, text){
  const employeeId = user && user.employee_id ? user.employee_id : null;
  if (!employeeId) return;
  const list = loadEmployeeNotifications(employeeId);
  list.unshift({ id: String(Date.now()), text, created_at: new Date().toISOString(), read: false });
  saveEmployeeNotifications(employeeId, list);
}

function toggleEmployeeNotificationRead(employeeId, id){
  const list = loadEmployeeNotifications(employeeId);
  const idx = list.findIndex(n => String(n.id) === String(id));
  if (idx >= 0) { list[idx].read = !list[idx].read; }
  saveEmployeeNotifications(employeeId, list);
}

function deleteEmployeeNotification(employeeId, id){
  const list = loadEmployeeNotifications(employeeId).filter(n => String(n.id) !== String(id));
  saveEmployeeNotifications(employeeId, list);
}

function loadEmployeeNotifications(employeeId){
  const key = notifStorageKey(employeeId);
  try { return JSON.parse(localStorage.getItem(key) || '[]'); } catch { return []; }
}

function saveEmployeeNotifications(employeeId, list){
  const key = notifStorageKey(employeeId);
  try { localStorage.setItem(key, JSON.stringify(list)); } catch {}
}

function notifStorageKey(employeeId){
  return `intro_emp_notifs_${employeeId}`;
}

function formatTime(iso){
  try { const d = new Date(iso); return d.toLocaleString(); } catch { return ''; }
}

// Toast notification system
function showToast(message, type = 'info') {
  try { ensureSweetAlertAssets(); } catch {}
  // Map types to SweetAlert2 icons and show toast
  const t = String(type || 'info').toLowerCase();
  const icon = (t === 'success' || t === 'error' || t === 'warning' || t === 'info') ? t : 'info';
  showSweetToast(message, icon);
  return;
  // Remove existing toast if any
  if (existingToast) {
    existingToast.remove();
  }

  // Create toast element
  const toast = document.createElement('div');
  toast.className = `toast-notification fixed top-4 right-4 z-50 px-6 py-3 rounded-lg shadow-lg text-white transform transition-all duration-300 translate-x-full`;

  // Set color based on type
  switch(type) {
    case 'success':
      toast.style.backgroundColor = '#10B981'; // green
      break;
    case 'error':
      toast.style.backgroundColor = '#EF4444'; // red
      break;
    case 'warning':
      toast.style.backgroundColor = '#F59E0B'; // yellow
      break;
    default:
      toast.style.backgroundColor = '#3B82F6'; // blue
  }

  toast.textContent = message;

  // Add to body
  document.body.appendChild(toast);

  // Animate in
  setTimeout(() => {
    toast.classList.remove('translate-x-full');
  }, 100);

  // Auto remove after 4 seconds
  setTimeout(() => {
    toast.classList.add('translate-x-full');
    setTimeout(() => {
      if (toast.parentNode) {
        toast.remove();
      }
    }, 300);
  }, 4000);

  // Click to dismiss
  toast.addEventListener('click', () => {
    toast.classList.add('translate-x-full');
    setTimeout(() => {
      if (toast.parentNode) {
        toast.remove();
      }
    }, 300);
  });
}

// Notification management functions
async function markNotificationAsRead(notificationId) {
  try {
    const fd = new FormData();
    fd.append('operation', 'markAsRead');
    fd.append('json', JSON.stringify({ notification_id: notificationId }));

    await axios.post(`${baseApiUrl}/notifications.php`, fd, { withCredentials: true });
    return true;
  } catch (error) {
    console.error('Failed to mark notification as read:', error);
    showToast('Failed to mark notification as read', 'error');
    return false;
  }
}

async function markNotificationAsUnread(notificationId) {
  try {
    // For now, we'll just delete and recreate the notification without read_at
    // In a real implementation, you'd want to add an unread operation to the API
    showToast('Marking as unread is not yet implemented', 'warning');
    return false;
  } catch (error) {
    console.error('Failed to mark notification as unread:', error);
    return false;
  }
}

async function deleteNotification(notificationId) {
  try {
    const fd = new FormData();
    fd.append('operation', 'deleteNotification');
    fd.append('json', JSON.stringify({ notification_id: notificationId }));

    await axios.post(`${baseApiUrl}/notifications.php`, fd, { withCredentials: true });
    showToast('Notification deleted', 'success');
    return true;
  } catch (error) {
    console.error('Failed to delete notification:', error);
    showToast('Failed to delete notification', 'error');
    return false;
  }
}

// Employee Profile Modal
function ensureEmpProfileModal(){
  if (document.getElementById('empProfileModal')) return;
  const html = `
    <div id="empProfileModal" class="fixed inset-0 z-50 hidden">
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
                  <img id="emp-prof-avatar" alt="Profile" class="w-full h-full object-cover hidden"/>
                  <svg id="emp-prof-avatar-ph" class="w-16 h-16 text-gray-400" viewBox="0 0 24 24" fill="currentColor"><path d="M12 12a5 5 0 100-10 5 5 0 000 10z"/><path d="M4 20a8 8 0 1116 0v1H4v-1z"/></svg>
                </div>
                <label class="mt-3 inline-flex items-center gap-2 px-3 py-1.5 text-sm rounded border bg-white cursor-pointer">
                  <svg class="w-4 h-4 text-gray-600" viewBox="0 0 20 20" fill="currentColor"><path d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V9.414a2 2 0 00-.586-1.414l-3.414-3.414A2 2 0 0012.586 4H12V3a1 1 0 10-2 0v1H7a1 1 0 00-1 1v1h8V5h1.586L19 8.414V15H1V5a2 2 0 012-2h1z"/></svg>
                  <span>Upload Image</span>
                  <input id="emp-prof-file" type="file" accept="image/*" class="hidden" />
                </label>
                <div class="flex items-center gap-3 mt-2">
                  <button id="emp-prof-save" class="px-3 py-1.5 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
                  <button id="emp-prof-remove" class="px-3 py-1.5 text-sm rounded border">Remove</button>
                  <a href="#" id="emp-prof-reset-link" class="text-sm text-blue-600 hover:text-blue-800 underline ml-2">Reset password</a>
                </div>
              </div>
              <div class="flex-1 text-sm space-y-6">
                <div>
                  <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Personal Information</div>
                  <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-2">
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Name</div>
                      <div id="emp-prof-name" class="font-semibold text-gray-900"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Gender</div>
                      <div id="emp-prof-gender" class="font-semibold text-gray-900"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Date of Birth</div>
                      <div id="emp-prof-dob" class="font-semibold text-gray-900"></div>
                    </div>
                  </div>
                </div>
                <div>
                  <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Contact Information</div>
                  <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-2">
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Email</div>
                      <div id="emp-prof-email" class="font-semibold text-gray-900 break-words"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Phone</div>
                      <div id="emp-prof-phone" class="font-semibold text-gray-900"></div>
                    </div>
                    <div class="sm:col-span-2">
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Address</div>
                      <div id="emp-prof-address" class="font-semibold text-gray-900"></div>
                    </div>
                  </div>
                </div>
                <div>
                  <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Employment Information</div>
                  <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-2">
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Employee ID</div>
                      <div id="emp-prof-eid" class="font-semibold text-gray-900"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Status</div>
                      <div id="emp-prof-status" class="font-semibold text-gray-900"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Department</div>
                      <div id="emp-prof-dept" class="font-semibold text-gray-900"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Position</div>
                      <div id="emp-prof-pos" class="font-semibold text-gray-900"></div>
                    </div>
                    <div>
                      <div class="text-xs uppercase tracking-wide text-gray-500 mb-1">Date Hired</div>
                      <div id="emp-prof-hired" class="font-semibold text-gray-900"></div>
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
  const modal = document.getElementById('empProfileModal');
  modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
}

// Floating card modal for resetting password
function ensureEmpResetPwdModal(){
  if (document.getElementById('empResetPwdModal')) return;
  const html = `
    <div id="empResetPwdModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto my-24 w-full max-w-md px-4">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">Reset Password</h5>
            <button class="text-gray-500 text-xl" data-close="true">×</button>
          </div>
          <div class="p-4 grid gap-3">
            <div>
              <label class="block text-sm text-gray-600 mb-1">New Password</label>
              <input id="emp-resetpwd-new" type="password" class="w-full border rounded px-3 py-2" placeholder="Enter new password" />
              <div id="emp-resetpwd-strength" class="mt-1 text-xs text-gray-500 hidden"></div>
            </div>
            <div>
              <label class="block text-sm text-gray-600 mb-1">Confirm Password</label>
              <input id="emp-resetpwd-confirm" type="password" class="w-full border rounded px-3 py-2" placeholder="Re-enter new password" />
              <div id="emp-resetpwd-match" class="mt-1 text-xs"></div>
            </div>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button id="emp-resetpwd-cancel" class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
            <button id="emp-resetpwd-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Update Password</button>
          </div>
        </div>
      </div>
    </div>`;
  document.body.insertAdjacentHTML('beforeend', html);
  const modal = document.getElementById('empResetPwdModal');
  modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
}

// Floating card modal to confirm leave cancellation with optional reason
function ensureLeaveCancelModal(){
  if (document.getElementById('leaveCancelModal')) return;
  const html = `
    <div id="leaveCancelModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto my-24 w-full max-w-md px-4">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">Cancel Leave Request</h5>
            <button class="text-gray-500 text-xl" data-close="true">×</button>
          </div>
          <div class="p-4 grid gap-3">
            <div class="text-sm text-gray-700">Are you sure you want to cancel this leave request?</div>
            <div>
              <label class="block text-sm text-gray-600 mb-1">Reason (optional)</label>
              <textarea id="leave-cancel-reason" rows="3" class="w-full border rounded px-3 py-2" placeholder="Enter a reason (optional)"></textarea>
            </div>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true" id="leave-cancel-no">No</button>
            <button class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700" id="leave-cancel-yes">Yes, Cancel</button>
          </div>
        </div>
      </div>
    </div>`;
  document.body.insertAdjacentHTML('beforeend', html);
  const modal = document.getElementById('leaveCancelModal');
  modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
}

function openLeaveCancelModal(){
  ensureLeaveCancelModal();
  const modal = document.getElementById('leaveCancelModal');
  const reasonEl = document.getElementById('leave-cancel-reason');
  const yesBtn = document.getElementById('leave-cancel-yes');
  const noBtn = document.getElementById('leave-cancel-no');
  if (reasonEl) reasonEl.value = '';
  modal.classList.remove('hidden');
  return new Promise((resolve) => {
    const onNo = () => { cleanup(); resolve({ confirmed: false, reason: '' }); };
    const onYes = () => { const reason = reasonEl ? reasonEl.value : ''; cleanup(); resolve({ confirmed: true, reason }); };
    function cleanup(){
      modal.classList.add('hidden');
      if (noBtn) noBtn.removeEventListener('click', onNo);
      if (yesBtn) yesBtn.removeEventListener('click', onYes);
    }
    if (noBtn) noBtn.addEventListener('click', onNo);
    if (yesBtn) yesBtn.addEventListener('click', onYes);
    // Also treat clicking overlay/close button as cancel
    modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', onNo, { once: true }));
  });
}

function profileImgKey(empId){ return `intro_emp_profile_img_${empId}`; }
function loadProfileImg(empId){ try { return localStorage.getItem(profileImgKey(empId)) || ''; } catch { return ''; } }
function saveProfileImg(empId, dataUrl){ try { if (dataUrl) localStorage.setItem(profileImgKey(empId), dataUrl); else localStorage.removeItem(profileImgKey(empId)); } catch {} }
function toTitleCaseName(s){ return String(s||'').split(' ').map(w => w? w[0].toUpperCase()+w.slice(1).toLowerCase() : '').join(' '); }

async function fileToDataUrl(file){
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

async function openEmployeeProfile(user){
  ensureEmpProfileModal();
  const modal = document.getElementById('empProfileModal');
  // Ensure a "Download QR" button is present next to the footer Close button and wire its click handler
  try {
    const closeBtns = modal ? modal.querySelectorAll('button[data-close="true"]') : [];
    let footerClose = null;
    if (closeBtns && closeBtns.length) {
      closeBtns.forEach(b => { if (String(b.textContent||'').trim() === 'Close') footerClose = b; });
    }
    if (footerClose && !document.getElementById('emp-prof-download-qr')) {
      const qrBtn = document.createElement('button');
      qrBtn.id = 'emp-prof-download-qr';
      qrBtn.className = 'px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700';
      qrBtn.textContent = 'Download QR';
      try { footerClose.parentNode.insertBefore(qrBtn, footerClose); } catch {}
    }
  } catch {}
  // Click handler to generate and download the employee QR code
  try {
    const dlBtn = document.getElementById('emp-prof-download-qr');
    if (dlBtn) {
      dlBtn.onclick = async () => {
        try {
          // Resolve user/employee info
          let me = null;
          try { const s = sessionStorage.getItem('currentUser'); if (s) me = JSON.parse(s); } catch {}
          if (!me || !me.employee_id) me = (typeof user !== 'undefined' && user) ? user : me;
          const id = me && me.employee_id ? me.employee_id : null;
          if (!id) { alert('Employee information unavailable'); return; }
          // Fetch latest employee info for accurate name
          let empRec = null; try { const r = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployee', employee_id: id } }); empRec = r && r.data ? r.data : null; } catch {}
          const first = (empRec && empRec.first_name) ? empRec.first_name : (me.first_name || '');
          const last = (empRec && empRec.last_name) ? empRec.last_name : (me.last_name || '');
          const fullName = (function toTitleCaseName(s){ return String(s||'').split(' ').map(w => w? w[0].toUpperCase()+w.slice(1).toLowerCase() : '').join(' '); })(`${first} ${last}`.trim());
          const pad3 = (n) => String(Number(n)||0).toString().padStart(3, '0');
          const year = new Date().getFullYear();
          const code = `EMP${year}-${pad3(id)}`;
          const payload = JSON.stringify({ type: 'employee', employee_id: id, name: fullName, code });
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
          if (!framed) { alert('Failed to generate QR code.'); return; }
          const a = document.createElement('a');
          a.href = framed;
          a.download = `employee-${code}.png`;
          document.body.appendChild(a);
          a.click();
          a.remove();
        } catch {}
      };
    }
  } catch {}
  const eidEl = document.getElementById('emp-prof-eid');
  const statusEl = document.getElementById('emp-prof-status');
  const nameEl = document.getElementById('emp-prof-name');
  const genderEl = document.getElementById('emp-prof-gender');
  const addrEl = document.getElementById('emp-prof-address');
  const emailEl = document.getElementById('emp-prof-email');
  const phoneEl = document.getElementById('emp-prof-phone');
  const deptEl = document.getElementById('emp-prof-dept');
  const posEl = document.getElementById('emp-prof-pos');
  const dobEl = document.getElementById('emp-prof-dob');
  const hiredEl = document.getElementById('emp-prof-hired');
  const img = document.getElementById('emp-prof-avatar');
  const imgPh = document.getElementById('emp-prof-avatar-ph');
  const fileInput = document.getElementById('emp-prof-file');
  const saveBtn = document.getElementById('emp-prof-save');
  const remBtn = document.getElementById('emp-prof-remove');

  // Load employee details
  let emp = null;
  try {
    const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployee', employee_id: user.employee_id } });
    emp = res.data || {};
  } catch {}

  const fmtDate = (s) => { try { const d = new Date(s); return isNaN(d.getTime()) ? '' : d.toLocaleDateString('en-US', { year:'numeric', month:'short', day:'numeric' }); } catch { return ''; } };
  const formatEmployeeCode = (id) => { const year = new Date().getFullYear(); const n = Number(id)||0; return `EMP${year}-${String(n).padStart(3,'0')}`; };
  const genderStr = toTitleCaseName(emp?.gender || '');
  const fullName = toTitleCaseName(`${emp?.first_name || user.first_name || ''} ${emp?.last_name || user.last_name || ''}`.trim());

  if (eidEl) eidEl.textContent = emp?.employee_id ? formatEmployeeCode(emp.employee_id) : String(user.employee_id || '');
  if (statusEl) statusEl.textContent = toTitleCaseName(emp?.status || 'Active');
  if (nameEl) nameEl.textContent = fullName;
  if (genderEl) genderEl.textContent = genderStr || '-';
  if (addrEl) addrEl.textContent = emp?.address || '-';
  if (emailEl) emailEl.textContent = user.username || emp?.email || '-';
  if (phoneEl) phoneEl.textContent = emp?.phone || '-';
  if (deptEl) deptEl.textContent = toTitleCaseName(emp?.department || user.department || '-');
  if (posEl) posEl.textContent = toTitleCaseName(emp?.position || '-');
  if (dobEl) dobEl.textContent = fmtDate(emp?.date_of_birth || '');
  if (hiredEl) hiredEl.textContent = fmtDate(emp?.date_hired || '');


  const dbImg = emp && emp.profile_image ? emp.profile_image : '';
  const stored = loadProfileImg(user.employee_id); // fallback for older sessions
  const effectiveImg = dbImg || stored;
  if (effectiveImg) { img.src = effectiveImg; img.classList.remove('hidden'); imgPh.classList.add('hidden'); }
  else { img.src = ''; img.classList.add('hidden'); imgPh.classList.remove('hidden'); }

  let pendingDataUrl = '';
  if (fileInput) {
    fileInput.value = '';
    fileInput.onchange = async (e) => {
      const f = e.target.files && e.target.files[0];
      if (!f) return;
      try {
        const dataUrl = await fileToDataUrl(f);
        pendingDataUrl = dataUrl;
        img.src = dataUrl; img.classList.remove('hidden'); imgPh.classList.add('hidden');
      } catch {}
    };
  }

  if (saveBtn) {
    saveBtn.onclick = async () => {
      try {
        if (pendingDataUrl) {
          // Save to DB
          const fd = new FormData();
          fd.append('operation', 'updateProfileImage');
          fd.append('json', JSON.stringify({ employee_id: user.employee_id, profile_image: pendingDataUrl }));
          const res = await axios.post(`${baseApiUrl}/employees.php`, fd);
          const ok = res && res.data && (res.data.success === 1 || res.data === 1);
          if (ok){
            // Optional: keep small cache for instant UX
            saveProfileImg(user.employee_id, pendingDataUrl);
            window.syncHeaderAvatar(user);
            // Update welcome section avatar if on dashboard
            await updateEmployeeWelcomeSection(user);
            showToast('Profile image saved', 'success');
          } else {
            showToast('Failed to save image', 'error');
          }
        } else {
          showToast('Select an image to upload', 'warning');
        }
      } catch { showToast('Failed to save image', 'error'); }
    };
  }
  if (remBtn) {
    remBtn.onclick = async () => {
      try {
        const fd = new FormData();
        fd.append('operation', 'updateProfileImage');
        fd.append('json', JSON.stringify({ employee_id: user.employee_id, profile_image: '' }));
        const res = await axios.post(`${baseApiUrl}/employees.php`, fd);
        const ok = res && res.data && (res.data.success === 1 || res.data === 1);
        if (ok){
          saveProfileImg(user.employee_id, '');
          pendingDataUrl = '';
          img.src = ''; img.classList.add('hidden'); imgPh.classList.remove('hidden');
          window.syncHeaderAvatar(user);
          // Update welcome section avatar if on dashboard
          await updateEmployeeWelcomeSection(user);
          showToast('Profile image removed', 'success');
        } else {
          showToast('Failed to remove image', 'error');
        }
      } catch {
        showToast('Failed to remove image', 'error');
      }
    };
  }

  // Wire the Reset Password floating card link and modal
  ensureEmpResetPwdModal();
  const resetLink = document.getElementById('emp-prof-reset-link');
  const resetModal = document.getElementById('empResetPwdModal');
  const newPwdInput = document.getElementById('emp-resetpwd-new');
  const confirmPwdInput = document.getElementById('emp-resetpwd-confirm');
  const strengthEl = document.getElementById('emp-resetpwd-strength');
  const matchEl = document.getElementById('emp-resetpwd-match');
  const savePwdBtn = document.getElementById('emp-resetpwd-save');

  const openReset = () => {
    if (newPwdInput) newPwdInput.value = '';
    if (confirmPwdInput) confirmPwdInput.value = '';
    if (strengthEl) { strengthEl.textContent = ''; strengthEl.classList.add('hidden'); }
    if (matchEl) { matchEl.textContent = ''; matchEl.className = 'mt-1 text-xs'; }
    if (resetModal) resetModal.classList.remove('hidden');
  };
  if (resetLink) {
    resetLink.onclick = (e) => { e.preventDefault(); openReset(); };
  }

  const evaluateStrength = (pwd) => {
    let score = 0;
    if (pwd.length >= 8) score++;
    if (/[a-z]/.test(pwd)) score++;
    if (/[A-Z]/.test(pwd)) score++;
    if (/[0-9]/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;
    return Math.min(score, 4);
  };
  const strengthText = (s) => ['Very Weak','Weak','Fair','Strong'][Math.max(0,s-1)] || '';

  if (newPwdInput && strengthEl) {
    newPwdInput.addEventListener('input', () => {
      const v = newPwdInput.value || '';
      if (v.length === 0) { strengthEl.classList.add('hidden'); strengthEl.textContent = ''; return; }
      const s = evaluateStrength(v);
      strengthEl.classList.remove('hidden');
      strengthEl.textContent = `Strength: ${strengthText(s)}`;
      strengthEl.className = `mt-1 text-xs ${s >= 3 ? 'text-green-600' : s >= 2 ? 'text-yellow-600' : 'text-red-600'}`;
    });
  }
  const syncMatch = () => {
    if (!matchEl || !newPwdInput || !confirmPwdInput) return;
    const a = newPwdInput.value;
    const b = confirmPwdInput.value;
    if (!b) { matchEl.textContent = ''; matchEl.className = 'mt-1 text-xs'; return; }
    if (a === b) { matchEl.textContent = 'Passwords match'; matchEl.className = 'mt-1 text-xs text-green-600'; }
    else { matchEl.textContent = 'Passwords do not match'; matchEl.className = 'mt-1 text-xs text-red-600'; }
  };
  if (confirmPwdInput) confirmPwdInput.addEventListener('input', syncMatch);
  if (newPwdInput) newPwdInput.addEventListener('input', syncMatch);

  if (savePwdBtn) {
    savePwdBtn.onclick = async (e) => {
      e.preventDefault();
      const pwd = (newPwdInput?.value || '').trim();
      const cpwd = (confirmPwdInput?.value || '').trim();
      if (pwd.length < 6) { showToast('Password must be at least 6 characters', 'warning'); return; }
      if (pwd !== cpwd) { showToast('Passwords do not match', 'error'); return; }
      savePwdBtn.disabled = true;
      const origText = savePwdBtn.textContent;
      savePwdBtn.textContent = 'Updating...';
      try {
        const fd = new FormData();
        fd.append('operation', 'updateProfile');
        fd.append('json', JSON.stringify({ password: pwd }));
        const res = await axios.post(`${baseApiUrl}/auth.php`, fd, { withCredentials: true });
        if (res.data && res.data.success) {
          showToast('Password updated successfully', 'success');
          if (resetModal) resetModal.classList.add('hidden');
        } else {
          const msg = res.data?.message || 'Failed to update password';
          showToast(msg, 'error');
        }
      } catch (err) {
        console.error('Update password error:', err);
        showToast('An error occurred while updating password', 'error');
      } finally {
        savePwdBtn.disabled = false;
        savePwdBtn.textContent = origText || 'Update Password';
      }
    };
  }


  if (modal) modal.classList.remove('hidden');
}

function syncHeaderAvatar(user){
  try {
    const img = document.getElementById('emp-prof-avatar-header');
    const ph = document.getElementById('emp-prof-avatar-header-ph');
    if (!img || !ph) return;
    const stored = loadProfileImg(user.employee_id);
    if (stored) {
      img.src = stored;
      img.classList.remove('hidden');
      ph.classList.add('hidden');
    } else {
      img.src = '';
      img.classList.add('hidden');
      ph.classList.remove('hidden');
    }
  } catch {}
}

function escapeHtml(text){
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Build a comprehensive lowercase search text for a payslip, including date tokens in multiple formats
function payslipSearchText(p){
  try {
    const base = [
      p.payroll_period_start, p.payroll_period_end, p.status, p.created_at, p.paid_at,
      p.net_pay, p.basic_salary, p.overtime_pay, p.first_name, p.last_name
    ].map(v => String(v || ''));
    const tokens = []
      .concat(dateTokens(p.payroll_period_start))
      .concat(dateTokens(p.payroll_period_end))
      .concat(dateTokens(p.created_at))
      .concat(dateTokens(p.paid_at));
    return base.concat(tokens).join(' ').toLowerCase();
  } catch { return ''; }
}

function dateTokens(val){
  const out = [];
  try {
    if (!val) return out;
    const d = new Date(val);
    if (isNaN(d.getTime())) return out;
    const pad2 = (n) => String(n).padStart(2, '0');
    const yyyy = d.getFullYear();
    const mm = pad2(d.getMonth() + 1);
    const dd = pad2(d.getDate());
    const monthNames = ['January','February','March','April','May','June','July','August','September','October','November','December'];
    const month = monthNames[d.getMonth()];
    const mon = month.slice(0,3);

    // Common formats
    out.push(`${yyyy}-${mm}-${dd}`); // ISO date
    out.push(`${yyyy}-${mm}`);
    out.push(`${mm}/${dd}/${yyyy}`); // US
    out.push(`${dd}/${mm}/${yyyy}`); // EU
    out.push(`${mm}/${yyyy}`);
    out.push(`${month} ${yyyy}`);
    out.push(`${mon} ${yyyy}`);
    out.push(String(yyyy));

    // Localized date
    try { out.push(d.toLocaleDateString()); } catch {}
  } catch {}
  return out;
}

// Payslip Done/History helpers and view state
function getPayslipsView(){ try { return __payslipsView === 'history' ? 'history' : 'active'; } catch { return 'active'; } }
function setPayslipsView(v){ __payslipsView = v === 'history' ? 'history' : 'active'; }
function updatePayslipViewButtons(){
  const act = document.getElementById('ps-active-btn');
  const hist = document.getElementById('ps-history-btn');
  if (!act || !hist) return;
  const active = getPayslipsView() === 'active';
  act.className = 'px-2 py-1 text-xs rounded border ' + (active ? 'bg-primary-600 text-white' : 'bg-white text-gray-700');
  hist.className = 'px-2 py-1 text-xs rounded border ' + (!active ? 'bg-primary-600 text-white' : 'bg-white text-gray-700');
}

function payslipDoneKey(employeeId){ return `intro_emp_payslips_done_${employeeId}`; }
function loadDonePayslips(employeeId){
  try {
    const raw = localStorage.getItem(payslipDoneKey(employeeId));
    const arr = raw ? JSON.parse(raw) : [];
    return Array.isArray(arr) ? arr : [];
  } catch { return []; }
}
function saveDonePayslips(employeeId, list){
  try { localStorage.setItem(payslipDoneKey(employeeId), JSON.stringify(list || [])); } catch {}
}
function isPayslipDone(employeeId, payrollId){
  return loadDonePayslips(employeeId).some(x => String(x.payroll_id) === String(payrollId));
}
function markPayslipDone(employeeId, payroll){
  if (!payroll || !payroll.payroll_id) return;
  const list = loadDonePayslips(employeeId);
  if (!list.some(x => String(x.payroll_id) === String(payroll.payroll_id))) {
    list.unshift({ payroll_id: payroll.payroll_id, payroll: payroll, done_at: new Date().toISOString() });
    saveDonePayslips(employeeId, list);
  }
}
function restorePayslip(employeeId, payrollId){
  const list = loadDonePayslips(employeeId).filter(x => String(x.payroll_id) !== String(payrollId));
  saveDonePayslips(employeeId, list);
}
