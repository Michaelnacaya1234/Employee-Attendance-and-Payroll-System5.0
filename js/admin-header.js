/**
 * ADMIN HEADER NAVIGATION MANAGER
 * Handles admin portal header functionality including profile, notifications, and user management
 * Provides unified interface for admin-specific features and navigation controls
 */
(function(){
  const baseApiUrl = window.baseApiUrl || `${location.origin}/intro/api`;
  try { if (!window.baseApiUrl) window.baseApiUrl = baseApiUrl; } catch {}
  // Immediate restore of stored unread count to avoid badge loss on navigation
  try {
    const __badge = document.getElementById('notif-badge');
    if (__badge) {
      const __stored = parseInt(sessionStorage.getItem('introUnreadNotifCount') || '0', 10);
      if (Number.isFinite(__stored) && __stored > 0) {
        __badge.textContent = __stored;
        __badge.classList.remove('hidden');
      }
    }
  } catch {}

  function byId(id){ return document.getElementById(id); }
  function hide(el){ if (el && !el.classList.contains('hidden')) el.classList.add('hidden'); }
  function toggle(el){ if (el) el.classList.toggle('hidden'); }
  function formatTime(iso){ try { const d = new Date(iso); return d.toLocaleString(); } catch { return ''; } }
  /**
   * ESCAPE HTML SPECIAL CHARACTERS
   * Prevents XSS attacks by sanitizing user input for safe display
   * Converts dangerous characters to HTML entities
   */
  function escapeHtml(text){
    return String(text || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * GET CURRENT AUTHENTICATED USER DATA
   * Retrieves admin user information from authentication API
   * Returns user object or null if not authenticated
   */
  async function getCurrentUser(){
    try {
      const res = await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
      return res.data && res.data.user ? res.data.user : null;
    } catch { return null; }
  }

  /**
   * POPULATE ADMIN PROFILE HEADER DISPLAY
   * Updates profile name, role, and avatar in admin navigation
   * Handles name formatting and fallback display logic
   */
  async function fillProfile(){
    try {
      const res = await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
      const user = res.data && res.data.user ? res.data.user : { username: 'Admin', role: 'admin' };
      const nameEl = byId('profile-name');
      const roleEl = byId('profile-role');
      const avatarEl = byId('profile-avatar');
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

  /**
   * SYNCHRONIZE ADMIN AVATAR IMAGE
   * Updates profile avatar from employee data if available
   * Falls back to text initials if no profile image exists
   */
  async function syncHeaderAvatar(){
    try {
      const img = byId('profile-avatar-img');
      const fallback = byId('profile-avatar');
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

  /**
   * MARK NOTIFICATION AS READ
   * Updates notification read status via API call
   * Returns boolean indicating operation success
   */
  async function markNotificationAsRead(notificationId){
    try {
      const fd = new FormData();
      fd.append('operation', 'markAsRead');
      fd.append('json', JSON.stringify({ notification_id: notificationId }));
      await axios.post(`${baseApiUrl}/notifications.php`, fd, { withCredentials: true });
      return true;
    } catch { return false; }
  }

  /**
   * DELETE NOTIFICATION FROM ADMIN SYSTEM
   * Removes notification permanently via API call
   * Returns boolean indicating deletion success
   */
  async function deleteNotification(notificationId){
    try {
      const fd = new FormData();
      fd.append('operation', 'deleteNotification');
      fd.append('json', JSON.stringify({ notification_id: notificationId }));
      await axios.post(`${baseApiUrl}/notifications.php`, fd, { withCredentials: true });
      return true;
    } catch { return false; }
  }

  /**
   * RENDER ADMIN HEADER NOTIFICATIONS
   * Updates notification dropdown with latest data and unread count
   * Wires interactive buttons for mark as read functionality
   */
  async function renderHeaderNotifications(){
    const badge = byId('notif-badge');
    const listEl = byId('admin-notif-dropdown-list');
    if (!badge || !listEl) return;
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
          </div>`).join('');
        
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

  /**
   * ENSURE SWEETALERT2 ASSETS ARE LOADED
   * Dynamically loads SweetAlert2 CSS and JavaScript with Tailwind fixes
   * Prevents duplicate loading and ensures compatibility
   */
  async function ensureSweetAlertAssets(){
    try {
      if (!document.getElementById('swal2-css')){
        const link = document.createElement('link');
        link.id = 'swal2-css'; link.rel = 'stylesheet';
        link.href = 'https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css';
        document.head.appendChild(link);
      }
      if (!window.Swal){
        await new Promise((resolve)=>{
          const s = document.createElement('script');
          s.id = 'swal2-js'; s.src = 'https://cdn.jsdelivr.net/npm/sweetalert2@11';
          s.onload = resolve; s.onerror = resolve; document.head.appendChild(s);
        });
      }
      if (!document.getElementById('swal2-tailwind-fix')){
        const st = document.createElement('style'); st.id = 'swal2-tailwind-fix';
        st.textContent = `.swal2-styled{color:#fff !important;}.swal2-styled.swal2-confirm{background-color:#2563EB !important;border:0 !important;}.swal2-styled.swal2-cancel{background-color:#6B7280 !important;border:0 !important;}.swal2-select{background-color:#ffffff !important;color:#111827 !important;border:1px solid #d1d5db !important;border-radius:0.5rem !important;padding:0.5rem 0.75rem !important;}`;
        document.head.appendChild(st);
      }
    } catch {}
  }

  /**
   * DISPLAY SWEETALERT2 TOAST NOTIFICATION
   * Shows brief notification message using SweetAlert2 toast
   * Supports different icon types (success, error, warning, info)
   */
  function showSweetToast(msg='Done', icon='info'){
    try {
      if (!window.Swal){ console.log(msg); return; }
      const Toast = Swal.mixin({ toast: true, position: 'top-end', showConfirmButton: false, timer: 1500, timerProgressBar: true });
      Toast.fire({ icon, title: msg });
    } catch {}
  }

  /**
   * FORMAT NOTIFICATION DATE FOR DISPLAY
   * Converts ISO date strings to readable format with time
   * Handles various date formats and provides fallback formatting
   */
  function formatNotifDate(val){
    try {
      if (!val) return '';
      const s = String(val); let d = new Date(s);
      if (isNaN(d.getTime())) d = new Date(s.includes('T')?s:`${s}T00:00:00`);
      if (isNaN(d.getTime())) return String(val);
      const months=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
      const mon=months[d.getMonth()], day=d.getDate(), year=d.getFullYear();
      let h=d.getHours(); const m=d.getMinutes(); const am=h>=12?'PM':'AM'; h=h%12; if (h===0) h=12; const mm=String(m).padStart(2,'0');
      return `${mon} ${day}, ${year} ${h}:${mm}${am}`;
    } catch { return String(val||''); }
  }

  /**
   * OPEN ADMIN NOTIFICATIONS MODAL
   * Displays all notifications in SweetAlert2 modal interface
   * Supports mark all as read and individual notification deletion
   */
  async function openAdminNotifSweetModal(){
    try {
      try { await ensureSweetAlertAssets(); } catch {}
      const resp = await axios.get(`${baseApiUrl}/notifications.php`, { params: { operation: 'getNotifications' }, withCredentials: true });
      
      // Handle different response formats properly
      let notifications = [];
      if (resp && resp.data) {
        // Check if it's the new format with success flag
        if (resp.data.success === 1 && Array.isArray(resp.data.notifications)) {
          notifications = resp.data.notifications;
        }
        // Check if it's the old format with tblnotifications
        else if (Array.isArray(resp.data.tblnotifications)) {
          notifications = resp.data.tblnotifications;
        }
        // Check if response.data is directly an array
        else if (Array.isArray(resp.data)) {
          notifications = resp.data;
        }
        // Handle case where response.data is an object with notifications property
        else if (resp.data.notifications && Array.isArray(resp.data.notifications)) {
          notifications = resp.data.notifications;
        }
        // Handle direct array response
        else if (Array.isArray(resp.data)) {
          notifications = resp.data;
        }
      }
      
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
          const html = Swal.getHtmlContainer(); if (!html) return;
          html.querySelectorAll('.sw-notif-item').forEach(el => {
            el.addEventListener('click', async () => {
              const id = el.getAttribute('data-id'); if (!id) return;
              try { await markNotificationAsRead(id); el.classList.remove('bg-blue-50'); await renderHeaderNotifications(); } catch {}
            });
          });
          html.querySelectorAll('.sw-del').forEach(btn => {
            btn.addEventListener('click', async (ev) => {
              ev.preventDefault(); ev.stopPropagation();
              const id = btn.getAttribute('data-id'); if (!id) return;
              try { await deleteNotification(id); const item = btn.closest('.sw-notif-item'); if (item) item.remove(); await renderHeaderNotifications(); showSweetToast('Notification deleted','success'); }
              catch { showSweetToast('Failed to delete notification','error'); }
            });
          });
        }
      });

      if (result && result.isConfirmed) {
        try {
          const unread = notifications.filter(n => !n.read_at && !n.readAt && !n.read);
          await Promise.all(unread.map(n => markNotificationAsRead(n.id || n.notification_id || n.notificationID)));
          await renderHeaderNotifications();
          showSweetToast('All notifications marked as read', 'success');
        } catch { showSweetToast('Failed to mark all as read', 'error'); }
      }
    } catch (error) {
      console.error('Error in openAdminNotifSweetModal:', error);
      try {
        await Swal.fire({
          title: 'Error',
          text: 'Failed to load notifications',
          icon: 'error'
        });
      } catch {}
    }
  }

  async function initHeaderNotifications(){
    const toggleBtn = byId('notif-toggle');
    const dropdown = byId('notif-dropdown');
    const closeBtn = byId('notif-close');
    const markAllBtn = byId('notif-mark-all');
    const profileMenu = byId('profile-menu');
    if (!toggleBtn || !dropdown) return;
    try {
      toggleBtn.classList.add('inline-flex','items-center','justify-center','w-9','h-9','rounded-full','bg-amber-50','ring-1','ring-amber-200','hover:bg-amber-100');
      const svg = toggleBtn.querySelector('svg');
      if (svg) { svg.classList.add('w-5','h-5','text-amber-600'); }
      const badge = byId('notif-badge');
      if (badge) {
        badge.classList.add('inline-flex','items-center','justify-center','rounded-full','bg-amber-600','text-white','text-[10px]','leading-4','min-w-[1rem]','h-4','px-1.5');
        // Show stored unread count immediately to avoid badge flicker on navigation
        try {
          const stored = parseInt(sessionStorage.getItem('introUnreadNotifCount') || '0', 10);
          if (Number.isFinite(stored) && stored > 0) {
            badge.textContent = stored;
            badge.classList.remove('hidden');
          } else {
            badge.textContent = '';
            badge.classList.add('hidden');
          }
        } catch {}
      }
    } catch {}
    const close = () => hide(dropdown);
    toggleBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      try { await ensureSweetAlertAssets(); } catch {}
      hide(dropdown);
      hide(profileMenu);
      try { await openAdminNotifSweetModal(); } catch {}
    });
    if (closeBtn) closeBtn.addEventListener('click', (e) => { e.preventDefault(); close(); });
    document.addEventListener('click', (e) => {
      if (!dropdown.contains(e.target) && !toggleBtn.contains(e.target)) close();
    });
    if (markAllBtn) {
      markAllBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        try {
          const response = await axios.get(`${baseApiUrl}/notifications.php`, { params: { operation: 'getNotifications' }, withCredentials: true });
          const notifications = (response.data && response.data.success) ? (response.data.notifications || []) : [];
          const unread = notifications.filter(n => !n.read_at);
          await Promise.all(unread.map(n => markNotificationAsRead(n.id)));
          await renderHeaderNotifications();
        } catch {}
      });
    }
    // initial
    renderHeaderNotifications();
    // badge refresh
    if (!window.__headerNotifInterval){
      window.__headerNotifInterval = setInterval(renderHeaderNotifications, 30000);
    }
  }

  function wireProfileDropdown(){
    const trigger = byId('profile-trigger');
    const menu = byId('profile-menu');
    const logoutBtn = byId('header-logout');
    const notifDropdown = byId('notif-dropdown');
    const settingsLink = menu ? menu.querySelector('a[href="#settings"]') : null;
    if (trigger && menu){
      trigger.addEventListener('click', (e) => {
        e.preventDefault(); e.stopPropagation();
        toggle(menu);
        hide(notifDropdown);
      });
      document.addEventListener('click', (e) => {
        if (!menu.classList.contains('hidden')){
          const within = trigger.contains(e.target) || menu.contains(e.target);
          if (!within) hide(menu);
        }
      });
      if (settingsLink) {
        settingsLink.addEventListener('click', (e) => {
          e.preventDefault(); e.stopPropagation();
          const isAdmin = /\/master\/admin\/admin\.html$/.test(location.pathname);
          if (isAdmin) {
            // On admin page, keep the menu open and just navigate the hash
            try { sessionStorage.setItem('introKeepProfileOpen','1'); } catch {}
            location.hash = '#settings';
          } else {
            // On manage pages, navigate directly to settings (no overlay)
            try { if (menu && !menu.classList.contains('hidden')) menu.classList.add('hidden'); } catch {}
            try { if (document.activeElement && document.activeElement.blur) document.activeElement.blur(); } catch {}
            location.href = '/intro/master/admin/admin.html#settings';
          }
        });
      }
    }
    if (logoutBtn){
      logoutBtn.addEventListener('click', async () => {
        try { await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'logout' }, withCredentials: true }); } catch {}
        try {
          const p = location.pathname || '';
          const idx = p.indexOf('/master/');
          const base = idx >= 0 ? p.slice(0, idx) : '';
          location.href = `${base}/master/login.html`;
        } catch {
          location.href = '../login.html';
        }
      });
    }
  }

  function wireSidebarLogout(){
    try {
      const container = document.querySelector('aside nav') || document;
      if (!container) return;
      const list = [];
      const btn = document.getElementById('btn-logout');
      if (btn) list.push(btn);
      container.querySelectorAll('a[href]').forEach(a => {
        const href = String(a.getAttribute('href') || '');
        if (/login\.html(\?.*)?$/i.test(href)) list.push(a);
      });
      const unique = Array.from(new Set(list));
      unique.forEach(el => {
        if (el.__wiredSidebarLogout) return;
        el.__wiredSidebarLogout = true;
        el.addEventListener('click', async (e) => {
          e.preventDefault();
          e.stopPropagation();
          try { await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'logout' }, withCredentials: true }); } catch {}
          try {
            const p = location.pathname || '';
            const idx = p.indexOf('/master/');
            const base = idx >= 0 ? p.slice(0, idx) : '';
            location.href = `${base}/master/login.html`;
          } catch {
            location.href = '../login.html';
          }
        });
      });
    } catch {}
  }

  
  function init(){
    // Only wire if header elements exist
    if (!byId('profile-trigger') && !byId('notif-toggle')) return;
    fillProfile();
    syncHeaderAvatar();
    wireProfileDropdown();
    wireSidebarLogout();
    initHeaderNotifications();
    // If coming from a manage page with a Settings click, keep the profile dropdown open
    try {
      const isAdmin = /\/master\/admin\/admin\.html$/.test(location.pathname);
      if (isAdmin && sessionStorage.getItem('introKeepProfileOpen') === '1'){
        const menu = byId('profile-menu');
        if (menu) menu.classList.remove('hidden');
        sessionStorage.removeItem('introKeepProfileOpen');
      }
    } catch {}
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
