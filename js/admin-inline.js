/**
 * ADMIN PORTAL CORE FUNCTIONALITY
 * Provides theme management, session handling, and security features
 * Loaded inline on all admin pages for consistent behavior
 */
window.baseApiUrl = `${location.origin}/intro/api`;

// Early, global restore of stored unread count for notification badge on all admin pages
(function restoreUnreadBadgeEarly(){
  try {
    const apply = () => {
      const badge = document.getElementById('notif-badge');
      if (!badge) return;
      const n = parseInt(sessionStorage.getItem('introUnreadNotifCount') || '0', 10);
      if (Number.isFinite(n) && n > 0) {
        badge.textContent = String(n);
        badge.classList.remove('hidden');
      } else {
        badge.textContent = '';
        badge.classList.add('hidden');
      }
    };
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', apply);
    } else {
      apply();
    }
  } catch {}
})();

/**
 * DYNAMIC THEME COLOR SYSTEM
 * Manages primary color schemes and CSS variable injection
 * Supports local storage persistence and server synchronization
 */
(function(){
  try {
    const map = { blue:['#2563eb','#1d4ed8'], emerald:['#059669','#047857'], rose:['#e11d48','#be123c'], violet:['#7c3aed','#6d28d9'], amber:['#d97706','#b45309'], teal:['#0d9488','#0f766e'] };
    /**
     * CONVERT HEX COLOR TO RGB VALUES
     * Parses hex color strings and returns RGB component array
     * Handles both 3-digit and 6-digit hex formats
     */
    function hexToRgb(hex){
      try {
        hex = (hex || '').replace('#','');
        if (hex.length === 3) hex = hex.split('').map(c => c + c).join('');
        var num = parseInt(hex, 16);
        return [(num >> 16) & 255, (num >> 8) & 255, num & 255];
      } catch(e){ return [0,0,0]; }
    }
    /**
     * INJECT DYNAMIC THEME CSS VARIABLES
     * Creates or updates theme stylesheet with primary color overrides
     * Supports both theme names and explicit color values
     */
    function ensureThemeStyle(themeOrColors){
      // Accept either a theme name or explicit colors {theme, p600, p700}
      let theme = typeof themeOrColors === 'string' ? themeOrColors : (themeOrColors && themeOrColors.theme) || 'blue';
      let p600 = null, p700 = null;
      if (themeOrColors && typeof themeOrColors === 'object'){
        p600 = themeOrColors.p600 || themeOrColors.primary_600 || null;
        p700 = themeOrColors.p700 || themeOrColors.primary_700 || null;
      }
      const v = (p600 && p700) ? [p600, p700] : (map[theme] || map.blue);
      const [r6,g6,b6] = hexToRgb(v[0]);
      const [r7,g7,b7] = hexToRgb(v[1]);
      const css = `
:root { --primary-600: ${v[0]}; --primary-700: ${v[1]}; --primary-600-rgb: ${r6} ${g6} ${b6}; --primary-700-rgb: ${r7} ${g7} ${b7}; }
.bg-primary-600, .hover\\:bg-primary-600:hover { background-color: var(--primary-600) !important; }
.bg-primary-700, .hover\\:bg-primary-700:hover { background-color: var(--primary-700) !important; }
.bg-primary-600\\/70, .hover\\:bg-primary-600\\/70:hover { background-color: rgba(var(--primary-600-rgb), 0.7) !important; }
.bg-primary-700\\/70, .hover\\:bg-primary-700\\/70:hover { background-color: rgba(var(--primary-700-rgb), 0.7) !important; }
.text-primary-700 { color: var(--primary-700) !important; }
.text-primary-600 { color: var(--primary-600) !important; }
.border-primary-600 { border-color: var(--primary-600) !important; }
.ring-primary-600 { --tw-ring-color: var(--primary-600) !important; }
.from-primary-700 { --tw-gradient-from: var(--primary-700) !important; }
.to-primary-600 { --tw-gradient-to: var(--primary-600) !important; }`;
      let el = document.getElementById('theme-overrides');
      if (!el){ el = document.createElement('style'); el.id = 'theme-overrides'; document.head.appendChild(el); }
      el.textContent = css;
    }
    window.__applyTheme = function(theme){ ensureThemeStyle(theme); };
    window.__setTheme = async function(theme){
      try { localStorage.setItem('introTheme', theme); } catch {}
      ensureThemeStyle(theme);
      try {
        const res = await fetch(`${window.baseApiUrl}/theme.php`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `operation=setTheme&json=${encodeURIComponent(JSON.stringify({ theme }))}`
        });
        // No hard dependency on response content
        await res.text();
      } catch(e){}
    };
    // Early local application, then fetch from server to sync
    const saved = (function(){ try { return localStorage.getItem('introTheme'); } catch { return null; } })();
    ensureThemeStyle(saved || 'blue');
    // Ensure consistent spacing for Audit Logs table cells across admin pages
    try {
      let st = document.getElementById('audit-logs-spacing-style');
      if (!st) {
        st = document.createElement('style');
        st.id = 'audit-logs-spacing-style';
        st.textContent = '#audit-logs-table table th, #audit-logs-table table td { padding: 0.75rem 1rem; vertical-align: middle; }';
        document.head.appendChild(st);
      }
    } catch (e) {}
    // Load from server if available
    try {
      fetch(`${window.baseApiUrl}/theme.php?operation=getTheme`, { method: 'GET' })
        .then(r => r.json())
        .then(data => {
          if (data && data.success){
            try { localStorage.setItem('introTheme', data.theme || 'blue'); } catch {}
            ensureThemeStyle({ theme: data.theme, p600: data.primary_600, p700: data.primary_700 });
          }
        })
        .catch(()=>{});
    } catch(e){}
  } catch (e) {}
})();

/**
 * SWEETALERT2 DYNAMIC LOADER
 * Ensures SweetAlert2 library is available for admin dialogs
 * Provides fallback loading mechanism
 */
async function ensureSwalAssets(){
  try { if (window.Swal) return; } catch {}
  return new Promise((resolve) => {
    const s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/npm/sweetalert2@11';
    s.onload = resolve;
    s.onerror = resolve;
    document.head.appendChild(s);
  });
}
/**
 * DISPLAY SESSION EXPIRATION WARNING
 * Shows SweetAlert2 dialog for session timeout events
 * Includes fallback alert for library loading failures
 */
async function showSessionExpiredSwal(){
  try {
    await ensureSwalAssets();
    if (window.Swal){
      await window.Swal.fire({
        title: 'Session expired',
        text: 'Please log in again.',
        icon: 'warning',
        confirmButtonText: 'OK',
        timer: 1800,
        timerProgressBar: true
      });
      return;
    }
  } catch {}
  // SweetAlert2 fallback only - removed Flowbite dependency
  try {
    console.warn('Session expired. Please log in again.');
    alert('Session expired. Please log in again.');
  } catch {}
}

/**
 * GLOBAL INACTIVITY LOGOUT WATCHDOG
 * Monitors user activity and enforces session timeout policies
 * Automatically logs out inactive users based on security settings
 */
(function initGlobalInactivityLogout(){
  try {
    if (window.__inactivityWatchdog) return;
    window.__inactivityWatchdog = true;
    let timeoutMinutes = 0; // default fallback disabled; admin controls via settings
    // Load configured timeout from Security Settings
    try {
      if (window.axios) {
        window.axios.get(`${window.baseApiUrl}/security.php`, { params: { operation: 'getSecuritySettings' } })
          .then(res => {
            const cfg = res && res.data ? res.data : {};
            const n = parseInt(cfg.session_timeout_minutes, 10);
            if (Number.isFinite(n)) timeoutMinutes = n;
            try { if (typeof schedule === 'function') schedule(); } catch {}
          })
          .catch(() => {});
      } else if (window.fetch) {
        // Fallback to native fetch if axios isn't loaded yet on this page
        fetch(`${window.baseApiUrl}/security.php?operation=getSecuritySettings`, { method: 'GET' })
          .then(r => r.json())
          .then(cfg => {
            const n = parseInt((cfg && cfg.session_timeout_minutes), 10);
            if (Number.isFinite(n)) timeoutMinutes = n;
            try { if (typeof schedule === 'function') schedule(); } catch {}
          })
          .catch(() => {});
      }
    } catch {}

    let lastActivity = Date.now();
    let __logoutTimer = null;

    const triggerLogout = async () => {
      try { if (window.axios) { await window.axios.get(`${window.baseApiUrl}/auth.php`, { params: { operation: 'logout' }, withCredentials: true }); }
            else if (window.fetch) { await fetch(`${window.baseApiUrl}/auth.php?operation=logout`, { method: 'GET', credentials: 'include' }); } } catch {}
      try { sessionStorage.removeItem('currentUser'); } catch {}
      try {} catch {}
      try {
        const mins = Number(timeoutMinutes) || 0;
        const url = `/intro/master/login.html?timeout=1${mins>0 ? `&mins=${encodeURIComponent(mins)}` : ''}`;
        location.href = url;
      } catch { location.href = '/intro/master/login.html'; }
    };

    const schedule = () => {
      try { if (__logoutTimer) { clearTimeout(__logoutTimer); __logoutTimer = null; } } catch {}
      if (timeoutMinutes <= 0) return; // disabled
      const elapsedMs = Date.now() - lastActivity;
      const remaining = Math.max(1000, (timeoutMinutes * 60 * 1000) - elapsedMs);
      __logoutTimer = setTimeout(triggerLogout, remaining);
    };

    const mark = () => { lastActivity = Date.now(); schedule(); };

    ['click','keydown','mousedown','touchstart','pointerdown'].forEach(ev => {
      try { window.addEventListener(ev, mark, { passive: true }); } catch { window.addEventListener(ev, mark); }
    });

    // kick off initial timer
    schedule();
  } catch {}
})();
