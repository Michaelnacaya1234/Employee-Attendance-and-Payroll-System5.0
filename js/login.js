/**
 * GLOBAL API BASE URL CONFIGURATION
 * Sets up the base URL for authentication API calls
 */
const baseApiUrl = `${location.origin}/intro/api`;

/**
 * MAIN LOGIN PAGE INITIALIZATION
 * Handles session timeout alerts, authentication check, and UI setup
 */
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const params = new URLSearchParams(location.search);
    if (params.get('timeout') === '1') {
      const mins = parseInt(params.get('mins') || '0', 10);
      const msg = mins > 0 ? `Session expired after ${mins} minute${mins===1?'':'s'}. Please log in again.` : 'Session expired. Please log in again.';
      await Swal.fire({
        icon: 'warning',
        title: 'Session expired',
        text: msg,
        confirmButtonText: 'OK'
      });
      // Clean the URL to avoid showing the alert again on refresh
      try { window.history.replaceState({}, document.title, location.pathname); } catch {}
    }
  } catch {}
  // If already authenticated, go to app
  try {
    const res = await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
    if (res.data && res.data.authenticated) {
      location.href = '/intro/master/admin/admin.html#dashboard';
      return;
    }
  } catch {}

    const form = document.getElementById('login-form');
  const error = document.getElementById('login-error');
  const toggle = document.getElementById('toggle-password');
  const pwdInput = document.getElementById('login-password');
  const captchaDisplay = document.getElementById('captcha-display');
  const captchaRefresh = document.getElementById('captcha-refresh');
  const captchaInput = document.getElementById('captcha-input');
  const captchaError = document.getElementById('captcha-error');
  // Remove/hide manual refresh button in favor of auto-refresh
  if (captchaRefresh) { try { captchaRefresh.remove(); } catch (e) { try { captchaRefresh.style.display = 'none'; } catch {} } }
  let __captchaTimer = null;

  /**
   * ENSURE ANIME.JS IS LOADED FOR ANIMATIONS
   * Dynamically loads animation library for UI interactions
   * Returns null if loading fails
   */
  async function ensureAnime(){
    if (window.anime) return window.anime;
    return new Promise((resolve) => {
      const s = document.createElement('script');
      s.src = 'https://cdnjs.cloudflare.com/ajax/libs/animejs/3.2.1/anime.min.js';
      s.async = true;
      s.onload = () => resolve(window.anime);
      s.onerror = () => resolve(null);
      document.head.appendChild(s);
    });
  }

  // Center CAPTCHA and add timer element
  const captchaGroup = document.getElementById('captcha-group');
  if (captchaDisplay && captchaDisplay.parentElement) {
    const row = captchaDisplay.parentElement;
    row.className = 'flex flex-col items-center gap-2';
  }
  let captchaTimerEl = document.getElementById('captcha-timer');
  if (!captchaTimerEl && captchaDisplay && captchaDisplay.parentElement) {
    captchaTimerEl = document.createElement('div');
    captchaTimerEl.id = 'captcha-timer';
    captchaTimerEl.className = 'text-xs text-gray-500';
    captchaDisplay.parentElement.appendChild(captchaTimerEl);
  }
  let __captchaCountdownInterval = null;
  let __captchaSecondsRemaining = 0;
  /**
   * RENDER CAPTCHA COUNTDOWN TIMER
   * Updates the visual countdown for CAPTCHA expiration
   * Shows minutes and seconds remaining
   */
  function renderCaptchaTimer(){
    if (!captchaTimerEl) return;
    const m = Math.floor(Math.max(0, __captchaSecondsRemaining) / 60);
    const s = Math.max(0, __captchaSecondsRemaining) % 60;
    captchaTimerEl.textContent = `Expires in ${m}:${String(s).padStart(2, '0')}`;
  }

  if (toggle && pwdInput){
    toggle.addEventListener('click', () => {
      const isPassword = pwdInput.type === 'password';
      pwdInput.type = isPassword ? 'text' : 'password';
      toggle.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    });
  }

  // Subtle click animation on submit button
  const submitBtn = form ? form.querySelector('button[type="submit"]') : null;
  if (submitBtn){
    submitBtn.addEventListener('click', async () => {
      const anime = await ensureAnime();
      if (!anime) return;
      anime.remove(submitBtn);
      anime({ targets: submitBtn, scale: [1, 0.98, 1], duration: 200, easing: 'easeOutQuad' });
    });
  }

  /**
   * LOAD AND DISPLAY NEW CAPTCHA
   * Fetches fresh CAPTCHA from server with auto-refresh timer
   * Includes visual animations and expiration countdown
   */
  async function loadCaptcha(){
    try {
      const res = await axios.get(`${baseApiUrl}/auth.php`, { params: { operation: 'getCaptcha', len: 6 }, withCredentials: true });
      if (res.data && res.data.success && captchaDisplay) {
        captchaDisplay.textContent = String(res.data.captcha || '').replace(/[^0-9]/g, '');
        if (captchaError) captchaError.classList.add('hidden');
        // Animate captcha appearance
        try {
          const anime = await ensureAnime();
          if (anime) {
            captchaDisplay.style.transformOrigin = '50% 50%';
            anime.remove(captchaDisplay);
            anime({ targets: captchaDisplay, scale: [0.92, 1], opacity: [0.6, 1], duration: 220, easing: 'easeOutQuad' });
          }
        } catch {}
        // Start countdown timer UI
        try {
          __captchaSecondsRemaining = Math.max(0, Number(res.data.expires_in || 120));
          renderCaptchaTimer();
          if (__captchaCountdownInterval) { clearInterval(__captchaCountdownInterval); __captchaCountdownInterval = null; }
          __captchaCountdownInterval = setInterval(async () => {
            __captchaSecondsRemaining = Math.max(0, __captchaSecondsRemaining - 1);
            renderCaptchaTimer();
            // Pulse timer color in final 10 seconds
            if (__captchaSecondsRemaining <= 10 && captchaTimerEl){
              try {
                const anime = await ensureAnime();
                if (anime) {
                  anime.remove(captchaTimerEl);
                  anime({ targets: captchaTimerEl, color: ['#6b7280', '#dc2626', '#6b7280'], duration: 600, easing: 'easeInOutQuad' });
                }
              } catch {}
            }
            if (__captchaSecondsRemaining <= 0) {
              clearInterval(__captchaCountdownInterval); __captchaCountdownInterval = null;
            }
          }, 1000);
        } catch {}
        // Auto-refresh a bit before expiration
        try {
          const ttl = Math.max(5, Number(res.data.expires_in || 120));
          if (__captchaTimer) { clearTimeout(__captchaTimer); __captchaTimer = null; }
          __captchaTimer = setTimeout(loadCaptcha, Math.max(1000, (ttl - 5) * 1000));
        } catch {}
      }
    } catch {}
  }
  await loadCaptcha();

  // Load System Configuration: populate company address and name on login page
  try {
    const cfgRes = await axios.get(`${baseApiUrl}/system.php`, { params: { operation: 'getSystemSettings' } });
    const cfg = cfgRes.data || {};

    // Company address
    const addr = (cfg.company_address || '').toString().trim();
    const addrEl = document.getElementById('company-address');
    if (addr && addrEl) {
      addrEl.textContent = addr;
      addrEl.style.display = '';
    }

    // Company name (fallback to existing H1 if no explicit id)
    const name = (cfg.company_name || '').toString().trim();
    const nameEl = document.getElementById('company-name') || document.querySelector('h1');
    if (name && nameEl) {
      nameEl.textContent = name;
    }
  } catch {}

  // Helpers: format datetime and duration in a consistent 24h format
  function pad2(n){ return String(n).padStart(2,'0'); }
  function formatDateTime(dt){
    try {
      const y = dt.getFullYear();
      const m = pad2(dt.getMonth()+1);
      const d = pad2(dt.getDate());
      const hh = pad2(dt.getHours());
      const mm = pad2(dt.getMinutes());
      const ss = pad2(dt.getSeconds());
      return `${y}-${m}-${d} ${hh}:${mm}:${ss}`;
    } catch { return ''; }
  }
  function formatDuration(secs){
    const s = Math.max(0, Math.floor(Number(secs)||0));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const r = s % 60;
    return h > 0 ? `${h}h ${m}m ${r}s` : `${m}m ${r}s`;
  }
  function formatTime12(dt){
    try {
      let h = dt.getHours();
      const m = String(dt.getMinutes()).padStart(2,'0');
      const ampm = h >= 12 ? 'pm' : 'am';
      h = h % 12;
      if (h === 0) h = 12;
      return `${h}:${m}${ampm}`;
    } catch { return ''; }
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    error.classList.add('hidden');

    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    const rememberMe = document.getElementById('remember-me').checked;
    const captcha = (captchaInput && captchaInput.value ? captchaInput.value.trim() : '');

    if (!username || !password) {
      Swal.fire({
        toast: true,
        position: 'top-end',
        icon: 'warning',
        title: 'Missing information: Please enter both username and password.',
        showConfirmButton: false,
        timer: 1500,
        timerProgressBar: true
      });
      return;
    }

    const fd = new FormData();
    fd.append('operation', 'login');
    fd.append('json', JSON.stringify({ username, password, rememberMe, captcha }));

    
    try {
      const res = await axios.post(`${baseApiUrl}/auth.php`, fd, { withCredentials: true });
      if (res.data && res.data.success) {
        if (captchaInput) captchaInput.value = '';
        await loadCaptcha();
        const role = res.data.user && res.data.user.role ? res.data.user.role : 'admin';

        // Store remember me preference
        if (rememberMe) {
          localStorage.setItem('rememberMe', 'true');
          localStorage.setItem('rememberedUsername', username);
        } else {
          localStorage.removeItem('rememberMe');
          localStorage.removeItem('rememberedUsername');
        }

        try { sessionStorage.setItem('introJustLoggedIn', '1'); } catch {}

        await Swal.fire({
          icon: 'success',
          title: 'Welcome',
          text: `Signed in as ${username}`,
          timer: 1000,
          showConfirmButton: false,
        });

        if (role === 'hr') {
          location.href = '/intro/master/hr/hr.html#dashboard';
        } else if (role === 'manager') {
          location.href = '/intro/master/manager.html#dashboard';
        } else if (role === 'employee') {
          location.href = '/intro/master/employee.html#dashboard';
        } else {
          location.href = '/intro/master/admin/admin.html#dashboard';
        }
      } else {
        // Show detailed lockout/attempt notifications
        const d = res.data || {};
        if (d.blocked) {
          Swal.fire({
            icon: 'error',
            text: 'Account locked. Please contact the administrator.',
            confirmButtonText: 'OK'
          });
        } else if (d.lockout) {
          const secs = Math.max(0, Number(d.remaining_seconds || 0));
          const mins = Math.floor(secs / 60);
          const secRem = secs % 60;
          const minLabel = mins === 1 ? 'minute' : 'minutes';
          const secLabel = secRem === 1 ? 'second' : 'seconds';
          const msg = `Oops! Too many failed attempts. You can try again in ${mins} ${minLabel} and ${secRem} ${secLabel}.`;
          Swal.fire({
            icon: 'error',
            text: msg,
            confirmButtonText: 'OK'
          });
        } else {
          const d = res.data || {};
          if (String(d.message || '').toLowerCase().includes('inactive')) {
            Swal.fire({
              toast: true,
              position: 'top-end',
              icon: 'warning',
              title: 'This account is inactive. Please contact the administrator.',
              showConfirmButton: false,
              timer: 1800,
              timerProgressBar: true
            });
          } else if (d.captcha_required || d.captcha_invalid || d.captcha_expired) {
            if (captchaError) {
              captchaError.textContent = d.captcha_expired ? 'Captcha expired. Please refresh and try again.' : (d.captcha_invalid ? 'Invalid captcha. Please try again.' : 'Captcha is required.');
              captchaError.classList.remove('hidden');
            }
            await loadCaptcha();
            if (captchaInput) captchaInput.focus();
            // Shake the number gently on invalid/expired captcha
            try {
              const anime = await ensureAnime();
              if (anime && captchaDisplay) {
                anime.remove(captchaDisplay);
                anime({ targets: captchaDisplay, translateX: [0, -6, 6, -4, 4, -2, 2, 0], duration: 360, easing: 'easeInOutQuad' });
              }
            } catch {}
          } else {
            Swal.fire({
              toast: true,
              position: 'top-end',
              icon: 'error',
              title: 'Login failed: Invalid username or password.',
              showConfirmButton: false,
              timer: 1500,
              timerProgressBar: true
            });
          }
        }
      }
    } catch (err) {
      // Show side toast for network errors (compact)
      Swal.fire({
        toast: true,
        position: 'top-end',
        icon: 'error',
        title: 'Network error. Please try again.',
        showConfirmButton: false,
        timer: 1500,
        timerProgressBar: true
      });
    }
  });
  
  // Check for remembered username
  const rememberedUsername = localStorage.getItem('rememberedUsername');
  if (rememberedUsername) {
    document.getElementById('login-username').value = rememberedUsername;
    document.getElementById('remember-me').checked = true;
  }
});


