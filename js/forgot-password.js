/**
 * PASSWORD RESET FUNCTIONALITY
 * Handles two-step password reset process with email verification
 * Includes password strength validation and user feedback
 */
const baseApiUrl = `${location.origin}/intro/api`;

document.addEventListener('DOMContentLoaded', () => {
  const requestForm = document.getElementById('request-code-form');
  const resetForm = document.getElementById('reset-password-form');
  const requestMessage = document.getElementById('request-message');
  const resetMessage = document.getElementById('reset-message');
  const toggle = document.getElementById('toggle-password');
  const pwdInput = document.getElementById('new-password');

  // Animation: load anime.js and animate card, title, fields, and button
  function ensureAnime(){
    if (window.anime) return Promise.resolve(window.anime);
    return new Promise((resolve) => {
      const s = document.createElement('script');
      s.src = 'https://cdnjs.cloudflare.com/ajax/libs/animejs/3.2.1/anime.min.js';
      s.async = true;
      s.onload = () => resolve(window.anime);
      s.onerror = () => resolve(null);
      document.head.appendChild(s);
    });
  }
  ensureAnime().then((anime) => {
    if (!anime) return;
    try {
      const card = document.getElementById('forgot-card');
      if (card) {
        card.style.opacity = '0';
        card.style.transform = 'translateY(6px) scale(0.98)';
        anime({ targets: card, translateY: [6,0], scale: [0.98,1], opacity: [0,1], easing: 'easeOutQuad', duration: 360 });
      }
      const title = document.querySelector('h2');
      if (title) {
        title.style.transformOrigin = '50% 50%';
        anime({ targets: title, scale: [0.96, 1], rotate: [-1, 0], easing: 'easeOutQuad', duration: 380, delay: 80 });
      }
            const fields = document.querySelectorAll('#request-code-form input, #reset-password-form input');
      if (fields && fields.length) {
        anime({ targets: fields, translateY: [4,0], opacity: [0,1], easing: 'easeOutQuad', duration: 240, delay: anime.stagger(30, { start: 140 }) });
      }
      const btn = document.getElementById('send-code-btn');
      if (btn) {
        btn.addEventListener('click', async () => {
          try { anime.remove(btn); anime({ targets: btn, scale: [1, 0.98, 1], duration: 200, easing: 'easeOutQuad' }); } catch {}
        });
      }
    } catch {}
  });

  // SweetAlert2 toast helper with same style as login page
  function swToast(title, icon = 'info', ms = 1800){
    try {
      Swal.fire({
        toast: true,
        position: 'top-end',
        icon,
        title,
        showConfirmButton: false,
        timer: ms,
        timerProgressBar: true
      });
    } catch (e) { console.warn('Swal not available'); }
  }
  
  /**
   * HANDLE PASSWORD RESET CODE REQUEST
   * Validates username/email and sends verification code via email
   * Includes timeout handling and loading state management
   */
  requestForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('forgot-username').value.trim();
    let controller;
    let timeoutId;
    if (!username) {
      swToast('Please enter a username or email', 'warning');
      return;
    }
    
    // Show loading state
    const sendBtn = document.getElementById('send-code-btn');
    const btnText = document.getElementById('btn-text');
    const loadingSpinner = document.getElementById('loading-spinner');
    
    sendBtn.disabled = true;
    btnText.textContent = 'Sending...';
    loadingSpinner.classList.remove('hidden');
    
    try {
      const fd = new FormData();
      fd.append('operation', 'forgotPassword');
      fd.append('json', JSON.stringify({ username }));
      
      // Add timeout to prevent hanging
      controller = new AbortController();
      timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
      
      const res = await axios.post(`${baseApiUrl}/auth.php`, fd, { 
        signal: controller.signal,
        timeout: 30000 // 30 second timeout
      });
      
      clearTimeout(timeoutId);
      
      if (res.data && res.data.success) {
        swToast('A 6-digit code has been sent to your email. Please check your inbox.', 'success');
        // Hide request form and show reset form
        requestForm.classList.add('hidden');
        resetForm.classList.remove('hidden');
        // Focus code input
        document.getElementById('reset-code').focus();
      } else {
        swToast(res.data.message || 'Failed to process request', 'error');
      }
    } catch (err) {
      if (timeoutId) clearTimeout(timeoutId);
      console.error('Error:', err);
      
      let errorMessage = 'An error occurred. Please try again.';
      
      if (err.name === 'AbortError') {
        errorMessage = 'Request timed out. Please check your internet connection and try again.';
      } else if (err.code === 'ECONNABORTED') {
        errorMessage = 'Connection timed out. Please try again.';
      } else if (err.response) {
        errorMessage = err.response.data?.message || 'Server error. Please try again.';
      }
      
      swToast(errorMessage, 'error');
    } finally {
      // Reset button state
      sendBtn.disabled = false;
      btnText.textContent = 'Send Reset Code';
      loadingSpinner.classList.add('hidden');
    }
  });
  
  /**
   * HANDLE PASSWORD RESET WITH VERIFICATION CODE
   * Validates 6-digit code and updates user password
   * Includes password confirmation and strength validation
   */
  resetForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const code = document.getElementById('reset-code').value.trim();
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    
    if (!code || code.length !== 6) {
      swToast('Please enter the 6-digit code', 'warning');
      return;
    }
    
    if (newPassword.length < 6) {
      swToast('Password must be at least 6 characters long', 'warning');
      return;
    }
    
    if (newPassword !== confirmPassword) {
      swToast('Passwords do not match', 'warning');
      return;
    }
    
    try {
      const fd = new FormData();
      fd.append('operation', 'resetPassword');
      fd.append('json', JSON.stringify({ 
        code, 
        newPassword 
      }));
      
      const res = await axios.post(`${baseApiUrl}/auth.php`, fd);
      
      if (res.data && res.data.success) {
        swToast('Password reset successfully! Redirecting to login...', 'success');
        setTimeout(() => {
          window.location.href = './login.html';
        }, 2000);
      } else {
        swToast(res.data.message || 'Failed to reset password', 'error');
      }
    } catch (err) {
      console.error('Error:', err);
      swToast('An error occurred. Please try again.', 'error');
    }
  });
  
  // Password toggle functionality
  if (toggle && pwdInput) {
    toggle.addEventListener('click', () => {
      const isPassword = pwdInput.type === 'password';
      pwdInput.type = isPassword ? 'text' : 'password';
      toggle.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    });
  }
  
  // Password strength checking
  pwdInput.addEventListener('input', () => {
    const password = pwdInput.value;
    const strengthDiv = document.getElementById('password-strength');
    
    if (password.length === 0) {
      strengthDiv.classList.add('hidden');
      return;
    }
    
    strengthDiv.classList.remove('hidden');
    const strength = checkPasswordStrength(password);
    updatePasswordStrengthIndicator(strength);
  });
  
  // Code input formatting (only allow numbers)
  document.getElementById('reset-code').addEventListener('input', (e) => {
    e.target.value = e.target.value.replace(/\D/g, '').substring(0, 6);
  });
  
  /**
   * EVALUATE PASSWORD STRENGTH SCORE
   * Checks multiple criteria: length, case, numbers, special characters
   * Returns strength score from 0-4 for visual indicator
   */
  function checkPasswordStrength(password) {
    let score = 0;
    
    if (password.length >= 8) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    
    return Math.min(score, 4);
  }
  
  /**
   * UPDATE PASSWORD STRENGTH VISUAL INDICATOR
   * Changes color and text based on password strength score
   * Provides real-time feedback to encourage strong passwords
   */
  function updatePasswordStrengthIndicator(strength) {
    const strengthText = document.getElementById('strength-text');
    const strength1 = document.getElementById('strength-1');
    const strength2 = document.getElementById('strength-2');
    const strength3 = document.getElementById('strength-3');
    const strength4 = document.getElementById('strength-4');
    
    const colors = ['bg-red-500', 'bg-orange-500', 'bg-yellow-500', 'bg-green-500'];
    const texts = ['Very Weak', 'Weak', 'Fair', 'Strong'];
    
    // Reset all indicators
    [strength1, strength2, strength3, strength4].forEach((el, index) => {
      el.className = `w-2 h-2 rounded-full ${index < strength ? colors[strength - 1] : 'bg-gray-300'}`;
    });
    
    strengthText.textContent = texts[strength - 1] || '';
    strengthText.className = `ml-2 ${strength >= 3 ? 'text-green-600' : strength >= 2 ? 'text-yellow-600' : 'text-red-600'}`;
  }
  
  /**
   * DISPLAY FEEDBACK MESSAGE TO USER
   * Shows success or error messages with appropriate styling
   * Auto-hides success messages after timeout
   */
  function showMessage(element, message, type) {
    element.textContent = message;
    element.className = `text-sm ${type === 'success' ? 'text-green-600' : 'text-red-600'}`;
    element.classList.remove('hidden');
    
    // Auto-hide success messages after 5 seconds
    if (type === 'success') {
      setTimeout(() => {
        element.classList.add('hidden');
      }, 5000);
    }
  }
});
