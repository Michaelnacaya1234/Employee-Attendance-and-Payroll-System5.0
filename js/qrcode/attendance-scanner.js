/**
 * QR CODE ATTENDANCE SCANNER
 * Comprehensive QR code scanning system for employee time tracking
 * Supports multiple contexts (admin, HR, standalone) with configurable endpoints
 */
'use strict';

/**
 * SCANNER CONFIGURATION
 * Defines API endpoints, payload formats, and context-specific mappings
 * Configurable for different admin contexts and authentication methods
 */
const CONFIG = {
  // Base API URL for the attendance system
  baseApiUrl: window.baseApiUrl || `${location.origin}/intro/api`,

  // Optional links to admin and HR attendance pages
  adminAttendanceUrl: 'master/admin/admin.html',
  hrAttendanceUrl: 'master/hr/hr.html',

  // Context determines the integration behavior
  context: 'standalone', // can be 'standalone', 'admin', or 'hr'

  // Use built-in scanner UI like admin/HR pages typically do
  useHtml5QrcodeScanner: false
};

/**
 * SCANNER STATE MANAGEMENT
 * Maintains active camera, scanning status, and HTML5 QR code instance
 */
let html5QrCode = null;
let currentCameraId = null;
let isScanning = false;

/**
 * ENSURE QR SCANNING LIBRARY IS LOADED
 * Dynamically loads HTML5 QR code library if not already available
 * Returns promise that resolves when library is ready
 */
async function ensureQrScanLib(){
  if (window.Html5Qrcode || window.Html5QrcodeScanner) return;
  await new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = 'https://unpkg.com/html5-qrcode';
    s.onload = resolve; s.onerror = reject;
    document.head.appendChild(s);
  });
}

// Cached DOM refs (initialized on DOMContentLoaded)
let scanStatusEl = null;
let cameraSelectEl = null;

// Debounce same code scans
const lastScan = { code: null, ts: 0 };

/**
 * DISPLAY STATUS MESSAGE WITH VISUAL FEEDBACK
 * Shows status using SweetAlert2 toast or fallback text display
 * Color-codes messages based on success/error/warning types
 */
function setStatus(msg, color = 'text-gray-600') {
  if (window.Swal && msg) {
    const Toast = Swal.mixin({
      toast: true,
      position: 'top-end',
      showConfirmButton: false,
      timer: 2200,
      timerProgressBar: true
    });
    let icon = 'info';
    if (/green|success/i.test(color) || /success/i.test(msg)) icon = 'success';
    else if (/red|error/i.test(color) || /failed|fail/i.test(msg)) icon = 'error';
    else if (/amber|warn|warning/i.test(color) || /warning|late|absent/i.test(msg)) icon = 'warning';
    Toast.fire({ icon, title: String(msg) });
  }
  if (!scanStatusEl) return;
  scanStatusEl.className = 'mt-3 text-sm ' + color;
  scanStatusEl.textContent = msg;
}

/**
 * GENERATE AUDIO FEEDBACK BEEP
 * Creates audible confirmation using Web Audio API
 * Customizable frequency, duration, and volume
 */
function beep(duration = 120, frequency = 880, volume = 0.2, type = 'sine') {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const oscillator = ctx.createOscillator();
    const gain = ctx.createGain();
    oscillator.type = type;
    oscillator.frequency.setValueAtTime(frequency, ctx.currentTime);
    gain.gain.setValueAtTime(volume, ctx.currentTime);
    oscillator.connect(gain);
    gain.connect(ctx.destination);
    oscillator.start();
    setTimeout(() => { oscillator.stop(); ctx.close(); }, duration);
  } catch (e) { /* ignore */ }
}

/**
 * GET CURRENT SCAN MODE
 * Since UI controls are removed, always use auto mode
 * The scanner will automatically determine time-in vs time-out
 */
function getMode() {
  // Always use auto mode - scanner determines time-in/time-out automatically
  return 'auto';
}

/**
 * PARSE QR CODE PAYLOAD
 * Extracts employee code from various QR code formats
 * Supports JSON objects, alphanumeric codes, and raw strings
 */
function parsePayload(raw) {
  // Try JSON format first
  try {
    const obj = JSON.parse(raw);
    const type = obj && obj.type ? String(obj.type).toLowerCase() : '';
    if (type === 'employee') {
      if (obj && (obj.employee_id || obj.id)) {
        const n = Number(obj.employee_id || obj.id);
        if (Number.isFinite(n) && n > 0) {
          return { employee_code: String(n) };
        }
      }
      if (obj && obj.code) {
        const eid = parseEmployeeIdFromText(obj.code);
        if (eid) return { employee_code: String(eid) };
      }
    }
  } catch (e) {
    // Not JSON, continue with other parsing
  }
  
  // Try to extract employee ID from text
  const eid = parseEmployeeIdFromText(raw);
  if (eid) {
    return { employee_code: String(eid) };
  }
  
  // Fallback: return the raw text
  return { employee_code: String(raw || '').trim() };
}

/**
 * PARSE EMPLOYEE ID FROM QR CODE TEXT
 * Extracts numeric employee ID from various QR code formats
 * Supports both JSON objects and plain text codes
 */
function parseEmployeeIdFromText(text) {
  const match = (text || '').match(/\b\d+\b/);
  return match ? parseInt(match[0], 10) : null;
}

/**
 * GET CURRENT DATE IN YYYY-MM-DD FORMAT
 * Returns today's date for attendance record creation
 */
function today() {
  return new Date().toLocaleDateString('en-CA');
}

/**
 * GET CURRENT TIME IN HH:MM FORMAT
 * Returns current time for attendance timestamps
 */
function nowHHMM() {
  return new Date().toLocaleTimeString('en-GB', { hour12: false }).slice(0, 5);
}

/**
 * BUILD FORM DATA FROM OBJECT
 * Creates FormData object for POST requests to PHP backend
 */
function buildFormData(obj) {
  const fd = new FormData();
  Object.entries(obj).forEach(([k, v]) => fd.append(k, v));
  return fd;
}

/**
 * COMPARE TWO TIME STRINGS IN HH:MM FORMAT
 * Returns negative if time1 < time2, positive if time1 > time2, 0 if equal
 */
function compareTimesHHMM(time1, time2) {
  const t1 = time1.split(':').map(Number);
  const t2 = time2.split(':').map(Number);
  const minutes1 = t1[0] * 60 + t1[1];
  const minutes2 = t2[0] * 60 + t2[1];
  return minutes1 - minutes2;
}

/**
 * RECORD ATTENDANCE USING EXISTING SYSTEM LOGIC
 * Integrates with the main attendance module's autoRecordAttendance function
 * Handles time-in, time-out, undertime, and leave validation
 */
async function recordScan(code, mode) {
  try {
    const employeeId = parseInt(code, 10);
    if (!employeeId || employeeId <= 0) {
      return { ok: false, error: 'Invalid employee ID' };
    }

    const date = today();
    const nowTime = nowHHMM();
    
    // Define shift constants (matching attendance module)
    const SHIFT_START = '08:00';
    const SHIFT_END = '20:00';
    const TIME_OUT_END = '20:30';
    
    const isLate = compareTimesHHMM(nowTime, SHIFT_START) > 0;
    const statusVal = isLate ? 'late' : 'present';

    // Check if employee is on approved leave today
    try {
      const leaveRes = await axios.get(`${CONFIG.baseApiUrl}/leaves.php`, {
        params: {
          operation: 'getLeaves',
          employee_id: employeeId,
          start_date: date,
          end_date: date,
          status: 'approved'
        }
      });
      const leaves = Array.isArray(leaveRes.data) ? leaveRes.data : [];
      if (leaves.length > 0) {
        return { ok: false, error: 'You are on leave today, so you cannot record attendance.' };
      }
    } catch (e) {
      // Continue if leave check fails
    }

    // Check for approved undertime
    let approvedUT = null;
    try {
      const utRes = await axios.get(`${CONFIG.baseApiUrl}/undertime.php`, {
        params: {
          operation: 'listAll',
          employee_id: employeeId,
          status: 'approved',
          start_date: date,
          end_date: date
        }
      });
      const list = Array.isArray(utRes.data) ? utRes.data : [];
      approvedUT = list.length ? list[0] : null;
    } catch (e) {
      // Continue if undertime check fails
    }

    // Check existing attendance record for today
    const listRes = await axios.get(`${CONFIG.baseApiUrl}/attendance.php`, {
      params: {
        operation: 'getAttendance',
        start_date: date,
        end_date: date
      }
    });
    const rows = Array.isArray(listRes.data) ? listRes.data : [];
    const row = rows.find(r => String(r.employee_id) === String(employeeId));

    // Handle different scenarios based on attendance mode and existing records
    if (!row || !row.time_in) {
      // Time-in scenario
      if (mode === 'time_out' || mode === 'break_in' || mode === 'break_out') {
        return { ok: false, error: 'No time-in record found. Please scan for time-in first.' };
      }

      // Check if it's too late to time in (after 8:00 PM)
      if (compareTimesHHMM(nowTime, SHIFT_END) >= 0) {
        return { ok: false, error: 'Time-in not allowed after 8:00 PM. You are marked as absent.' };
      }

      // Record time-in
      const payload = {
        employee_id: employeeId,
        attendance_date: date,
        status: statusVal,
        time_in: nowTime,
        time_out: null,
        remarks: ''
      };

      const res = await axios.post(`${CONFIG.baseApiUrl}/attendance.php`, 
        buildFormData({ operation: 'recordAttendance', json: JSON.stringify(payload) })
      );
      
      const success = String(res.data) === '1' || res.data === 1 || (res.data && res.data.success === 1);
      if (success) {
        return { 
          ok: true, 
          data: { 
            action: 'time_in',
            message: isLate ? 'Time in recorded (late)' : 'Time in recorded',
            time: nowTime
          }
        };
      } else {
        return { ok: false, error: 'Failed to record time-in' };
      }
    }

    // Handle time-out scenario
    if (!row.time_out) {
      if (mode === 'time_in') {
        return { ok: false, error: 'Already timed in. Next scan should be for time-out.' };
      }

      // Handle approved undertime
      if (approvedUT) {
        const utEndTime = approvedUT.end_time || '17:00'; // Default undertime end
        const upd = {
          attendance_id: row.attendance_id,
          employee_id: employeeId,
          attendance_date: date,
          status: 'undertime',
          time_in: row.time_in,
          time_out: utEndTime,
          remarks: row.remarks || 'Auto from approved undertime'
        };
        
        await axios.post(`${CONFIG.baseApiUrl}/attendance.php`,
          buildFormData({ operation: 'updateAttendance', json: JSON.stringify(upd) })
        );
        
        return {
          ok: true,
          data: {
            action: 'time_out',
            message: `Undertime recorded. Time out set to ${utEndTime}`,
            time: utEndTime
          }
        };
      }

      // Emergency early-out before 8:00 PM (limit 3 per day)
      if (compareTimesHHMM(nowTime, SHIFT_END) < 0) {
        const prevRemarks = row.remarks || '';
        const usedCount = ((prevRemarks.match(/\[emergency_scan_used\b/gi) || []).length) | 0;
        if (usedCount >= 3) {
          return { ok: false, error: 'Daily scan limit reached (3) for undertime emergencies.' };
        }
        const upd2 = {
          attendance_id: row.attendance_id,
          employee_id: employeeId,
          attendance_date: date,
          status: 'undertime',
          time_in: row.time_in,
          time_out: nowTime,
          remarks: (prevRemarks ? (prevRemarks + ' ') : '') + `[emergency_scan_used ${nowTime}]`
        };
        await axios.post(`${CONFIG.baseApiUrl}/attendance.php`,
          buildFormData({ operation: 'updateAttendance', json: JSON.stringify(upd2) })
        );
        return {
          ok: true,
          data: {
            action: 'emergency',
            message: 'Emergency scan recorded. Status set to Undertime',
            time: nowTime
          }
        };
      }

      // Disallow time-out after 8:30 PM
      if (compareTimesHHMM(nowTime, TIME_OUT_END) > 0) {
        return { 
          ok: false, 
          error: 'Please contact the admin to reopen the QR code scanner.' 
        };
      }

      // Record normal time-out (8:00–8:30 PM) and preserve existing status (late remains late)
      const upd = {
        attendance_id: row.attendance_id,
        employee_id: employeeId,
        attendance_date: date,
        status: row.status || 'present',
        time_in: row.time_in,
        time_out: nowTime,
        remarks: row.remarks || ''
      };

      await axios.post(`${CONFIG.baseApiUrl}/attendance.php`,
        buildFormData({ operation: 'updateAttendance', json: JSON.stringify(upd) })
      );

      return {
        ok: true,
        data: {
          action: 'time_out',
          message: 'Time out recorded',
          time: nowTime
        }
      };
    }

    // Time-in and time-out already recorded
    // Allow resume before 8:00 PM if an emergency early-out was used
    try {
      const prevRemarks = row.remarks || '';
      const usedCount = ((prevRemarks.match(/\[emergency_scan_used\b/gi) || []).length) | 0;
      if (compareTimesHHMM(nowTime, SHIFT_END) < 0 && usedCount > 0) {
        const statusBack = compareTimesHHMM(row.time_in || nowTime, SHIFT_START) > 0 ? 'late' : 'present';
        const upd3 = {
          attendance_id: row.attendance_id,
          employee_id: employeeId,
          attendance_date: date,
          status: statusBack,
          time_in: row.time_in,
          time_out: null,
          remarks: (prevRemarks ? (prevRemarks + ' ') : '') + `[resume_scan ${nowTime}]`
        };
        await axios.post(`${CONFIG.baseApiUrl}/attendance.php`,
          buildFormData({ operation: 'updateAttendance', json: JSON.stringify(upd3) })
        );
        return {
          ok: true,
          data: {
            action: 'resume',
            message: 'Resumed.',
            time: nowTime
          }
        };
      }
    } catch (e) {}

    // Otherwise, already completed
    return {
      ok: true,
      data: {
        action: 'complete',
        message: 'Attendance already completed for today',
        time: nowTime
      }
    };

  } catch (err) {
    let message = 'Request failed';
    if (err.response) {
      const data = err.response.data;
      message = (data && (data.error || data.message)) ? (data.error || data.message) : ('HTTP ' + err.response.status);
    } else if (err.request) {
      message = 'No response from server';
    } else if (err.message) {
      message = err.message;
    }
    return { ok: false, error: message };
  }
}

/**
 * ADD SCAN TO RECENT ACTIVITY LOG
 * Displays scan result in UI with timestamp and status
 * Color-codes entries based on success/failure status
 */
function addRecentScan({ code, mode, ok, message }) {
  const wrap = document.getElementById('recentScans');
  if (!wrap) return;
  const time = new Date().toLocaleTimeString();
  const row = document.createElement('div');
  row.className = 'p-2 rounded border ' + (ok ? 'bg-green-50 border-green-200 text-green-800' : 'bg-red-50 border-red-200 text-red-800');
  row.innerHTML = `<div class="flex items-center justify-between gap-2">
    <div class="text-xs">${time}</div>
    <div class="text-[11px] px-2 py-[2px] rounded bg-gray-100 text-gray-700 border">${mode}</div>
  </div>
  <div class="font-mono text-sm break-all">${code}</div>
  <div class="text-xs opacity-80">${message || ''}</div>`;
  wrap.prepend(row);
}

/**
 * HANDLE QR CODE SCAN EVENT
 * Processes scanned QR code, prevents duplicates, and records attendance
 * Provides audio/visual feedback and updates recent scan history
 */
async function handleScan(rawText) {
  const now = Date.now();
  if (lastScan.code === rawText && now - lastScan.ts < 5000) {
    return; // ignore duplicate within 5s
  }
  lastScan.code = rawText;
  lastScan.ts = now;

  const parsed = parsePayload(rawText);
  const code = parsed.employee_code;
  const mode = getMode();
  
  if (!code) {
    addRecentScan({ code: rawText, mode, ok: false, message: 'Invalid/empty payload' });
    setStatus('Invalid payload scanned', 'text-red-600');
    beep(150, 240);
    return;
  }

  // Try to get employee name for better feedback
  let empName = '';
  try {
    const res = await axios.get(`${CONFIG.baseApiUrl}/employees.php`, {
      params: { operation: 'getEmployee', employee_id: code }
    });
    const emp = res.data || {};
    empName = `${emp.first_name || ''} ${emp.last_name || ''}`.trim();
    if (!empName) empName = `Employee #${code}`;
  } catch (e) {
    empName = `Employee #${code}`;
  }

  setStatus(`Processing scan for ${empName}...`, 'text-blue-600');
  
  const result = await recordScan(code, mode);
  
  if (result.ok) {
    const data = result.data || {};
    const action = data.action || 'recorded';
    const message = data.message || 'Recorded successfully';
    
    let statusColor = 'text-green-700';
    let beepType = [120, 880]; // success beep
    
    if (action === 'time_in') {
      statusColor = message.includes('late') ? 'text-amber-600' : 'text-green-700';
    } else if (action === 'complete') {
      statusColor = 'text-blue-600';
      beepType = [100, 660]; // info beep
    }
    
    setStatus(`${empName}: ${message}`, statusColor);
    addRecentScan({ 
      code: empName, 
      mode: action === 'auto' ? 'auto' : action.replace('_', ' '), 
      ok: true, 
      message: message 
    });
    beep(beepType[0], beepType[1]);
    
  } else {
    const errorMsg = result.error || 'Unknown error';
    setStatus(`${empName}: ${errorMsg}`, 'text-red-700');
    addRecentScan({ 
      code: empName, 
      mode: mode === 'auto' ? 'auto' : mode.replace('_', ' '), 
      ok: false, 
      message: errorMsg 
    });
    beep(180, 280); // error beep
  }
}

async function populateCameras() {
  try {
    const devices = await Html5Qrcode.getCameras();
    if (!devices || !devices.length) {
      setStatus('No camera devices were detected.', 'text-red-600');
      return;
    }
    // Prefer back camera if available, otherwise use first camera
    const back = devices.find(d => /back|rear|environment/i.test(d.label));
    currentCameraId = back?.id || devices[0].id;
  } catch (e) {
    setStatus('Unable to enumerate cameras: ' + e, 'text-red-600');
  }
}

async function startScanner() {
  if (isScanning) return;

  // Ensure library available
  if (typeof window.Html5Qrcode === 'undefined') {
    setStatus('Scanner library not loaded. Check network/CDN.', 'text-red-700');
    if (window.Swal) Swal.fire({ icon: 'error', title: 'Library Error', text: 'html5-qrcode is not available.' });
    return;
  }

  // Ensure container exists
  const containerEl = document.getElementById('qr-reader');
  if (!containerEl) {
    setStatus('Scanner container #qr-reader not found in DOM.', 'text-red-700');
    if (window.Swal) Swal.fire({ icon: 'error', title: 'Container Missing', text: '#qr-reader element was not found on the page.' });
    return;
  }

  try {
    if (!html5QrCode) {
      html5QrCode = new Html5Qrcode('qr-reader');
    }
    let cameraConfig = currentCameraId;
    if (!cameraConfig) {
      // Try default back camera via facingMode fallback
      cameraConfig = { facingMode: { exact: 'environment' } };
    }
    
    // Fullscreen scanner configuration - uses entire viewport without frame
    const scannerConfig = {
      fps: 15,
      qrbox: function(viewfinderWidth, viewfinderHeight) {
        // Use maximum possible scanning area for fullscreen experience
        const scanWidth = Math.min(viewfinderWidth * 0.9, 800);
        const scanHeight = Math.min(viewfinderHeight * 0.9, 1800);
        return { width: scanWidth, height: scanHeight };
      },
      aspectRatio: viewfinderWidth => viewfinderWidth, // Use full viewport aspect ratio
      rememberLastUsedCamera: true
    };
    
    await html5QrCode.start(
      cameraConfig,
      scannerConfig,
      (decodedText) => handleScan(decodedText),
      (errorMessage) => { /* throttled errors are fine to ignore */ }
    );
    isScanning = true;
    setStatus('Scanning... Show a QR/barcode to the camera.', 'text-green-700');
  } catch (e) {
    // Retry with relaxed facingMode and ensure scanner instance exists
    try {
      if (!html5QrCode) {
        html5QrCode = new Html5Qrcode('qr-reader');
      }
      await html5QrCode.start(
        { facingMode: 'environment' },
        {
          fps: 15,
          qrbox: function(viewfinderWidth, viewfinderHeight) {
            const scanWidth = Math.min(viewfinderWidth * 0.9, 600);
            const scanHeight = Math.min(viewfinderHeight * 0.9, 600);
            return { width: scanWidth, height: scanHeight };
          },
          aspectRatio: viewfinderWidth => viewfinderWidth
        },
        (decodedText) => handleScan(decodedText),
        (errorMessage) => { /* ignore */ }
      );
      isScanning = true;
      setStatus('Scanning... Show a QR/barcode to the camera.', 'text-green-700');
      return;
    } catch (e2) {
      setStatus('Failed to start camera: ' + e2, 'text-red-700');
      if (window.Swal) Swal.fire({ icon: 'error', title: 'Camera Error', text: String(e2 || 'Unable to access camera') });
    }
  }
}

async function stopScanner() {
  if (!isScanning || !html5QrCode) return;
  try {
    await html5QrCode.stop();
    await html5QrCode.clear();
  } catch (e) { /* ignore */ }
  isScanning = false;
  setStatus('Scanner stopped.');
}

// Initialize once DOM is ready
window.addEventListener('DOMContentLoaded', () => {
  // Cache elements
  scanStatusEl = document.getElementById('scanStatus');

  // Set base API URL to match the project structure
  if (!CONFIG.baseApiUrl) {
    CONFIG.baseApiUrl = `${window.location.origin}/intro/api`;
  }

  if (!window.isSecureContext) {
    setStatus('Camera access requires HTTPS or localhost. Open via http://localhost/...', 'text-red-700');
    if (window.Swal) Swal.fire({ icon: 'warning', title: 'Insecure Context', text: 'Use http://localhost/... or HTTPS to enable camera access.' });
  }

  // Auto-start scanning
  (async () => {
    try { 
      await ensureQrScanLib(); 
      await populateCameras();
      // Auto-start the scanner immediately
      setStatus('Starting scanner...', 'text-blue-600');
      await startScanner();
    } catch (e) {
      setStatus('Failed to initialize scanner', 'text-red-700');
    }
  })();
});
