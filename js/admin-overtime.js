/**
 * ADMIN OVERTIME MANAGEMENT SYSTEM
 * Comprehensive overtime tracking with QR code scanning capabilities
 * Handles overtime requests, approvals, and time recording
 */
(function(){
  const baseApiUrl = window.baseApiUrl || `${location.origin}/intro/api`;
  /**
   * QR SCANNER STATE MANAGEMENT
   * Maintains scanner instance and prevents duplicate scans
   */
  let qrScanner = null;
  let isScanning = false;
  // Continuous scan throttling (match attendance behavior)
  let scanningBusy = false;
  let lastDecodedText = '';
  let lastScanTime = 0;
  let qrShutdownTimer = null;

  /**
   * ENSURE QR SCANNING LIBRARY IS LOADED
   * Dynamically loads HTML5 QR code library for scanner functionality
   */
  async function ensureQrScanLib(){
    if (window.Html5Qrcode) return;
    await new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://unpkg.com/html5-qrcode';
      s.onload = resolve; s.onerror = reject;
      document.head.appendChild(s);
    });
  }

  /**
   * DISPLAY FEEDBACK MESSAGE WITH STYLING
   * Shows colored feedback messages for user actions
   * Supports success, error, warning, and info types
   */
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

  /**
   * GET TODAY'S DATE IN YYYY-MM-DD FORMAT
   * Returns current date string for date comparisons
   */
  function today(){
    const d = new Date();
    const y = d.getFullYear();
    const m = String(d.getMonth()+1).padStart(2,'0');
    const day = String(d.getDate()).padStart(2,'0');
    return `${y}-${m}-${day}`;
  }
  /**
   * GET CURRENT TIME IN HH:MM FORMAT
   * Returns current time string for time inputs
   */
  function nowHHMM(){
    const d = new Date();
    const hh = String(d.getHours()).padStart(2,'0');
    const mm = String(d.getMinutes()).padStart(2,'0');
    return `${hh}:${mm}`;
  }

  /**
   * COMPARE TWO TIMES IN HH:MM FORMAT
   * Returns -1, 0, or 1 for time comparison
   * Used for validating time ranges
   */
  function compareTimesHHMM(a, b){
    try {
      const [ah, am] = String(a||'').split(':').map(Number);
      const [bh, bm] = String(b||'').split(':').map(Number);
      const at = (ah||0)*60 + (am||0);
      const bt = (bh||0)*60 + (bm||0);
      return at === bt ? 0 : (at > bt ? 1 : -1);
    } catch { return 0; }
  }

  function capitalizeWords(str){
    if (!str) return '';
    return String(str).split(' ').map(w => w ? (w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()) : '').join(' ');
  }

  function formatDate(dateStr){
    if (!dateStr) return '';
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return String(dateStr);
      return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch { return String(dateStr || ''); }
  }

  function formatTimeOfDay(timeStr){
    if (!timeStr) return '';
    try {
      const parts = String(timeStr).split(':');
      if (parts.length < 2) return String(timeStr);
      let h = parseInt(parts[0], 10);
      const m = parseInt(parts[1], 10) || 0;
      if (!Number.isFinite(h)) return String(timeStr);
      const ampm = h >= 12 ? 'PM' : 'AM';
      h = h % 12; if (h === 0) h = 12;
      const mm = String(m).padStart(2,'0');
      return `${h}:${mm} ${ampm}`;
    } catch { return String(timeStr || ''); }
  }

  /**
   * GET STATUS BADGE CSS CLASS
   * Returns appropriate styling for overtime status display
   * Handles approval workflow and completion states
   */
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

  /**
   * CHECK FOR APPROVED OVERTIME TODAY
   * Verifies if employee has approved overtime for current date
   * Used to validate overtime recording eligibility
   */
  async function hasApprovedOvertimeForToday(employeeId){
    try {
      const res = await axios.get(`${baseApiUrl}/overtime.php`, { params: { operation: 'listApproved' } });
      const rows = Array.isArray(res.data) ? res.data : [];
      const t = today();
      return rows.some(r => String(r.employee_id) === String(employeeId)
        && String(r.work_date) === String(t)
        && /^(approved|approve)$/i.test(String(r.status || '')));
    } catch { return false; }
  }

  /**
   * CALCULATE DURATION BETWEEN TWO TIMES
   * Computes time difference and formats as hours/minutes
   * Handles overnight spans and edge cases
   */
  function calcDurationStr(start, end){
    try {
      const toMinutes = (t) => {
        const parts = String(t).split(':').map(n => parseInt(n,10));
        const h = parts[0] || 0, m = parts[1] || 0, s = parts[2] || 0;
        let total = h*60 + m + Math.round(s/60);
        return Number.isFinite(total) ? total : NaN;
      };
      let a = toMinutes(start), b = toMinutes(end);
      if (!Number.isFinite(a) || !Number.isFinite(b)) return '-';
      if (b < a) b += 24*60;
      const diff = b - a;
      if (diff < 0) return '-';
      const hh = Math.floor(diff/60);
      const mm = diff % 60;
      return `${hh}h ${mm}m`;
    } catch { return '-'; }
  }

  function formatHoursMinutesFromHours(hrs){
    const n = Number(hrs);
    if (!Number.isFinite(n) || n < 0) return '-';
    const totalMinutes = Math.round(n * 60);
    const h = Math.floor(totalMinutes / 60);
    const m = totalMinutes % 60;
    return `${h}h ${m}m`;
  }

  /**
   * PARSE EMPLOYEE ID FROM QR CODE TEXT
   * Extracts employee ID from various QR code formats
   * Supports EMP#### patterns and numeric IDs
   */
  function parseEmployeeIdFromText(text){
    try {
      const s = String(text || '').trim();
      const m = s.match(/EMP(\d{4})-(\d{3,})/i);
      if (m && m[2]) {
        const n = Number(m[2]);
        if (Number.isFinite(n) && n > 0) return n;
      }
      const n2 = Number(s);
      if (Number.isFinite(n2) && n2 > 0) return n2;
      return null;
    } catch { return null; }
  }

  function buildFormData(map){ const fd = new FormData(); Object.entries(map).forEach(([k,v])=>fd.append(k,v)); return fd; }

  /**
   * LOG OVERTIME SCAN VIA QR CODE
   * Records overtime time in/out via QR code scanning
   * Provides feedback and refreshes overtime table
   */
  async function logOvertimeScan(employeeId, feedbackId = 'qr-feedback-ot'){
    const feedback = document.getElementById(feedbackId);
    try {
      const work_date = today();
      const res = await axios.post(`${baseApiUrl}/overtime.php`, buildFormData({ operation: 'logScan', json: JSON.stringify({ employee_id: employeeId, work_date }) }));
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
      // Refresh table after successful scan
      try { await fetchApprovedOvertime(); } catch {}
    } catch (e) {
      if (feedback) setFeedback(feedback, 'error', 'Failed to record overtime.');
    }
  }

  /**
   * ENSURE QR OVERTIME SCANNER MODAL EXISTS
   * Creates QR scanner modal if not already present
   * Provides scanning interface for overtime recording
   */
  function ensureQrOtModal(){
    if (document.getElementById('qrOtModal')) return;
    const modal = document.createElement('div');
    modal.id = 'qrOtModal';
    modal.className = 'fixed inset-0 z-50 hidden';
    modal.innerHTML = `
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
      </div>`;
    document.body.appendChild(modal);
    modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', async () => { await stopScanner(); modal.classList.add('hidden'); }));
    const stopBtn = modal.querySelector('#qr-stop-ot');
    const resumeBtn = modal.querySelector('#qr-resume-ot');
    if (stopBtn) stopBtn.addEventListener('click', async () => { await stopScanner(); });
    if (resumeBtn) resumeBtn.addEventListener('click', async () => {
      resumeBtn.classList.add('hidden');
      await startScannerInto('qr-reader-ot', 'qr-feedback-ot', 'qr-resume-ot');
    });
  }

  async function startScannerInto(readerId, feedbackId, resumeBtnId){
    const feedback = document.getElementById(feedbackId);
    try {
      await ensureQrScanLib();
      if (!window.Html5Qrcode) { if (feedback) setFeedback(feedback, 'error', 'Scanner library failed to load.'); return; }
      if (qrScanner) { try { await qrScanner.stop(); qrScanner.clear(); } catch {} }
      qrScanner = new window.Html5Qrcode(readerId);
      isScanning = true;
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
          // Require approved overtime request for today and restrict to 8:30 PM–10:00 PM
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
          
          // Continuous standby: throttle duplicate scans and keep camera running
          const nowTs = Date.now();
          if (scanningBusy) return;
          if (decodedText === lastDecodedText && (nowTs - lastScanTime) < 1500) return;
          scanningBusy = true;
          lastDecodedText = decodedText;
          lastScanTime = nowTs;
          await logOvertimeScan(eid, feedbackId);
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
          await stopScanner('Scanner closed. Please contact HR or Admin to open again.', 'warning', true);
          return;
        }
        if (qrShutdownTimer) { clearInterval(qrShutdownTimer); qrShutdownTimer = null; }
        qrShutdownTimer = setInterval(async () => {
          try {
            if (compareTimesHHMM(nowHHMM(), '22:01') >= 0) {
              try { alert('Scanner closed. Please contact HR or Admin to open again.'); } catch {}
              await stopScanner('Scanner closed. Please contact HR or Admin to open again.', 'warning', true);
            }
          } catch {}
        }, 10000);
      } catch {}
    } catch (e) {
      if (feedback) setFeedback(feedback, 'error', 'Camera permission denied or unavailable.');
    }
  }

  async function stopScanner(message, type = 'info', hideModal = false){
    const fb = document.getElementById('qr-feedback-ot');
    try {
      if (qrScanner) { await qrScanner.stop(); qrScanner.clear(); }
      isScanning = false;
      if (fb) setFeedback(fb, type, message || 'Scanner stopped.');
      if (qrShutdownTimer) { try { clearInterval(qrShutdownTimer); } catch {}; qrShutdownTimer = null; }
      if (hideModal) { try { const modal = document.getElementById('qrOtModal'); if (modal) modal.classList.add('hidden'); } catch {} }
    } catch {}
  }

  // -------------------- Edit/Record Overtime Modal --------------------
  async function loadEmployeesSelect(selectedId){
    if (employeesCache.length === 0){
      try {
        const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
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

  function resetOtForm(){
    const d = document.getElementById('ot-date'); if (d) d.value = '';
    const si = document.getElementById('ot-start'); if (si) si.value = '';
    const so = document.getElementById('ot-end'); if (so) so.value = '';
    const r = document.getElementById('ot-reason'); if (r) r.value = '';
    const s = document.getElementById('ot-emp-search'); if (s) s.value = '';
  }

  function ensureOtModal(){
    if (document.getElementById('otModal')) return;
    const modal = document.createElement('div');
    modal.id = 'otModal';
    modal.className = 'fixed inset-0 z-50 hidden';
    modal.innerHTML = `
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
      </div>`;
    document.body.appendChild(modal);
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
          const start_time = document.getElementById('ot-start')?.value || '';
          const end_time = document.getElementById('ot-end')?.value || '';
          fd.append('json', JSON.stringify({ ot_id: otEditContext.ot_id, employee_id, work_date, start_time, end_time, reason }));
          await axios.post(`${baseApiUrl}/overtime.php`, fd);
          alert('Overtime updated. Time In/Out will be recorded via QR after approval.');
        } else {
          const fd = new FormData();
          fd.append('operation', 'requestOvertime');
          fd.append('json', JSON.stringify({ employee_id, work_date, reason }));
          await axios.post(`${baseApiUrl}/overtime.php`, fd);
          alert('Overtime request submitted (pending). Employee must scan to record overtime.');
        }
        close();
        await fetchApprovedOvertime();
      } catch (e){
        alert('Failed to save overtime');
      }
    });
  }

  // -------------------- Overtime table rendering --------------------
  let otRows = [];
  let otPage = 1;
  let otEditContext = null;
  let employeesCache = [];

  function getPageSize(){
    const sel = document.getElementById('ot-page-size');
    const n = sel ? parseInt(sel.value, 10) : 10;
    return Number.isFinite(n) && n > 0 ? n : 10;
  }

  function getFilterTerm(){
    const inp = document.getElementById('ot-filter-emp');
    return (inp && inp.value ? String(inp.value) : '').trim().toLowerCase();
  }
  function getFilterDept(){
    const sel = document.getElementById('ot-filter-dept');
    return (sel && sel.value ? String(sel.value) : '').trim().toLowerCase();
  }
  function getFilterDate(){
    const el = document.getElementById('ot-filter-date');
    return el && el.value ? String(el.value) : '';
  }

  function filterRows(rows){
    const term = getFilterTerm();
    const dept = getFilterDept();
    const dsel = getFilterDate();
    return rows.filter(r => {
      const name = `${r.first_name || ''} ${r.last_name || ''}`.toLowerCase();
      const idStr = String(r.employee_id || r.employeeId || '').toLowerCase();
      const empMatch = term === '' ? true : (name.includes(term) || idStr.includes(term));
      if (!empMatch) return false;
      if (dsel) {
        const w = String(r.work_date || '').slice(0,10);
        if (w !== dsel) return false;
      }
      if (dept === '') return true;
      // department might not be included in OT rows; join via employeesCache if needed
      const rowDept = (r.department || '').toLowerCase();
      if (rowDept) return rowDept === dept;
      const emp = employeesCache.find(e => String(e.employee_id) === String(r.employee_id));
      const empDept = emp && emp.department ? String(emp.department).toLowerCase() : '';
      return empDept === dept;
    });
  }

  function renderPagination(total){
    const pag = document.getElementById('ot-pagination');
    if (!pag) return;
    const pageSize = getPageSize();
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (otPage > totalPages) otPage = totalPages;
    const start = total === 0 ? 0 : (otPage - 1) * pageSize + 1;
    const end = Math.min(total, otPage * pageSize);
    pag.innerHTML = `
      <div>Showing ${start}-${end} of ${total}</div>
      <div class="flex items-center gap-2">
        <button id="ot-prev" class="px-2 py-1 border rounded text-sm" ${otPage<=1?'disabled':''}>Prev</button>
        <span class="text-sm">Page ${otPage} / ${totalPages}</span>
        <button id="ot-next" class="px-2 py-1 border rounded text-sm" ${otPage>=totalPages?'disabled':''}>Next</button>
      </div>`;
    const prev = document.getElementById('ot-prev');
    const next = document.getElementById('ot-next');
    if (prev) prev.onclick = () => { if (otPage>1){ otPage--; renderTable(); } };
    if (next) next.onclick = () => { if (otPage<totalPages){ otPage++; renderTable(); } };
  }

  async function editOtRow(row){
    ensureOtModal();
    const modal = document.getElementById('otModal');
    if (modal) { try { const title = modal.querySelector('h5'); if (title) title.textContent = 'Edit Overtime'; const save = modal.querySelector('#ot-save'); if (save) save.textContent = 'Update'; } catch {} }
    otEditContext = { ot_id: row.ot_id || row.id };
    await loadEmployeesSelect(row.employee_id);
    // Ensure Time In/Out inputs exist for edit mode
    try {
      const form = modal.querySelector('#ot-form');
      const dateEl = document.getElementById('ot-date');
      if (form && dateEl && !document.getElementById('ot-start')) {
        const timeOutDiv = document.createElement('div');
        timeOutDiv.innerHTML = '<label class="block text-sm text-gray-600 mb-1">Time Out<\/label><input type="time" id="ot-end" class="w-full border rounded px-3 py-2" />';
        const timeInDiv = document.createElement('div');
        timeInDiv.innerHTML = '<label class="block text-sm text-gray-600 mb-1">Time In<\/label><input type="time" id="ot-start" class="w-full border rounded px-3 py-2" />';
        dateEl.parentElement.insertAdjacentElement('afterend', timeOutDiv);
        timeOutDiv.insertAdjacentElement('afterend', timeInDiv);
      }
    } catch {}
    const d = document.getElementById('ot-date'); if (d) d.value = row.work_date || '';
    const si = document.getElementById('ot-start'); if (si) si.value = row.start_time || '';
    const so = document.getElementById('ot-end'); if (so) so.value = row.end_time || '';
    const rzn = document.getElementById('ot-reason'); if (rzn) rzn.value = row.reason || '';
    const sel = document.getElementById('ot-emp'); if (sel) sel.value = String(row.employee_id || '');
    const sInp = document.getElementById('ot-emp-search'); if (sInp) sInp.value = '';
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
      await axios.post(`${baseApiUrl}/overtime.php`, fd);
    } catch {}
    await fetchApprovedOvertime();
  }

  function closeOtFloatingMenu(){
    const m = document.getElementById('ot-floating-menu');
    if (m) m.remove();
    document.removeEventListener('scroll', closeOtFloatingMenu, true);
    window.removeEventListener('resize', closeOtFloatingMenu, true);
  }

  function openOtFloatingMenu(btn, row){
    closeOtFloatingMenu();
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
    const onDocClick = (ev) => {
      if (menu && !menu.contains(ev.target) && ev.target !== btn) closeOtFloatingMenu();
    };
    setTimeout(() => document.addEventListener('click', onDocClick, { once: true }), 0);
    document.addEventListener('scroll', closeOtFloatingMenu, true);
    window.addEventListener('resize', closeOtFloatingMenu, true);

    const eBtn = menu.querySelector('[data-float-action="edit"]');
    const dBtn = menu.querySelector('[data-float-action="delete"]');
    if (eBtn) eBtn.addEventListener('click', async () => { closeOtFloatingMenu(); await editOtRow(row); });
    if (dBtn) dBtn.addEventListener('click', async () => { closeOtFloatingMenu(); await deleteOtRow(row); });
  }

  function renderTable(){
    const tbody = document.getElementById('ot-tbody');
    if (!tbody) return;
    const rows = filterRows(otRows);
    const pageSize = getPageSize();
    const startIdx = (otPage - 1) * pageSize;
    const pageRows = rows.slice(startIdx, startIdx + pageSize);
    if (!pageRows.length) {
      tbody.innerHTML = `<tr><td colspan="10" class="px-3 py-6 text-sm text-center text-gray-500">No overtime recorded</td></tr>`;
    } else {
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
          if (r.start_time && r.end_time) {
            const effEnd = compareTimesHHMM(r.end_time, '22:00') > 0 ? '22:00' : r.end_time;
            return calcDurationStr(r.start_time, effEnd);
          }
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
            <div class="relative inline-block text-left" data-ot-menu-container data-idx="${idx}">
              <button class="inline-flex items-center justify-center w-8 h-8 rounded hover:bg-gray-100" aria-label="Actions" data-action="menu-toggle">
                <span class="text-gray-600 font-bold text-lg">•••</span>
              </button>
              <div class="hidden origin-top-right absolute right-0 mt-2 w-36 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 z-10" role="menu" data-menu>
                <div class="py-1">
                  <button class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50" data-menu-action="edit" data-idx="${idx}" role="menuitem">Edit</button>
                  <button class="w-full text-left px-3 py-2 text-sm text-red-600 hover:bg-gray-50" data-menu-action="delete" data-idx="${idx}" role="menuitem">Delete</button>
                </div>
              </div>
            </div>
          </td>
        </tr>`;
      }).join('');
    }

    // Wire per-row menu actions
    tbody.querySelectorAll('[data-ot-menu-container]').forEach((container) => {
      const idx = parseInt(container.getAttribute('data-idx'), 10);
      const menu = container.querySelector('[data-menu]');
      const toggle = container.querySelector('[data-action="menu-toggle"]');
      if (toggle) toggle.addEventListener('click', (ev) => {
        ev.preventDefault(); ev.stopPropagation();
        openOtFloatingMenu(toggle, pageRows[idx]);
      });
    });

    if (!window.__otMenuGlobalClose){
      window.__otMenuGlobalClose = true;
      document.addEventListener('click', () => {
        document.querySelectorAll('[data-ot-menu-container] [data-menu]').forEach(m => m.classList.add('hidden'));
      });
    }

    renderPagination(rows.length);
  }

  async function fetchApprovedOvertime(){
    try {
      const res = await axios.get(`${baseApiUrl}/overtime.php`, { params: { operation: 'listApproved' } });
      const data = Array.isArray(res.data) ? res.data : [];
      // Only include entries that have been recorded by a scan (have start_time)
      otRows = data.filter(r => !!r.start_time);
      otPage = 1;
      renderTable();
    } catch (e) {
      otRows = [];
      renderTable();
    }
  }

  async function populateDepartmentsDropdown(){
    try {
      const sel = document.getElementById('ot-filter-dept');
      if (!sel) return;
      const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getDepartments' } });
      const list = Array.isArray(res.data) ? res.data : [];
      const current = sel.value;
      sel.innerHTML = '<option value="">All Departments</option>' + list.map(d => `<option value="${String(d)}">${String(d)}</option>`).join('');
      // restore previous selection if still present
      if (current && list.includes(current)) sel.value = current;
    } catch {}
  }

  document.addEventListener('DOMContentLoaded', () => {
    // Ensure header columns: Employee, Reason, Date, Time In, Time Out, Total Hours, Status, Actions
    try {
      const thead = document.querySelector('table thead');
      if (thead) {
        thead.innerHTML = `
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
          </tr>`;
      }
    } catch {}
    const btn = document.getElementById('btn-qr-scan-ot');
    if (btn) btn.addEventListener('click', async () => {
      ensureQrOtModal();
      const modal = document.getElementById('qrOtModal');
      modal.classList.remove('hidden');
      try { await ensureQrScanLib(); } catch {}
      await startScannerInto('qr-reader-ot', 'qr-feedback-ot', 'qr-resume-ot');
    });

    const addBtn = document.getElementById('btn-add-ot');
    if (addBtn) addBtn.addEventListener('click', async () => {
      ensureOtModal();
      otEditContext = null;
      await loadEmployeesSelect();
      resetOtForm();
      const modal = document.getElementById('otModal');
      if (modal) { try { const title = modal.querySelector('h5'); if (title) title.textContent = 'Record Overtime'; const save = modal.querySelector('#ot-save'); if (save) save.textContent = 'Save'; } catch {} }
      modal.classList.remove('hidden');
    });

    // Initial fetch and wire up filters/pagination
    // Default date filter to today
    try { const df = document.getElementById('ot-filter-date'); if (df) df.value = today(); } catch {}

    fetchApprovedOvertime();
    populateDepartmentsDropdown();
    // Prefetch employees to allow dept join for filtering
    (async () => {
      try {
        const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
        employeesCache = Array.isArray(res.data) ? res.data : [];
        renderTable();
      } catch {
        employeesCache = [];
        renderTable();
      }
    })();

    const filterInp = document.getElementById('ot-filter-emp');
    if (filterInp) filterInp.addEventListener('input', () => { otPage = 1; renderTable(); });
    const deptSel = document.getElementById('ot-filter-dept');
    if (deptSel) deptSel.addEventListener('change', () => { otPage = 1; renderTable(); });
    const pageSel = document.getElementById('ot-page-size');
    if (pageSel) pageSel.addEventListener('change', () => { otPage = 1; renderTable(); });
    const dateSel = document.getElementById('ot-filter-date');
    if (dateSel) {
      dateSel.addEventListener('change', () => { if (!dateSel.value) { try { dateSel.value = today(); } catch {} } otPage = 1; renderTable(); });
      dateSel.addEventListener('input', () => { if (!dateSel.value) { try { dateSel.value = today(); } catch {} } otPage = 1; renderTable(); });
    }

    // Auto-refresh running totals every minute until 10:00 PM, then stop
    let __otLiveTotalsTimer = setInterval(() => {
      try {
        renderTable();
        if (compareTimesHHMM(nowHHMM(), '22:00') >= 0) {
          clearInterval(__otLiveTotalsTimer);
          __otLiveTotalsTimer = null;
        }
      } catch {}
    }, 60000);
  // Daily rollover: when day changes, reset date filter to today and refresh
    let __otDayKey = today();
    function __maybeOtRollover(){
      const d = today();
      if (d !== __otDayKey) {
        __otDayKey = d;
        const df = document.getElementById('ot-filter-date');
        if (df) df.value = d;
        otPage = 1;
        renderTable();
      }
    }
    try {
      setInterval(__maybeOtRollover, 60000);
      window.addEventListener('focus', __maybeOtRollover);
      document.addEventListener('visibilitychange', __maybeOtRollover);
    } catch {}
  });
})();