/**
 * RENDER ATTENDANCE MANAGEMENT INTERFACE
 * Main function that renders the attendance tracking interface
 * Includes employee selection, QR scanning, and attendance recording
 */
export async function render() {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h4 class="text-xl font-semibold">Attendance</h4>
      <div class="flex items-center gap-2">
        <button id="btn-qr-scan" class="inline-flex items-center px-3 py-2 text-sm font-medium rounded border text-gray-700 hover:bg-gray-50">Scan QR</button>
        <button id="btn-add-att" class="inline-flex items-center px-3 py-2 text-sm font-medium rounded bg-primary-600 text-white hover:bg-primary-700">Record Attendance</button>
      </div>
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
          <select id="att-dept-filter" class="border rounded px-2 py-1 text-sm"><option value="all" selected>All Departments</option></select>
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
    </div>

    <div id="attModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-lg">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">Record Attendance</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
          </div>
          <div class="p-4">
            <form id="att-form" class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <input type="hidden" id="attendance_id" />
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Employee</label>
                <div class="flex items-center gap-2 mb-2">
                  <div class="relative">
                    <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
                    <input id="employee_search" type="text" placeholder="Search employee by name..." class="w-44 border rounded pl-9 pr-2 py-1 text-sm" />
                  </div>
                  <select id="employee_dept_filter" class="border rounded px-2 py-1 text-sm"><option value="all" selected>All Departments</option></select>
                </div>
                <label class="inline-flex items-center gap-2 text-sm text-gray-700 mb-2">
                  <input id="employee_select_all" type="checkbox" class="rounded border-gray-300" />
                  <span>Select all</span>
                </label>
                <div id="employee_list" class="border rounded max-h-64 overflow-y-auto divide-y divide-gray-100 bg-white">
                  <div class="p-3 text-sm text-gray-500">Loading employees...</div>
                </div>
                <div class="mt-1 text-xs text-gray-500"><span id="employee_selected_count">0</span> selected</div>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Date</label>
                <input type="date" id="attendance_date" class="w-full border rounded px-3 py-2" required />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Status</label>
                <select id="status" class="w-full border rounded px-3 py-2">
                  <option value="present">Present</option>
                  <option value="late">Late</option>
                  <option value="absent">Absent</option>
                  <option value="leave">On Leave</option>
                  <option value="undertime">Undertime</option>
                </select>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Time In</label>
                <input type="time" id="time_in" class="w-full border rounded px-3 py-2" />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Time Out</label>
                <input type="time" id="time_out" class="w-full border rounded px-3 py-2" />
              </div>
                          </form>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
            <button id="save-att" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Edit Attendance Floating Card -->
    <div id="attEditModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-md">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">Edit Attendance</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
          </div>
          <div class="p-4">
            <form id="att-edit-form" class="grid grid-cols-1 gap-3">
              <input type="hidden" id="edit_attendance_id" />
              <input type="hidden" id="edit_employee_id" />
              <div>
                <label class="block text-sm text-gray-600 mb-1">Employee</label>
                <div id="edit_employee_name" class="text-sm text-gray-800"></div>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Department</label>
                <div id="edit_employee_department" class="text-sm text-gray-800"></div>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Date</label>
                <input type="date" id="edit_attendance_date" class="w-full border rounded px-3 py-2" required />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Status</label>
                <select id="edit_status" class="w-full border rounded px-3 py-2">
                  <option value="present">Present</option>
                  <option value="late">Late</option>
                  <option value="absent">Absent</option>
                  <option value="leave">On Leave</option>
                  <option value="undertime">Undertime</option>
                </select>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Time In</label>
                <input type="time" id="edit_time_in" class="w-full border rounded px-3 py-2" />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Time Out</label>
                <input type="time" id="edit_time_out" class="w-full border rounded px-3 py-2" />
              </div>
            </form>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
            <button id="save-edit-att" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
          </div>
        </div>
      </div>
    </div>`;

  const modalEl = document.getElementById('attModal');
  let qrScanner = null;
  let isScanning = false;
  // Admin continuous scan helpers
  let scanningBusy = false;
  let lastDecodedText = '';
  let lastScanTime = 0;
  const openModal = () => modalEl.classList.remove('hidden');
  const closeModal = () => { try { if (qrScanner) { qrScanner.stop().then(() => qrScanner.clear()).catch(() => {}); } } catch {} isScanning = false; modalEl.classList.add('hidden'); };
  modalEl.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeModal));

  // Edit modal controls
  const editModalEl = document.getElementById('attEditModal');
  const openEditModal = () => editModalEl.classList.remove('hidden');
  const closeEditModal = () => editModalEl.classList.add('hidden');
  if (editModalEl) editModalEl.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeEditModal));

  let employeesCache = [];
  let allAttendance = [];
  let currentQuery = '';
  let currentPage = 1;
  let pageSize = 10;
  let leavesCache = [];
  let empFiltered = [];
  const empSelected = new Set();
  let currentEditEmployeeId = null;

  /**
   * UPDATE SELECTED EMPLOYEE COUNT
   * Updates the display showing how many employees are selected
   */
  function updateSelectedCount() {
    const el = document.getElementById('employee_selected_count');
    if (el) el.textContent = String(empSelected.size);
  }

  /**
   * RENDER EMPLOYEE SELECTION LIST
   * Displays filterable list of employees with checkboxes
   * Handles select all functionality and search filtering
   */
  function renderEmployeeList() {
    const list = document.getElementById('employee_list');
    const selAll = document.getElementById('employee_select_all');
    if (!list) return;
    if (!Array.isArray(empFiltered) || empFiltered.length === 0) {
      list.innerHTML = '<div class="p-3 text-sm text-gray-500">No employees</div>';
      if (selAll) { selAll.checked = false; selAll.indeterminate = false; }
      updateSelectedCount();
      return;
    }
    list.innerHTML = empFiltered.map(e => {
      const id = String(e.employee_id);
      const checked = empSelected.has(id) ? 'checked' : '';
      const name = `${e.first_name || ''} ${e.last_name || ''}`.trim();
      return `<label class="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-gray-50">
        <input type="checkbox" class="rounded border-gray-300 emp-cb" data-id="${id}" ${checked} />
        <span class="text-sm text-gray-800">${name}</span>
      </label>`;
    }).join('');
    if (!list.__bound) {
      list.__bound = true;
      list.addEventListener('change', (ev) => {
        const t = ev.target;
        if (t && t.classList && t.classList.contains('emp-cb')) {
          const id = String(t.getAttribute('data-id') || '');
          if (t.checked) empSelected.add(id); else empSelected.delete(id);
          updateSelectedCount();
          const allIds = empFiltered.map(e => String(e.employee_id));
          const allSel = allIds.length > 0 && allIds.every(id => empSelected.has(id));
          if (selAll) {
            selAll.checked = allSel;
            selAll.indeterminate = !allSel && allIds.some(id => empSelected.has(id));
          }
        }
      });
    }
    const allIds = empFiltered.map(e => String(e.employee_id));
    const allSel = allIds.length > 0 && allIds.every(id => empSelected.has(id));
    if (selAll) {
      selAll.checked = allSel;
      selAll.indeterminate = !allSel && allIds.some(id => empSelected.has(id));
    }
    updateSelectedCount();
  }

  // Helper function to capitalize first letter of each word
  function capitalizeWords(str) {
    if (!str) return '';
    return str.split(' ').map(word => 
      word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
    ).join(' ');
  }

  // Helper function to format dates
  function formatDate(dateStr) {
    if (!dateStr) return '';
    try {
      const date = new Date(dateStr);
      if (isNaN(date.getTime())) return dateStr;
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    } catch {
      return dateStr;
    }
  }
  
  // Helper to format time as 12-hour with AM/PM (e.g., 7:30 PM)
  function formatTimeOfDay(timeStr) {
    if (!timeStr) return '';
    try {
      const parts = String(timeStr).split(':');
      if (parts.length < 2) return timeStr;
      let h = parseInt(parts[0], 10);
      const m = parseInt(parts[1], 10) || 0;
      if (!Number.isFinite(h)) return timeStr;
      const ampm = h >= 12 ? 'PM' : 'AM';
      h = h % 12;
      if (h === 0) h = 12;
      const mm = String(m).padStart(2, '0');
      return `${h}:${mm} ${ampm}`;
    } catch {
      return timeStr;
    }
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
    } catch {
      // ignore
    }
  }
  
  function today(){
    const d = new Date();
    const y = d.getFullYear();
    const m = String(d.getMonth()+1).padStart(2,'0');
    const day = String(d.getDate()).padStart(2,'0');
    return `${y}-${m}-${day}`;
  }
  function nowHHMM(){
    const d = new Date();
    const hh = String(d.getHours()).padStart(2,'0');
    const mm = String(d.getMinutes()).padStart(2,'0');
    return `${hh}:${mm}`;
  }

  function parseEmployeeIdFromText(text){
    try {
      const s = String(text || '').trim();
      // Match EMPYYYY-NNN... pattern
      const m = s.match(/EMP(\d{4})-(\d{3,})/i);
      if (m && m[2]) {
        const n = Number(m[2]);
        if (Number.isFinite(n) && n > 0) return n;
      }
      // If the entire string is just a number
      const n2 = Number(s);
      if (Number.isFinite(n2) && n2 > 0) return n2;
      return null;
    } catch { return null; }
  }

  const SHIFT_START = '08:00';
  const SHIFT_END = '20:00';
  const TIME_OUT_END = '20:30';
  function compareTimesHHMM(a, b){
    try {
      const [ah, am] = String(a || '').split(':').map(Number);
      const [bh, bm] = String(b || '').split(':').map(Number);
      const at = (ah||0)*60 + (am||0);
      const bt = (bh||0)*60 + (bm||0);
      return at === bt ? 0 : (at > bt ? 1 : -1);
    } catch { return 0; }
  }

  async function hasApprovedLeaveForDate(employeeId, date){
    try {
      // Try local cache first
      const base = Array.isArray(leavesCache) ? leavesCache : [];
      if (base.length) {
        const hit = base.some(l => String(l.employee_id) === String(employeeId)
          && String(l.status || '').toLowerCase() === 'approved'
          && String(l.start_date || '') <= date && String(l.end_date || '') >= date);
        if (hit) return true;
      }
      // Fallback to API query for the specific date overlap
      const res = await axios.get(`${window.baseApiUrl}/leaves.php`, { params: { operation: 'listApproved', start_date: date, end_date: date } });
      const rows = Array.isArray(res.data) ? res.data : [];
      return rows.some(l => String(l.employee_id) === String(employeeId));
    } catch { return false; }
  }

  function computeUtEndTime(ut, shiftEndHHMM) {
    try {
      const end = String(ut.end_time || '').trim();
      if (end) return end;
      const hours = Number(ut.hours || 0);
      if (!Number.isFinite(hours) || hours <= 0) return shiftEndHHMM;
      const [eh, em] = String(shiftEndHHMM || '20:00').split(':').map(n => parseInt(n,10));
      let total = (eh||0)*60 + (em||0) - Math.round(hours*60);
      while (total < 0) total += 24*60;
      const hh = String(Math.floor(total/60)).padStart(2,'0');
      const mm = String(total%60).padStart(2,'0');
      return `${hh}:${mm}`;
    } catch { return shiftEndHHMM; }
  }

  async function autoRecordAttendance(employeeId, feedbackId = 'qr-feedback-att'){
    const feedback = document.getElementById(feedbackId);
    try {
      const date = today();
      const nowTime = nowHHMM();
      const isLate = compareTimesHHMM(nowTime, SHIFT_START) > 0;
      const statusVal = isLate ? 'late' : 'present';

      // If employee is on approved leave today, block attendance and show leave message
      try {
        const onLeave = await hasApprovedLeaveForDate(employeeId, date);
        if (onLeave) {
          if (feedback) setFeedback(feedback, 'warning', 'You are on leave today, so you cannot record attendance.');
          return 'onleave';
        }
      } catch {}

      // Check approved undertime for today
      let approvedUT = null;
      try {
        const utRes = await axios.get(`${window.baseApiUrl}/undertime.php`, { params: { operation: 'listAll', employee_id: employeeId, status: 'approved', start_date: date, end_date: date } });
        const list = Array.isArray(utRes.data) ? utRes.data : [];
        approvedUT = list.length ? list[0] : null;
      } catch {}

      // Check existing record for today
      const listRes = await axios.get(`${window.baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date: date, end_date: date } });
      const rows = Array.isArray(listRes.data) ? listRes.data : [];
      const row = rows.find(r => String(r.employee_id) === String(employeeId));

      if (!row || !row.time_in) {
        // If approved undertime today, set status to undertime and auto time out based on request
        if (approvedUT) {
          const utEnd = computeUtEndTime(approvedUT, SHIFT_END);
          const payload = {
            employee_id: employeeId,
            attendance_date: date,
            status: 'undertime',
            time_in: (row && row.time_in) ? row.time_in : nowTime,
            time_out: utEnd,
            remarks: 'Auto from approved undertime'
          };
          if (!row) {
            const res = await axios.post(`${window.baseApiUrl}/attendance.php`, buildFormData({ operation: 'recordAttendance', json: JSON.stringify(payload) }));
            const ok = String(res.data) === '1' || res.data === 1 || (res.data && res.data.success === 1);
            if (ok) { if (feedback) setFeedback(feedback, 'success', `Undertime recorded. Time out set to ${utEnd}.`); await loadAttendance(); return 'out'; }
          } else {
            const upd = { ...payload, attendance_id: row.attendance_id };
            await axios.post(`${window.baseApiUrl}/attendance.php`, buildFormData({ operation: 'updateAttendance', json: JSON.stringify(upd) }));
            if (feedback) setFeedback(feedback, 'success', `Undertime time out recorded (${utEnd}).`); await loadAttendance(); return 'out';
          }
        }
        // After 8:00 PM, do not allow time in; mark as absent
        if (compareTimesHHMM(nowTime, SHIFT_END) >= 0) {
          if (feedback) setFeedback(feedback, 'warning', 'You are absent today.');
          return 'absent_today';
        }
        // Record time in
        const payload = { employee_id: employeeId, attendance_date: date, status: statusVal, time_in: nowTime, time_out: null, remarks: '' };
        const res = await axios.post(`${window.baseApiUrl}/attendance.php`, buildFormData({ operation: 'recordAttendance', json: JSON.stringify(payload) }));
        const inserted = String(res.data) === '1' || res.data === 1 || (res.data && res.data.success === 1);
        if (inserted) {
          if (feedback) setFeedback(feedback, isLate ? 'warning' : 'success', isLate ? 'Time in recorded (late).' : 'Time in recorded.');
          await loadAttendance();
          return 'in';
        }
        // If failed unexpectedly
        if (feedback) setFeedback(feedback, 'error', 'Failed to record attendance.');
        return 'error';
      }

      // Already has time_in
      if (!row.time_out) {
        // If approved undertime, auto time out to the request's end time regardless of current time
        if (approvedUT) {
          const utEnd = computeUtEndTime(approvedUT, SHIFT_END);
          const upd = { attendance_id: row.attendance_id, employee_id: employeeId, attendance_date: date, status: 'undertime', time_in: row.time_in || null, time_out: utEnd, remarks: row.remarks || 'Auto from approved undertime' };
          await axios.post(`${window.baseApiUrl}/attendance.php`, buildFormData({ operation: 'updateAttendance', json: JSON.stringify(upd) }));
          if (feedback) setFeedback(feedback, 'success', `Undertime time out recorded (${utEnd}).`);
          await loadAttendance();
          return 'out';
        }
        // Before 8:00 PM: treat scan as emergency undertime time-out (limit 3 per day)
        if (compareTimesHHMM(nowTime, SHIFT_END) < 0) {
          const prevRemarks2 = row.remarks || '';
          const usedCount = ((prevRemarks2.match(/\[emergency_scan_used\b/gi) || []).length) | 0;
          if (usedCount >= 3) {
            if (feedback) setFeedback(feedback, 'warning', 'Daily scan limit reached (3) for undertime emergencies.');
            return 'limit';
          }
          const upd2 = { attendance_id: row.attendance_id, employee_id: employeeId, attendance_date: date, status: 'undertime', time_in: row.time_in || null, time_out: nowTime, remarks: (prevRemarks2 ? (prevRemarks2 + ' ') : '') + `[emergency_scan_used ${nowTime}]` };
          await axios.post(`${window.baseApiUrl}/attendance.php`, buildFormData({ operation: 'updateAttendance', json: JSON.stringify(upd2) }));
          if (feedback) setFeedback(feedback, 'success', 'Emergency scan recorded. Status set to Undertime.');
          await loadAttendance();
          return 'emergency';
        }
        // Disallow time out after 8:30 PM; require HR/Admin intervention
        if (compareTimesHHMM(nowTime, TIME_OUT_END) > 0) {
          if (feedback) setFeedback(feedback, 'warning', 'Please contact the admin to reopen the QR code scanner.');
          return 'timeout_closed';
        }
        // Record time out as current time
        const upd = { attendance_id: row.attendance_id, employee_id: employeeId, attendance_date: date, status: row.status || 'present', time_in: row.time_in || null, time_out: nowTime, remarks: row.remarks || '' };
        await axios.post(`${window.baseApiUrl}/attendance.php`, buildFormData({ operation: 'updateAttendance', json: JSON.stringify(upd) }));
        if (feedback) setFeedback(feedback, 'success', 'Time out recorded.');
        await loadAttendance();
        return 'out';
      }

      // If employee had an emergency undertime earlier and it's still before 8:00 PM, allow resume: set back to Present and clear time_out
      try {
        const prevRemarks3 = row.remarks || '';
        const usedCount3 = ((prevRemarks3.match(/\[emergency_scan_used\b/gi) || []).length) | 0;
        if (compareTimesHHMM(nowTime, SHIFT_END) < 0 && usedCount3 > 0) {
          const statusBack = compareTimesHHMM(row.time_in || nowTime, SHIFT_START) > 0 ? 'late' : 'present';
          const upd3 = { attendance_id: row.attendance_id, employee_id: employeeId, attendance_date: date, status: statusBack, time_in: row.time_in || null, time_out: null, remarks: (prevRemarks3 ? (prevRemarks3 + ' ') : '') + `[resume_scan ${nowTime}]` };
          await axios.post(`${window.baseApiUrl}/attendance.php`, buildFormData({ operation: 'updateAttendance', json: JSON.stringify(upd3) }));
          if (feedback) setFeedback(feedback, 'success', 'Resumed.');
          await loadAttendance();
          return 'resume';
        }
      } catch {}
      if (feedback) setFeedback(feedback, 'info', 'Attendance already completed for today.');
      return 'done';
    } catch (e) {
      try {
        if (e && e.response && e.response.status === 409) {
          if (feedback) setFeedback(feedback, 'warning', 'You are on leave today, so you cannot record attendance.');
          return 'onleave';
        }
      } catch {}
      if (feedback) setFeedback(feedback, 'error', 'Failed to record attendance.');
      return 'error';
    }
  }

  async function getEmployeeName(employeeId){
    try {
      const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployee', employee_id: employeeId } });
      const e = res.data || {};
      const name = `${e.first_name || ''} ${e.last_name || ''}`.trim();
      return name;
    } catch { return ''; }
  }

  async function startScannerInto(readerId, feedbackId, resumeBtnId){
    const feedback = document.getElementById(feedbackId);
    try {
      await ensureQrScanLib();
      if (!window.Html5Qrcode) { if (feedback) feedback.textContent = 'Scanner library failed to load.'; return; }
      if (qrScanner) { try { await qrScanner.stop(); qrScanner.clear(); } catch {} }
      qrScanner = new window.Html5Qrcode(readerId);
      isScanning = true;
      if (feedback) setFeedback(feedback, 'info', 'Point the camera at the QR code');
      const onScanSuccess = async (decodedText) => {
        try {
          let eid = null;
          // Try JSON format first
          try {
            const data = JSON.parse(decodedText);
            const type = data && data.type ? String(data.type).toLowerCase() : '';
            if (type === 'employee') {
              if (data && (data.employee_id || data.id)) {
                const n = Number(data.employee_id || data.id);
                if (Number.isFinite(n) && n > 0) eid = n;
              }
              if (!eid && data && data.code) {
                eid = parseEmployeeIdFromText(data.code);
              }
            }
          } catch {}
          // Fallback: plain code text (e.g., EMP2025-001)
          if (!eid) {
            eid = parseEmployeeIdFromText(decodedText);
          }
          if (!eid) { if (feedback) setFeedback(feedback, 'error', 'Invalid or unsupported QR code.'); return; }
          {
            // Keep scanner running for both Admin and HR; throttle duplicate scans
            const nowTs = Date.now();
            if (scanningBusy) return;
            if (decodedText === lastDecodedText && (nowTs - lastScanTime) < 1500) return;
            scanningBusy = true;
            lastDecodedText = decodedText;
            lastScanTime = nowTs;
            const action = await autoRecordAttendance(eid, feedbackId);
            let empName = await getEmployeeName(eid);
            empName = empName ? capitalizeWords(empName) : `Employee #${eid}`;
            const actionMsg = (a) => {
              if (a === 'in') return 'Time in recorded.';
              if (a === 'early') return 'You have time in already. Next scan is 8:00 PM for time out.';
              if (a === 'out') return 'Time out recorded.';
              if (a === 'resume') return 'Resumed.';
              if (a === 'done') return 'Attendance already completed for today.';
              if (a === 'onleave') return 'You are on leave today, so you cannot record attendance.';
              if (a === 'absent_today') return 'You are absent today.';
              if (a === 'timeout_closed') return 'Please contact the admin to reopen the QR code scanner.';
              if (a === 'emergency') return 'Emergency scan recorded. Status set to Undertime.';
              if (a === 'limit') return 'Daily scan limit reached (3) for undertime emergencies.';
              if (a === 'error') return 'Failed to record attendance.';
              return 'Updated.';
            };
            if (feedback) setFeedback(
              feedback,
              (action === 'in' || action === 'out' || action === 'emergency' || action === 'resume') ? 'success' : (action === 'early' || action === 'onleave' || action === 'absent_today' || action === 'timeout_closed' || action === 'limit') ? 'warning' : (action === 'error') ? 'error' : 'info',
              `${empName}: ${actionMsg(action)}`
            );
            // Keep scanner running; rely on throttling and scanningBusy to avoid duplicate scans
            scanningBusy = false;
          }
        } catch (e) {
          if (feedback) setFeedback(feedback, 'error', 'Error processing QR.');
        }
      };
      const onScanFailure = () => {};
      await qrScanner.start({ facingMode: 'environment' }, { fps: 10, qrbox: 250 }, onScanSuccess, onScanFailure);
    } catch (e) {
      if (feedback) setFeedback(feedback, 'error', 'Camera permission denied or unavailable.');
    }
  }

  async function stopScanner(keepMessage = false){
    const fb1 = document.getElementById('qr-feedback');
    const fb2 = document.getElementById('qr-feedback-att');
    try {
      if (qrScanner) { await qrScanner.stop(); qrScanner.clear(); }
      isScanning = false;
      if (!keepMessage) {
        if (fb1) setFeedback(fb1, 'info', 'Scanner stopped.');
        if (fb2) setFeedback(fb2, 'info', 'Scanner stopped.');
      }
    } catch {}
  }
  
  document.getElementById('btn-add-att').addEventListener('click', async () => {
    await loadEmployeesSelect();
    resetForm();
    openModal();
  });

  document.getElementById('save-att').addEventListener('click', async () => {
    await saveAttendance();
    closeModal();
    await loadAttendance();
  });

  // Save Edit Attendance
  const saveEditBtn = document.getElementById('save-edit-att');
  if (saveEditBtn) saveEditBtn.addEventListener('click', async () => {
    await saveAttendanceEdit();
    closeEditModal();
    await loadAttendance();
  });

  // QR scanner modal (external)
  function ensureQrAttModal(){
    if (document.getElementById('qrAttModal')) return;
    const modal = document.createElement('div');
    modal.id = 'qrAttModal';
    modal.className = 'fixed inset-0 z-50 hidden';
    modal.innerHTML = `
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-lg">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">QR Attendance Scanner</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
          </div>
          <div class="p-4">
            <div id="qr-reader-att" class="w-full max-w-sm mx-auto"></div>
            <div id="qr-feedback-att" class="text-sm text-center mt-2"></div>
            <div class="flex justify-center gap-2 mt-3">
              <button id="qr-stop-att" class="px-3 py-1 text-sm rounded border">Stop</button>
            </div>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);
    modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', async () => {
      await stopScanner();
      modal.classList.add('hidden');
    }));
    const stopBtn = modal.querySelector('#qr-stop-att');
    if (stopBtn) stopBtn.addEventListener('click', async () => { await stopScanner(); });
  }

  document.getElementById('btn-qr-scan')?.addEventListener('click', async () => {
    ensureQrAttModal();
    const modal = document.getElementById('qrAttModal');
    modal.classList.remove('hidden');
    try { await ensureQrScanLib(); } catch {}
    await startScannerInto('qr-reader-att', 'qr-feedback-att', 'qr-resume-att');
  });

  // Wire search and page size controls
  const attSearchInput = document.getElementById('att-search-input');
  const attSearchClear = document.getElementById('att-search-clear');
  const attPageSizeSelect = document.getElementById('att-page-size');
  if (attSearchInput) {
    attSearchInput.addEventListener('input', () => {
      currentQuery = (attSearchInput.value || '').trim().toLowerCase();
      currentPage = 1;
      renderAttendanceTable();
    });
  }
  if (attSearchClear) {
    attSearchClear.addEventListener('click', () => {
      if (attSearchInput) attSearchInput.value = '';
      currentQuery = '';
      currentPage = 1;
      renderAttendanceTable();
    });
  }
  if (attPageSizeSelect) {
    attPageSizeSelect.addEventListener('change', () => {
      const num = Number(attPageSizeSelect.value);
      pageSize = Number.isFinite(num) && num > 0 ? num : 10;
      currentPage = 1;
      renderAttendanceTable();
    });
  }
  const attDeptFilter = document.getElementById('att-dept-filter');
  if (attDeptFilter) { attDeptFilter.addEventListener('change', () => { currentPage = 1; renderAttendanceTable(); }); }
  const attDate = document.getElementById('att-date');
  const attStatus = document.getElementById('att-status-filter');

  // Default to today's date on initial load
  if (attDate) { try { attDate.value = today(); } catch {} }
  // Default status filter to All
  if (attStatus) { try { attStatus.value = 'all'; } catch {} }

  // Listen to changes
  if (attDate) {
    attDate.addEventListener('change', () => {
      // If cleared, default back to today
      if (!attDate.value) { try { attDate.value = today(); } catch {} }
      currentPage = 1; 
      loadAttendance();
    });
    attDate.addEventListener('input', () => {
      if (!attDate.value) { try { attDate.value = today(); } catch {} }
      currentPage = 1;
      loadAttendance();
    });
  }
  if (attStatus) attStatus.addEventListener('change', () => { currentPage = 1; renderAttendanceTable(); });

  // Auto rollover daily: when the day changes, reset filters and show today's list
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
    if (nowDay !== __attDayKey) {
      __attDayKey = nowDay;
      resetForNewDay();
    }
  }
  try {
    setInterval(maybeRollover, 60000); // check every minute
    window.addEventListener('focus', maybeRollover);
    document.addEventListener('visibilitychange', maybeRollover);
  } catch {}

  await loadAttendance();

  async function loadAttendance() {
    const tableDiv = document.getElementById('attendance-table');
    if (tableDiv) tableDiv.innerHTML = '<div class="text-gray-500">Loading...</div>';
    const selEl = document.getElementById('att-date');
    const effectiveDate = (selEl && selEl.value) ? selEl.value : today();
    const params = {
      operation: 'getAttendance',
      start_date: effectiveDate,
      end_date: effectiveDate,
    };
    const response = await axios.get(`${window.baseApiUrl}/attendance.php`, { params });
    let rows = response.data || [];
    // In HR portal, restrict to Manager/Employee roles (exclude HR and inactive)
    if (isHrPortal()) {
      try {
        const empRes = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
        const empList = Array.isArray(empRes.data) ? empRes.data : [];
        const allowed = empList.filter(e => {
          const role = String(e.user_role || e.role || '').toLowerCase();
          const st = String(e.status || '').toLowerCase();
          return (role === 'manager' || role === 'employee') && st !== 'inactive';
        });
        const allowedIds = new Set(allowed.map(e => String(e.employee_id)));
        rows = rows.filter(r => allowedIds.has(String(r.employee_id)));
      } catch {}
    }
    // Deduplicate 'leave' entries per employee per date (display one name only)
    // This prevents multiple leave rows for the same employee and date from showing
    try {
      const unique = [];
      const seenLeave = new Set();
      for (const r of rows) {
        const st = String(r.status || '').toLowerCase();
        if (st === 'leave') {
          const key = `${r.employee_id}|${r.attendance_date}`;
          if (seenLeave.has(key)) continue;
          seenLeave.add(key);
        }
        unique.push(r);
      }
      rows = unique;
    } catch {}

    
    // Attach department mapping and populate department filter
    try {
      const empRes2 = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
      const empList2 = Array.isArray(empRes2.data) ? empRes2.data : [];
      const deptOf = new Map(empList2.map(e => [String(e.employee_id), e.department || '']));
      rows = rows.map(r => Object.assign({}, r, { department: r.department || deptOf.get(String(r.employee_id)) || '' }));
      const deptSel = document.getElementById('att-dept-filter');
      if (deptSel) {
        const currentVal = deptSel.value;
        const depts = Array.from(new Set(empList2.map(e => e.department).filter(Boolean))).sort((a,b)=>String(a).localeCompare(String(b)));
        deptSel.innerHTML = '<option value="all">All Departments</option>' + depts.map(d => `<option value="${d}">${d}</option>`).join('');
        if (currentVal && (currentVal === 'all' || depts.includes(currentVal))) deptSel.value = currentVal;
      }
    } catch {}

    allAttendance = rows;
    // Preload approved leaves for range rendering in Leave filter
    try {
      const lr = await axios.get(`${window.baseApiUrl}/leaves.php`, { params: { operation: 'listApproved' } });
      leavesCache = Array.isArray(lr.data) ? lr.data : [];
    } catch { leavesCache = []; }
    currentPage = 1;
    renderAttendanceTable();
  }

  function getFilteredAttendance() {
    const q = (currentQuery || '').toLowerCase();
    const statusFilterEl = document.getElementById('att-status-filter');
    const statusFilter = statusFilterEl ? (statusFilterEl.value || 'all').toLowerCase() : 'all';
    const deptFilterEl = document.getElementById('att-dept-filter');
    const deptFilter = deptFilterEl ? (deptFilterEl.value || 'all').toLowerCase() : 'all';

    let base = allAttendance.slice();
    if (deptFilter !== 'all') {
      const dval = deptFilter;
      base = base.filter(r => String(r.department || '').toLowerCase() === dval);
    }
    const filteredBySearch = !q ? base : base.filter(r => {
      const name = `${r.first_name || ''} ${r.last_name || ''}`.toLowerCase();
      const status = (r.status || '').toLowerCase();
      const date = (r.attendance_date || '').toLowerCase();
      const dept = String(r.department || '').toLowerCase();
      return name.includes(q) || status.includes(q) || date.includes(q) || dept.includes(q);
    });
    if (statusFilter === 'all') return filteredBySearch;
    if (statusFilter === 'present') {
      return filteredBySearch.filter(r => {
        const st = String(r.status || '').toLowerCase();
        return st === 'present' || st === 'late';
      });
    }
    return filteredBySearch.filter(r => (String(r.status || '').toLowerCase() === statusFilter));
  }

  function calcTotalHours(attDate, tIn, tOut) {
    try {
      if (!tIn) return '';
      const toMin = (hhmm) => {
        const [h, m] = String(hhmm || '').split(':').map(n => parseInt(n, 10));
        return (isNaN(h) ? 0 : h) * 60 + (isNaN(m) ? 0 : m);
      };
      const inMin = toMin(tIn);
      let outMin;

      if (tOut && String(tOut).trim()) {
        outMin = toMin(tOut);
      } else {
        // No explicit time out
        const todayStr = today();
        const now = nowHHMM();
        if (attDate === todayStr) {
          const nowMin = toMin(now);
          // If it's earlier than time-in, show empty (avoid ~24h bug)
          if (nowMin < inMin) return '';
          outMin = nowMin;
        } else {
          // For past dates without timeout, cap at shift end
          outMin = toMin(SHIFT_END);
        }
      }

      // Cap at SHIFT_END
      const capMin = toMin(SHIFT_END);
      if (outMin > capMin) outMin = capMin;

      // Overnight only when explicit time_out exists and is less than time_in
      if (outMin < inMin && tOut) outMin += 24 * 60;

      const diff = outMin - inMin;
      if (!Number.isFinite(diff) || diff <= 0) return '';
      const h = Math.floor(diff / 60);
      const m = diff % 60;
      return m ? `${h}h ${m}m` : `${h}h`;
    } catch { return ''; }
  }

  // Live Total Hours updater: refreshes totals for today's rows without time-out
  function refreshLiveTotalCell(td) {
    try {
      if (!td) return;
      const attDate = td.getAttribute('data-att-date') || '';
      const tIn = td.getAttribute('data-time-in') || '';
      const tOut = td.getAttribute('data-time-out') || '';
      td.textContent = calcTotalHours(attDate, tIn, tOut);
    } catch {}
  }
  function runLiveTotalsOnce() {
    try {
      const todayStr = today();
      const cells = document.querySelectorAll('#attendance-table td[data-total-live="1"]');
      cells.forEach(td => {
        const attDate = td.getAttribute('data-att-date') || '';
        const tOut = (td.getAttribute('data-time-out') || '').trim();
        // Only update live when it's today and still no time-out recorded
        if (attDate === todayStr && !tOut) refreshLiveTotalCell(td);
      });
    } catch {}
  }
  function startLiveTotalsUpdater(){
    try { if (window.__attLiveTotalsTimer) { clearInterval(window.__attLiveTotalsTimer); } } catch {}
    runLiveTotalsOnce();
    try { window.__attLiveTotalsTimer = setInterval(runLiveTotalsOnce, 60000); } catch {}
  }

  function consolidateLeaveRows(rows) {
    try {
      const leaveRows = rows.filter(r => String(r.status || '').toLowerCase() === 'leave');
      const byEmp = new Map();
      for (const r of leaveRows) {
        const k = String(r.employee_id);
        if (!byEmp.has(k)) byEmp.set(k, []);
        byEmp.get(k).push(r);
      }
      const toDate = (s) => {
        const [y,m,d] = String(s||'').split('-').map(n=>parseInt(n,10));
        return new Date(y, (m||1)-1, d||1);
      };
      const addDays = (dt, n) => new Date(dt.getFullYear(), dt.getMonth(), dt.getDate()+n);
      const fmtYmd = (dt) => {
        const y = dt.getFullYear();
        const m = String(dt.getMonth()+1).padStart(2,'0');
        const d = String(dt.getDate()).padStart(2,'0');
        return `${y}-${m}-${d}`;
      };
      const result = [];
      for (const [empId, list] of byEmp.entries()) {
        const uniqueDates = Array.from(new Set(list.map(r => r.attendance_date))).filter(Boolean).sort();
        let i = 0;
        while (i < uniqueDates.length) {
          const start = uniqueDates[i];
          let end = start;
          let j = i + 1;
          while (j < uniqueDates.length) {
            const prev = toDate(end);
            const next = toDate(uniqueDates[j]);
            const expected = addDays(prev, 1);
            if (fmtYmd(expected) === fmtYmd(next)) {
              end = uniqueDates[j];
              j++;
            } else {
              break;
            }
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

  function renderAttendanceTable() {
    const container = document.getElementById('attendance-table');
    if (!container) return;
    let rows;
    const statusFilterEl = document.getElementById('att-status-filter');
    const __statusFilter = statusFilterEl ? (statusFilterEl.value || 'all').toLowerCase() : 'all';
    if (__statusFilter === 'leave') {
      const selectedDateEl = document.getElementById('att-date');
      const selectedDate = selectedDateEl ? (selectedDateEl.value || '').trim() : '';
      const q = (currentQuery || '').toLowerCase();
      const base = Array.isArray(leavesCache) ? leavesCache : [];
      rows = base
        .filter(l => String(l.status || '').toLowerCase() === 'approved')
        .filter(l => !selectedDate || (String(l.start_date || '') <= selectedDate && String(l.end_date || '') >= selectedDate))
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
      rows.sort((a, b) =>
        String(b.range_start || '').localeCompare(String(a.range_start || '')) ||
        String(a.last_name || '').localeCompare(String(b.last_name || '')) ||
        String(a.first_name || '').localeCompare(String(b.first_name || ''))
      );
    } else {
      rows = getFilteredAttendance();
      // If a specific date is selected, annotate leave rows with the full approved range
      try {
        const selectedDateEl = document.getElementById('att-date');
        const selectedDate = selectedDateEl ? (selectedDateEl.value || '').trim() : '';
        if (selectedDate && Array.isArray(rows) && rows.length) {
          const baseLeaves = Array.isArray(leavesCache) ? leavesCache : [];
          const byEmpLeaves = new Map();
          for (const l of baseLeaves) {
            if (String(l.status || '').toLowerCase() !== 'approved') continue;
            const s = String(l.start_date || '');
            const e = String(l.end_date || '');
            if (!(s && e)) continue;
            if (!(s <= selectedDate && e >= selectedDate)) continue; // overlap with the selected day
            const k = String(l.employee_id);
            const prev = byEmpLeaves.get(k);
            if (!prev) byEmpLeaves.set(k, l);
            else {
              // prefer later end_date if multiple
              if (String(l.end_date).localeCompare(String(prev.end_date)) > 0) byEmpLeaves.set(k, l);
            }
          }
          rows = rows.map(r => {
            if (String(r.status || '').toLowerCase() === 'leave') {
              const l = byEmpLeaves.get(String(r.employee_id));
              if (l) return { ...r, range_start: l.start_date, range_end: l.end_date };
            }
            return r;
          });
        }
        // If no specific date, consolidate multiple daily 'leave' rows into a single range row per employee
        if (!selectedDate && Array.isArray(rows) && rows.length) {
          const nonLeave = rows.filter(r => String(r.status || '').toLowerCase() !== 'leave');
          const consolidatedLeave = consolidateLeaveRows(rows);
          rows = nonLeave.concat(consolidatedLeave);
          // Sort by most recent date range or attendance date desc
          rows.sort((a, b) => {
            const ad = a.range_start || a.attendance_date || '';
            const bd = b.range_start || b.attendance_date || '';
            return String(bd).localeCompare(String(ad));
          });
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
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Department</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Date</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time In</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Time Out</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Total Hours</th>
          <th class="px-3 py-2 text-right text-xs font-semibold text-gray-600">Actions</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-200 bg-white"></tbody>`;

    const tbody = table.querySelector('tbody');
    if (!pageRows.length) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="9" class="px-3 py-6 text-sm text-center text-gray-500">No attendance records</td>`;
      tbody.appendChild(tr);
    } else {
      pageRows.forEach((r, i) => {
        const tr = document.createElement('tr');
        const name = capitalizeWords(`${r.first_name} ${r.last_name}`);
        const displayIndex = startIdx + i + 1;
        const statusHtml = statusBadge(r.status || '');
        tr.innerHTML = `
          <td class="px-3 py-2 text-sm text-gray-700">${displayIndex}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${name}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${r.department || ''}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${r.range_start ? (formatDate(r.range_start) + ' → ' + formatDate(r.range_end)) : formatDate(r.attendance_date)}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${statusHtml}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${formatTimeOfDay(r.time_in) || ''}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${formatTimeOfDay(r.time_out) || ''}</td>
          <td class="px-3 py-2 text-sm text-gray-700" data-total-live="1" data-att-date="${r.attendance_date || ''}" data-time-in="${r.time_in || ''}" data-time-out="${r.time_out || ''}">${calcTotalHours(r.attendance_date, r.time_in, r.time_out)}</td>
          <td class="px-3 py-2 text-sm text-right">
            <div class="relative inline-block text-left" data-att-menu-container>
              <button class="inline-flex items-center justify-center w-8 h-8 rounded hover:bg-gray-100" aria-label="Actions" data-action="menu-toggle">
                <span class="text-gray-600 font-bold text-lg">•••</span>
              </button>
              <div class="hidden origin-top-right absolute right-0 mt-2 w-36 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 z-10" role="menu" data-menu>
                <div class="py-1">
                  <button class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50" data-menu-action="edit" role="menuitem">Edit</button>
                </div>
              </div>
            </div>
          </td>`;

        const toggleBtn = tr.querySelector('[data-action="menu-toggle"]');
        const menu = tr.querySelector('[data-menu]');
        if (toggleBtn && menu) {
          toggleBtn.addEventListener('click', (ev) => {
            ev.preventDefault();
            ev.stopPropagation();
            document.querySelectorAll('[data-att-menu-container] [data-menu]').forEach(m => m.classList.add('hidden'));
            menu.classList.toggle('hidden');
          });
        }
        const onEdit = tr.querySelector('[data-menu-action="edit"]');
        if (onEdit) onEdit.addEventListener('click', async (ev) => {
          ev.preventDefault();
          if (menu) menu.classList.add('hidden');
          fillEditForm(r);
          openEditModal();
        });
                tbody.appendChild(tr);
      });
    }

    container.innerHTML = '';
    container.appendChild(table);
    // Kick off/refresh live totals updater for current table
    try { startLiveTotalsUpdater(); } catch {}

    if (!window.__attMenuGlobalClose) {
      window.__attMenuGlobalClose = true;
      document.addEventListener('click', () => {
        document.querySelectorAll('[data-att-menu-container] [data-menu]').forEach(m => m.classList.add('hidden'));
      });
    }

    const footer = document.getElementById('attendance-pagination');
    if (footer) {
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
      if (prev) prev.addEventListener('click', () => { if (currentPage > 1) { currentPage -= 1; renderAttendanceTable(); } });
      if (next) next.addEventListener('click', () => { if (currentPage < totalPages) { currentPage += 1; renderAttendanceTable(); } });
    }
  }

  async function loadEmployeesSelect(selectedId) {
    if (employeesCache.length === 0) {
      const response = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
      const list = response.data || [];
      if (isHrPortal()) {
        const allowed = list.filter(e => {
          const role = String(e.user_role || e.role || '').toLowerCase();
          const st = String(e.status || '').toLowerCase();
          return (role === 'manager' || role === 'employee') && st !== 'inactive';
        });
        employeesCache = allowed;
      } else {
        employeesCache = list;
      }
    }
    empFiltered = employeesCache.slice();
    // If creating new, clear selection; editing will set currentEditEmployeeId
    const searchInput = document.getElementById('employee_search');
    const deptSel = document.getElementById('employee_dept_filter');
    const selAll = document.getElementById('employee_select_all');

    // Populate department dropdown
    if (deptSel && !deptSel.__loaded) {
      deptSel.__loaded = true;
      const currentVal = deptSel.value;
      const depts = Array.from(new Set(employeesCache.map(e => e.department).filter(Boolean))).sort((a,b)=>String(a).localeCompare(String(b)));
      deptSel.innerHTML = '<option value="all">All Departments</option>' + depts.map(d => `<option value="${d}">${d}</option>`).join('');
      if (currentVal && (currentVal === 'all' || depts.includes(currentVal))) deptSel.value = currentVal;
    }

    const applyEmpFilters = () => {
      const q = (searchInput && searchInput.value ? searchInput.value : '').toLowerCase();
      const dsel = deptSel ? (deptSel.value || 'all').toLowerCase() : 'all';
      empFiltered = employeesCache.filter(e => {
        const name = `${e.first_name || ''} ${e.last_name || ''}`.toLowerCase();
        const dept = String(e.department || '').toLowerCase();
        const okName = !q || name.includes(q);
        const okDept = dsel === 'all' || dept === dsel;
        return okName && okDept;
      });
      renderEmployeeList();
      updateSelectedCount();
    };

    if (selectedId) { empSelected.add(String(selectedId)); }
    applyEmpFilters();

    if (searchInput && !searchInput.__bound) {
      searchInput.__bound = true;
      searchInput.addEventListener('input', applyEmpFilters);
    }
    if (deptSel && !deptSel.__bound) {
      deptSel.__bound = true;
      deptSel.addEventListener('change', applyEmpFilters);
    }
    if (selAll && !selAll.__bound) {
      selAll.__bound = true;
      selAll.addEventListener('change', () => {
        const allIds = empFiltered.map(e => String(e.employee_id));
        if (selAll.checked) { allIds.forEach(id => empSelected.add(id)); }
        else { allIds.forEach(id => empSelected.delete(id)); }
        renderEmployeeList();
      });
    }
  }

  function resetForm() {
    fillForm({});
  }

  function fillForm(r) {
    document.getElementById('attendance_id').value = r.attendance_id || '';
    currentEditEmployeeId = r.employee_id || null;
    // preselect employee for edit
    empSelected.clear();
    if (currentEditEmployeeId) empSelected.add(String(currentEditEmployeeId));
    const searchInput = document.getElementById('employee_search');
    if (searchInput) searchInput.value = '';
    const deptSel = document.getElementById('employee_dept_filter');
    const q = (searchInput && searchInput.value ? searchInput.value : '').toLowerCase();
    const dsel = deptSel ? (deptSel.value || 'all').toLowerCase() : 'all';
    empFiltered = employeesCache.filter(e => {
      const name = `${e.first_name || ''} ${e.last_name || ''}`.toLowerCase();
      const dept = String(e.department || '').toLowerCase();
      const okName = !q || name.includes(q);
      const okDept = dsel === 'all' || dept === dsel;
      return okName && okDept;
    });
    renderEmployeeList();
    updateSelectedCount();
    document.getElementById('attendance_date').value = r.attendance_date || '';
    document.getElementById('status').value = r.status || 'present';
    document.getElementById('time_in').value = r.time_in || '';
    document.getElementById('time_out').value = r.time_out || '';
  }

  function fillEditForm(r) {
    try {
      const fullName = capitalizeWords(`${r.first_name || ''} ${r.last_name || ''}`.trim());
      document.getElementById('edit_attendance_id').value = r.attendance_id || '';
      document.getElementById('edit_employee_id').value = r.employee_id || '';
      const nameEl = document.getElementById('edit_employee_name');
      if (nameEl) nameEl.textContent = fullName || `Employee #${r.employee_id || ''}`;
      const deptEl = document.getElementById('edit_employee_department');
      if (deptEl) deptEl.textContent = r.department || '';
      document.getElementById('edit_attendance_date').value = r.attendance_date || '';
      document.getElementById('edit_status').value = r.status || 'present';
      document.getElementById('edit_time_in').value = r.time_in || '';
      document.getElementById('edit_time_out').value = r.time_out || '';
      currentEditEmployeeId = r.employee_id || null;
    } catch {}
  }

  async function saveAttendanceEdit() {
    const attendanceId = document.getElementById('edit_attendance_id').value;
    const employeeId = document.getElementById('edit_employee_id').value || currentEditEmployeeId;
    if (!attendanceId || !employeeId) { alert('Missing attendance or employee ID'); return; }
    const payload = {
      attendance_id: attendanceId,
      employee_id: employeeId,
      attendance_date: document.getElementById('edit_attendance_date').value,
      status: document.getElementById('edit_status').value,
      time_in: document.getElementById('edit_time_in').value || null,
      time_out: document.getElementById('edit_time_out').value || null,
      remarks: ''
    };
    await axios.post(`${window.baseApiUrl}/attendance.php`, buildFormData({ operation: 'updateAttendance', json: JSON.stringify(payload) }));
  }

  async function saveAttendance() {
    const attendanceId = document.getElementById('attendance_id').value;
    const selectedIds = Array.from(empSelected);
    const base = {
      attendance_date: document.getElementById('attendance_date').value,
      status: document.getElementById('status').value,
      time_in: document.getElementById('time_in').value || null,
      time_out: document.getElementById('time_out').value || null,
      remarks: '',
    };

    if (attendanceId) {
      // Update a single existing record; prefer the original employee
      const eid = currentEditEmployeeId || selectedIds[0];
      if (!eid) { alert('No employee selected for update'); return; }
      const payload = { ...base, attendance_id: attendanceId, employee_id: eid };
      await axios.post(`${window.baseApiUrl}/attendance.php`, buildFormData({ operation: 'updateAttendance', json: JSON.stringify(payload) }));
    } else {
      if (!selectedIds.length) { alert('Select at least one employee'); return; }
      for (const id of selectedIds) {
        const payload = { ...base, employee_id: id };
        try { await axios.post(`${window.baseApiUrl}/attendance.php`, buildFormData({ operation: 'recordAttendance', json: JSON.stringify(payload) })); } catch {}
      }
    }
  }
}

function isAdminPortal(){
  // Detect admin main dashboard path
  return /\/master\/admin\/admin\.html$/i.test(location.pathname);
}

function buildFormData(map) {
  const fd = new FormData();
  Object.entries(map).forEach(([k, v]) => fd.append(k, v));
  return fd;
}

function isHrPortal(){
  return location.pathname.endsWith('/hr.html') || location.pathname.endsWith('hr.html');
}


