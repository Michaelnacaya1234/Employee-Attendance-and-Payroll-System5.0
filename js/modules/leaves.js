/**
 * RENDER LEAVE MANAGEMENT INTERFACE
 * Creates comprehensive leave request management system
 * Includes filing new leaves, overtime/undertime requests, and approval workflow
 */
export async function render() {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h4 class="text-xl font-semibold">Leave Requests</h4>
      <button id="btn-file-leave" class="inline-flex items-center px-3 py-2 text-sm font-medium rounded bg-primary-600 text-white hover:bg-primary-700">File Leave</button>
    </div>
        <div class="bg-white rounded-lg shadow p-4">
          <div class="mb-3 flex flex-wrap items-center gap-2">
            <div class="relative">
              <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M12.9 14.32a8 8 0 111.414-1.414l4.387 4.387a1 1 0 01-1.414 1.414l-4.387-4.387zM8 14a6 6 0 100-12 6 6 0 000 12z" clip-rule="evenodd"/></svg>
              <input id="lv_search" class="border rounded pl-8 pr-3 py-2 text-sm" placeholder="Search name or reason" />
            </div>
                        <select id="status_filter" class="border rounded px-3 py-2 text-sm">
              <option value="pending" selected>Pending</option>
              <option value="all">All Requested</option>
              <option value="rejected">Rejected</option>
              <option value="approved">Approved</option>
            </select>
            <input type="date" id="on_date" class="border rounded px-3 py-2 text-sm" />
            <div class="ml-auto flex items-center gap-2 text-sm text-gray-600">
              <button id="lv-open-archived" class="inline-flex items-center justify-center w-9 h-9 rounded border border-gray-200 hover:bg-gray-50" title="View archived">
                <svg class="w-5 h-5 text-gray-700" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7h18M5 7v12a2 2 0 002 2h10a2 2 0 002-2V7M9 11h6" /></svg>
              </button>
              <button id="lv-archive-all" class="inline-flex items-center px-3 py-1.5 text-sm font-medium rounded bg-red-600 text-white hover:bg-red-700" title="Archive all filtered">Archive All</button>
              <select id="lv_page_size" class="border rounded px-2 py-1">
                <option value="5">5</option>
                <option value="10" selected>10</option>
                <option value="20">20</option>
                <option value="50">50</option>
              </select>
            </div>
          </div>
          <div id="leaves-table"></div>
          <div id="leaves-pagination" class="mt-3 flex items-center justify-between text-sm text-gray-600"></div>
        </div>

    <div id="leaveModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-lg">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold" id="leaveModalLabel">File Leave</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
          </div>
          <div class="p-4">
            <form id="leave-form" class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="md:col-span-2">
                <div class="relative">
                  <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M12.9 14.32a8 8 0 111.414-1.414l4.387 4.387a1 1 0 01-1.414 1.414l-4.387-4.387zM8 14a6 6 0 100-12 6 6 0 000 12z" clip-rule="evenodd"/></svg>
                  <input id="emp_search" class="w-full border rounded pl-8 pr-3 py-2" placeholder="Search employee..." />
                </div>
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Employee</label>
                <select id="employee_id" class="w-full border rounded px-3 py-2" required></select>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Start date</label>
                <input type="date" id="lv_start" class="w-full border rounded px-3 py-2" required />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">End date</label>
                <input type="date" id="lv_end" class="w-full border rounded px-3 py-2" required />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Leave Type</label>
                <select id="lv_type" class="w-full border rounded px-3 py-2"></select>
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Reason</label>
                <textarea id="lv_reason" rows="3" class="w-full border rounded px-3 py-2"></textarea>
              </div>
            </form>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
            <button id="save-leave" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
          </div>
        </div>
      </div>
    </div>

    <div id="otModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-lg">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">Request Overtime</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
          </div>
          <div class="p-4">
            <form id="ot-form" class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="md:col-span-2">
                <div class="relative">
                  <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M12.9 14.32a8 8 0 111.414-1.414l4.387 4.387a1 1 0 01-1.414 1.414l-4.387-4.387zM8 14a6 6 0 100-12 6 6 0 000 12z" clip-rule="evenodd"/></svg>
                  <input id="ot_emp_search" class="w-full border rounded pl-8 pr-3 py-2" placeholder="Search employee..." />
                </div>
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Employee</label>
                <select id="ot_employee_id" class="w-full border rounded px-3 py-2" required></select>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Date</label>
                <input type="date" id="ot_date" class="w-full border rounded px-3 py-2" required />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Hours</label>
                <input type="number" step="0.25" min="0.25" id="ot_hours" class="w-full border rounded px-3 py-2" placeholder="e.g., 2.5" required />
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Reason</label>
                <textarea id="ot_reason" rows="3" class="w-full border rounded px-3 py-2"></textarea>
              </div>
            </form>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
            <button id="save-ot" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
          </div>
        </div>
      </div>
    </div>

    <div id="utModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-lg">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">Request Undertime</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
          </div>
          <div class="p-4">
            <form id="ut-form" class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="md:col-span-2">
                <div class="relative">
                  <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M12.9 14.32a8 8 0 111.414-1.414l4.387 4.387a1 1 0 01-1.414 1.414l-4.387-4.387zM8 14a6 6 0 100-12 6 6 0 000 12z" clip-rule="evenodd"/></svg>
                  <input id="ut_emp_search" class="w-full border rounded pl-8 pr-3 py-2" placeholder="Search employee..." />
                </div>
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Employee</label>
                <select id="ut_employee_id" class="w-full border rounded px-3 py-2" required></select>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Date</label>
                <input type="date" id="ut_date" class="w-full border rounded px-3 py-2" required />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Hours</label>
                <input type="number" step="0.25" min="0.25" id="ut_hours" class="w-full border rounded px-3 py-2" placeholder="e.g., 1" required />
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Reason</label>
                <textarea id="ut_reason" rows="3" class="w-full border rounded px-3 py-2"></textarea>
              </div>
            </form>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
            <button id="save-ut" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
          </div>
        </div>
      </div>
    </div>

    <div id="hrLeaveViewModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-24 w-full max-w-lg">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold">Leave Details</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
          <div class="p-4 text-sm space-y-2">
            <div><span class="text-gray-500">Employee:</span> <span id="lvw-emp"></span></div>
            <div><span class="text-gray-500">Dates:</span> <span id="lvw-dates"></span></div>
            <div><span class="text-gray-500">Reason:</span> <div id="lvw-reason" class="mt-1 whitespace-pre-wrap"></div></div>
            <div><span class="text-gray-500">Status:</span> <span id="lvw-status"></span></div>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
          </div>
        </div>
      </div>
    </div>`;

  const modalEl = document.getElementById('leaveModal');
  const openModal = () => modalEl.classList.remove('hidden');
  const closeModal = () => modalEl.classList.add('hidden');
  modalEl.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeModal));
  const viewModal = document.getElementById('hrLeaveViewModal');
  const closeView = () => viewModal.classList.add('hidden');
  viewModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeView));
  // Wire filters inside the table card
  let employeeList = [];
  let lvPage = 1;
  let lvPageSize = 10;
  let lastFilteredLeaves = [];
  let archivedQuery = '';
  const lvSearch = document.getElementById('lv_search');
  const statusSelect = document.getElementById('status_filter');
  const dateInput = document.getElementById('on_date');
  if (lvSearch) lvSearch.addEventListener('input', async () => { lvPage = 1; await loadLeaves(); });
  if (statusSelect) statusSelect.addEventListener('change', async () => { lvPage = 1; await loadLeaves(); });
  if (dateInput) dateInput.addEventListener('change', async () => { lvPage = 1; await loadLeaves(); });
  const pageSizeSelect = document.getElementById('lv_page_size');
  if (pageSizeSelect) pageSizeSelect.addEventListener('change', async () => { const n = Number(pageSizeSelect.value); lvPageSize = Number.isFinite(n) && n > 0 ? n : 10; lvPage = 1; await loadLeaves(); });
  // Archive controls
  const btnOpenArchived = document.getElementById('lv-open-archived');
  if (btnOpenArchived) btnOpenArchived.addEventListener('click', (e) => { e.preventDefault(); openArchivedLeavesModal(); });
  const btnArchiveAll = document.getElementById('lv-archive-all');
  if (btnArchiveAll) btnArchiveAll.addEventListener('click', async (e) => {
    e.preventDefault();
    if (!Array.isArray(lastFilteredLeaves) || lastFilteredLeaves.length === 0) { alert('No leave requests to archive for current filters.'); return; }
    if (!confirm(`Archive ${lastFilteredLeaves.length} leave request(s)?`)) return;
    btnArchiveAll.disabled = true;
    try {
      const ids = lastFilteredLeaves.map(r => r.leave_id).filter(Boolean);
      const fd = new FormData();
      fd.append('operation', 'archiveLeaveBulk');
      fd.append('json', JSON.stringify({ leave_ids: ids }));
      const res = await axios.post(`${window.baseApiUrl}/leaves.php`, fd);
      const info = res && res.data ? res.data : {};
      if (info && (info.succeeded != null)) {
        alert(`Archived: ${info.succeeded || 0}${info.skipped ? `, Skipped: ${info.skipped}` : ''}${info.failed ? `, Failed: ${info.failed}` : ''}`);
      }
      await loadLeaves();
    } catch (err) {
      alert('Failed to archive leave requests');
    } finally { btnArchiveAll.disabled = false; }
  });

    document.getElementById('btn-file-leave').addEventListener('click', async () => {
    await loadEmployeesSelect();
    await loadLeaveTypesOptions('lv_type', '');
    resetForm();
    // Wire employee search to filter list
    const empSearch = document.getElementById('emp_search');
    if (empSearch) {
      empSearch.value = '';
      empSearch.addEventListener('input', () => {
        const q = (empSearch.value || '').toLowerCase().trim();
        const selectedId = document.getElementById('employee_id')?.value || '';
        const filtered = !q ? employeeList.slice() : employeeList.filter(e => {
          const name = `${e.first_name || ''} ${e.last_name || ''}`.toLowerCase();
          const email = String(e.email || '').toLowerCase();
          return name.includes(q) || email.includes(q);
        });
        renderEmployeeOptions(filtered, selectedId);
      });
    }
    openModal();
  });
  document.getElementById('save-leave').addEventListener('click', async () => {
    await saveLeave();
    closeModal();
    await loadLeaves();
  });

  // Wire OT/UT modals
  const otModal = document.getElementById('otModal');
  const utModal = document.getElementById('utModal');
  const openOt = () => otModal && otModal.classList.remove('hidden');
  const closeOt = () => otModal && otModal.classList.add('hidden');
  const openUt = () => utModal && utModal.classList.remove('hidden');
  const closeUt = () => utModal && utModal.classList.add('hidden');
  if (otModal) otModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeOt));
  if (utModal) utModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeUt));

  const btnOt = document.getElementById('btn-file-ot');
  if (btnOt) btnOt.addEventListener('click', async () => {
    if (!Array.isArray(employeeList) || employeeList.length === 0) { await loadEmployeesSelect(); }
    renderEmployeeOptionsFor('ot_employee_id', employeeList);
    const search = document.getElementById('ot_emp_search');
    if (search) {
      search.value = '';
      search.oninput = () => {
        const q = (search.value || '').toLowerCase().trim();
        const selected = document.getElementById('ot_employee_id')?.value || '';
        const filtered = !q ? employeeList.slice() : employeeList.filter(e => `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.includes(q) || String(e.email||'').toLowerCase().includes(q));
        renderEmployeeOptionsFor('ot_employee_id', filtered, selected);
      };
    }
    openOt();
  });

  const btnUt = document.getElementById('btn-file-ut');
  if (btnUt) btnUt.addEventListener('click', async () => {
    if (!Array.isArray(employeeList) || employeeList.length === 0) { await loadEmployeesSelect(); }
    renderEmployeeOptionsFor('ut_employee_id', employeeList);
    const search = document.getElementById('ut_emp_search');
    if (search) {
      search.value = '';
      search.oninput = () => {
        const q = (search.value || '').toLowerCase().trim();
        const selected = document.getElementById('ut_employee_id')?.value || '';
        const filtered = !q ? employeeList.slice() : employeeList.filter(e => `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.includes(q) || String(e.email||'').toLowerCase().includes(q));
        renderEmployeeOptionsFor('ut_employee_id', filtered, selected);
      };
    }
    openUt();
  });

  const saveOt = document.getElementById('save-ot');
  if (saveOt) saveOt.addEventListener('click', async () => {
    const employee_id = document.getElementById('ot_employee_id')?.value;
    const work_date = document.getElementById('ot_date')?.value;
    const hoursStr = document.getElementById('ot_hours')?.value;
    const hours = Number(hoursStr || '0');
    const reason = document.getElementById('ot_reason')?.value || '';
    if (!employee_id || !work_date || !Number.isFinite(hours) || hours <= 0) { alert('Select employee, date and valid hours'); return; }
    try {
      await axios.post(`${window.baseApiUrl}/overtime.php`, buildFormData({ operation: 'requestOvertime', json: JSON.stringify({ employee_id, work_date, hours, reason }) }));
      closeOt();
      alert('Overtime request submitted');
    } catch { alert('Failed to submit overtime'); }
  });

  const saveUt = document.getElementById('save-ut');
  if (saveUt) saveUt.addEventListener('click', async () => {
    const employee_id = document.getElementById('ut_employee_id')?.value;
    const work_date = document.getElementById('ut_date')?.value;
    const hoursStr = document.getElementById('ut_hours')?.value;
    const hours = Number(hoursStr || '0');
    const reason = document.getElementById('ut_reason')?.value || '';
    if (!employee_id || !work_date || !Number.isFinite(hours) || hours <= 0) { alert('Select employee, date and valid hours'); return; }
    try {
      await axios.post(`${window.baseApiUrl}/undertime.php`, buildFormData({ operation: 'requestUndertime', json: JSON.stringify({ employee_id, work_date, hours, reason }) }));
      closeUt();
      alert('Undertime request submitted');
    } catch { alert('Failed to submit undertime'); }
  });

  // moved pagination vars above initial load
  await loadLeaves();

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
  
  async function loadLeaves() {
    const tableDiv = document.getElementById('leaves-table');
    tableDiv.innerHTML = '<div class="text-gray-500">Loading...</div>';
    // server returns last 20 of any status; filter locally by status/date range
    let rows = [];
    try {
      const response = await axios.get(`${window.baseApiUrl}/leaves.php`, { params: { operation: 'listRecent' } });
      rows = response.data || [];
    } catch (e) {
      rows = [];
    }
    const q = (document.getElementById('lv_search')?.value || '').toLowerCase().trim();
    const status = (document.getElementById('status_filter')?.value || 'all');
    const onDate = document.getElementById('on_date')?.value || null;
    if (status !== 'all') rows = rows.filter(r => (r.status || '').toLowerCase() === status);
    if (onDate) rows = rows.filter(r => (!r.start_date || r.start_date <= onDate) && (!r.end_date || r.end_date >= onDate));
    if (q) rows = rows.filter(r => {
      const name = (`${r.first_name || ''} ${r.last_name || ''}`).toLowerCase();
      const reason = String(r.reason || '').toLowerCase();
      const typeStr = String(r.leave_type || '').toLowerCase();
      const idStr = String(r.leave_id || '').toLowerCase();
      return name.includes(q) || reason.includes(q) || typeStr.includes(q) || idStr.includes(q);
    });
    lastFilteredLeaves = rows.slice();
    
    const total = rows.length;
    const totalPages = Math.max(1, Math.ceil(total / lvPageSize));
    if (lvPage > totalPages) lvPage = totalPages;
    const startIdx = (lvPage - 1) * lvPageSize;
    const endIdx = Math.min(startIdx + lvPageSize, total);
    const pageRows = rows.slice(startIdx, endIdx);

    const table = document.createElement('table');
    table.className = 'min-w-full divide-y divide-gray-200';
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
        <th class="px-3 py-2 text-right text-xs font-semibold text-gray-600">Actions</th>
      </tr></thead>
      <tbody class="divide-y divide-gray-200 bg-white"></tbody>`;
    const tbody = table.querySelector('tbody');
    if (!pageRows.length) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="10" class="px-3 py-6 text-sm text-center text-gray-500">No requests found</td>`;
      tbody.appendChild(tr);
    } else {
      pageRows.forEach((l, i) => {
        const tr = document.createElement('tr');
        const name = capitalizeWords(`${l.first_name} ${l.last_name}`);
        const type = capitalizeWords(l.leave_type || '');
        const daysInclusive = (start, end) => {
          try {
            const a = new Date(start);
            const b = new Date(end || start);
            if (isNaN(a.getTime()) || isNaN(b.getTime())) return '';
            const diff = Math.floor((b - a) / (1000*60*60*24)) + 1;
            return diff > 0 ? diff : 1;
          } catch { return ''; }
        };
        const days = daysInclusive(l.start_date, l.end_date);
        const submitted = formatDate(String(l.created_at || '').slice(0, 10));
        tr.innerHTML = `
          <td class="px-3 py-2 text-sm text-gray-700">${startIdx + i + 1}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${name}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${type}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${formatDate(l.start_date)} → ${formatDate(l.end_date)}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${days}</td>
          <td class="px-3 py-2 text-sm text-gray-700 truncate max-w-[16rem]" title="${(l.reason||'').replace(/"/g,'&quot;')}">${l.reason || ''}</td>
          <td class="px-3 py-2 text-sm">
            <span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${badgeClass(l.status)}">${capitalizeWords(l.status)}</span>
          </td>
          <td class="px-3 py-2 text-sm text-gray-700">${submitted}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${capitalizeWords(l.approved_by_username || '')}</td>
          <td class="px-3 py-2 text-sm text-right">
            <div class="relative inline-block text-left" data-lv-menu-container data-idx="${i}">
              <button class="inline-flex items-center justify-center w-8 h-8 rounded hover:bg-gray-100" aria-label="Actions" data-action="menu-toggle">
                <span class="text-gray-600 font-bold text-lg">•••</span>
              </button>
              <div class="hidden origin-top-right absolute right-0 mt-2 w-40 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 z-10" role="menu" data-menu>
                <div class="py-1">
                  <button class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50" data-menu-action="view">View</button>
                  ${l.status === 'pending' ? `
                    <button class="w-full text-left px-3 py-2 text-sm text-green-700 hover:bg-gray-50" data-menu-action="approve">Approve</button>
                    <button class="w-full text-left px-3 py-2 text-sm text-red-600 hover:bg-gray-50" data-menu-action="reject">Reject</button>
                  ` : ''}
                  <button class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50" data-menu-action="archive">Archive</button>
                </div>
              </div>
            </div>
          </td>`;

        tbody.appendChild(tr);
      });
    }
    tableDiv.innerHTML = '';
    tableDiv.appendChild(table);
    // Wire per-row 3-dots actions dropdown
    try {
      const containers = tbody.querySelectorAll('[data-lv-menu-container]');
      containers.forEach((container) => {
        const idx = parseInt(container.getAttribute('data-idx'), 10);
        const menu = container.querySelector('[data-menu]');
        const toggle = container.querySelector('[data-action="menu-toggle"]');
        if (!toggle || !menu) return;
        toggle.addEventListener('click', (ev) => {
          ev.preventDefault(); ev.stopPropagation();
          // Close other menus
          tbody.querySelectorAll('[data-lv-menu-container] [data-menu]').forEach(m => { if (m !== menu) m.classList.add('hidden'); });
          menu.classList.toggle('hidden');
        });
        menu.querySelectorAll('[data-menu-action]').forEach(btn => {
          btn.addEventListener('click', async () => {
            const action = btn.getAttribute('data-menu-action');
            const row = pageRows[idx];
            if (!row) return;
            if (action === 'view') {
              openView(row);
            } else if (action === 'approve') {
              await setStatus(row.leave_id, 'approve');
              await loadLeaves();
            } else if (action === 'reject') {
              await setStatus(row.leave_id, 'reject');
              await loadLeaves();
            } else if (action === 'archive') {
              const ok = window.confirm('Archive this leave request?');
              if (ok) {
                try {
                  const fd = new FormData();
                  fd.append('operation', 'archiveLeaveBulk');
                  fd.append('json', JSON.stringify({ leave_ids: [row.leave_id] }));
                  await axios.post(`${window.baseApiUrl}/leaves.php`, fd);
                  await loadLeaves();
                } catch (e) { alert('Failed to archive leave request'); }
              }
            }
            menu.classList.add('hidden');
          });
        });
      });
      if (!window.__lvMenuGlobalClose){
        window.__lvMenuGlobalClose = true;
        document.addEventListener('click', () => {
          document.querySelectorAll('[data-lv-menu-container] [data-menu]').forEach(m => m.classList.add('hidden'));
        });
      }
    } catch {}
    const pager = document.getElementById('leaves-pagination');
    if (pager) {
      const showingFrom = total === 0 ? 0 : (startIdx + 1);
      const showingTo = endIdx;
      pager.innerHTML = `
        <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${total}</span></div>
        <div class="flex items-center gap-2">
          <button id="lv-prev" class="px-1.5 py-0.5 text-xs rounded border ${lvPage <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
          <span>Page ${lvPage} of ${totalPages}</span>
          <button id="lv-next" class="px-1.5 py-0.5 text-xs rounded border ${lvPage >= totalPages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
        </div>`;
      const prev = document.getElementById('lv-prev');
      const next = document.getElementById('lv-next');
      if (prev) prev.addEventListener('click', async () => { if (lvPage > 1) { lvPage -= 1; await loadLeaves(); } });
      if (next) next.addEventListener('click', async () => { if (lvPage < totalPages) { lvPage += 1; await loadLeaves(); } });
    }
  }

  // Archived leaves modal helpers
  function ensureArchivedLeavesModal(){
    let modal = document.getElementById('archivedLeavesModal');
    if (modal) return modal;
    modal = document.createElement('div');
    modal.id = 'archivedLeavesModal';
    modal.className = 'fixed inset-0 z-50 hidden';
    modal.innerHTML = `
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-2xl">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">Archived Leave Requests</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" aria-label="Close" data-close="true">×</button>
          </div>
          <div class="p-4">
            <div class="flex items-center justify-between mb-3">
              <div class="relative">
                <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
                <input id="lv-arch-search" class="w-64 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search archived leaves" />
              </div>
            </div>
            <div id="lv-arch-wrap" class="max-h-[60vh] overflow-y-auto"></div>
          </div>
          <div class="flex justify-between items-center gap-2 border-t px-4 py-3">
            <div class="text-sm text-gray-600" id="lv-arch-count"></div>
            <div class="flex gap-2">
              <button id="lv-arch-clear" class="px-3 py-2 text-sm rounded border">Clear</button>
              <button id="lv-arch-restore-all" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Restore All</button>
            </div>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);
    // Wire close
    modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
    const restoreAll = modal.querySelector('#lv-arch-restore-all');
    if (restoreAll) restoreAll.addEventListener('click', async (e) => {
      e.preventDefault();
      if (!confirm('Restore all archived leave records?')) return;
      try {
        const fd = new FormData();
        fd.append('operation', 'unarchiveAllLeaves');
        await axios.post(`${window.baseApiUrl}/leaves.php`, fd);
        await loadLeaves();
        await renderArchivedLeavesList();
        modal.classList.add('hidden');
      } catch (err) { alert('Failed to restore archived leaves'); }
    });
    const clearBtn = modal.querySelector('#lv-arch-clear');
    if (clearBtn) clearBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      if (!confirm('Clear archived items? This will unarchive all leave records.')) return;
      try {
        const fd = new FormData();
        fd.append('operation', 'unarchiveAllLeaves');
        await axios.post(`${window.baseApiUrl}/leaves.php`, fd);
        await loadLeaves();
        await renderArchivedLeavesList();
      } catch (err) { alert('Failed to clear archive'); }
    });
    const search = modal.querySelector('#lv-arch-search');
    if (search) search.addEventListener('input', () => { archivedQuery = (search.value || '').trim().toLowerCase(); renderArchivedLeavesList(); });
    return modal;
  }
  async function renderArchivedLeavesList(){
    const wrap = document.getElementById('lv-arch-wrap');
    const countEl = document.getElementById('lv-arch-count');
    if (!wrap) return;
    wrap.innerHTML = '<div class="text-sm text-gray-500">Loading...</div>';
    let items = [];
    try {
      const res = await axios.get(`${window.baseApiUrl}/leaves.php`, { params: { operation: 'listLeaveArchive' } });
      items = Array.isArray(res.data) ? res.data : [];
    } catch { items = []; }
    if (archivedQuery) {
      const q = archivedQuery;
      items = items.filter(r => {
        const name = `${(r.first_name||'').toLowerCase()} ${(r.last_name||'').toLowerCase()}`.trim();
        const dept = String(r.department || '').toLowerCase();
        const lid = `LV-${String(r.leave_id || 0).padStart(3,'0')}`.toLowerCase();
        const dates = `${r.start_date || ''} ${r.end_date || ''}`.toLowerCase();
        const st = String(r.status || '').toLowerCase();
        return name.includes(q) || dept.includes(q) || lid.includes(q) || dates.includes(q) || st.includes(q);
      });
    }
    if (countEl) countEl.textContent = `${items.length} item(s) archived`;
    if (!items.length) { wrap.innerHTML = '<div class="text-sm text-gray-500">No archived items.</div>'; return; }
    const rows = items.map((r, idx) => `
      <tr class="border-b">
        <td class="px-3 py-2 text-sm text-gray-700">${idx+1}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${(r.first_name || '')} ${(r.last_name || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${(r.department || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${(r.start_date || '')} → ${(r.end_date || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${(r.status || '')}</td>
      </tr>
    `).join('');
    wrap.innerHTML = `
      <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Department</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Dates</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-200 bg-white">${rows}</tbody>
      </table>`;
  }
  function openArchivedLeavesModal(){
    const modal = ensureArchivedLeavesModal();
    const s = modal.querySelector('#lv-arch-search'); if (s) s.value = archivedQuery || '';
    renderArchivedLeavesList();
    modal.classList.remove('hidden');
  }

  async function loadEmployeesSelect(selectedId) {
    const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
    employeeList = (res.data || []).filter(e => String(e.position || '').toLowerCase() !== 'hr');
    renderEmployeeOptions(employeeList, selectedId);
  }

  function renderEmployeeOptions(list, selectedId){
    const select = document.getElementById('employee_id');
    if (!select) return;
    const current = selectedId != null ? String(selectedId) : String(select.value || '');
    select.innerHTML = '';
    list.forEach(e => {
      const opt = document.createElement('option');
      opt.value = e.employee_id;
      opt.textContent = capitalizeWords(`${e.first_name} ${e.last_name}`);
      if (current && String(current) === String(e.employee_id)) opt.selected = true;
      select.appendChild(opt);
    });
  }

  function renderEmployeeOptionsFor(selectId, list, selectedId){
    const select = document.getElementById(selectId);
    if (!select) return;
    const current = selectedId != null ? String(selectedId) : String(select.value || '');
    select.innerHTML = '';
    list.forEach(e => {
      const opt = document.createElement('option');
      opt.value = e.employee_id;
      opt.textContent = capitalizeWords(`${e.first_name} ${e.last_name}`);
      if (current && String(current) === String(e.employee_id)) opt.selected = true;
      select.appendChild(opt);
    });
  }

  async function fetchActiveLeaveTypes(){
    try {
      const res = await axios.get(`${window.baseApiUrl}/leave-types.php`, { params: { operation: 'listActive' } });
      return Array.isArray(res.data) ? res.data : [];
    } catch { return []; }
  }

  async function loadLeaveTypesOptions(selectId, current){
    const select = document.getElementById(selectId);
    if (!select) return;
    select.innerHTML = '';
    // Add placeholder hint
    const ph = document.createElement('option');
    ph.value = '';
    ph.textContent = 'Select leave type';
    ph.disabled = true;
    ph.selected = true;
    select.appendChild(ph);
    const types = await fetchActiveLeaveTypes();
    if (!types.length){
      // fallback to defaults (sorted A→Z)
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
    // Set current/default
    const val = String(current || '').toLowerCase();
    if (val && Array.from(select.options).some(o => String(o.value).toLowerCase() === val)) {
      select.value = val;
    } else if (!select.value && select.options.length){
      select.selectedIndex = 0;
    }
  }

  function resetForm() { fillForm({}); }

  function fillForm(l){
    document.getElementById('employee_id').value = l.employee_id || '';
    document.getElementById('lv_start').value = l.start_date || '';
    document.getElementById('lv_end').value = l.end_date || '';
    const typeEl = document.getElementById('lv_type'); if (typeEl) typeEl.value = l.leave_type || '';
    document.getElementById('lv_reason').value = l.reason || '';
  }

  async function saveLeave(){
    const payload = {
      employee_id: document.getElementById('employee_id').value,
      start_date: document.getElementById('lv_start').value,
      end_date: document.getElementById('lv_end').value,
      leave_type: (document.getElementById('lv_type')?.value || ''),
      reason: document.getElementById('lv_reason').value,
    };
    await axios.post(`${window.baseApiUrl}/leaves.php`, buildFormData({ operation: 'requestLeave', json: JSON.stringify(payload) }));
  }

  async function setStatus(leaveId, op){
    const operation = op === 'approve' ? 'approve' : 'reject';
    await axios.post(`${window.baseApiUrl}/leaves.php`, buildFormData({ operation, json: JSON.stringify({ leave_id: leaveId }) }));
  }

  function openView(leave){
    const modal = document.getElementById('hrLeaveViewModal');
    modal.querySelector('#lvw-emp').textContent = `${leave.first_name} ${leave.last_name}`;
    modal.querySelector('#lvw-dates').textContent = `${formatDate(leave.start_date)} → ${formatDate(leave.end_date)}`;
    modal.querySelector('#lvw-reason').textContent = leave.reason || '';
    modal.querySelector('#lvw-status').textContent = leave.status || 'pending';
    modal.classList.remove('hidden');
  }

  function badgeClass(status){
    const s = String(status||'').toLowerCase();
    if (s === 'approved') return 'bg-green-100 text-green-700';
    if (s === 'rejected') return 'bg-red-100 text-red-700';
    return 'bg-yellow-100 text-yellow-700';
  }
}

function buildFormData(map) {
  const fd = new FormData();
  Object.entries(map).forEach(([k, v]) => fd.append(k, v));
  return fd;
}
