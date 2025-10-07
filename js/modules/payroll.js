/**
 * RENDER PAYROLL MANAGEMENT INTERFACE
 * Main function that renders the payroll processing system
 * Includes payroll generation, employee selection, and archive management
 */
export async function render() {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h4 class="text-xl font-semibold">Payroll</h4>
      <div class="flex items-center gap-2">
        <button id="mark-all-paid" class="inline-flex items-center px-3 py-2 text-sm font-medium rounded bg-emerald-600 text-white hover:bg-emerald-700">Paid All</button>
        <button id="open-process-card" class="inline-flex items-center px-3 py-2 text-sm font-medium rounded bg-primary-600 text-white hover:bg-primary-700">Process Payroll</button>
      </div>
    </div>
    <div class="bg-white rounded-lg shadow h-full">
      <div class="p-4">
        <div class="flex items-center justify-between mb-3">
          <div class="flex items-center gap-2">
                        <div class="relative">
              <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
              <input id="pay-search-input" class="w-56 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search by name, period" />
            </div>
                        <select id="proc-dept-filter" class="border rounded px-2 py-1 text-sm">
              <option value="all" selected>All Departments</option>
            </select>
            <select id="proc-status-filter" class="border rounded px-2 py-1 text-sm">
              <option value="all" selected>All</option>
              <option value="processed">Processed</option>
              <option value="paid">Paid</option>
            </select>
                        </div>
                      <div class="flex items-center gap-2">
                        <button id="pay-open-removed" class="inline-flex items-center justify-center w-9 h-9 rounded border border-gray-200 hover:bg-gray-50" title="View archived">
                          <svg class="w-5 h-5 text-gray-700" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7h18M5 7v12a2 2 0 002 2h10a2 2 0 002-2V7M9 11h6" />
                          </svg>
                        </button>
                        <button id="pay-remove-all" class="inline-flex items-center px-3 py-1.5 text-sm font-medium rounded bg-red-600 text-white hover:bg-red-700" title="Archive all filtered">Archive All</button>
                        <select id="pay-page-size" class="border rounded px-2 py-1 text-sm">
                          <option value="10" selected>10</option>
                          <option value="25">25</option>
                          <option value="50">50</option>
                          <option value="100">100</option>
                        </select>
                      </div>
                  </div>
        <div id="payroll-table"></div>
      </div>
    </div>

    <div id="procModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-lg">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h6 class="font-semibold">Process Payroll</h6>
            <button id="close-process-card" class="text-gray-500 hover:text-gray-700 text-xl leading-none" aria-label="Close" data-close="true">×</button>
          </div>
          <div class="p-4">
            <div class="space-y-3">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label class="block text-sm text-gray-600 mb-1">Pay Period Start</label>
                  <input type="date" id="proc-period-start" class="w-full border rounded px-3 py-2" required />
                </div>
                <div>
                  <label class="block text-sm text-gray-600 mb-1">Pay Period End</label>
                  <input type="date" id="proc-period-end" class="w-full border rounded px-3 py-2" required />
                </div>
              </div>
              <div class="mt-2">
                <div class="mb-2">
                  <div class="flex flex-col gap-2">
                    <div class="flex items-center gap-2">
                      <div class="relative">
                        <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
                        <input id="proc-emp-search" class="w-64 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search employees" />
                      </div>
                      <select id="proc-emp-dept-filter" class="border rounded px-2 py-1 text-sm">
                        <option value="all" selected>All Departments</option>
                      </select>
                    </div>
                    <label class="inline-flex items-center gap-2 text-sm text-gray-700 mt-1">
                      <input id="proc-emp-select-all" type="checkbox" class="rounded border-gray-300" />
                      <span>Select all</span>
                    </label>
                  </div>
                </div>
                <div id="proc-emp-list" class="border rounded max-h-64 overflow-y-auto divide-y divide-gray-100 bg-white">
                  <div class="p-3 text-sm text-gray-500">Loading employees...</div>
                </div>
                <div class="mt-1 text-xs text-gray-500"><span id="proc-emp-selected-count">0</span> selected</div>
              </div>
            </div>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button id="proc-cancel" class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
            <button id="proc-generate" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Process</button>
          </div>
        </div>
      </div>
    </div>`;

  // Inject View modal (floating card)
  app.insertAdjacentHTML('beforeend', `
    <div id="viewPayrollModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-lg">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h6 class="font-semibold">Payroll Details</h6>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" aria-label="Close" data-close="true">×</button>
          </div>
          <div class="p-4">
            <div class="space-y-2 text-sm">
              <div><span class="text-gray-500">Employee:</span> <span id="vp-employee" class="font-medium"></span></div>
              <div><span class="text-gray-500">Pay Period:</span> <span id="vp-period" class="font-medium"></span></div>
              <div class="grid grid-cols-2 gap-2 mt-2">
                <div><span class="text-gray-500">Total Work Days</span><div id="vp-workdays" class="font-medium"></div></div>
                <div><span class="text-gray-500">Total Overtime Hours</span><div id="vp-ot-hours" class="font-medium"></div></div>
                <div><span class="text-gray-500">Overtime Pay</span><div id="vp-otpay" class="font-medium"></div></div>
                <div><span class="text-gray-500">Late Deductions</span><div id="vp-late-ded" class="font-medium"></div></div>
                <div><span class="text-gray-500">Absent Deductions</span><div id="vp-absent-ded" class="font-medium"></div></div>
                <div><span class="text-gray-500">Gross Pay</span><div id="vp-gross" class="font-medium"></div></div>
                <div><span class="text-gray-500">Withholding</span><div id="vp-withholding" class="font-medium"></div></div>
                <div><span class="text-gray-500">SSS</span><div id="vp-sss" class="font-medium"></div></div>
                <div><span class="text-gray-500">PhilHealth</span><div id="vp-philhealth" class="font-medium"></div></div>
                <div><span class="text-gray-500">Pag-IBIG</span><div id="vp-pagibig" class="font-medium"></div></div>
                <div><span class="text-gray-500">Provident Fund</span><div id="vp-provident" class="font-medium"></div></div>
                <div><span class="text-gray-500">Total Deductions</span><div id="vp-deductions" class="font-medium"></div></div>
                <div class="col-span-2"><span class="text-gray-500">Net Pay</span><div id="vp-net" class="font-semibold text-gray-900"></div></div>
              </div>
            </div>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
          </div>
        </div>
      </div>
    </div>
  `);

  app.insertAdjacentHTML('beforeend', `
    <div id="editPayrollModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-lg">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h6 class="font-semibold">Edit Payroll</h6>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" aria-label="Close" data-close="true">×</button>
          </div>
          <div class="p-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label class="block text-sm text-gray-600 mb-1">Pay Period Start</label>
                <input type="date" id="edit-period-start" class="w-full border rounded px-3 py-2" required />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Pay Period End</label>
                <input type="date" id="edit-period-end" class="w-full border rounded px-3 py-2" required />
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Status</label>
                <select id="edit-status" class="w-full border rounded px-3 py-2">
                  <option value="processed">processed</option>
                  <option value="paid">paid</option>
                </select>
              </div>
            </div>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
            <button id="edit-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
          </div>
        </div>
      </div>
    </div>
  `);

  // Removed items modal
  app.insertAdjacentHTML('beforeend', `
    <div id="removedPayrollModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-2xl">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h6 class="font-semibold">Archive Payroll Items</h6>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" aria-label="Close" data-close="true">×</button>
          </div>
          <div class="p-4">
            <div class="flex items-center justify-between mb-3">
              <div class="relative">
                <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
                <input id="removed-search-input" class="w-64 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search archived items" />
              </div>
            </div>
            <div id="removed-list-wrap" class="max-h-[60vh] overflow-y-auto"></div>
          </div>
          <div class="flex justify-between items-center gap-2 border-t px-4 py-3">
            <div class="text-sm text-gray-600" id="removed-count"></div>
            <div class="flex gap-2">
              <button id="removed-clear" class="px-3 py-2 text-sm rounded border">Clear</button>
              <button id="removed-restore-all" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Restore All</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  `);

  // SweetAlert2 helpers for notifications and confirmations
  async function ensureSwal(){
    try {
      if (window.Swal) return;
      if (window.ensureSweetAlertAssets) { await window.ensureSweetAlertAssets(); return; }
      await new Promise((resolve) => {
        let pending = 0; const done = () => { if (--pending <= 0) resolve(); };
        if (!document.getElementById('swal2-css')){
          pending++;
          const link = document.createElement('link');
          link.id = 'swal2-css';
          link.rel = 'stylesheet';
          link.href = 'https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css';
          link.onload = done; link.onerror = done;
          document.head.appendChild(link);
        }
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
    } catch {}
  }
  function swalToast(message, icon = 'info'){
    try {
      if (!window.Swal) { try { console.log(String(message)); } catch {}; return; }
      const Toast = Swal.mixin({ toast: true, position: 'top-end', showConfirmButton: false, timer: 1500, timerProgressBar: true });
      Toast.fire({ icon, title: String(message) });
    } catch {}
  }

  let allPayroll = [];
  let currentQuery = '';
  let pageSize = 10;
  let currentPage = 1;
  let removedQuery = '';

  // Process Payroll modal: employee selection, search, and checkboxes
  let procAllEmployees = [];
  let procFilteredEmployees = [];
  const procSelected = new Set();
  let procUiBound = false;

  function updateProcSelectedCount() {
    const el = document.getElementById('proc-emp-selected-count');
    if (el) el.textContent = String(procSelected.size);
  }

  function renderProcEmployees() {
    const list = document.getElementById('proc-emp-list');
    if (!list) return;
    if (!procFilteredEmployees.length) {
      list.innerHTML = '<div class="p-3 text-sm text-gray-500">No employees</div>';
      const sa = document.getElementById('proc-emp-select-all');
      if (sa) { sa.checked = false; sa.indeterminate = false; }
      return;
    }
    list.innerHTML = procFilteredEmployees.map(e => {
      const id = e.employee_id;
      const checked = procSelected.has(String(id)) ? 'checked' : '';
      const name = `${e.first_name || ''} ${e.last_name || ''}`.trim();
      return `<label class="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-gray-50">
        <input type="checkbox" class="rounded border-gray-300 proc-emp-cb" data-id="${id}" ${checked} />
        <span class="text-sm text-gray-800">${name}</span>
      </label>`;
    }).join('');
    const sa = document.getElementById('proc-emp-select-all');
    if (sa) {
      const allIds = procFilteredEmployees.map(e => String(e.employee_id));
      const allSelected = allIds.length > 0 && allIds.every(id => procSelected.has(id));
      sa.checked = allSelected;
      sa.indeterminate = !allSelected && allIds.some(id => procSelected.has(id));
    }
  }

  async function ensureProcEmployeesLoaded() {
    if (!Array.isArray(procAllEmployees) || procAllEmployees.length === 0) {
      try {
        const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
        const all = Array.isArray(res.data) ? res.data : [];
        procAllEmployees = all.filter(e => String(e.status || '').toLowerCase() === 'active');
      } catch (e) {
        procAllEmployees = [];
      }
    }
    procFilteredEmployees = procAllEmployees.slice();
    if (!procUiBound) {
      const search = document.getElementById('proc-emp-search');
      const selectAll = document.getElementById('proc-emp-select-all');
      const list = document.getElementById('proc-emp-list');
      if (search) {
        const deptSel = document.getElementById('proc-emp-dept-filter');
        const applyProcFilters = () => {
          const q = (search.value || '').toLowerCase();
          const dval = deptSel ? (deptSel.value || 'all') : 'all';
          procFilteredEmployees = procAllEmployees.filter(e => {
            const name = `${e.first_name || ''} ${e.last_name || ''}`.toLowerCase();
            const dept = String(e.department || '').toLowerCase();
            const deptOk = (dval.toLowerCase() === 'all') ? true : (dept === dval.toLowerCase());
            return name.includes(q) && deptOk;
          });
          renderProcEmployees();
          updateProcSelectedCount();
        };
        search.addEventListener('input', applyProcFilters);
        if (deptSel) deptSel.addEventListener('change', applyProcFilters);
        // Populate departments for modal filter
        if (deptSel && !deptSel.__loaded) {
          deptSel.__loaded = true;
          (async () => {
            try {
              const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getDepartments' } });
              const depts = Array.isArray(res.data) ? res.data : [];
              const currentVal = deptSel.value;
              deptSel.innerHTML = '<option value="all">All Departments</option>' + depts.map(d => `<option value="${d}">${d}</option>`).join('');
              if (currentVal && (currentVal === 'all' || depts.includes(currentVal))) deptSel.value = currentVal;
            } catch (e) {
              const depts = Array.from(new Set(procAllEmployees.map(x => x.department).filter(Boolean)));
              const currentVal = deptSel.value;
              deptSel.innerHTML = '<option value="all">All Departments</option>' + depts.map(d => `<option value="${d}">${d}</option>`).join('');
              if (currentVal && (currentVal === 'all' || depts.includes(currentVal))) deptSel.value = currentVal;
            }
          })();
        }
      }
      if (selectAll) {
        selectAll.addEventListener('change', () => {
          const allIds = procFilteredEmployees.map(e => String(e.employee_id));
          if (selectAll.checked) { allIds.forEach(id => procSelected.add(id)); }
          else { allIds.forEach(id => procSelected.delete(id)); }
          renderProcEmployees();
          updateProcSelectedCount();
        });
      }
      if (list) {
        list.addEventListener('change', (ev) => {
          const t = ev.target;
          if (t && t.classList && t.classList.contains('proc-emp-cb')) {
            const id = String(t.getAttribute('data-id') || '');
            if (t.checked) procSelected.add(id); else procSelected.delete(id);
            updateProcSelectedCount();
            const sa = document.getElementById('proc-emp-select-all');
            if (sa) {
              const allIds = procFilteredEmployees.map(e => String(e.employee_id));
              const allSelected = allIds.length > 0 && allIds.every(x => procSelected.has(x));
              sa.checked = allSelected;
              sa.indeterminate = !allSelected && allIds.some(x => procSelected.has(x));
            }
          }
        });
      }
      procUiBound = true;
    }
    renderProcEmployees();
    updateProcSelectedCount();
  }

  const paySearchInput = document.getElementById('pay-search-input');
  const paySearchClear = document.getElementById('pay-search-clear');
  if (paySearchInput) {
    paySearchInput.addEventListener('input', () => {
      currentQuery = (paySearchInput.value || '').trim().toLowerCase();
      currentPage = 1;
      renderPayrollTable();
    });
  }
  if (paySearchClear) {
    paySearchClear.addEventListener('click', (e) => {
      e.preventDefault();
      if (paySearchInput) paySearchInput.value = '';
      currentQuery = '';
      currentPage = 1;
      renderPayrollTable();
    });
  }
  const procDeptFilter = document.getElementById('proc-dept-filter');
  if (procDeptFilter) {
    procDeptFilter.addEventListener('change', () => { currentPage = 1; renderPayrollTable(); });
  }
  const procStatusFilter = document.getElementById('proc-status-filter');
  if (procStatusFilter) {
    procStatusFilter.addEventListener('change', () => { currentPage = 1; renderPayrollTable(); });
  }
  const pageSizeSelect = document.getElementById('pay-page-size');
  if (pageSizeSelect) {
    pageSizeSelect.addEventListener('change', () => {
      const num = Number(pageSizeSelect.value);
      pageSize = Number.isFinite(num) && num > 0 ? num : 10;
      currentPage = 1;
      renderPayrollTable();
    });
  }

  // Remove All and View Removed bindings
  const removeAllBtn = document.getElementById('pay-remove-all');
  if (removeAllBtn) {
    removeAllBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const rows = getFilteredPayroll();
      if (!rows.length) { try { await ensureSwal(); swalToast('No payroll records to archive for current filters.','warning'); } catch {} return; }
      await ensureSwal();
      { const resSw = await Swal.fire({ icon: 'warning', title: `Archive ${rows.length} payroll record(s)?`, showCancelButton: true, confirmButtonText: 'Archive', cancelButtonText: 'Cancel' }); if (!resSw.isConfirmed) return; }
      try {
        removeAllBtn.disabled = true;
        const fd = new FormData();
        fd.append('operation', 'archivePayrollBulk');
        fd.append('json', JSON.stringify({ payroll_ids: rows.map(r => r.payroll_id) }));
        const res = await axios.post(`${window.baseApiUrl}/payroll.php`, fd);
        const info = res && res.data ? res.data : {};
        await ensureSwal();
        swalToast('Archived', (info.failed ? 'warning' : 'success'));
        await loadPayroll();
      } catch (err) {
        console.error('Archive all failed:', err);
        try { await ensureSwal(); await Swal.fire({ icon: 'error', title: 'Failed to archive payroll records' }); } catch {}
      } finally {
        removeAllBtn.disabled = false;
      }
    });
  }
  const openRemovedBtn = document.getElementById('pay-open-removed');
  if (openRemovedBtn) {
    openRemovedBtn.addEventListener('click', (e) => { e.preventDefault(); openRemovedModal(); });
  }
  const removedModal = document.getElementById('removedPayrollModal');
  if (removedModal && !removedModal.__bound) {
    removedModal.__bound = true;
    removedModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', (e) => { e.preventDefault(); closeRemovedModal(); }));
    const restoreAll = removedModal.querySelector('#removed-restore-all');
    if (restoreAll) restoreAll.addEventListener('click', async (e) => {
      e.preventDefault();
      await ensureSwal();
      { const r = await Swal.fire({ icon: 'warning', title: 'Restore all archived payroll records?', showCancelButton: true, confirmButtonText: 'Restore', cancelButtonText: 'Cancel' }); if (!r.isConfirmed) return; }
      try {
        const fd = new FormData();
        fd.append('operation', 'unarchiveAllPayroll');
        await axios.post(`${window.baseApiUrl}/payroll.php`, fd);
        await loadPayroll();
        await renderRemovedList();
        closeRemovedModal();
      } catch (err) {
        console.error('Restore all failed:', err);
        try { await ensureSwal(); await Swal.fire({ icon: 'error', title: 'Failed to restore archived payroll records' }); } catch {}
      }
    });
    const clearBtn = removedModal.querySelector('#removed-clear');
    if (clearBtn) clearBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      await ensureSwal();
      { const r = await Swal.fire({ icon: 'warning', title: 'Clear archived items?', text: 'This will unarchive all payroll records.', showCancelButton: true, confirmButtonText: 'Clear', cancelButtonText: 'Cancel' }); if (!r.isConfirmed) return; }
      try {
        const fd = new FormData();
        fd.append('operation', 'unarchiveAllPayroll');
        await axios.post(`${window.baseApiUrl}/payroll.php`, fd);
        await loadPayroll();
        await renderRemovedList();
      } catch (err) {
        console.error('Clear archive failed:', err);
        try { await ensureSwal(); await Swal.fire({ icon: 'error', title: 'Failed to clear archive' }); } catch {}
      }
    });
    const removedSearch = removedModal.querySelector('#removed-search-input');
    if (removedSearch) removedSearch.addEventListener('input', () => { removedQuery = (removedSearch.value || '').trim().toLowerCase(); renderRemovedList(); });
  }

  // Process Payroll interactions
  const openProcessBtn = document.getElementById('open-process-card');
  const procModal = document.getElementById('procModal');
  const closeProcessBtn = document.getElementById('close-process-card');
  const cancelProcessBtn = document.getElementById('proc-cancel');
  const procGenerateBtn = document.getElementById('proc-generate');
  const markAllPaidBtn = document.getElementById('mark-all-paid');
    const openProc = () => procModal && procModal.classList.remove('hidden');
  const closeProc = () => procModal && procModal.classList.add('hidden');
  if (procModal) {
    procModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', (e) => { e.preventDefault(); closeProc(); }));
  }

  if (openProcessBtn && procModal) {
    openProcessBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      await ensureProcEmployeesLoaded();
      const s = document.getElementById('proc-emp-search'); if (s) s.value = '';
      const df = document.getElementById('proc-emp-dept-filter'); if (df) df.value = 'all';
      const sa = document.getElementById('proc-emp-select-all'); if (sa) { sa.checked = false; sa.indeterminate = false; }
      procSelected.clear(); updateProcSelectedCount();
      // Reset to show all employees after clearing filters
      procFilteredEmployees = procAllEmployees.slice();
      renderProcEmployees();
      openProc();
    });
  }

  if (procGenerateBtn) procGenerateBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    await processPayroll();
    closeProc();
    await loadPayroll();
  });

  if (markAllPaidBtn) markAllPaidBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      // Limit to current filtered rows and only those not yet paid
      const rows = getFilteredPayroll().filter(r => String(r.status) !== 'paid');
      if (!rows.length) { try { await ensureSwal(); swalToast('No processed payrolls to mark as paid for the current filters.','warning'); } catch {} return; }
      await ensureSwal();
      { const r = await Swal.fire({ icon: 'warning', title: `Mark ${rows.length} payroll record(s) as paid?`, showCancelButton: true, confirmButtonText: 'Yes, mark paid', cancelButtonText: 'Cancel' }); if (!r.isConfirmed) return; }
      markAllPaidBtn.disabled = true;
      const prevText = markAllPaidBtn.textContent;
      markAllPaidBtn.textContent = 'Processing...';
      let success = 0, failed = 0;
      for (const r of rows) {
        try {
          const fd = new FormData();
          fd.append('operation', 'updateStatus');
          fd.append('payroll_id', String(r.payroll_id));
          fd.append('status', 'paid');
          await axios.post(`${window.baseApiUrl}/payroll.php`, fd);
          success++;
        } catch (err) { failed++; }
      }
      markAllPaidBtn.disabled = false;
      markAllPaidBtn.textContent = prevText;
      await loadPayroll();
      try { await ensureSwal(); swalToast('Completed', failed ? 'warning' : 'success'); } catch {}
    } catch (err) {
      console.error('Bulk mark paid failed:', err);
      try { await ensureSwal(); await Swal.fire({ icon: 'error', title: 'Failed to mark all as paid' }); } catch {}
      try { markAllPaidBtn.disabled = false; markAllPaidBtn.textContent = 'Paid All'; } catch {}
    }
  });

  await loadPayroll();

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

  // Helper to format monetary amounts with thousand separators
  function formatAmount(val) {
    const num = Number(val || 0);
    return num.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }

  // Removed items helpers and modal
  function loadRemoved(){
    try { return JSON.parse(localStorage.getItem('payroll_removed') || '[]'); } catch { return []; }
  }
  function saveRemoved(items){
    try { localStorage.setItem('payroll_removed', JSON.stringify(items || [])); } catch {}
  }
  function openRemovedModal(){
    const m = document.getElementById('removedPayrollModal');
    if (!m) return;
    const s = m.querySelector('#removed-search-input'); if (s) s.value = removedQuery || '';
    renderRemovedList();
    m.classList.remove('hidden');
  }
  function closeRemovedModal(){
    const m = document.getElementById('removedPayrollModal');
    if (!m) return;
    m.classList.add('hidden');
  }
  async function renderRemovedList(){
    const wrap = document.getElementById('removed-list-wrap');
    const countEl = document.getElementById('removed-count');
    if (!wrap) return;
    wrap.innerHTML = '<div class="text-gray-500">Loading...</div>';
    let items = [];
    try {
      const res = await axios.get(`${window.baseApiUrl}/payroll.php`, { params: { operation: 'listPayrollArchive' } });
      items = Array.isArray(res.data) ? res.data : [];
    } catch (e) { items = []; }
    if (removedQuery) {
      const q = removedQuery;
      items = items.filter(r => {
        const name = `${r.first_name || ''} ${r.last_name || ''}`.toLowerCase();
        const dept = String(r.department || '').toLowerCase();
        const pid = `PR-${String(r.payroll_id || 0).padStart(3,'0')}`.toLowerCase();
        const period = `${r.payroll_period_start || ''} ${r.payroll_period_end || ''}`.toLowerCase();
        const status = String(r.status || '').toLowerCase();
        return name.includes(q) || dept.includes(q) || pid.includes(q) || period.includes(q) || status.includes(q);
      });
    }
    if (countEl) countEl.textContent = `${items.length} item(s) archived`;
    if (!items.length){
      wrap.innerHTML = '<div class="text-sm text-gray-500">No archived items.</div>';
      return;
    }
    const rows = items.map((r, idx) => `
      <tr class="border-b">
        <td class="px-3 py-2 text-sm text-gray-700">${idx+1}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${`PR-${String(r.payroll_id || 0).toString().padStart(3, '0')}`}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${(r.first_name || '')} ${(r.last_name || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${(r.department || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${formatDate(r.payroll_period_start)} → ${formatDate(r.payroll_period_end)}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${String(r.status || 'processed')}</td>
      </tr>
    `).join('');
    wrap.innerHTML = `
      <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Payroll ID</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Department</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Period</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-200 bg-white">${rows}</tbody>
      </table>
    `;
  }

  async function loadPayroll() {
    const tableDiv = document.getElementById('payroll-table');
    tableDiv.innerHTML = '<div class="text-gray-500">Loading...</div>';
    const params = { operation: 'listPayroll' };
    const [response, empRes] = await Promise.all([
      axios.get(`${window.baseApiUrl}/payroll.php`, { params }),
      axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } })
    ]);
    const employees = Array.isArray(empRes.data) ? empRes.data : [];
    const deptOf = new Map(employees.map(e => [String(e.employee_id), e.department || '']));
    allPayroll = (response.data || []).map(r => Object.assign({}, r, { department: r.department || deptOf.get(String(r.employee_id)) || '' }));
    // Populate department filter (load all departments from server; fallback to current dataset)
    const deptSel = document.getElementById('proc-dept-filter');
    if (deptSel) {
      try {
        const resDepts = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getDepartments' } });
        const depts = Array.isArray(resDepts.data) ? resDepts.data : [];
        const currentVal = deptSel.value;
        deptSel.innerHTML = '<option value="all">All Departments</option>' + depts.map(d => `<option value="${d}">${d}</option>`).join('');
        if (currentVal && (currentVal === 'all' || depts.includes(currentVal))) deptSel.value = currentVal;
      } catch (e) {
        const depts = Array.from(new Set(allPayroll.map(r => r.department).filter(Boolean))).sort((a,b)=>String(a).localeCompare(String(b)));
        const currentVal = deptSel.value;
        deptSel.innerHTML = '<option value="all">All Departments</option>' + depts.map(d => `<option value="${d}">${d}</option>`).join('');
        if (currentVal && (currentVal === 'all' || depts.includes(currentVal))) deptSel.value = currentVal;
      }
    }
    currentPage = 1;
    renderPayrollTable();
  }

  function getFilteredPayroll() {
    const q = (currentQuery || '').toLowerCase();
    const statusSel = document.getElementById('proc-status-filter');
    const statusFilter = statusSel ? (statusSel.value || 'all') : 'all';
    const deptSel = document.getElementById('proc-dept-filter');
    const deptFilter = deptSel ? (deptSel.value || 'all') : 'all';
    let base = allPayroll.slice();
    if (statusFilter !== 'all') {
      base = base.filter(r => (statusFilter === 'paid') ? (String(r.status) === 'paid') : (String(r.status) !== 'paid'));
    }
    if (deptFilter !== 'all') {
      const d = String(deptFilter).toLowerCase();
      base = base.filter(r => String(r.department || '').toLowerCase() === d);
    }
    if (!q) return base;
    return base.filter(r => {
      const name = `${r.first_name || ''} ${r.last_name || ''}`.toLowerCase();
      const period = `${r.payroll_period_start || ''} ${r.payroll_period_end || ''}`.toLowerCase();
      const dept = String(r.department || '').toLowerCase();
      return name.includes(q) || period.includes(q) || dept.includes(q);
    });
  }

  // Paid status helpers and View/Edit controllers
  function getPaidMap(){ try { return JSON.parse(localStorage.getItem('payroll_paid') || '{}'); } catch { return {}; } }
  function isPaid(id){ const map = getPaidMap(); return !!map[String(id)]; }
  function markPaid(id){ const map = getPaidMap(); map[String(id)] = true; localStorage.setItem('payroll_paid', JSON.stringify(map)); }
  function unmarkPaid(id){ const map = getPaidMap(); delete map[String(id)]; localStorage.setItem('payroll_paid', JSON.stringify(map)); }

  function getPeriodOverrideMap(){ try { return JSON.parse(localStorage.getItem('payroll_period_overrides') || '{}'); } catch { return {}; } }
  function setPeriodOverride(id, start, end){ const map = getPeriodOverrideMap(); map[String(id)] = { start, end }; localStorage.setItem('payroll_period_overrides', JSON.stringify(map)); }
  function getEffectivePeriod(r){ const map = getPeriodOverrideMap(); const ov = map[String(r.payroll_id)] || {}; return { start: ov.start || r.payroll_period_start, end: ov.end || r.payroll_period_end } }

  let currentViewRecord = null;
  const viewModal = document.getElementById('viewPayrollModal');
  const openView = () => viewModal && viewModal.classList.remove('hidden');
  const closeView = () => viewModal && viewModal.classList.add('hidden');
  if (viewModal) { viewModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', (e) => { e.preventDefault(); closeView(); })); }

  async function openViewFor(r){
    currentViewRecord = r;
    const name = `${r.first_name} ${r.last_name}`;
    const gross = (Number(r.net_pay || 0) + Number(r.deductions || 0));
    const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setText('vp-employee', name);
    const eff = getEffectivePeriod(r);
    setText('vp-period', `${formatDate(eff.start)} to ${formatDate(eff.end)}`);
    setText('vp-gross', formatAmount(gross));
    setText('vp-withholding', formatAmount(r.tax_deduction || 0));
    setText('vp-sss', formatAmount(r.sss_deduction || 0));
    setText('vp-philhealth', formatAmount(r.philhealth_deduction || 0));
    setText('vp-pagibig', formatAmount(r.pagibig_deduction || 0));
    setText('vp-provident', formatAmount(r.provident_fund_deduction || 0));
    setText('vp-deductions', formatAmount(r.deductions || 0));
    setText('vp-net', formatAmount(r.net_pay || 0));
    // Populate overtime and attendance deduction details
    try {
      const eff2 = getEffectivePeriod(r);
      const fd = new FormData();
      fd.append('operation','calculatePayrollDeductions');
      fd.append('json', JSON.stringify({ employee_id: r.employee_id, start_date: eff2.start, end_date: eff2.end }));
      const res = await axios.post(`${window.baseApiUrl}/attendance-deductions.php`, fd);
      const summary = res && res.data && res.data.summary ? res.data.summary : null;
      if (summary) {
        // Prefer gross pay computed from period days + overtime (attendance-deductions)
        const grossFromSummary = Number(summary.gross_pay || 0);
        if (grossFromSummary > 0) setText('vp-gross', formatAmount(grossFromSummary));
        setText('vp-workdays', String(summary.total_work_days || 0));
        setText('vp-late-ded', Number(summary.total_late_deduction || 0).toFixed(2));
        setText('vp-absent-ded', Number(summary.total_absent_deduction || 0).toFixed(2));
        // Compute overall overtime hours from total overtime pay, per-minute rate, and multiplier
        const perMin = Number(res?.data?.formulas_used?.per_minute_rate || 0);
        const otMult = Number(res?.data?.formulas_used?.overtime_multiplier || 0) || 1;
        const otPay = Number(summary.total_overtime_pay || 0);
        const calcHours = (perMin > 0 && otMult > 0) ? (otPay / (perMin * otMult) / 60) : null;
        const hrs = Number(calcHours != null ? calcHours : (r.total_overtime_hours || 0));
        const hrsStr = Number.isFinite(hrs) ? ((Math.abs(hrs - Math.round(hrs)) < 1e-9) ? String(Math.round(hrs)) : hrs.toFixed(2)) : '0';
        setText('vp-ot-hours', `${hrsStr}hours`);
        setText('vp-otpay', formatAmount(otPay));
      } else {
        const hrs2 = Number(r.total_overtime_hours || 0);
        const hrs2Str = Number.isFinite(hrs2) ? ((Math.abs(hrs2 - Math.round(hrs2)) < 1e-9) ? String(Math.round(hrs2)) : hrs2.toFixed(2)) : '0';
        setText('vp-ot-hours', `${hrs2Str}hours`);
        setText('vp-otpay', formatAmount(r.overtime_pay || 0));
      }
    } catch(e) {
      // ignore
    }
        openView();
  }


  // Edit modal controller
  const editModal = document.getElementById('editPayrollModal');
  const editSaveBtn = document.getElementById('edit-save');
  const openEdit = () => editModal && editModal.classList.remove('hidden');
  const closeEdit = () => editModal && editModal.classList.add('hidden');
  if (editModal) { editModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', (e) => { e.preventDefault(); closeEdit(); })); }
  let currentEditRecord = null;
  function openEditFor(r){
    currentEditRecord = r;
    const eff = getEffectivePeriod(r);
    const paid = String(r.status) === 'paid';
    const startEl = document.getElementById('edit-period-start');
    const endEl = document.getElementById('edit-period-end');
    const statusEl = document.getElementById('edit-status');
    if (startEl) startEl.value = eff.start || '';
    if (endEl) endEl.value = eff.end || '';
    if (statusEl) statusEl.value = paid ? 'paid' : 'processed';
    openEdit();
  }
  if (editSaveBtn) {
    editSaveBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      if (!currentEditRecord) return;
      const start = document.getElementById('edit-period-start').value;
      const end = document.getElementById('edit-period-end').value;
      const status = document.getElementById('edit-status').value;
      setPeriodOverride(currentEditRecord.payroll_id, start, end);
      try {
        const fd = new FormData();
        fd.append('operation', 'updateStatus');
        fd.append('payroll_id', String(currentEditRecord.payroll_id));
        fd.append('status', status);
        await axios.post(`${window.baseApiUrl}/payroll.php`, fd);
        await loadPayroll();
      } catch (err) {
        console.error('Failed to update payroll status:', err);
      }
      closeEdit();
    });
  }

  async function downloadPayslip(r) {
    try {
      if (String(r.status) !== 'paid') {
        try { await ensureSwal(); swalToast('Cannot download payslip. Status is not paid.','warning'); } catch {}
        return;
      }
      const fmtProcessed = (() => {
        const s = r.created_at || '';
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
      const rows = [
        ['Employee', `${r.first_name || ''} ${r.last_name || ''}`.trim()],
        ['Pay Period Start', r.payroll_period_start || ''],
        ['Pay Period End', r.payroll_period_end || ''],
        ['Basic Salary', Number(r.basic_salary || 0).toFixed(2)],
        ['Total Overtime Hours', (() => { const h = Number(r.total_overtime_hours || 0); const s = Number.isFinite(h) ? ((Math.abs(h - Math.round(h)) < 1e-9) ? String(Math.round(h)) : h.toFixed(2)) : '0'; return `${s}hours`; })()],
        ['Overtime Pay', Number(r.overtime_pay || 0).toFixed(2)],
        ['SSS Deduction', Number(r.sss_deduction || 0).toFixed(2)],
        ['PhilHealth Deduction', Number(r.philhealth_deduction || 0).toFixed(2)],
        ['Pag-IBIG Deduction', Number(r.pagibig_deduction || 0).toFixed(2)],
        ['Provident Fund Deduction', Number(r.provident_fund_deduction || 0).toFixed(2)],
        ['Tax Deduction', Number(r.tax_deduction || 0).toFixed(2)],
        ['Other Deductions', Number((r.deductions || 0) - (r.sss_deduction || 0) - (r.philhealth_deduction || 0) - (r.pagibig_deduction || 0) - (r.provident_fund_deduction || 0) - (r.tax_deduction || 0)).toFixed(2)],
        ['Total Deductions', Number(r.deductions || 0).toFixed(2)],
        ['Net Pay', Number(r.net_pay || 0).toFixed(2)],
        ['Processed Date', fmtProcessed]
      ];
      // Render payslip image on canvas (real format)
      // Preload company logo
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
      const money = (n) => Number(n || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

      // Background
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, width, height);

      // Border
      ctx.strokeStyle = '#e5e7eb';
      ctx.lineWidth = 2;
      ctx.strokeRect(margin/2, margin/2, width - margin, height - margin);

      // Header
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

      // Subtitle with period (custom formatted: 'august 1 -> August 30, 2025')
      const fmtPayPeriod = (() => {
        const s = r.payroll_period_start || '';
        const e = r.payroll_period_end || '';
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
        return `${s} → ${e}`;
      })();
      ctx.font = '400 18px Arial';
      ctx.fillStyle = '#374151';
      ctx.fillText(`Pay Period: ${fmtPayPeriod}`, margin, margin + 50);
      // Period summary (Total Work Days, Total Overtime Hours)
      let twdText = 'Total Work Days: 0';
      let tohText = 'Total Overtime Hours: 0hours';
      try {
        const fd2 = new FormData();
        fd2.append('operation','calculatePayrollDeductions');
        fd2.append('json', JSON.stringify({ employee_id: r.employee_id, start_date: r.payroll_period_start, end_date: r.payroll_period_end }));
        const res2 = await axios.post(`${window.baseApiUrl}/attendance-deductions.php`, fd2);
        const sum = res2 && res2.data && res2.data.summary ? res2.data.summary : null;
        const fm = res2 && res2.data && res2.data.formulas_used ? res2.data.formulas_used : null;
        if (sum) {
          let twd = Number(sum.total_work_days || 0);
          if (!(twd > 0)) {
            const s2 = new Date(r.payroll_period_start || '');
            const e2 = new Date(r.payroll_period_end || '');
            const ms2 = 24*60*60*1000;
            twd = (isNaN(s2) || isNaN(e2)) ? 0 : Math.max(0, Math.round((Date.UTC(e2.getFullYear(),e2.getMonth(),e2.getDate()) - Date.UTC(s2.getFullYear(),s2.getMonth(),s2.getDate()))/ms2));
          }
          twdText = `Total Work Days: ${twd}`;
          // compute hours from pay and per-minute rate
          const perMin = Number(fm?.per_minute_rate || 0);
          const otMult = Number(fm?.overtime_multiplier || 1) || 1;
          const otPay = Number(sum.total_overtime_pay || 0);
          let hours = 0;
          if (perMin > 0 && otMult > 0) { hours = otPay / (perMin * otMult) / 60; }
          else { hours = Number(r.total_overtime_hours || 0); }
          const hrsStr = Number.isFinite(hours) ? ((Math.abs(hours - Math.round(hours)) < 1e-9) ? String(Math.round(hours)) : hours.toFixed(2)) : '0';
          tohText = `Total Overtime Hours: ${hrsStr}hours`;
        } else {
          // Fallbacks
          const s = new Date(r.payroll_period_start || '');
          const e = new Date(r.payroll_period_end || '');
          const ms = 24*60*60*1000;
          const twd = (isNaN(s) || isNaN(e)) ? 0 : Math.max(0, Math.round((Date.UTC(e.getFullYear(),e.getMonth(),e.getDate()) - Date.UTC(s.getFullYear(),s.getMonth(),s.getDate()))/ms));
          twdText = `Total Work Days: ${twd}`;
          const h = Number(r.total_overtime_hours || 0);
          const hrsStr = Number.isFinite(h) ? ((Math.abs(h - Math.round(h)) < 1e-9) ? String(Math.round(h)) : h.toFixed(2)) : '0';
          tohText = `Total Overtime Hours: ${hrsStr}hours`;
        }
      } catch {}
      ctx.fillText(twdText, margin, margin + 72);
      ctx.fillText(tohText, margin, margin + 92);

      // Divider under summary
      ctx.strokeStyle = '#e5e7eb';
      ctx.beginPath();
      ctx.moveTo(margin, margin + 104);
      ctx.lineTo(width - margin, margin + 104);
      ctx.stroke();

      // Employee info
      let y = margin + 130;
      const lineGap = 34;
      const name = `${r.first_name || ''} ${r.last_name || ''}`.trim();
      const periodDate = r.payroll_period_end || r.payroll_period_start || r.created_at || '';
      let year;
      try {
        const d = new Date(periodDate);
        year = isNaN(d.getTime()) ? String(new Date().getFullYear()) : String(d.getFullYear());
      } catch { year = String(new Date().getFullYear()); }
      const paddedId = String(r.employee_id || '').padStart(3, '0');
      const displayEmpId = `EMP${year}-${paddedId}`;
      const fmtProcessedInfo = (() => {
        const s = r.created_at || '';
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
        ['Payroll ID', `PR-${String(r.payroll_id || 0).toString().padStart(3, '0')}`],
        ['Processed Date', fmtProcessedInfo]
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

      // Divider
      y += 20;
      ctx.strokeStyle = '#e5e7eb';
      ctx.beginPath();
      ctx.moveTo(margin, y);
      ctx.lineTo(width - margin, y);
      ctx.stroke();

      // Columns
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
        ['Basic Salary', Number(r.basic_salary || 0)],
        ['Overtime Pay', Number(r.overtime_pay || 0)]
      ];
      earnings.forEach(([label, amt]) => {
        ctx.fillText(label, colLeftX, leftY);
        ctx.textAlign = 'right';
        ctx.fillText(money(amt), colRightX - 40, leftY);
        ctx.textAlign = 'left';
        leftY += lineGap;
      });

      let rightY = y;
      // Fetch attendance-based deduction breakdown (late, undertime, absent)
      let attSummary = null;
      try {
        const fd2 = new FormData();
        fd2.append('operation','calculatePayrollDeductions');
        fd2.append('json', JSON.stringify({ employee_id: r.employee_id, start_date: r.payroll_period_start, end_date: r.payroll_period_end }));
        const res2 = await axios.post(`${window.baseApiUrl}/attendance-deductions.php`, fd2);
        attSummary = res2 && res2.data && res2.data.summary ? res2.data.summary : null;
      } catch {}
      const statSSS = Number(r.sss_deduction || 0);
      const statPH = Number(r.philhealth_deduction || 0);
      const statPagibig = Number(r.pagibig_deduction || 0);
      const statProvident = Number(r.provident_fund_deduction || 0);
      const statTax = Number(r.tax_deduction || 0);
      const lateDed = Number(attSummary?.total_late_deduction || 0);
      const utDed = Number(attSummary?.total_undertime_deduction || 0);
      const absDed = Number(attSummary?.total_absent_deduction || 0);
      const otherDed = Math.max(0, Number(r.deductions || 0) - statSSS - statPH - statPagibig - statProvident - statTax - lateDed - utDed - absDed);
      const deductions = [
        ['SSS', statSSS],
        ['PhilHealth', statPH],
        ['Pag-IBIG', statPagibig],
        ['Provident Fund', statProvident],
        ['Withholding Tax', statTax],
        ['Late Deductions', lateDed],
        ['Undertime Deductions', utDed],
        ['Absent Deductions', absDed],
        ['Other Deductions', otherDed]
      ];
      deductions.forEach(([label, amt]) => {
        ctx.fillText(label, colRightX, rightY);
        ctx.textAlign = 'right';
        ctx.fillText(money(amt), width - margin, rightY);
        ctx.textAlign = 'left';
        rightY += lineGap;
      });

      // Totals
      let totalsY = Math.max(leftY, rightY) + 20;
      ctx.strokeStyle = '#e5e7eb';
      ctx.beginPath();
      ctx.moveTo(margin, totalsY);
      ctx.lineTo(width - margin, totalsY);
      ctx.stroke();

      totalsY += 40;
      const gross = Number(r.net_pay || 0) + Number(r.deductions || 0);
      const totalDeductions = Number(r.deductions || 0);
      const net = Number(r.net_pay || 0);

      ctx.font = '600 20px Arial';
      ctx.fillStyle = '#111827';
      const labelX = colLeftX;
      const valueX = width - margin;

      const drawRow = (label, amount) => {
        ctx.fillText(label, labelX, totalsY);
        ctx.textAlign = 'right';
        ctx.fillText(money(amount), valueX, totalsY);
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
      ctx.fillText(money(net), valueX, totalsY);
      ctx.textAlign = 'left';

      // Signature
      let footY = totalsY + 80;
      ctx.font = '400 16px Arial';
      ctx.fillStyle = '#6b7280';
      ctx.fillText('This payslip is a system-generated document.', margin, footY);
      footY += 80;
      ctx.strokeStyle = '#9ca3af';
      ctx.beginPath();
      ctx.moveTo(margin, footY);
      ctx.lineTo(margin + 260, footY);
      ctx.moveTo(width - margin - 260, footY);
      ctx.lineTo(width - margin, footY);
      ctx.stroke();
      ctx.fillStyle = '#374151';
      ctx.fillText('Prepared By', margin, footY + 24);
      ctx.textAlign = 'right';
      ctx.fillText('Received By', width - margin, footY + 24);
      ctx.textAlign = 'left';

      // Download image
      const dataUrl = canvas.toDataURL('image/png');
      const a = document.createElement('a');
      const sanitize = (s) => String(s || '').replace(/[^a-z0-9]+/gi, '_').replace(/^_+|_+$/g, '').toLowerCase();
      const fname = `payslip_${sanitize(r.last_name || 'employee')}_${sanitize(r.payroll_period_end || 'period')}.png`;
      a.href = dataUrl;
      a.download = fname;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => { try { document.body.removeChild(a); } catch {} }, 200);
    } catch (e) { console.error('Failed to download payslip:', e); }
  }

  function renderPayrollTable() {
    const tableDiv = document.getElementById('payroll-table');
    if (!tableDiv) return;
    const rows = getFilteredPayroll();
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
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Payroll ID</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Employee</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Department</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Date</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
          <th class="px-3 py-2 text-center text-xs font-semibold text-gray-600">Actions</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-200 bg-white"></tbody>`;
    const tbody = table.querySelector('tbody');

    if (!pageRows.length) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="7" class="px-3 py-6 text-sm text-center text-gray-500">No payroll records</td>`;
      tbody.appendChild(tr);
    } else {

    pageRows.forEach((r, i) => {
      const tr = document.createElement('tr');
      const name = capitalizeWords(`${r.first_name} ${r.last_name}`);
      const displayIndex = startIdx + i + 1;
      const processedDateStr = formatDate(r.created_at || new Date());
      const paid = String(r.status) === 'paid';
      tr.innerHTML = `
        <td class="px-3 py-2 text-sm text-gray-700">${displayIndex}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${`PR-${String(r.payroll_id || 0).toString().padStart(3, '0')}`}</td>
        <td class="px-3 py-2 text-sm text-gray-700">
          <div class="text-gray-800">${name}</div>
          <div class="text-xs text-gray-500">ID: ${(() => { const d = new Date(r.payroll_period_end || r.payroll_period_start || r.created_at || new Date()); const y = isNaN(d.getTime()) ? new Date().getFullYear() : d.getFullYear(); return `EMP${y}-${String(r.employee_id || 0).toString().padStart(3,'0')}`; })()}</div>
        </td>
        <td class="px-3 py-2 text-sm text-gray-700">${capitalizeWords(r.department || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${formatDate(r.payroll_period_start)} → ${formatDate(r.payroll_period_end)}</td>
        <td class="px-3 py-2 text-sm text-gray-700"><button class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${paid ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'} hover:ring-2 hover:ring-primary-600 focus:outline-none" data-action="toggle-status" data-id="${r.payroll_id}" data-status="${paid ? 'paid' : 'processed'}">${capitalizeWords(paid ? 'paid' : 'processed')}</button></td>
        <td class="px-3 py-2 text-sm text-center">
          <div class="relative inline-flex justify-center" data-pay-menu-container>
            <button class="inline-flex items-center justify-center w-8 h-8 rounded hover:bg-gray-100" aria-label="Actions" data-action="menu-toggle">
              <span class="text-gray-600 font-bold text-lg">•••</span>
            </button>
            <div class="hidden origin-top-right absolute right-0 mt-2 w-36 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 z-10" role="menu" data-menu>
              <div class="py-1">
                <button class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50" data-menu-action="view" role="menuitem">View</button>
                <button class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50" data-menu-action="edit" role="menuitem">Edit</button>
                ${paid
                  ? `<button class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50" data-menu-action="download" role="menuitem">Download</button>`
                  : `<button class="w-full text-left px-3 py-2 text-sm opacity-50 cursor-not-allowed" disabled title="Available when paid">Download</button>`}
                <button class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50" data-menu-action="archive" role="menuitem">Archive</button>
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
          document.querySelectorAll('[data-pay-menu-container] [data-menu]').forEach(m => m.classList.add('hidden'));
          menu.classList.toggle('hidden');
        });
      }
      const onView = tr.querySelector('[data-menu-action="view"]');
      if (onView) onView.addEventListener('click', (ev) => { ev.preventDefault(); if (menu) menu.classList.add('hidden'); openViewFor(r); });
      const onEdit = tr.querySelector('[data-menu-action="edit"]');
      if (onEdit) onEdit.addEventListener('click', (ev) => { ev.preventDefault(); if (menu) menu.classList.add('hidden'); openEditFor(r); });
      const onDownload = tr.querySelector('[data-menu-action="download"]');
      if (onDownload) onDownload.addEventListener('click', (ev) => { ev.preventDefault(); if (menu) menu.classList.add('hidden'); downloadPayslip(r); });
      const onArchive = tr.querySelector('[data-menu-action="archive"]');
      if (onArchive) onArchive.addEventListener('click', async (ev) => {
        ev.preventDefault();
        if (menu) menu.classList.add('hidden');
        await ensureSwal();
        { const rSw = await Swal.fire({ icon: 'warning', title: 'Archive this payroll record?', showCancelButton: true, confirmButtonText: 'Archive', cancelButtonText: 'Cancel' }); if (!rSw.isConfirmed) return; }
        try {
          const fd = new FormData();
          fd.append('operation', 'archivePayrollBulk');
          fd.append('json', JSON.stringify({ payroll_ids: [r.payroll_id] }));
          await axios.post(`${window.baseApiUrl}/payroll.php`, fd);
          await loadPayroll();
        } catch (err) {
          console.error('Archive payroll failed:', err);
          try { await ensureSwal(); await Swal.fire({ icon: 'error', title: 'Failed to archive payroll' }); } catch {}
        }
      });
      const statusBtn = tr.querySelector('[data-action="toggle-status"]');
      if (statusBtn) statusBtn.addEventListener('click', async (ev) => {
        ev.preventDefault();
        const curr = (statusBtn.getAttribute('data-status') || '').toLowerCase();
        const next = curr === 'paid' ? 'processed' : 'paid';
        await ensureSwal();
        { const rSw = await Swal.fire({ icon: 'question', title: 'Change status?', text: 'Change status to ' + next + '?', showCancelButton: true, confirmButtonText: 'Change', cancelButtonText: 'Cancel' }); if (!rSw.isConfirmed) return; }
        statusBtn.disabled = true;
        try {
          const fd = new FormData();
          fd.append('operation', 'updateStatus');
          fd.append('payroll_id', String(r.payroll_id));
          fd.append('status', next);
          await axios.post(`${window.baseApiUrl}/payroll.php`, fd);
          await loadPayroll();
        } catch (err) {
          console.error('Failed to update payroll status:', err);
          try { await ensureSwal(); await Swal.fire({ icon: 'error', title: 'Failed to update status' }); } catch {}
        } finally {
          statusBtn.disabled = false;
        }
      });
      tbody.appendChild(tr);
    });

    }

    tableDiv.innerHTML = '';
    tableDiv.appendChild(table);
    const footer = document.createElement('div');
    footer.id = 'payroll-pagination';
    footer.className = 'mt-3 flex items-center justify-between text-sm text-gray-600';
    const showingFrom = total === 0 ? 0 : (startIdx + 1);
    const showingTo = endIdx;
    footer.innerHTML = `
      <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${total}</span></div>
      <div class="flex items-center gap-2">
        <button id="pay-prev" class="px-2 py-1 text-xs rounded border ${currentPage <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
        <span>Page ${currentPage} of ${totalPages}</span>
        <button id="pay-next" class="px-2 py-1 text-xs rounded border ${currentPage >= totalPages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
      </div>`;
    tableDiv.appendChild(footer);
    const prev = document.getElementById('pay-prev');
    const next = document.getElementById('pay-next');
    if (prev) prev.addEventListener('click', () => { if (currentPage > 1) { currentPage -= 1; renderPayrollTable(); } });
    if (next) next.addEventListener('click', () => { if (currentPage < totalPages) { currentPage += 1; renderPayrollTable(); } });
    if (!window.__payMenuGlobalClose) {
      window.__payMenuGlobalClose = true;
      document.addEventListener('click', () => {
        document.querySelectorAll('[data-pay-menu-container] [data-menu]').forEach(m => m.classList.add('hidden'));
      });
    }
  }


  async function processPayroll(){
    try {
      const start = document.getElementById('proc-period-start').value;
      const end = document.getElementById('proc-period-end').value;
      if (!start || !end) { try { await ensureSwal(); swalToast('Select a valid pay period start and end','warning'); } catch {} return; }
      // Fetch employees and process payroll for all active employees
      const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
      const all = Array.isArray(res.data) ? res.data : [];
      const active = all.filter(e => String(e.status || '').toLowerCase() === 'active');
      // Narrow to selected employees from the Process Payroll modal
      const selectedIds = Array.from(procSelected).map(id => String(id));
      if (selectedIds.length === 0) { try { await ensureSwal(); swalToast('Select at least one employee to process','warning'); } catch {} return; }
      const toProcess = active.filter(e => selectedIds.includes(String(e.employee_id)));
      await ensureSwal();
      try {
        Swal.fire({ title: 'Processing payroll', html: 'Please wait...', allowOutsideClick: false, didOpen: () => { try { Swal.showLoading(); } catch {} } });
      } catch {}
      let __pp_ok = 0, __pp_fail = 0;
      for (const e of toProcess) {
        const payload = {
          employee_id: e.employee_id,
          payroll_period_start: start,
          payroll_period_end: end,
          overtime_hours: 0,
          overtime_rate: 0,
          deductions: 0
        };
        const fd = new FormData();
        fd.append('operation', 'generatePayroll');
        fd.append('json', JSON.stringify(payload));
        try { await axios.post(`${window.baseApiUrl}/payroll.php`, fd); __pp_ok++; } catch { __pp_fail++; }
      }
      try { Swal.close(); } catch {}
      try { swalToast('Payroll processed', __pp_fail ? 'warning' : 'success'); } catch {}
    } catch (err) {
      console.error('Error processing payroll:', err);
    }
  }
}
