/**
 * RENDER MANAGER LEAVE APPROVAL INTERFACE
 * Provides leave request approval system for department managers
 * Includes filtering, approval/rejection controls, and leave filing capability
 */
export async function render() {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h4 class="text-xl font-semibold">Leave Approvals</h4>
      <button id="mgr-btn-file-leave" class="inline-flex items-center px-3 py-2 text-sm font-medium rounded bg-primary-600 text-white hover:bg-primary-700">File Leave</button>
    </div>
    <div class="bg-white rounded-lg shadow p-4">
      <div class="mb-3 flex flex-wrap items-center gap-2">
        <div class="relative">
          <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M12.9 14.32a8 8 0 111.414-1.414l4.387 4.387a1 1 0 01-1.414 1.414l-4.387-4.387zM8 14a6 6 0 100-12 6 6 0 000 12z" clip-rule="evenodd"/></svg>
          <input id="mgr_lv_search" class="border rounded pl-8 pr-3 py-2 text-sm" placeholder="Search name, type or reason" />
        </div>
        <select id="mgr_lv_status_filter" class="border rounded px-3 py-2 text-sm">
          <option value="pending" selected>Pending</option>
          <option value="all">All Requested</option>
          <option value="approved">Approved</option>
          <option value="rejected">Rejected</option>
        </select>
        <input type="date" id="mgr_lv_on_date" class="border rounded px-3 py-2 text-sm" />
        <div class="ml-auto flex items-center gap-2 text-sm text-gray-600">
          <span>Rows per page</span>
          <select id="mgr_lv_page_size" class="border rounded px-2 py-1">
            <option value="5">5</option>
            <option value="10" selected>10</option>
            <option value="20">20</option>
            <option value="50">50</option>
          </select>
        </div>
      </div>
      <div id="mgr-leaves-table"></div>
      <div id="mgr-leaves-pagination" class="mt-3 flex items-center justify-between text-sm text-gray-600"></div>
    </div>

    <div id="mgrLeaveModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-lg">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">File Leave</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
          </div>
          <div class="p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
            <div class="md:col-span-2">
              <div class="relative">
                <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M12.9 14.32a8 8 0 111.414-1.414l4.387 4.387a1 1 0 01-1.414 1.414l-4.387-4.387zM8 14a6 6 0 100-12 6 6 0 000 12z" clip-rule="evenodd"/></svg>
                <input id="mgr-emp-search" class="w-full border rounded pl-8 pr-3 py-2" placeholder="Search employee..." />
              </div>
            </div>
            <div class="md:col-span-2">
              <label class="block text-sm text-gray-600 mb-1">Employee</label>
              <select id="mgr-employee-id" class="w-full border rounded px-3 py-2" required></select>
            </div>
            <div>
              <label class="block text-sm text-gray-600 mb-1">Start date</label>
              <input type="date" id="mgr-lv-start" class="w-full border rounded px-3 py-2" required />
            </div>
            <div>
              <label class="block text-sm text-gray-600 mb-1">End date</label>
              <input type="date" id="mgr-lv-end" class="w-full border rounded px-3 py-2" required />
            </div>
            <div>
              <label class="block text-sm text-gray-600 mb-1">Leave Type</label>
              <select id="mgr-lv-type" class="w-full border rounded px-3 py-2"></select>
            </div>
            <div class="md:col-span-2">
              <label class="block text-sm text-gray-600 mb-1">Reason</label>
              <textarea id="mgr-lv-reason" rows="3" class="w-full border rounded px-3 py-2"></textarea>
            </div>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
            <button id="mgr-lv-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
          </div>
        </div>
      </div>
    </div>`;

  // Helpers
  const capitalizeWords = (str) => {
    if (!str) return '';
    return String(str).split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ');
  };
  const formatDate = (dateStr) => {
    if (!dateStr) return '';
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return dateStr;
      return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch { return dateStr; }
  };
  const daysInclusive = (start, end) => {
    try {
      const a = new Date(start);
      const b = new Date(end || start);
      if (isNaN(a.getTime()) || isNaN(b.getTime())) return '';
      const diff = Math.floor((b - a) / (1000*60*60*24)) + 1;
      return diff > 0 ? diff : 1;
    } catch { return '';
    }
  };
  const badgeClass = (status) => {
    const s = String(status||'').toLowerCase();
    if (s === 'approved') return 'bg-green-100 text-green-700';
    if (s === 'rejected') return 'bg-red-100 text-red-700';
    return 'bg-yellow-100 text-yellow-700';
  };

  async function ensureSwal(){
    if (window.Swal) return;
    await new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://cdn.jsdelivr.net/npm/sweetalert2@11';
      s.onload = resolve;
      s.onerror = reject;
      document.head.appendChild(s);
    });
  }

  function swalToast({ icon = 'success', title = '', timer = 1500 } = {}){
    if (!window.Swal) { try { if (title) alert(title); } catch {} return; }
    const Toast = Swal.mixin({ toast: true, position: 'top-end', showConfirmButton: false, timer, timerProgressBar: true });
    Toast.fire({ icon, title });
  }

  async function me(){
    try {
      const res = await axios.get(`${window.baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
      return res.data && res.data.user ? res.data.user : null;
    } catch { return null; }
  }

  async function setStatus(leaveId, op){
    const operation = op === 'approve' ? 'approve' : 'reject';
    await axios.post(`${window.baseApiUrl}/leaves.php`, buildFormData({ operation, json: JSON.stringify({ leave_id: leaveId }) }), { withCredentials: true });
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
    const ph = document.createElement('option'); ph.value = ''; ph.textContent = 'Select leave type'; ph.disabled = true; ph.selected = true; select.appendChild(ph);
    const types = await fetchActiveLeaveTypes();
    if (!types.length){
      const defaults = ['vacation','sick leave','birthday leave','deductible against pay','maternity','paternity']
        .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
      defaults.forEach(n => { const opt = document.createElement('option'); opt.value = n.toLowerCase(); opt.textContent = n.replace(/\b\w/g, c => c.toUpperCase()); select.appendChild(opt); });
    } else {
      types.slice().sort((a,b)=> String(a.name||'').localeCompare(String(b.name||''), undefined, { sensitivity: 'base' }))
        .forEach(t => { const name = String(t.name||'').trim(); if (!name) return; const opt = document.createElement('option'); opt.value = name.toLowerCase(); opt.textContent = name; select.appendChild(opt); });
    }
    const val = String(current || '').toLowerCase();
    if (val && Array.from(select.options).some(o => String(o.value).toLowerCase() === val)) select.value = val;
    else if (!select.value && select.options.length) select.selectedIndex = 0;
  }

  // State for table
  let lvPage = 1;
  let lvPageSize = 10;
  const searchInput = document.getElementById('mgr_lv_search');
  const statusSelect = document.getElementById('mgr_lv_status_filter');
  const onDateInput = document.getElementById('mgr_lv_on_date');
  const pageSizeSelect = document.getElementById('mgr_lv_page_size');

  if (searchInput) searchInput.addEventListener('input', async () => { lvPage = 1; await loadLeaves(); });
  if (statusSelect) statusSelect.addEventListener('change', async () => { lvPage = 1; await loadLeaves(); });
  if (onDateInput) onDateInput.addEventListener('change', async () => { lvPage = 1; await loadLeaves(); });
  if (pageSizeSelect) pageSizeSelect.addEventListener('change', async () => { const n = Number(pageSizeSelect.value); lvPageSize = Number.isFinite(n) && n > 0 ? n : 10; lvPage = 1; await loadLeaves(); });

  await loadLeaves();

  async function loadLeaves(){
    const tableDiv = document.getElementById('mgr-leaves-table');
    tableDiv.innerHTML = '<div class="text-gray-500">Loading...</div>';

    const status = (document.getElementById('mgr_lv_status_filter')?.value || 'pending');

    let rows = [];
    try {
      const leavesOp = status === 'pending' ? 'listPending' : 'listRecent';
      const [user, empRes, leavesRes] = await Promise.all([
        me(),
        axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } }),
        axios.get(`${window.baseApiUrl}/leaves.php`, { params: { operation: leavesOp } })
      ]);
      const myDeptLc = (user && user.department ? String(user.department) : '').toLowerCase().trim();
      const myIdStr = user && user.employee_id ? String(user.employee_id) : '';
      const emps = Array.isArray(empRes.data) ? empRes.data : [];
      const allowed = new Set(emps
        .filter(e => String(e.department || '').toLowerCase().trim() === myDeptLc)
        .map(e => String(e.employee_id)));
      rows = (leavesRes.data || []).filter(r => allowed.has(String(r.employee_id)));
      // Exclude manager's own record if employee_id matches
      if (myIdStr) rows = rows.filter(r => String(r.employee_id) !== myIdStr);
    } catch { rows = []; }

    const q = (document.getElementById('mgr_lv_search')?.value || '').toLowerCase().trim();
    const onDate = document.getElementById('mgr_lv_on_date')?.value || null;

    if (status !== 'all') rows = rows.filter(r => (String(r.status || '').toLowerCase()) === status);
    if (onDate) rows = rows.filter(r => (!r.start_date || r.start_date <= onDate) && (!r.end_date || r.end_date >= onDate));
    if (q) rows = rows.filter(r => {
      const name = (`${r.first_name || ''} ${r.last_name || ''}`).toLowerCase();
      const reason = String(r.reason || '').toLowerCase();
      const typeStr = String(r.leave_type || '').toLowerCase();
      const idStr = String(r.leave_id || '').toLowerCase();
      return name.includes(q) || reason.includes(q) || typeStr.includes(q) || idStr.includes(q);
    });

    rows = rows.slice().sort((a,b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));

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
      tr.innerHTML = `<td colspan="10" class="px-3 py-6 text-sm text-center text-gray-500">No leave requests</td>`;
      tbody.appendChild(tr);
    } else {
      pageRows.forEach((l, i) => {
        const tr = document.createElement('tr');
        const name = capitalizeWords(`${l.first_name || ''} ${l.last_name || ''}`.trim());
        const type = capitalizeWords(l.leave_type || '');
        const days = daysInclusive(l.start_date, l.end_date);
        const submitted = formatDate(String(l.created_at || '').slice(0, 10));
        const approvedBy = capitalizeWords(l.approved_by_username || '') || '';
        tr.innerHTML = `
          <td class="px-3 py-2 text-sm text-gray-700">${startIdx + i + 1}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${name}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${type}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${formatDate(l.start_date)} → ${formatDate(l.end_date)}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${days}</td>
          <td class="px-3 py-2 text-sm text-gray-700 truncate max-w-[16rem]" title="${(l.reason||'').replace(/\"/g,'&quot;')}">${l.reason || ''}</td>
          <td class="px-3 py-2 text-sm"><span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${badgeClass(l.status)}">${capitalizeWords(l.status || 'pending')}</span></td>
          <td class="px-3 py-2 text-sm text-gray-700">${submitted}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${approvedBy}</td>
          <td class="px-3 py-2 text-sm text-right">
            ${String(l.status || '').toLowerCase() === 'pending' ? `
              <div class="relative inline-block text-left">
                <button type="button" class="inline-flex items-center justify-center w-8 h-8 rounded hover:bg-gray-100 focus:outline-none" data-menu="toggle" aria-haspopup="true" aria-expanded="false" title="Actions">
                  <span class="text-gray-600 font-bold text-lg leading-none select-none" aria-hidden="true">•••</span>
                </button>
                <div class="absolute right-0 mt-1 w-32 origin-top-right rounded-md bg-white shadow-lg ring-1 ring-black/5 focus:outline-none z-10 hidden" role="menu" data-menu="menu">
                  <div class="py-1">
                    <button class="w-full text-left px-3 py-1.5 text-sm text-green-700 hover:bg-green-50 inline-flex items-center gap-2" data-action="approve" role="menuitem">
                      <svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                      </svg>
                      <span>Approve</span>
                    </button>
                    <button class="w-full text-left px-3 py-1.5 text-sm text-red-700 hover:bg-red-50 inline-flex items-center gap-2" data-action="reject" role="menuitem">
                      <svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                      <span>Reject</span>
                    </button>
                  </div>
                </div>
              </div>
            ` : ''}
          </td>`;
        const menuToggle = tr.querySelector('[data-menu="toggle"]');
        const menu = tr.querySelector('[data-menu="menu"]');
        if (menuToggle && menu) {
          menuToggle.addEventListener('click', (ev) => {
            ev.stopPropagation();
            // Close other open menus within this table
            table.querySelectorAll('[data-menu="menu"]').forEach(m => { if (m !== menu) m.classList.add('hidden'); });
            menu.classList.toggle('hidden');
          });
        }
        // Global click to close any open menus (wired once)
        if (!document.__mgrLeavesMenuCloseWired) {
          document.addEventListener('click', () => {
            document.querySelectorAll('[data-menu="menu"]').forEach(m => m.classList.add('hidden'));
          });
          document.__mgrLeavesMenuCloseWired = true;
        }
        const approveBtn = tr.querySelector('[data-action="approve"]');
        const rejectBtn = tr.querySelector('[data-action="reject"]');
        if (approveBtn) approveBtn.addEventListener('click', async () => {
          try {
            await ensureSwal();
            const r = await Swal.fire({ title: 'Approve this leave?', icon: 'question', showCancelButton: true, confirmButtonText: 'Approve' });
            if (r.isConfirmed) { await setStatus(l.leave_id, 'approve'); swalToast({ icon: 'success', title: 'Approved' }); await loadLeaves(); }
          } catch { swalToast({ icon: 'error', title: 'Failed to approve' }); }
        });
        if (rejectBtn) rejectBtn.addEventListener('click', async () => {
          try {
            await ensureSwal();
            const r = await Swal.fire({ title: 'Reject this leave?', icon: 'warning', showCancelButton: true, confirmButtonText: 'Reject', confirmButtonColor: '#dc2626' });
            if (r.isConfirmed) { await setStatus(l.leave_id, 'reject'); swalToast({ icon: 'success', title: 'Rejected' }); await loadLeaves(); }
          } catch { swalToast({ icon: 'error', title: 'Failed to reject' }); }
        });
        tbody.appendChild(tr);
      });
    }
    tableDiv.innerHTML = '';
    tableDiv.appendChild(table);

    // Animate leave approval rows using anime.js (align with other manager pages)
    try {
      // Load anime.js if not already loaded
      if (!window.anime) {
        await new Promise((resolve) => {
          const s = document.createElement('script');
          s.src = 'https://cdnjs.cloudflare.com/ajax/libs/animejs/3.2.1/anime.min.js';
          s.async = true;
          s.onload = resolve; s.onerror = resolve;
          document.head.appendChild(s);
        });
      }
      const anime = window.anime;
      if (anime) {
        const rows = Array.from(tableDiv.querySelectorAll('tbody tr'));
        if (rows.length) {
          rows.forEach(r => { r.style.transformOrigin = '50% 50%'; r.style.opacity = '0'; });
          anime({
            targets: rows,
            translateY: [6, 0],
            scale: [0.99, 1],
            opacity: [0, 1],
            easing: 'easeOutQuad',
            duration: 260,
            delay: anime.stagger(20)
          });
        }
      }
    } catch {}

    const pager = document.getElementById('mgr-leaves-pagination');
    if (pager) {
      const showingFrom = total === 0 ? 0 : (startIdx + 1);
      const showingTo = endIdx;
      pager.innerHTML = `
        <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${total}</span></div>
        <div class="flex items-center gap-2">
          <button id="mgr-lv-prev" class="px-1.5 py-0.5 text-xs rounded border ${lvPage <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
          <span>Page ${lvPage} of ${totalPages}</span>
          <button id="mgr-lv-next" class="px-1.5 py-0.5 text-xs rounded border ${lvPage >= totalPages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
        </div>`;
      const prev = document.getElementById('mgr-lv-prev');
      const next = document.getElementById('mgr-lv-next');
      if (prev) prev.addEventListener('click', async () => { if (lvPage > 1) { lvPage -= 1; await loadLeaves(); } });
      if (next) next.addEventListener('click', async () => { if (lvPage < totalPages) { lvPage += 1; await loadLeaves(); } });
    }
  }

  // File Leave modal/controller
  const mgrLeaveModal = document.getElementById('mgrLeaveModal');
  const openMgrLeave = () => { mgrLeaveModal && mgrLeaveModal.classList.remove('hidden'); };
  const closeMgrLeave = () => { mgrLeaveModal && mgrLeaveModal.classList.add('hidden'); };
  if (mgrLeaveModal) mgrLeaveModal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeMgrLeave));

  let employeeList = [];
  async function loadEmployeesSelectForManager(selectedId){
    try {
      const [user, empRes] = await Promise.all([
        me(),
        axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } })
      ]);
      const myDeptLc = (user && user.department ? String(user.department) : '').toLowerCase().trim();
      const myIdStr = user && user.employee_id ? String(user.employee_id) : '';
      const list = (empRes.data || [])
        .filter(e => String(e.department || '').toLowerCase().trim() === myDeptLc)
        .filter(e => String(e.position || '').toLowerCase() !== 'hr')
        .filter(e => !myIdStr || String(e.employee_id) !== myIdStr);
      employeeList = list;
      renderEmployeeOptionsFor('mgr-employee-id', employeeList, selectedId);
    } catch { employeeList = []; renderEmployeeOptionsFor('mgr-employee-id', employeeList, selectedId); }
  }
  function renderEmployeeOptionsFor(selectId, list, selectedId){
    const select = document.getElementById(selectId);
    if (!select) return;
    const current = selectedId != null ? String(selectedId) : String(select.value || '');
    select.innerHTML = '';
    list.forEach(e => {
      const opt = document.createElement('option');
      opt.value = e.employee_id;
      opt.textContent = capitalizeWords(`${e.first_name || ''} ${e.last_name || ''}`.trim());
      if (current && String(current) === String(e.employee_id)) opt.selected = true;
      select.appendChild(opt);
    });
  }
  function resetLeaveForm(){
    const f = { emp: document.getElementById('mgr-employee-id'), s: document.getElementById('mgr-lv-start'), e: document.getElementById('mgr-lv-end'), t: document.getElementById('mgr-lv-type'), r: document.getElementById('mgr-lv-reason'), q: document.getElementById('mgr-emp-search') };
    if (f.s) f.s.value = '';
    if (f.e) f.e.value = '';
    if (f.t) f.t.value = '';
    if (f.r) f.r.value = '';
    if (f.q) f.q.value = '';
  }
  function wireMgrEmpSearch(){
    const search = document.getElementById('mgr-emp-search');
    if (!search) return;
    search.oninput = () => {
      const q = (search.value || '').toLowerCase().trim();
      const selected = document.getElementById('mgr-employee-id')?.value || '';
      const filtered = !q ? employeeList.slice() : employeeList.filter(e => `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.includes(q) || String(e.email||'').toLowerCase().includes(q));
      renderEmployeeOptionsFor('mgr-employee-id', filtered, selected);
    };
  }

  const btnFileLeave = document.getElementById('mgr-btn-file-leave');
  if (btnFileLeave) btnFileLeave.addEventListener('click', async () => {
    // Open admin-style modal (in-page) instead of SweetAlert
    await loadEmployeesSelectForManager();
    await loadLeaveTypesOptions('mgr-lv-type', '');
    resetLeaveForm();
    wireMgrEmpSearch();
    // Show the in-page modal matching admin File Leave design
    const modal = document.getElementById('mgrLeaveModal');
    if (modal) modal.classList.remove('hidden');
  });

  const saveBtn = document.getElementById('mgr-lv-save');
  if (saveBtn) saveBtn.addEventListener('click', async () => {
    const employee_id = document.getElementById('mgr-employee-id')?.value;
    const start_date = document.getElementById('mgr-lv-start')?.value;
    const end_date = document.getElementById('mgr-lv-end')?.value;
    const leave_type = (document.getElementById('mgr-lv-type')?.value || '');
    const reason = document.getElementById('mgr-lv-reason')?.value || '';
    if (!employee_id || !start_date || !end_date || !leave_type) { try { await ensureSwal(); } catch {}; swalToast({ icon: 'warning', title: 'Fill employee, dates and leave type' }); return; }
    try {
      const fd = new FormData();
      fd.append('operation', 'requestLeave');
      fd.append('json', JSON.stringify({ employee_id, start_date, end_date, leave_type, reason }));
      await axios.post(`${window.baseApiUrl}/leaves.php`, fd);
      closeMgrLeave();
      try { await ensureSwal(); } catch {}
      swalToast({ icon: 'success', title: 'Leave request submitted' });
      await loadLeaves();
    } catch {
      try { await ensureSwal(); } catch {}
      swalToast({ icon: 'error', title: 'Failed to submit leave' });
    }
  });
}

function buildFormData(map) {
  const fd = new FormData();
  Object.entries(map).forEach(([k, v]) => fd.append(k, v));
  return fd;
}
