/**
 * RENDER EMPLOYEE MANAGEMENT INTERFACE
 * Main function that renders the employee management system
 * Handles CRUD operations, filtering, and role-based access
 */
async function ensureAnimeEmployees(){
  return new Promise((resolve) => {
    if (window.anime) return resolve(window.anime);
    const s = document.createElement('script');
    s.src = 'https://cdnjs.cloudflare.com/ajax/libs/animejs/3.2.1/anime.min.js';
    s.async = true;
    s.onload = () => resolve(window.anime);
    s.onerror = () => resolve(null);
    document.head.appendChild(s);
  });
}
export async function render() {
  const app = document.getElementById('app');
  // Local state for filtering and pagination
  let allEmployees = [];
  let currentQuery = '';
  let currentPage = 1;
  let pageSize = 10;
  let departmentOptions = [];
  let currentDeptFilter = '';
  let currentEditingOriginalRole = null;
  const roleOptions = isHrPortal()
    ? '<option value="employee">Employee</option>'
    : '<option value="employee">Employee</option><option value="hr">HR</option><option value="manager">Manager</option>';
  app.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h4 class="text-xl font-semibold">Employees</h4>
      <button id="btn-add-employee" class="inline-flex items-center px-3 py-2 text-sm font-medium rounded bg-primary-600 text-white hover:bg-primary-700">Add Employee</button>
    </div>
    <div id="employees-stats" class="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4"></div>
    <div class="bg-white rounded-lg shadow p-4">
      <div class="mb-3 flex items-center justify-between gap-3">
        <div class="flex items-center gap-2">
          <div class="relative">
            <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
            <input id="emp-search-input" class="w-56 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search by name, department, role" />
          </div>
          <button id="emp-search-clear" aria-label="Clear search" class="inline-flex items-center gap-1.5 border border-gray-300 rounded px-2.5 py-1 text-sm text-gray-700 hover:bg-gray-50 active:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1">
            <svg class="w-4 h-4 text-gray-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
            <span>Clear</span>
          </button>
          <select id="emp-dept-filter" class="border rounded px-2 py-1 text-sm">
            <option value="">All departments</option>
          </select>
        </div>
        <div class="flex items-center gap-2">
          <span class="text-sm text-gray-600">Rows per page</span>
          <select id="emp-page-size" class="border rounded px-2 py-1">
            <option value="10" selected>10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </div>
      </div>
      <div id="employees-table"></div>
      <div id="employees-pagination" class="mt-3 flex items-center justify-between text-sm text-gray-600"></div>
    </div>

    <div id="employeeModal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-lg">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold" id="employeeModalLabel">Add Employee</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
          </div>
          <div class="p-4 max-h-[70vh] overflow-y-auto">
            <form id="employee-form" class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <input type="hidden" id="employee_id" />
              <div>
                <label class="block text-sm text-gray-600 mb-1">Employee ID</label>
                <input class="w-full border rounded px-3 py-2 bg-gray-50" id="employee_id_visible" placeholder="Auto-generated" readonly />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">First name</label>
                <input class="w-full border rounded px-3 py-2" id="first_name" required />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Last name</label>
                <input class="w-full border rounded px-3 py-2" id="last_name" required />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Middle name</label>
                <input class="w-full border rounded px-3 py-2" id="middle_name" required />
              </div>

              <div>
                <label class="block text-sm text-gray-600 mb-1">Date of Birth</label>
                <input class="w-full border rounded px-3 py-2" id="date_of_birth" type="date" required />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Gender</label>
                <select class="w-full border rounded px-3 py-2" id="gender" required>
                  <option value="">Select gender</option>
                  <option value="male">Male</option>
                  <option value="female">Female</option>
                </select>
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm text-gray-600 mb-1">Address</label>
                <textarea class="w-full border rounded px-3 py-2" id="address" rows="2" required></textarea>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Email</label>
                <input class="w-full border rounded px-3 py-2" id="email" type="email" required />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Phone</label>
                <input class="w-full border rounded px-3 py-2" id="phone" required />
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Role</label>
                <select class="w-full border rounded px-3 py-2" id="user_role" required>${roleOptions}</select>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Department</label>
                <select class="w-full border rounded px-3 py-2" id="department" required>
                  <option value="">Select department</option>
                </select>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Position</label>
                <select class="w-full border rounded px-3 py-2" id="position" required>
                  <option value="">Select position</option>
                </select>
              </div>
              <div id="date_hired_wrap">
                <label class="block text-sm text-gray-600 mb-1">Date Hired</label>
                <input class="w-full border rounded px-3 py-2" id="date_hired" type="date" />
              </div>
              <div id="hr_pw_wrap" class="hidden">
                <label class="block text-sm text-gray-600 mb-1">Account Password</label>
                <input class="w-full border rounded px-3 py-2" id="hr_password" type="password" placeholder="Set a password (optional for employees)" />
                <div class="text-xs text-gray-500 mt-1">Optional for employees (leave blank to auto-generate). Required for HR. Username will be the email address.</div>
              </div>
              <div class="md:col-span-2 pt-2">
                <div class="text-sm font-semibold text-gray-700 mb-2">Payroll Information</div>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Salary Rate</label>
                <select class="w-full border rounded px-3 py-2" id="salary_rate_type" required>
                  <option value="semi_monthly">Semi-Monthly (15 days)</option>
                  <option value="monthly">Monthly</option>
                  <option value="weekly">Weekly</option>
                </select>
                <div class="text-xs text-gray-500 mt-1">Choose how base pay is computed.</div>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Basic Salary</label>
                <input class="w-full border rounded px-3 py-2" id="basic_salary" type="number" step="0.01" placeholder="Enter base pay (e.g., 100000.00)" required />
                <div class="text-xs text-gray-500 mt-1">Gross base pay per selected rate.</div>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Bank Account Number</label>
                <input class="w-full border rounded px-3 py-2" id="bank_account" placeholder="e.g., 0123456789" />
                <div class="text-xs text-gray-500 mt-1">Optional. Used for payroll deposits.</div>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Tax ID (TIN)</label>
                <input class="w-full border rounded px-3 py-2" id="tax_id" placeholder="e.g., 123-456-789-000" />
                <div class="text-xs text-gray-500 mt-1">Optional. Used for tax reporting.</div>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">SSS Number</label>
                <input class="w-full border rounded px-3 py-2" id="sss_number" placeholder="e.g., 12-3456789-0" />
                <div class="text-xs text-gray-500 mt-1">Optional. Used for SSS contributions.</div>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">PhilHealth Number</label>
                <input class="w-full border rounded px-3 py-2" id="philhealth_number" placeholder="e.g., 12-345678901-2" />
                <div class="text-xs text-gray-500 mt-1">Optional. Used for PhilHealth contributions.</div>
              </div>
              <div>
                <label class="block text-sm text-gray-600 mb-1">Pag-IBIG Number</label>
                <input class="w-full border rounded px-3 py-2" id="pagibig_number" placeholder="e.g., 1234-5678-9012" />
                <div class="text-xs text-gray-500 mt-1">Optional. Used for Pag-IBIG contributions.</div>
              </div>
                          </form>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
            <button id="save-employee" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
          </div>
        </div>
      </div>
    </div>`;

  const modalEl = document.getElementById('employeeModal');
  const addEmpBtn = document.getElementById('btn-add-employee');
  if (isManagerPortal() && addEmpBtn) addEmpBtn.classList.add('hidden');
  const openModal = () => modalEl.classList.remove('hidden');
  const closeModal = () => modalEl.classList.add('hidden');
  modalEl.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeModal));

  const roleSelect = document.getElementById('user_role');
  const hrPwWrap = document.getElementById('hr_pw_wrap');
  const syncHrPwVisibility = () => {
    if (!roleSelect || !hrPwWrap) return;
    const show = ['hr','employee','manager'].includes(String(roleSelect.value || '').toLowerCase());
    hrPwWrap.classList.toggle('hidden', !show);
  };
  if (roleSelect) {
    roleSelect.addEventListener('change', syncHrPwVisibility);
    // In HR portal, lock the role to Employee
    if (isHrPortal()) {
      roleSelect.value = 'employee';
      roleSelect.disabled = true;
    }
  }

  document.getElementById('btn-add-employee').addEventListener('click', async () => {
    await loadDepartmentOptions();
    // Ensure we have the latest employees so we can compute the next employee number for display
    await loadEmployees();
    resetForm();
    currentEditingOriginalRole = null;
    // Set visible Employee ID to next formatted value for new employees
    const vis = document.getElementById('employee_id_visible');
    if (vis) {
      const nextId = computeNextEmployeeId();
      vis.value = formatEmployeeCode(nextId);
    }
    document.getElementById('employeeModalLabel').innerText = 'Add Employee';
    const dhw = document.getElementById('date_hired_wrap'); if (dhw) dhw.classList.remove('hidden');
    // Load positions for selected department on open
    try { await loadPositionOptions(document.getElementById('department')?.value || ''); } catch {}
    openModal();
  });

  document.getElementById('save-employee').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const { operation, ok, position, username_updated, username_conflict, generated_password, created_employee_id, plain_password } = await saveEmployee();
      if (ok) {
        closeModal();
        await loadEmployees();
        ensureToastContainer();
        const updatedFullName = toTitleCase(`${document.getElementById('first_name')?.value || ''} ${document.getElementById('last_name')?.value || ''}`.trim());
        const msg = operation === 'createEmployee'
          ? (position === 'hr' ? 'HR user added successfully' : 'Employee added successfully')
          : `Successfully updated: ${updatedFullName}`;
        showToast(msg, 'success');
        if (username_updated) {
          showToast('HR username updated to the new email.', 'success');
        }
        if (username_conflict) {
          showToast('New email is already used by another account. Username not changed.', 'error');
        }
        if (generated_password) {
          showToast(`Temporary password: ${generated_password}`, 'success');
        } else if (plain_password) {
          showToast(`Temporary password: ${plain_password}`, 'success');
        }
        const newRole = (document.getElementById('user_role')?.value || '').toLowerCase();
        const origRole = (currentEditingOriginalRole || '').toLowerCase();
        if (operation === 'updateEmployee' && origRole && origRole !== newRole) {
          if (newRole === 'hr') {
            showToast('Role set to HR. The user can access the dashboard.', 'success');
          } else if (newRole === 'manager') {
            showToast('Role set to Manager. The user can access the manager dashboard.', 'success');
          } else if (newRole === 'employee') {
            showToast('Role set to Employee. The user can access the employee portal.', 'success');
          }
        }
        if (operation === 'createEmployee' && created_employee_id) {
          try { await ensureQrLib(); } catch {}
          showEmployeeQr({
            id: created_employee_id,
            first: document.getElementById('first_name')?.value || '',
            last: document.getElementById('last_name')?.value || ''
          });
        }
      }
    } finally {
      btn.disabled = false;
    }
  });

  // Wire search and page size controls
  const searchInput = document.getElementById('emp-search-input');
  const searchClear = document.getElementById('emp-search-clear');
  const pageSizeSelect = document.getElementById('emp-page-size');
  if (searchInput) {
    const handleSearch = () => {
      currentQuery = (searchInput.value || '').trim().toLowerCase();
      currentPage = 1;
      renderEmployeesTable();
    };
    searchInput.addEventListener('input', handleSearch);
  }
  if (searchClear) {
    searchClear.addEventListener('click', () => {
      if (searchInput) searchInput.value = '';
      currentQuery = '';
      currentPage = 1;
      renderEmployeesTable();
    });
  }
  if (pageSizeSelect) {
    pageSizeSelect.addEventListener('change', () => {
      const num = Number(pageSizeSelect.value);
      pageSize = Number.isFinite(num) && num > 0 ? num : 10;
      currentPage = 1;
      renderEmployeesTable();
    });
  }
  const deptFilterSelect = document.getElementById('emp-dept-filter');
  if (deptFilterSelect) {
    deptFilterSelect.addEventListener('change', () => {
      currentDeptFilter = (deptFilterSelect.value || '').toLowerCase();
      currentPage = 1;
      renderEmployeesTable();
    });
  }

  await loadDepartmentOptions();
  await loadEmployees();
  // Manager portal: animate stats cards using anime.js
  if (isManagerPortal()) {
    try {
      const anime = await ensureAnimeEmployees();
      if (anime) {
        const statsWrap = document.getElementById('employees-stats');
        const cards = statsWrap ? Array.from(statsWrap.children) : [];
        if (cards.length) {
          cards.forEach(c => { c.style.transformOrigin = '50% 50%'; c.style.opacity = '0'; });
          anime({
            targets: cards,
            translateY: [6, 0],
            scale: [0.98, 1],
            opacity: [0, 1],
            easing: 'easeOutQuad',
            duration: 360,
            delay: anime.stagger(80)
          });
        }
      }
    } catch {}
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>\"]/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[s]));
  }
  function toTitleCase(s){
    return String(s || '')
      .toLowerCase()
      .split(/([ -])/)
      .map(part => (/^[ -]$/.test(part) ? part : part.charAt(0).toUpperCase() + part.slice(1)))
      .join('');
  }

  // Helper function to format dates
  function formatDate(dateStr) {
    if (!dateStr) return '';
    if (dateStr === '0000-00-00') return '';
    try {
      const date = new Date(dateStr);
      if (isNaN(date.getTime())) return '';
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    } catch {
      return '';
    }
  }
  // Format numbers like 10,000 (no decimals)
  function formatNumberNoDecimals(val){
    const n = Number(val || 0);
    if (!Number.isFinite(n)) return '';
    return n.toLocaleString('en-US', { minimumFractionDigits: 0, maximumFractionDigits: 0 });
  }

  function prettySalaryRate(v){
    const s = String(v || 'monthly').toLowerCase();
    if (s === 'semi_monthly') return 'Semi-Monthly (15 days)';
    if (s === 'weekly') return 'Weekly';
    return 'Monthly';
  }

  // Employee code helpers
  function padNumber(num, length = 3){
    return String(num).padStart(length, '0');
  }
  function formatEmployeeCode(idNumber){
    // Format: EMPYYYY-NNN e.g. EMP2025-001
    const year = new Date().getFullYear();
    const n = Number(idNumber) || 0;
    return `EMP${year}-${padNumber(n, 3)}`;
  }
  function computeNextEmployeeId(){
    try {
      const ids = Array.isArray(allEmployees) ? allEmployees.map(e => Number(e.employee_id || 0)).filter(n => Number.isFinite(n) && n > 0) : [];
      const max = ids.length ? Math.max(...ids) : 0;
      return max + 1;
    } catch {
      return 1;
    }
  }

  function populateDepartmentSelect(selected = '') {
    const sel = document.getElementById('department');
    if (!sel) return;
    const opts = Array.isArray(departmentOptions) ? departmentOptions.slice() : [];
        sel.innerHTML = '<option value="">Select department</option>' + opts.map(d => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join('');
    if (selected && opts.includes(selected)) {
      sel.value = selected;
    } else {
      sel.value = '';
    }
  }

  async function loadDepartmentOptions() {
    try {
      const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getDepartments' } });
      let list = Array.isArray(res.data) ? res.data : [];
      // Normalize and correct naming
      list = list.map(s => String(s || '').trim()).filter(Boolean);
            // Normalize Finance naming to 'Finance Department'
      list = list.map(d => (/^finance(\s*department)?$/i.test(d) ? 'Finance Department' : d));
      // Ensure requested departments are present
      const extras = ['Warehouse Department', 'Retail Operations Department', 'Marketing Department', 'Human Resources Department'];
      for (const x of extras) {
        if (!list.some(d => d.toLowerCase() === x.toLowerCase())) list.push(x);
      }
      // Deduplicate case-insensitively and sort
      const seen = new Set();
      const final = [];
      for (const d of list) { const key = d.toLowerCase(); if (!seen.has(key)) { seen.add(key); final.push(d); } }
      final.sort((a, b) => a.localeCompare(b));
      departmentOptions = final;
    } catch (e) {
      // Fallback to default set if API fails
      departmentOptions = ['IT Department', 'Finance Department', 'Warehouse Department', 'Retail Operations Department', 'Marketing Department'];
    }
    populateDepartmentSelect(document.getElementById('department') ? document.getElementById('department').value : '');
    const deptFilterEl = document.getElementById('emp-dept-filter');
    if (deptFilterEl) {
      const opts = Array.isArray(departmentOptions) ? departmentOptions.slice() : [];
      const prev = deptFilterEl.value || '';
      deptFilterEl.innerHTML = '<option value="">All departments</option>' + opts.map(function(d){ return '<option value="' + escapeHtml(d) + '">' + escapeHtml(d) + '</option>'; }).join('');
      if (prev) {
        const match = opts.find(function(x){ return String(x).toLowerCase() === String(prev).toLowerCase(); });
        deptFilterEl.value = match || '';
      }
    }
  }

  // Load position options based on department
  async function loadPositionOptions(deptName, selected = ''){
    const sel = document.getElementById('position');
    if (!sel) return;
    sel.innerHTML = '<option value="">Loading...</option>';

    const normalize = (s) => String(s || '').trim().toLowerCase();
    let key = normalize(deptName);
    // Handle minor naming variations
    if (key === 'department it') key = 'it department';
    if (key === 'finance deparment') key = 'finance department';

    const positionsByDept = {
      'marketing department': ['Marketing Manager','Event Coordinator','Social Media Specialist','Content Writer'],
      'finance department': ['Accountant','Accounts Payable Clerk','Accounts Receivable Clerk','Cash Handling Specialist','Payroll Specialist'],
      'warehouse department': ['Diser','Warehouseman','Head','Assistant Head','Merchandiser'],
      'retail operations department': ['Product Specialist','Store Manager','Retail Supervisor','Assistant Store Manager','Cashier','Bagger'],
      'it department': ['System Administrator','Web Developer','Database Administrator','Cybersecurity Specialist'],
      'human resources department': ['HR DIRECTOR']
    };

    let list = [];
    if (positionsByDept[key]) {
      list = positionsByDept[key].slice();
    } else {
      try {
        if (deptName) {
          const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getDepartmentPositions', dept_name: deptName } });
          list = Array.isArray(res.data) ? res.data : [];
        }
      } catch {}
    }

    // If nothing provided, keep empty list (no generic fallbacks)
    if (!Array.isArray(list)) { list = []; }
    // Sort positions alphabetically (case-insensitive)
    list = list.map(x => String(x)).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
    const opts = list.map(p => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join('');
    sel.innerHTML = `<option value="">Select position</option>${opts}`;
    if (selected) {
      sel.value = selected;
    }
  }

  async function loadEmployees() {
    const container = document.getElementById('employees-table');
    container.innerHTML = '<div class="text-gray-500">Loading...</div>';
    const response = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
    // Exclude HR from list only in HR portal; show all in admin area
    const employeesRaw = response.data || [];
    allEmployees = isHrPortal()
      ? employeesRaw.filter(e => {
          const r = String(e.user_role || e.role || '').toLowerCase();
          const p = String(e.position || '').toLowerCase();
          // Include only Manager and Employee
          return r === 'employee' || r === 'manager' || (!r && (p === 'employee' || p === 'manager'));
        })
      : employeesRaw;
    // Restrict to manager's department when in Manager portal
    try {
      if (isManagerPortal()) {
        const meRes = await axios.get(`${window.baseApiUrl}/auth.php`, { params: { operation: 'me' }, withCredentials: true });
        const meUser = (meRes && meRes.data && meRes.data.user) ? meRes.data.user : null;
        const scopeDept = meUser ? String(meUser.department || '').toLowerCase() : '';
        if (scopeDept) {
          allEmployees = allEmployees.filter(e => String(e.department || '').toLowerCase() === scopeDept);
        }
        const meId = meUser ? String(meUser.employee_id || '') : '';
        if (meId) {
          allEmployees = allEmployees.filter(e => String(e.employee_id || '') !== meId);
        }
      }
    } catch {}

    // Render stats
    // In HR portal, exclude HR from stats; in Admin/Manager portals, include all
    const base = isHrPortal()
      ? allEmployees.filter(e => (String(e.user_role || e.role || '').toLowerCase() !== 'hr'))
      : allEmployees;
    const active = base.filter(e => String(e.status || '').toLowerCase() === 'active').length;
    const inactive = base.length - active;
    const total = active; // Count all (excluding HR if applicable)
    const stats = document.getElementById('employees-stats');
    stats.innerHTML = `
      <div class="bg-white rounded-lg shadow p-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-full bg-blue-50 flex items-center justify-center">
            <svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path>
            </svg>
          </div>
          <div>
            <div class="text-sm text-gray-500">Total Employees</div>
            <div class="text-2xl font-semibold">${total}</div>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-full bg-green-50 flex items-center justify-center">
            <svg class="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
          </div>
          <div>
            <div class="text-sm text-gray-500">Active</div>
            <div class="text-2xl font-semibold text-green-700">${active}</div>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center">
            <svg class="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728L5.636 5.636m12.728 12.728L18.364 5.636M5.636 18.364l12.728-12.728"></path>
            </svg>
          </div>
          <div>
            <div class="text-sm text-gray-500">Inactive</div>
            <div class="text-2xl font-semibold text-gray-700">${inactive}</div>
          </div>
        </div>
      </div>`;
    renderEmployeesTable();
  }

  function getFilteredEmployees() {
    let list = allEmployees.slice();
    const deptFilter = (currentDeptFilter || '').toLowerCase();
    if (deptFilter) {
      list = list.filter(e => (e.department || '').toLowerCase() === deptFilter);
    }
    if (currentQuery) {
      const q = currentQuery;
      list = list.filter(e => {
        const name = `${e.first_name || ''} ${e.last_name || ''}`.toLowerCase();
        const dept = (e.department || '').toLowerCase();
        const pos = (e.position || '').toLowerCase();
        const accRole = (e.user_role || '').toLowerCase();
        const email = (e.email || '').toLowerCase();
        return name.includes(q) || dept.includes(q) || pos.includes(q) || accRole.includes(q) || email.includes(q);
      });
    }
    return list;
  }

  function renderEmployeesTable() {
    const container = document.getElementById('employees-table');
    if (!container) return;
    const employees = getFilteredEmployees();
    const total = employees.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (currentPage > totalPages) currentPage = totalPages;
    const startIdx = (currentPage - 1) * pageSize;
    const endIdx = Math.min(startIdx + pageSize, total);
    const pageRows = employees.slice(startIdx, endIdx);

    const table = document.createElement('table');
    table.className = 'min-w-full divide-y divide-gray-200';
    table.innerHTML = `
      <thead class="bg-gray-50">
        <tr>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">#</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Name</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Department</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Position</th>
           <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Role</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Salary</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Status</th>
          <th class="px-3 py-2 text-right text-xs font-semibold text-gray-600">Actions</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-200 bg-white"></tbody>`;

    const tbody = table.querySelector('tbody');
    pageRows.forEach((e, i) => {
      const tr = document.createElement('tr');
      const fullName = toTitleCase(`${e.first_name} ${e.last_name}`);
      const displayIndex = startIdx + i + 1;
      tr.innerHTML = `
        <td class="px-3 py-2 text-sm text-gray-700">${displayIndex}</td>
        <td class="px-3 py-2 text-sm text-gray-700">
          <div class="font-medium">${fullName}</div>
          <div class="text-xs text-gray-500 mt-0.5">${e.employee_id ? formatEmployeeCode(e.employee_id) : ''}</div>
        </td>
        <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(e.department || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(e.position || '')}</td>
         <td class="px-3 py-2 text-sm text-gray-700">${toTitleCase(e.user_role || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${formatNumberNoDecimals(e.basic_salary)}</td>
        <td class="px-3 py-2 text-sm">
          <button class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${e.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-gray-200 text-gray-700'} hover:ring-2 hover:ring-primary-600 focus:outline-none" data-action="toggle-status" data-employee-id="${e.employee_id}" data-current-status="${e.status}">${toTitleCase(e.status || '')}</button>
        </td>
        <td class="px-3 py-2 text-sm text-right">
          <div class="relative inline-block text-left" data-emp-menu-container>
            <button class="inline-flex items-center justify-center w-8 h-8 rounded hover:bg-gray-100" aria-label="Actions" data-action="menu-toggle">
              <span class="text-gray-600 font-bold text-lg">•••</span>
            </button>
            <div class="hidden origin-top-right absolute right-0 mt-2 w-36 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 z-10" role="menu" data-menu>
              <div class="py-1">
                <button class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 inline-flex items-center gap-2" data-menu-action="preview" role="menuitem">
                  <svg class="w-4 h-4 text-gray-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0" />
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.477 0 8.268 2.943 9.542 7-1.274 4.057-5.065 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  </svg>
                  <span>Preview</span>
                </button>
                <button class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 inline-flex items-center gap-2" data-menu-action="edit" role="menuitem">
                  <svg class="w-4 h-4 text-blue-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536M4 20h4l10.606-10.606a2 2 0 10-2.828-2.828L5.172 17.172A4 4 0 004 20z" />
                  </svg>
                  <span>Edit</span>
                </button>
                <button class="w-full text-left px-3 py-2 text-sm text-red-600 hover:bg-gray-50 inline-flex items-center gap-2" data-menu-action="delete" role="menuitem">
                  <svg class="w-4 h-4 text-red-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-1 12a2 2 0 01-2 2H8a2 2 0 01-2-2L5 7m5-3h4m-7 3h10" />
                  </svg>
                  <span>Delete</span>
                </button>
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
          // Close other open menus first
          document.querySelectorAll('[data-emp-menu-container] [data-menu]').forEach(m => m.classList.add('hidden'));
          menu.classList.toggle('hidden');
        });

        const onPreview = tr.querySelector('[data-menu-action="preview"]');
        const onEdit = tr.querySelector('[data-menu-action="edit"]');
        const onDelete = tr.querySelector('[data-menu-action="delete"]');
        if (isManagerPortal()) {
          if (onEdit) onEdit.remove();
          if (onDelete) onDelete.remove();
        }
        if (onPreview) onPreview.addEventListener('click', async (ev) => {
          ev.preventDefault();
          menu.classList.add('hidden');
          await openPreview(e.employee_id);
        });
        if (onEdit) onEdit.addEventListener('click', async (ev) => {
          ev.preventDefault();
          menu.classList.add('hidden');
        await loadDepartmentOptions();
        fillForm(e);
        currentEditingOriginalRole = (e.user_role || e.position || 'employee');
        document.getElementById('employeeModalLabel').innerText = 'Edit Employee';
        const roleSel = document.getElementById('user_role');
        if (roleSel) {
          if (isHrPortal()) {
            roleSel.value = 'employee';
            roleSel.disabled = true;
          } else {
            roleSel.disabled = false;
            const r = String(e.user_role || e.position || '').toLowerCase();
            roleSel.value = (r === 'hr' || r === 'manager') ? r : 'employee';
          }
        }
        // Ensure position options for selected department and set position value
        try { await loadPositionOptions(e.department || '', e.position || ''); } catch {}
        const dhw = document.getElementById('date_hired_wrap'); if (dhw) dhw.classList.remove('hidden');
        openModal();
      });
        if (onDelete) onDelete.addEventListener('click', async (ev) => {
          ev.preventDefault();
          menu.classList.add('hidden');
        if (confirm('Delete this employee?')) {
          await axios.post(`${window.baseApiUrl}/employees.php`, buildFormData({ operation: 'deleteEmployee', json: JSON.stringify({ employee_id: e.employee_id }) }));
          await loadEmployees();
        }
      });
      }
      tbody.appendChild(tr);
    });

    container.innerHTML = '';
    container.appendChild(table);
    // Manager portal: animate employees table rows using anime.js
    if (isManagerPortal()) {
      try {
        ensureAnimeEmployees().then(anime => {
          if (!anime) return;
          const rows = Array.from(container.querySelectorAll('tbody tr'));
          if (!rows.length) return;
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
        });
      } catch {}
    }

    // Wire clickable status toggles
    if (!isManagerPortal()) {
      container.querySelectorAll('[data-action="toggle-status"]').forEach(btn => {
        btn.addEventListener('click', async (ev) => {
        const el = ev.currentTarget;
        const id = Number(el.getAttribute('data-employee-id'));
        const curr = (el.getAttribute('data-current-status') || '').toLowerCase();
        const next = curr === 'active' ? 'inactive' : 'active';
        try {
          const res = await axios.post(`${window.baseApiUrl}/employees.php`, buildFormData({ operation: 'setEmployeeStatus', json: JSON.stringify({ employee_id: id, status: next }) }));
          const ok = res && res.data && res.data.success;
          if (ok) {
            await loadEmployees();
            ensureToastContainer();
            showToast(`Status changed to ${next}`, 'success');
          } else {
            ensureToastContainer();
            showToast('Failed to change status', 'error');
          }
        } catch {
          ensureToastContainer();
          showToast('Failed to change status', 'error');
        }
      });
      });
    } else {
      container.querySelectorAll('[data-action="toggle-status"]').forEach(btn => {
        btn.disabled = true;
        btn.classList.add('cursor-not-allowed','opacity-60');
        btn.removeAttribute('data-action');
      });
    }

    // Pagination footer
    const footer = document.getElementById('employees-pagination');
    if (footer) {
      const showingFrom = total === 0 ? 0 : (startIdx + 1);
      const showingTo = endIdx;
      footer.innerHTML = `
        <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${total}</span></div>
        <div class="flex items-center gap-2">
          <button id="emp-prev" class="px-2 py-1 text-xs rounded border ${currentPage <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
          <span>Page ${currentPage} of ${totalPages}</span>
          <button id="emp-next" class="px-2 py-1 text-xs rounded border ${currentPage >= totalPages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
        </div>`;
      const prev = document.getElementById('emp-prev');
      const next = document.getElementById('emp-next');
      if (prev) prev.addEventListener('click', () => { if (currentPage > 1) { currentPage -= 1; renderEmployeesTable(); } });
      if (next) next.addEventListener('click', () => { if (currentPage < totalPages) { currentPage += 1; renderEmployeesTable(); } });
    }
  }

  // Global outside-click handler to close any open action menus
  if (!window.__empMenuGlobalClose) {
    window.__empMenuGlobalClose = true;
    document.addEventListener('click', () => {
      document.querySelectorAll('[data-emp-menu-container] [data-menu]').forEach(m => m.classList.add('hidden'));
    });
  }

  function ensurePreviewModal(){
    if (document.getElementById('employeePreviewModal')) return;
    const modal = document.createElement('div');
    modal.id = 'employeePreviewModal';
    modal.className = 'fixed inset-0 z-50 hidden';
    modal.innerHTML = `
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-xl">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">Employee Preview</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
          </div>
          <div id="empPreviewBody" class="p-4 text-sm text-gray-700 max-h-[70vh] overflow-y-auto"></div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button id="empPreviewQr" class="px-3 py-2 text-sm rounded border">View QR Code</button>
            <button class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700" data-close="true">Close</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);
    modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
  }

  async function openPreview(employeeId){
    ensurePreviewModal();
    const modal = document.getElementById('employeePreviewModal');
    const body = document.getElementById('empPreviewBody');
    if (!modal || !body) return;
    body.innerHTML = '<div class="text-gray-500">Loading...</div>';
    try {
      const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getEmployee', employee_id: employeeId } });
      const e = res.data || {};
      body.innerHTML = `
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3">
          <div>
            <div class="text-gray-500 mb-0.5">Employee ID</div>
            <div class="font-medium">${e.employee_id ? formatEmployeeCode(e.employee_id) : ''}</div>
          </div>
          <div>
            <div class="text-gray-500 mb-0.5">Status</div>
            <div class="font-medium">${toTitleCase(e.status || '')}</div>
          </div>
          <div>
            <div class="text-gray-500 mb-0.5">Name</div>
            <div class="font-medium">${toTitleCase(`${e.first_name || ''} ${e.last_name || ''}`)}</div>
          </div>
          <div>
            <div class="text-gray-500 mb-0.5">Middle Name</div>
            <div class="font-medium">${toTitleCase(e.middle_name || '')}</div>
          </div>
          <div>
            <div class="text-gray-500 mb-0.5">Date of Birth</div>
            <div class="font-medium">${formatDate(e.date_of_birth || '')}</div>
          </div>
          <div>
            <div class="text-gray-500 mb-0.5">Gender</div>
            <div class="font-medium">${toTitleCase(e.gender || '')}</div>
          </div>
          <div>
            <div class="text-gray-500 mb-0.5">Address</div>
            <div class="font-medium">${e.address ? escapeHtml(e.address) : ''}</div>
          </div>
          <div>
            <div class="text-gray-500 mb-0.5">Email</div>
            <div class="font-medium">${e.email || ''}</div>
          </div>
          <div>
            <div class="text-gray-500 mb-0.5">Phone</div>
            <div class="font-medium">${e.phone || ''}</div>
          </div>
          <div>
            <div class="text-gray-500 mb-0.5">Department</div>
            <div class="font-medium">${toTitleCase(e.department || '')}</div>
          </div>
          <div>
            <div class="text-gray-500 mb-0.5">Position</div>
            <div class="font-medium">${toTitleCase(e.position || '')}</div>
          </div>
          <div>
            <div class="text-gray-500 mb-0.5">Role</div>
            <div class="font-medium">${toTitleCase(e.user_role || '')}</div>
          </div>
          <div>
            <div class="text-gray-500 mb-0.5">Date Hired</div>
            <div class="font-medium">${formatDate(e.date_hired || '')}</div>
          </div>
        </div>
        <div class="mt-4">
          <div class="text-sm font-semibold text-gray-700 mb-2">Payroll Information</div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <div class="text-gray-500">Salary Rate</div>
              <div class="font-medium">${prettySalaryRate(e.salary_rate_type)}</div>
            </div>
            <div>
              <div class="text-gray-500">Basic Salary</div>
              <div class="font-medium">${e.basic_salary != null ? formatNumberNoDecimals(e.basic_salary) : ''}</div>
            </div>
            <div>
              <div class="text-gray-500">Bank Account</div>
              <div class="font-medium">${e.bank_account || ''}</div>
            </div>
            <div>
              <div class="text-gray-500">Tax ID (TIN)</div>
              <div class="font-medium">${e.tax_id || ''}</div>
            </div>
            <div>
              <div class="text-gray-500">SSS Number</div>
              <div class="font-medium">${e.sss_number || ''}</div>
            </div>
            <div>
              <div class="text-gray-500">PhilHealth Number</div>
              <div class="font-medium">${e.philhealth_number || ''}</div>
            </div>
            <div>
              <div class="text-gray-500">Pag-IBIG Number</div>
              <div class="font-medium">${e.pagibig_number || ''}</div>
            </div>
          </div>
        </div>`;
      // Wire QR button
      const qrBtn = document.getElementById('empPreviewQr');
      if (qrBtn) {
        qrBtn.onclick = async () => {
          try { await ensureQrLib(); } catch {}
          showEmployeeQr({ id: e.employee_id, first: e.first_name || '', last: e.last_name || '' });
        };
      }
    } catch {
      body.innerHTML = '<div class="text-red-600">Failed to load employee details.</div>';
    }
    modal.classList.remove('hidden');
  }

  function fillForm(e) {
    document.getElementById('employee_id').value = e.employee_id || '';
    const vis = document.getElementById('employee_id_visible');
    if (vis) {
      if (e && e.employee_id) {
        vis.value = formatEmployeeCode(e.employee_id);
      } else {
        vis.value = '';
      }
    }
    document.getElementById('first_name').value = e.first_name || '';
    document.getElementById('last_name').value = e.last_name || '';
    const mid = document.getElementById('middle_name'); if (mid) mid.value = e.middle_name || '';

    const dob = document.getElementById('date_of_birth'); if (dob) dob.value = e.date_of_birth || '';
    const gen = document.getElementById('gender'); if (gen) gen.value = (e.gender || '');
    const addr = document.getElementById('address'); if (addr) addr.value = e.address || '';
    document.getElementById('email').value = e.email || '';
    document.getElementById('phone').value = e.phone || '';
    populateDepartmentSelect(e.department || '');
    // Populate positions list for selected department and set value
    try { loadPositionOptions(e.department || '', e.position || ''); } catch {}
    // Set account role selection
    {
      const r = String(e.user_role || e.position || '').toLowerCase();
      const roleSel = document.getElementById('user_role');
      if (roleSel) roleSel.value = (r === 'hr' || r === 'manager') ? r : 'employee';
    }
    if (isHrPortal()) {
      const roleSel = document.getElementById('user_role');
      if (roleSel) roleSel.value = 'employee';
    }
    const hrPwd = document.getElementById('hr_password');
    if (hrPwd) hrPwd.value = '';
    syncHrPwVisibility();
    document.getElementById('basic_salary').value = e.basic_salary || '';
    document.getElementById('date_hired').value = e.date_hired || '';
    const srt = document.getElementById('salary_rate_type'); if (srt) srt.value = (e.salary_rate_type || 'monthly');
    const bank = document.getElementById('bank_account'); if (bank) bank.value = e.bank_account || '';
    const tin = document.getElementById('tax_id'); if (tin) tin.value = e.tax_id || '';
    const sss = document.getElementById('sss_number'); if (sss) sss.value = e.sss_number || '';
    const ph = document.getElementById('philhealth_number'); if (ph) ph.value = e.philhealth_number || '';
    const pagibig = document.getElementById('pagibig_number'); if (pagibig) pagibig.value = e.pagibig_number || '';
  }

  function resetForm() {
    fillForm({});
    // For a new/empty form, populate the visible employee id with the next formatted code
    const vis = document.getElementById('employee_id_visible');
    if (vis) {
      const curHidden = document.getElementById('employee_id')?.value;
      if (!curHidden) {
        const nextId = computeNextEmployeeId();
        vis.value = formatEmployeeCode(nextId);
      } else {
        // If hidden has a value, keep it formatted
        vis.value = formatEmployeeCode(Number(curHidden));
      }
    }
  }

  async function saveEmployee() {
    const payload = {
      employee_id: document.getElementById('employee_id').value || undefined,
      first_name: document.getElementById('first_name').value,
      middle_name: (document.getElementById('middle_name')?.value || ''),
      last_name: document.getElementById('last_name').value,

      date_of_birth: (document.getElementById('date_of_birth')?.value || ''),
      gender: (document.getElementById('gender')?.value || ''),
      address: (document.getElementById('address')?.value || ''),
      email: document.getElementById('email').value,
      phone: document.getElementById('phone').value,
      department: document.getElementById('department').value,
      position: document.getElementById('position').value,
      user_role: (document.getElementById('user_role')?.value || ''),
      basic_salary: document.getElementById('basic_salary').value,
      salary_rate_type: (document.getElementById('salary_rate_type')?.value || 'monthly'),
            bank_account: (document.getElementById('bank_account')?.value || ''),
      tax_id: (document.getElementById('tax_id')?.value || ''),
      sss_number: (document.getElementById('sss_number')?.value || ''),
      philhealth_number: (document.getElementById('philhealth_number')?.value || ''),
      pagibig_number: (document.getElementById('pagibig_number')?.value || ''),
          };
    // If provided, include date_hired for both create and update
    const _dh = document.getElementById('date_hired')?.value || '';
    if (_dh) { payload.date_hired = _dh; }
    // In HR portal, force employee role only
    if (isHrPortal()) {
      payload.user_role = 'employee';
    }
    // Validate all required fields
    resetValidation();
    const invalidEls = [];
    const requiredIds = ['first_name','last_name','middle_name','date_of_birth','gender','address','email','phone','department','position','user_role','basic_salary','salary_rate_type'];
    requiredIds.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      const value = (el.value || '').toString().trim();
      if (!value) invalidEls.push(el);
    });
    // Numeric validation for salary
    const salaryNum = Number(payload.basic_salary);
    if (!Number.isFinite(salaryNum) || salaryNum <= 0) invalidEls.push(document.getElementById('basic_salary'));

    // Account password rules
    if (!payload.email || !payload.email.includes('@')) invalidEls.push(document.getElementById('email'));
    const accPwd = document.getElementById('hr_password').value;
    // Require password only when creating HR accounts; for employees it's optional
    if (payload.user_role === 'hr' && !payload.employee_id && !accPwd) {
      invalidEls.push(document.getElementById('hr_password'));
    }
    if (accPwd) payload.user_password = accPwd;

    if (invalidEls.length){
      ensureToastContainer();
      showToast('Please complete all fields correctly before saving.', 'error');
      markInvalid(invalidEls);
      invalidEls[0].focus();
      return { operation: payload.employee_id ? 'updateEmployee' : 'createEmployee', ok: false, position: payload.position };
    }

    const operation = payload.employee_id ? 'updateEmployee' : 'createEmployee';
    try {
      const res = await axios.post(`${window.baseApiUrl}/employees.php`, buildFormData({ operation, json: JSON.stringify(payload) }));
      const data = res && res.data ? res.data : {};
      return { operation, ok: true, position: payload.user_role || payload.position, username_updated: !!data.username_updated, username_conflict: !!data.username_conflict, generated_password: data.generated_password, created_employee_id: data.employee_id, plain_password: accPwd };
    } catch {
      ensureToastContainer();
      showToast('Failed to save employee', 'error');
      return { operation, ok: false, position: payload.position };
    }
  }

  function ensureToastContainer(){
    if (document.getElementById('toast-container')) return;
    const container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'fixed top-4 right-4 z-50 space-y-2';
    document.body.appendChild(container);
  }

  function showToast(message, variant){
    const container = document.getElementById('toast-container');
    if (!container) return;
    const bg = variant === 'error' ? 'bg-red-600' : 'bg-green-600';
    const toast = document.createElement('div');
    toast.className = `${bg} text-white rounded shadow px-4 py-2 text-sm transition-opacity duration-300 opacity-0`;
    toast.textContent = message;
    container.appendChild(toast);
    requestAnimationFrame(() => { toast.classList.remove('opacity-0'); });
    setTimeout(() => {
      toast.classList.add('opacity-0');
      setTimeout(() => { toast.remove(); }, 300);
    }, 2500);
  }

  function resetValidation(){
    const ids = ['first_name','last_name','middle_name','date_of_birth','gender','address','email','phone','department','position','user_role','basic_salary','salary_rate_type','bank_account','tax_id','sss_number','philhealth_number','pagibig_number','hr_password'];
    ids.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.classList.remove('border-red-500','focus:ring-red-500','focus:border-red-500');
    });
  }

  function markInvalid(elements){
    const arr = Array.isArray(elements) ? elements : [elements];
    arr.forEach(el => {
      if (!el) return;
      el.classList.add('border-red-500','focus:ring-red-500','focus:border-red-500');
    });
  }

  async function ensureQrLib(){
    if (window.QRCode) return;
    await new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';
      s.onload = resolve; s.onerror = reject;
      document.head.appendChild(s);
    });
  }

  function ensureQrModal(){
    if (document.getElementById('employeeQrModal')) return;
    const modal = document.createElement('div');
    modal.id = 'employeeQrModal';
    modal.className = 'fixed inset-0 z-50 hidden';
    const footerButtons = isManagerPortal()
      ? `<button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>`
      : `<button id=\"qr-print\" class=\"px-3 py-2 text-sm rounded border\">Print</button>
              <button id=\"qr-download\" class=\"px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700\">Download</button>
              <button class=\"px-3 py-2 text-sm rounded border\" data-close="true">Close</button>`;
    modal.innerHTML = `
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-md">
        <div class="bg-white rounded-lg shadow">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold">Employee QR Code</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
          </div>
          <div class="p-5 text-center">
            <div id="qr-emp-name" class="font-semibold text-lg"></div>
            <div id="qr-emp-code" class="text-xs text-gray-500 mb-4 tracking-wider font-mono"></div>
            <div class="flex justify-center">
              <div class="p-3 bg-white rounded-lg border shadow-sm">
                <div id="qr-code" class="w-[256px] h-[256px]"></div>
              </div>
            </div>
            <div class="text-[11px] text-gray-500 mt-3">Scan this code to identify the employee</div>
          </div>
          <div class="flex items-center justify-between border-t px-4 py-3">
            <div class="text-xs text-gray-500"></div>
            <div class="flex gap-2">
              ${footerButtons}
            </div>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);
    modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
  }

  function createFramedQrDataUrl(qrWrap, opts = {}) {
    const img = qrWrap.querySelector('img');
    const canvas = qrWrap.querySelector('canvas');
    let srcCanvas = null;
    let size = 256;
    if (canvas) {
      srcCanvas = canvas;
      size = canvas.width || 256;
    } else if (img && img.src) {
      const temp = document.createElement('canvas');
      const tctx = temp.getContext('2d');
      temp.width = img.naturalWidth || 256;
      temp.height = img.naturalHeight || 256;
      try { tctx.drawImage(img, 0, 0, temp.width, temp.height); } catch {}
      srcCanvas = temp;
      size = temp.width;
    } else {
      return '';
    }
    const borderWidth = Number.isFinite(opts.borderWidth) ? opts.borderWidth : 8;
    const margin = Number.isFinite(opts.margin) ? opts.margin : 16;
    const borderColor = opts.borderColor || '#111827';
    const bgColor = opts.bgColor || '#ffffff';
    const radius = Number.isFinite(opts.radius) ? opts.radius : 12;

    const outSize = size + 2 * (borderWidth + margin);
    const out = document.createElement('canvas');
    out.width = outSize;
    out.height = outSize;
    const ctx = out.getContext('2d');
    if (ctx) {
      ctx.imageSmoothingEnabled = false;
      const drawRoundedRect = (c, x, y, w, h, r) => {
        if (!r) { c.beginPath(); c.rect(x, y, w, h); c.closePath(); return; }
        const rr = Math.max(0, Math.min(r, Math.min(w, h) / 2));
        c.beginPath();
        c.moveTo(x + rr, y);
        c.arcTo(x + w, y, x + w, y + h, rr);
        c.arcTo(x + w, y + h, x, y + h, rr);
        c.arcTo(x, y + h, x, y, rr);
        c.arcTo(x, y, x + w, y, rr);
        c.closePath();
      };
      // background
      ctx.fillStyle = bgColor;
      drawRoundedRect(ctx, 0, 0, out.width, out.height, radius);
      ctx.fill();
      // border
      const bx = margin;
      const by = margin;
      const bw = out.width - 2 * margin;
      const bh = out.height - 2 * margin;
      ctx.strokeStyle = borderColor;
      ctx.lineWidth = borderWidth;
      drawRoundedRect(ctx, bx + borderWidth / 2, by + borderWidth / 2, bw - borderWidth, bh - borderWidth, Math.max(0, radius - margin / 2));
      ctx.stroke();
      // draw QR
      const offset = margin + borderWidth;
      ctx.drawImage(srcCanvas, offset, offset, size, size);
    }
    return out.toDataURL('image/png');
  }

  async function showEmployeeQr(info){
    try { await ensureQrLib(); } catch {}
    ensureQrModal();
    const modal = document.getElementById('employeeQrModal');
    const nameEl = document.getElementById('qr-emp-name');
    const codeEl = document.getElementById('qr-emp-code');
    const qrWrap = document.getElementById('qr-code');
    if (!modal || !qrWrap) return;
    const fullName = toTitleCase(`${info.first || ''} ${info.last || ''}`.trim());
    const code = formatEmployeeCode(info.id);
    if (nameEl) nameEl.textContent = fullName;
    if (codeEl) codeEl.textContent = code;
    qrWrap.innerHTML = '';
    const payload = JSON.stringify({ type: 'employee', employee_id: info.id, name: fullName, code: code });
    if (window.QRCode) {
      new window.QRCode(qrWrap, { text: payload, width: 256, height: 256, correctLevel: window.QRCode.CorrectLevel.M });
    } else {
      qrWrap.innerHTML = '<div class="text-xs text-red-600">QR library failed to load.</div><div class="break-all text-xs">' + payload + '</div>';
    }
    const dl = document.getElementById('qr-download');
    if (dl) {
      dl.onclick = () => {
        const dataUrl = createFramedQrDataUrl(qrWrap, { borderWidth: 8, margin: 16, borderColor: '#ffffff', bgColor: '#ffffff', radius: 12 });
        if (dataUrl) {
          const a = document.createElement('a');
          a.href = dataUrl;
          a.download = `employee-${code}.png`;
          document.body.appendChild(a);
          a.click();
          a.remove();
        }
      };
    }
    const pr = document.getElementById('qr-print');
    if (pr) {
      pr.onclick = () => {
        const dataUrl = createFramedQrDataUrl(qrWrap, { borderWidth: 8, margin: 16, borderColor: '#ffffff', bgColor: '#ffffff', radius: 12 });
        const printWin = window.open('', '_blank');
        if (printWin) {
          printWin.document.write(`<!DOCTYPE html><html><head><title>${fullName} - ${code}</title><style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;text-align:center;padding:20px;} .code{font:12px/1 monospace;color:#555;margin-top:6px;} img{image-rendering: pixelated;}</style></head><body>`);
          printWin.document.write(`<div style="font-weight:600;font-size:16px;">${fullName}</div>`);
          printWin.document.write(`<div class="code">${code}</div>`);
          if (dataUrl) {
            printWin.document.write(`<div style="display:inline-block;margin-top:12px;"><img src="${dataUrl}"/></div>`);
          } else {
            printWin.document.write(`<div>QR not available</div>`);
          }
          printWin.document.write('</body></html>');
          printWin.document.close();
          printWin.focus();
          printWin.print();
          setTimeout(() => { try { printWin.close(); } catch {} }, 300);
        }
      };
    }
    modal.classList.remove('hidden');
  }

  // Wire department change to reload positions
  const deptSel = document.getElementById('department');
  if (deptSel) {
    deptSel.addEventListener('change', async () => {
      try { await loadPositionOptions(deptSel.value || ''); } catch {}
    });
  }

  function isHrPortal(){
    return location.pathname.endsWith('/hr.html') || location.pathname.endsWith('hr.html');
  }
  function isManagerPortal(){
    return location.pathname.endsWith('/manager.html') || location.pathname.endsWith('manager.html');
  }
}

function buildFormData(map) {
  const fd = new FormData();
  Object.entries(map).forEach(([k, v]) => fd.append(k, v));
  return fd;
}


