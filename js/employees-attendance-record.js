/**
 * EMPLOYEES ATTENDANCE RECORD PAGE
 * Handles the display and filtering of employee attendance records
 */

document.addEventListener('DOMContentLoaded', async function() {
  // Initialize page elements
  initializeElements();
  // Load initial data
  await loadDepartments();
  if (minimalColumns) {
    await loadEmployees();
  } else {
    await loadAttendanceRecords();
  }
  // Setup event listeners
  setupEventListeners();
});

// Global variables
let allAttendanceRecords = [];
let currentPage = 1;
let pageSize = 10;
let currentQuery = '';
// Toggle minimal columns mode via window.attendanceColumnsMode = 'minimal'
const minimalColumns = (typeof window !== 'undefined' && window.attendanceColumnsMode === 'minimal');
let allEmployees = [];

function isHrPortal() {
  try {
    const p = (window.location && window.location.pathname) ? window.location.pathname.toLowerCase() : '';
    return p.includes('/master/hr/');
  } catch { return false; }
}

/**
 * INITIALIZE PAGE ELEMENTS
 * Set default values and states for page elements
 */
function initializeElements() {
  // Set today as default end date
  const today = new Date().toISOString().split('T')[0];
  document.getElementById('attendance-filter-end-date').value = today;
  
  // Set default start date to 30 days ago
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - 30);
  document.getElementById('attendance-filter-start-date').value = startDate.toISOString().split('T')[0];
}

/**
 * SETUP EVENT LISTENERS
 * Attach event handlers to interactive elements
 */
function setupEventListeners() {
  // Search input
  const searchInput = document.getElementById('attendance-filter-emp');
  if (searchInput) {
    searchInput.addEventListener('input', function() {
      currentQuery = this.value.trim().toLowerCase();
      currentPage = 1;
      renderAttendanceTable();
    });
  }
  
  // Department filter
  const deptFilter = document.getElementById('attendance-filter-dept');
  if (deptFilter) {
    deptFilter.addEventListener('change', function() {
      currentPage = 1;
      renderAttendanceTable();
    });
  }
  
  // Date filters
  const startDateFilter = document.getElementById('attendance-filter-start-date');
  const endDateFilter = document.getElementById('attendance-filter-end-date');
  if (startDateFilter) {
    startDateFilter.addEventListener('change', function() {
      currentPage = 1;
      if (minimalColumns) { renderAttendanceTable(); } else { loadAttendanceRecords(); }
    });
  }
  if (endDateFilter) {
    endDateFilter.addEventListener('change', function() {
      currentPage = 1;
      if (minimalColumns) { renderAttendanceTable(); } else { loadAttendanceRecords(); }
    });
  }
  
  // Page size selector
  const pageSizeSelect = document.getElementById('attendance-page-size');
  if (pageSizeSelect) {
    pageSizeSelect.addEventListener('change', function() {
      pageSize = parseInt(this.value) || 10;
      currentPage = 1;
      renderAttendanceTable();
    });
  }
  
  // Export button
  const exportBtn = document.getElementById('btn-export');
  if (exportBtn) {
    exportBtn.addEventListener('click', exportAttendanceRecords);
  }

  // Delegate clicks on Action buttons in minimal mode
  if (minimalColumns) {
    const tbody = document.getElementById('attendance-tbody');
    if (tbody) {
      tbody.addEventListener('click', async (e) => {
        const btn = e.target.closest('.btn-view-records');
        if (!btn) return;
        const eid = btn.getAttribute('data-eid');
        const emp = (allEmployees || []).find(x => String(x.employee_id) === String(eid));
        if (!emp) return;
        await openEmployeeRecordsModal(emp);
      });
    }
  }
}

/**
 * LOAD DEPARTMENTS
 * Fetch and populate the department filter dropdown
 */
async function loadDepartments() {
  try {
    const response = await axios.get(`${window.baseApiUrl}/employees.php?operation=getEmployees`);
    const all = response.data || [];
    const baseEmployees = isHrPortal() 
      ? all.filter(e => String(e.user_role || e.role || '').toLowerCase() !== 'hr')
      : all;
    
    // Get unique departments
    const departments = [...new Set(baseEmployees.map(emp => emp.department).filter(Boolean))].sort();
    
    const deptSelect = document.getElementById('attendance-filter-dept');
    if (deptSelect) {
      deptSelect.innerHTML = '<option value="">All Departments</option>' + 
        departments.map(dept => `<option value="${dept}">${dept}</option>`).join('');
    }
  } catch (error) {
    console.error('Error loading departments:', error);
  }
}

async function loadEmployees() {
  try {
    const resp = await axios.get(`${window.baseApiUrl}/employees.php?operation=getEmployees`);
    let list = (resp.data || []).map(e => ({
      ...e,
      full_name: `${e.first_name || ''} ${e.last_name || ''}`.trim()
    }));
    if (isHrPortal()) {
      list = list.filter(e => String(e.user_role || e.role || '').toLowerCase() !== 'hr');
    }
    allEmployees = list;
    currentPage = 1;
    renderAttendanceTable();
  } catch (error) {
    console.error('Error loading employees:', error);
    showErrorMessage('Failed to load employees');
  }
}

/**
 * LOAD ATTENDANCE RECORDS
 * Fetch attendance records from the API
 */
async function loadAttendanceRecords() {
  try {
    const startDate = document.getElementById('attendance-filter-start-date').value;
    const endDate = document.getElementById('attendance-filter-end-date').value;
    
    const params = {
      operation: 'getAttendance',
      start_date: startDate,
      end_date: endDate
    };
    
    const response = await axios.get(`${window.baseApiUrl}/attendance.php`, { params });
    allAttendanceRecords = response.data || [];
    
    // Add department information from employees
    try {
      const empResponse = await axios.get(`${window.baseApiUrl}/employees.php?operation=getEmployees`);
      const employees = empResponse.data || [];
      const empMap = new Map(employees.map(emp => [emp.employee_id, emp]));
      
      allAttendanceRecords = allAttendanceRecords.map(record => {
        const employee = empMap.get(record.employee_id);
        return {
          ...record,
          department: employee ? employee.department : ''
        };
      });
    } catch (empError) {
      console.error('Error loading employee data:', empError);
    }
    
    currentPage = 1;
    renderAttendanceTable();
  } catch (error) {
    console.error('Error loading attendance records:', error);
    showErrorMessage('Failed to load attendance records');
  }
}

/**
 * RENDER ATTENDANCE TABLE
 * Display attendance records in the table with filtering and pagination
 */
function renderAttendanceTable() {
  const tbody = document.getElementById('attendance-tbody');
  const pagination = document.getElementById('attendance-pagination');
  
  if (!tbody || !pagination) return;
  
  // Minimal mode: list all employees
  if (minimalColumns) {
    let filteredEmployees = applyEmployeeFilters(allEmployees);
    // Sort by name then by ID for stability
    filteredEmployees.sort((a, b) => {
      const an = `${a.first_name || ''} ${a.last_name || ''}`.trim().toLowerCase();
      const bn = `${b.first_name || ''} ${b.last_name || ''}`.trim().toLowerCase();
      if (an === bn) return String(a.employee_id || '').localeCompare(String(b.employee_id || ''));
      return an.localeCompare(bn);
    });

    const totalRecords = filteredEmployees.length;
    const totalPages = Math.ceil(totalRecords / pageSize) || 1;
    if (currentPage > totalPages && totalPages > 0) {
      currentPage = totalPages;
    } else if (currentPage < 1) {
      currentPage = 1;
    }
    const startIndex = (currentPage - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    const pageRecords = filteredEmployees.slice(startIndex, endIndex);

    if (pageRecords.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="4" class="px-3 py-4 text-center text-gray-500">
            No employees found
          </td>
        </tr>
      `;
    } else {
      tbody.innerHTML = pageRecords.map((emp, index) => {
        const fullName = `${emp.first_name || ''} ${emp.last_name || ''}`.trim() || 'Unknown';
        const department = emp.department || '-';
        return `
          <tr>
            <td class="px-3 py-2 text-sm text-gray-700">${startIndex + index + 1}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${fullName}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${department}</td>
            <td class="px-3 py-2 text-sm text-gray-700">
              <button class="btn-view-records inline-flex items-center gap-1 px-2 py-1 text-xs rounded border hover:bg-gray-50" data-eid="${emp.employee_id}">
                <svg class="w-4 h-4 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" xmlns="http://www.w3.org/2000/svg">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h10M7 11h10M7 15h6M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h9l5 5v11a2 2 0 01-2 2z"></path>
                </svg>
                <span>View DTR</span>
              </button>
            </td>
          </tr>
        `;
      }).join('');
    }
    renderPagination(pagination, totalRecords, totalPages);
    return;
  }
  
  // Apply filters
  let filteredRecords = applyFilters(allAttendanceRecords);
  
  // Sort by date (newest first)
  filteredRecords.sort((a, b) => new Date(b.attendance_date) - new Date(a.attendance_date));
  
  // Pagination
  const totalRecords = filteredRecords.length;
  const totalPages = Math.ceil(totalRecords / pageSize);
  
  // Ensure current page is within bounds
  if (currentPage > totalPages && totalPages > 0) {
    currentPage = totalPages;
  } else if (currentPage < 1) {
    currentPage = 1;
  }
  
  // Get records for current page
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = startIndex + pageSize;
  const pageRecords = filteredRecords.slice(startIndex, endIndex);
  
  // Render table rows
  if (pageRecords.length === 0) {
    const colCount = minimalColumns ? 4 : 8;
    tbody.innerHTML = `
      <tr>
        <td colspan="${colCount}" class="px-3 py-4 text-center text-gray-500">
          No attendance records found
        </td>
      </tr>
    `;
  } else {
    tbody.innerHTML = pageRecords.map((record, index) => {
      const fullName = `${record.first_name || ''} ${record.last_name || ''}`.trim() || 'Unknown';
      const department = record.department || '-';

      // Minimal columns rendering
      if (minimalColumns) {
        return `
          <tr>
            <td class="px-3 py-2 text-sm text-gray-700">${startIndex + index + 1}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${fullName}</td>
            <td class="px-3 py-2 text-sm text-gray-700">${department}</td>
            <td class="px-3 py-2 text-sm text-gray-700">
              <button class="btn-view-records inline-flex items-center gap-1 px-2 py-1 text-xs rounded border hover:bg-gray-50" data-eid="${record.employee_id}">
                <svg class="w-4 h-4 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" xmlns="http://www.w3.org/2000/svg">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h10M7 11h10M7 15h6M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h9l5 5v11a2 2 0 01-2 2z"></path>
                </svg>
                <span>View DTR</span>
              </button>
            </td>
          </tr>
        `;
      }

      const status = getStatusBadge(record.status);
      const timeIn = formatTime(record.time_in);
      const timeOut = formatTime(record.time_out);
      const totalHours = calculateTotalHours(record.time_in, record.time_out);
      
      return `
        <tr>
          <td class="px-3 py-2 text-sm text-gray-700">${startIndex + index + 1}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${formatDate(record.attendance_date)}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${fullName}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${department}</td>
          <td class="px-3 py-2">${status}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${timeIn}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${timeOut}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${totalHours}</td>
        </tr>
      `;
    }).join('');
  }
  
  // Render pagination controls
  renderPagination(pagination, totalRecords, totalPages);
}

/**
 * APPLY FILTERS
 * Filter attendance records based on search criteria
 */
function applyFilters(records) {
  let filtered = records;
  
  // Employee name/ID filter
  if (currentQuery) {
    filtered = filtered.filter(record => {
      const fullName = `${record.first_name || ''} ${record.last_name || ''}`.toLowerCase();
      const employeeId = String(record.employee_id);
      return fullName.includes(currentQuery) || employeeId.includes(currentQuery);
    });
  }
  
  // Department filter
  const deptFilter = document.getElementById('attendance-filter-dept');
  if (deptFilter && deptFilter.value) {
    const selectedDept = deptFilter.value;
    filtered = filtered.filter(record => record.department === selectedDept);
  }
  
  return filtered;
}

function applyEmployeeFilters(records) {
  let filtered = records || [];
  // Employee name/ID filter
  if (currentQuery) {
    filtered = filtered.filter(emp => {
      const fullName = `${emp.first_name || ''} ${emp.last_name || ''}`.toLowerCase();
      const employeeId = String(emp.employee_id || '');
      return fullName.includes(currentQuery) || employeeId.includes(currentQuery);
    });
  }
  // Department filter
  const deptFilter = document.getElementById('attendance-filter-dept');
  if (deptFilter && deptFilter.value) {
    const selectedDept = deptFilter.value;
    filtered = filtered.filter(emp => emp.department === selectedDept);
  }
  return filtered;
}

// Modal for per-employee categorized records
function ensureEmployeeRecordsModal(){
  let wrap = document.getElementById('emp-rec-modal');
  if (wrap) return wrap;
  wrap = document.createElement('div');
  wrap.id = 'emp-rec-modal';
  wrap.className = 'fixed inset-0 z-50 hidden';
  wrap.innerHTML = `
    <div class="absolute inset-0 bg-black/40"></div>
    <div class="absolute inset-0 flex items-center justify-center p-4 overflow-y-auto">
      <div class="bg-white w-full max-w-5xl max-h-[90vh] overflow-y-auto rounded-lg shadow-lg">
        <div class="flex items-center justify-between px-4 py-3 border-b">
          <h3 id="emp-rec-title" class="text-lg font-semibold">Employee Records</h3>
          <button id="emp-rec-close" class="text-gray-500 hover:text-gray-700 text-xl leading-none">×</button>
        </div>
        <div id="emp-rec-body" class="p-4">
          <div class="text-sm text-gray-600">Loading...</div>
        </div>
      </div>
    </div>`;
  document.body.appendChild(wrap);
  wrap.addEventListener('click', (e) => {
    if (e.target.id === 'emp-rec-close' || e.target === wrap.firstElementChild) wrap.classList.add('hidden');
  });
  return wrap;
}

function ensureEmployeeSubModal(){
  let el = document.getElementById('emp-rec-submodal');
  if (el) return el;
  el = document.createElement('div');
  el.id = 'emp-rec-submodal';
  el.className = 'fixed inset-0 z-[60] hidden';
  el.innerHTML = `
    <div class="absolute inset-0 bg-black/30"></div>
    <div class="absolute inset-0 flex items-start justify-center p-4 overflow-y-auto">
      <div class="bg-white w-full max-w-3xl rounded-lg shadow-lg ring-1 ring-gray-200 mt-12">
        <div class="flex items-center justify-between px-4 py-2 border-b">
          <h4 id="emp-rec-submodal-title" class="font-semibold">Details</h4>
          <button id="emp-rec-submodal-close" class="text-gray-500 hover:text-gray-700 text-xl leading-none">×</button>
        </div>
        <div id="emp-rec-submodal-body" class="p-4">
          <div class="text-sm text-gray-600">Loading...</div>
        </div>
      </div>
    </div>`;
  document.body.appendChild(el);
  el.addEventListener('click', (e) => {
    if (e.target.id === 'emp-rec-submodal-close' || e.target === el.firstElementChild) {
      el.classList.add('hidden');
    }
  });
  return el;
}

async function openEmployeeRecordsModal(emp){
  const modal = ensureEmployeeRecordsModal();
  const title = modal.querySelector('#emp-rec-title');
  const body = modal.querySelector('#emp-rec-body');
  if (title) title.textContent = `${emp.full_name || (emp.first_name || '') + ' ' + (emp.last_name || '')} • ${emp.department || ''}`;
  if (body) body.innerHTML = `<div class="text-sm text-gray-600">Loading...</div>`;
  modal.classList.remove('hidden');

  try {
    const start_date = document.getElementById('attendance-filter-start-date')?.value || '';
    const end_date = document.getElementById('attendance-filter-end-date')?.value || '';
    // Attendance for date range
    const attReq = axios.get(`${window.baseApiUrl}/attendance.php`, { params: { operation: 'getAttendance', start_date, end_date } });
    // Overtime for employee in range
    const otReq = axios.get(`${window.baseApiUrl}/overtime.php`, { params: { operation: 'listAll', employee_id: emp.employee_id, start_date, end_date } });
    const [attRes, otRes] = await Promise.allSettled([attReq, otReq]);

    const attRows = attRes.status === 'fulfilled' && Array.isArray(attRes.value.data) ? attRes.value.data : [];
    const empAtt = attRows.filter(r => String(r.employee_id) === String(emp.employee_id));
    const norm = (s) => String(s || '').toLowerCase();
    const present = empAtt.filter(r => norm(r.status) === 'present' || norm(r.status) === 'on time' || norm(r.status) === 'ontime');
    const absent = empAtt.filter(r => norm(r.status) === 'absent');
    const undertime = empAtt.filter(r => norm(r.status) === 'undertime');
    const onleave = empAtt.filter(r => norm(r.status) === 'leave');
    const late = empAtt.filter(r => norm(r.status) === 'late');

    const otRows = otRes.status === 'fulfilled' && Array.isArray(otRes.value.data) ? otRes.value.data : [];

    const section = (label, rows, mapper, empty='No records') => {
      if (!rows || rows.length === 0) {
        // Do not render empty sections
        return '';
      }
      return `<div class="mb-6">
        <div class="overflow-x-auto border rounded">
          <table class="min-w-full text-sm">
            <tbody class="divide-y">${rows.map(r => `<tr>${mapper('row', r)}</tr>`).join('')}</tbody>
          </table>
        </div>
      </div>`;
    };

    const attMapper = (mode, r) => {
      if (mode === 'thead') return '<th class="px-3 py-2 text-left">Date</th><th class="px-3 py-2 text-left">Status</th><th class="px-3 py-2 text-left">Time In</th><th class="px-3 py-2 text-left">Time Out</th>';
      const date = formatDate(r.attendance_date);
      const st = String(r.status || '');
      const tin = formatTime(r.time_in);
      const tout = formatTime(r.time_out);
      return `<td class="px-3 py-2">${date}</td><td class="px-3 py-2">${st}</td><td class="px-3 py-2">${tin}</td><td class="px-3 py-2">${tout}</td>`;
    };

    const otMapper = (mode, r) => {
      if (mode === 'thead') return '<th class="px-3 py-2 text-left">Date</th><th class="px-3 py-2 text-left">Status</th><th class="px-3 py-2 text-left">Time In</th><th class="px-3 py-2 text-left">Time Out</th>';
      const date = formatDate(r.work_date);
      const st = String(r.status || '');
      const start = formatTime(r.start_time);
      const end = formatTime(r.end_time);
      return `<td class="px-3 py-2">${date}</td><td class="px-3 py-2">${st}</td><td class="px-3 py-2">${start}</td><td class="px-3 py-2">${end}</td>`;
    };

    const getOtHours = (r) => {
      if (r && r.hours != null && r.hours !== '' && !isNaN(parseFloat(r.hours))) return parseFloat(r.hours);
      if (r && r.start_time && r.end_time) {
        try {
          const [sh, sm] = String(r.start_time).split(':').map(Number);
          const [eh, em] = String(r.end_time).split(':').map(Number);
          let start = sh * 60 + sm;
          let end = eh * 60 + em;
          if (!Number.isFinite(start) || !Number.isFinite(end)) return 0;
          if (end < start) end += 24 * 60;
          return (end - start) / 60;
        } catch { return 0; }
      }
      return 0;
    };
    const otTotalHours = (otRows || []).reduce((sum, r) => sum + getOtHours(r), 0);

    // Cards grid for categories
    const categories = [
      { key: 'present', label: 'Present', rows: present, color: 'green' },
      { key: 'absent', label: 'Absent', rows: absent, color: 'red' },
      { key: 'undertime', label: 'Undertime', rows: undertime, color: 'purple' },
      { key: 'late', label: 'Late', rows: late, color: 'yellow' },
      { key: 'leave', label: 'On Leave', rows: onleave, color: 'blue' },
      { key: 'overtime', label: 'Overtime', rows: otRows, color: 'indigo' }
    ];

    const colorClasses = (name) => {
      switch (name) {
        case 'green': return { bg: 'bg-green-50', text: 'text-green-700', ring: 'ring-green-200', dot: 'bg-green-500' };
        case 'red': return { bg: 'bg-red-50', text: 'text-red-700', ring: 'ring-red-200', dot: 'bg-red-500' };
        case 'purple': return { bg: 'bg-purple-50', text: 'text-purple-700', ring: 'ring-purple-200', dot: 'bg-purple-500' };
        case 'yellow': return { bg: 'bg-yellow-50', text: 'text-yellow-700', ring: 'ring-yellow-200', dot: 'bg-yellow-500' };
        case 'blue': return { bg: 'bg-blue-50', text: 'text-blue-700', ring: 'ring-blue-200', dot: 'bg-blue-500' };
        case 'indigo': return { bg: 'bg-indigo-50', text: 'text-indigo-700', ring: 'ring-indigo-200', dot: 'bg-indigo-500' };
        default: return { bg: 'bg-gray-50', text: 'text-gray-700', ring: 'ring-gray-200', dot: 'bg-gray-500' };
      }
    };

    const firstRow = categories.slice(0, 3);
    const secondRow = categories.slice(3);

    const cardsHtml = `
      <div class="mb-6">
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
          ${firstRow.map(cat => {
            const cls = colorClasses(cat.color);
            return `
              <button type="button" class="emp-rec-cat-card w-full ${cls.bg} ${cls.text} ring-1 ${cls.ring} hover:shadow transition rounded-lg p-4 text-left flex items-center gap-3" data-target="sec-${cat.key}">
                <span class="inline-block w-2 h-2 rounded-full ${cls.dot}"></span>
                <span class="flex-1">
                  <span class="block text-xs opacity-70">${cat.label}</span>
                  <span class="block text-2xl font-semibold">${cat.rows.length}</span>
                </span>
              </button>`;
          }).join('')}
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-3">
          ${secondRow.map(cat => {
            const cls = colorClasses(cat.color);
            return `
              <button type="button" class="emp-rec-cat-card w-full ${cls.bg} ${cls.text} ring-1 ${cls.ring} hover:shadow transition rounded-lg p-4 text-left flex items-center gap-3" data-target="sec-${cat.key}">
                <span class="inline-block w-2 h-2 rounded-full ${cls.dot}"></span>
                <span class="flex-1">
                  <span class="block text-xs opacity-70">${cat.label}</span>
                  <span class="block text-2xl font-semibold">${cat.rows.length}</span>
                </span>
              </button>`;
          }).join('')}
        </div>
      </div>`;

    // Sections removed: only show cards; clicking a card opens a floating submodal
    body.innerHTML = `${cardsHtml}`;

    
    // Helper to open submodal for a category
    const openCatSub = (titleText, rows, mapper, sortKey, emptyMsg) => {
      const sub = ensureEmployeeSubModal();
      const subTitle = sub.querySelector('#emp-rec-submodal-title');
      const subBody = sub.querySelector('#emp-rec-submodal-body');
      if (subTitle) subTitle.textContent = titleText;
      const sorted = [...(rows || [])].sort((a,b) => new Date(b?.[sortKey]) - new Date(a?.[sortKey]));
      if (!sorted.length) {
        subBody.innerHTML = `<div class="text-sm text-gray-600">${emptyMsg}</div>`;
      } else {
        subBody.innerHTML = `
          <div class="overflow-x-auto border rounded">
            <table class="min-w-full text-sm">
              <thead class="bg-gray-50"><tr>${mapper('thead')}</tr></thead>
              <tbody class="divide-y">
                ${sorted.map(r => `<tr>${mapper('row', r)}</tr>`).join('')}
              </tbody>
            </table>
          </div>`;
      }
      sub.classList.remove('hidden');
    };

    // Wire up all category cards to open floating submodal with list
    const cardSelectors = [
      { sel: '.emp-rec-cat-card[data-target="sec-present"]',  title: 'Present Records',   rows: present,   mapper: attMapper, sortKey: 'attendance_date', empty: 'No present records.' },
      { sel: '.emp-rec-cat-card[data-target="sec-absent"]',   title: 'Absent Records',    rows: absent,    mapper: attMapper, sortKey: 'attendance_date', empty: 'No absent records.' },
      { sel: '.emp-rec-cat-card[data-target="sec-undertime"]',title: 'Undertime Records', rows: undertime, mapper: attMapper, sortKey: 'attendance_date', empty: 'No undertime records.' },
      { sel: '.emp-rec-cat-card[data-target="sec-late"]',     title: 'Late Records',      rows: late,      mapper: attMapper, sortKey: 'attendance_date', empty: 'No late records.' },
      { sel: '.emp-rec-cat-card[data-target="sec-leave"]',    title: 'On Leave Records',  rows: onleave,   mapper: attMapper, sortKey: 'attendance_date', empty: 'No on-leave records.' },
      { sel: '.emp-rec-cat-card[data-target="sec-overtime"]', title: 'Overtime Records',  rows: otRows,    mapper: otMapper,  sortKey: 'work_date',      empty: 'No overtime records.' }
    ];
    cardSelectors.forEach(c => {
      const el = body.querySelector(c.sel);
      if (!el) return;
      el.addEventListener('click', () => openCatSub(c.title, c.rows, c.mapper, c.sortKey, c.empty));
    });
  } catch (e) {
    body.innerHTML = `<div class="text-sm text-red-600">Failed to load records.</div>`;
  }
}

/**
 * RENDER PAGINATION
 * Create pagination controls
 */
function renderPagination(container, totalRecords, totalPages) {
  if (!container) return;
  
  if (totalPages <= 1) {
    container.innerHTML = '';
    return;
  }
  
  let paginationHTML = `
    <div class="flex items-center gap-2">
      <span class="text-sm text-gray-600">
        Showing ${(currentPage - 1) * pageSize + 1} to ${Math.min(currentPage * pageSize, totalRecords)} of ${totalRecords}
      </span>
    </div>
    <div class="flex items-center gap-1">
  `;
  
  // Previous button
  paginationHTML += `
    <button id="prev-page" class="px-2 py-1 text-sm rounded border ${currentPage === 1 ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-50'}"
            ${currentPage === 1 ? 'disabled' : ''}>
      Previous
    </button>
  `;
  
  // Page numbers (show up to 5 pages around current page)
  const startPage = Math.max(1, currentPage - 2);
  const endPage = Math.min(totalPages, currentPage + 2);
  
  for (let i = startPage; i <= endPage; i++) {
    paginationHTML += `
      <button class="px-3 py-1 text-sm rounded border ${i === currentPage ? 'bg-primary-600 text-white' : 'hover:bg-gray-50'} page-btn" 
              data-page="${i}">
        ${i}
      </button>
    `;
  }
  
  // Next button
  paginationHTML += `
    <button id="next-page" class="px-2 py-1 text-sm rounded border ${currentPage === totalPages ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-50'}"
            ${currentPage === totalPages ? 'disabled' : ''}>
      Next
    </button>
  `;
  
  paginationHTML += '</div>';
  container.innerHTML = paginationHTML;
  
  // Attach event listeners to pagination buttons
  document.getElementById('prev-page')?.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      renderAttendanceTable();
    }
  });
  
  document.getElementById('next-page')?.addEventListener('click', () => {
    if (currentPage < totalPages) {
      currentPage++;
      renderAttendanceTable();
    }
  });
  
  document.querySelectorAll('.page-btn').forEach(button => {
    button.addEventListener('click', () => {
      const page = parseInt(button.getAttribute('data-page'));
      if (page && page !== currentPage) {
        currentPage = page;
        renderAttendanceTable();
      }
    });
  });
}

/**
 * EXPORT ATTENDANCE RECORDS
 * Export attendance records to CSV
 */
function exportAttendanceRecords() {
  try {
    // Apply current filters
    let recordsToExport = applyFilters(allAttendanceRecords);
    
    // Sort by date
    recordsToExport.sort((a, b) => new Date(b.attendance_date) - new Date(a.attendance_date));
    
    // Create CSV content
    const headers = ['Date', 'Employee ID', 'Employee Name', 'Department', 'Status', 'Time In', 'Time Out', 'Total Hours'];
    const csvContent = [
      headers.join(','),
      ...recordsToExport.map(record => {
        const fullName = `${record.first_name || ''} ${record.last_name || ''}`.trim();
        const timeIn = formatTime(record.time_in);
        const timeOut = formatTime(record.time_out);
        const totalHours = calculateTotalHours(record.time_in, record.time_out);
        
        return [
          record.attendance_date,
          record.employee_id,
          `"${fullName}"`,
          `"${record.department || ''}"`,
          record.status,
          timeIn,
          timeOut,
          totalHours
        ].join(',');
      })
    ].join('\n');
    
    // Create download link
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `attendance_records_${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  } catch (error) {
    console.error('Error exporting attendance records:', error);
    showErrorMessage('Failed to export attendance records');
  }
}

/**
 * HELPER FUNCTIONS
 */

/**
 * FORMAT DATE
 * Format date as MM/DD/YYYY
 */
function formatDate(dateString) {
  if (!dateString) return '-';
  try {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  } catch {
    return dateString;
  }
}

/**
 * FORMAT TIME
 * Format time as HH:MM AM/PM
 */
function formatTime(timeString) {
  if (!timeString) return '-';
  try {
    const [hours, minutes] = timeString.split(':');
    const hour = parseInt(hours, 10);
    const minute = parseInt(minutes, 10);
    
    if (isNaN(hour) || isNaN(minute)) return timeString;
    
    const period = hour >= 12 ? 'PM' : 'AM';
    const displayHour = hour % 12 || 12;
    
    return `${displayHour}:${minute.toString().padStart(2, '0')} ${period}`;
  } catch {
    return timeString;
  }
}

/**
 * CALCULATE TOTAL HOURS
 * Calculate total hours between time in and time out
 */
function calculateTotalHours(timeIn, timeOut) {
  if (!timeIn) return '-';
  
  try {
    const parseTime = (timeStr) => {
      const [hours, minutes] = timeStr.split(':').map(Number);
      return hours * 60 + minutes;
    };
    
    const inMinutes = parseTime(timeIn);
    let outMinutes;
    
    if (timeOut) {
      outMinutes = parseTime(timeOut);
      // Handle overnight shifts
      if (outMinutes < inMinutes) {
        outMinutes += 24 * 60;
      }
    } else {
      // If no time out, use current time
      const now = new Date();
      outMinutes = now.getHours() * 60 + now.getMinutes();
      // If current time is before time in, it's likely an overnight shift
      if (outMinutes < inMinutes) {
        outMinutes += 24 * 60;
      }
    }
    
    const totalMinutes = outMinutes - inMinutes;
    if (totalMinutes <= 0) return '-';
    
    const hours = Math.floor(totalMinutes / 60);
    const minutes = totalMinutes % 60;
    
    if (minutes === 0) return `${hours}h`;
    return `${hours}h ${minutes}m`;
  } catch {
    return '-';
  }
}

/**
 * GET STATUS BADGE
 * Create a styled badge for attendance status
 */
function getStatusBadge(status) {
  const statusLower = (status || '').toLowerCase();
  
  const statusMap = {
    'present': { class: 'bg-green-100 text-green-800', text: 'Present' },
    'absent': { class: 'bg-red-100 text-red-800', text: 'Absent' },
    'late': { class: 'bg-yellow-100 text-yellow-800', text: 'Late' },
    'leave': { class: 'bg-blue-100 text-blue-800', text: 'On Leave' },
    'undertime': { class: 'bg-purple-100 text-purple-800', text: 'Undertime' }
  };
  
  const statusInfo = statusMap[statusLower] || { class: 'bg-gray-100 text-gray-800', text: status || 'Unknown' };
  
  return `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${statusInfo.class}">
    ${statusInfo.text}
  </span>`;
}

/**
 * SHOW ERROR MESSAGE
 * Display an error message using SweetAlert
 */
function showErrorMessage(message) {
  if (typeof Swal !== 'undefined') {
    Swal.fire({
      icon: 'error',
      title: 'Error',
      text: message,
      confirmButtonColor: '#3b82f6'
    });
  } else {
    alert(message);
  }
}
