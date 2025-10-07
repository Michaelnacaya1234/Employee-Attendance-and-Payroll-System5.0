/**
 * ADMIN UNDERTIME REQUEST MANAGEMENT
 * Handles undertime request submissions, approvals, and employee management
 * Provides filtering and search capabilities for administrative oversight
 */
(function(){
  const baseApiUrl = `${location.origin}/intro/api`;
  window.baseApiUrl = baseApiUrl;

  /**
   * LOCAL STATE MANAGEMENT
   * Maintains application state for filtering, pagination, and data
   */
  let allItems = [];
  let employees = [];
  let query = '';
  let page = 1;
  let pageSize = 10;
  let statusFilter = 'pending';
  let deptFilter = '';
  let editingUtId = null;

  function toTitleCase(s){
    return String(s||'')
      .toLowerCase()
      .split(/([ -])/)
      .map(part => (/^[ -]$/.test(part) ? part : part.charAt(0).toUpperCase() + part.slice(1)))
      .join('');
  }

  function escapeHtml(text){
    return String(text || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * LOAD EMPLOYEE DATA FROM API
   * Fetches all employees for selection and filtering purposes
   */
  async function loadEmployees(){
    try{
      const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getEmployees' } });
      employees = Array.isArray(res.data) ? res.data : [];
    }catch{ employees = []; }
  }

  /**
   * LOAD DEPARTMENT FILTER OPTIONS
   * Populates department dropdown for filtering undertime requests
   */
  async function loadDepartments(){
    try {
      const sel = document.getElementById('ut-req-dept-filter');
      if (!sel) return;
      const res = await axios.get(`${baseApiUrl}/employees.php`, { params: { operation: 'getDepartments' } });
      const list = Array.isArray(res.data) ? res.data : [];
      sel.innerHTML = '<option value="">All Departments</option>' + list.map(d => `<option value="${d}">${d}</option>`).join('');
    } catch {}
  }

  /**
   * LOAD ALL UNDERTIME REQUESTS
   * Fetches undertime data from API for display and processing
   */
  async function loadUndertime(){
    try{
      const res = await axios.get(`${baseApiUrl}/undertime.php`, { params: { operation: 'listAll' } });
      allItems = Array.isArray(res.data) ? res.data : [];
    }catch{ allItems = []; }
  }

  /**
   * GET EMPLOYEE DEPARTMENT FOR ROW
   * Retrieves department info from request data or employee lookup
   */
  function getRowDept(it){
    const d = String(it.department || '').trim();
    if (d) return d;
    const emp = employees.find(e => String(e.employee_id) === String(it.employee_id));
    return emp && emp.department ? emp.department : '';
  }

  /**
   * GENERATE STATUS BADGE HTML
   * Creates colored status badges for approval workflow states
   */
  function statusBadge(st){
    const s = String(st||'').toLowerCase();
    let cls = 'inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full ring-1 ';
    let label = 'Pending';
    if (s === 'approved' || s === 'approve') { cls += 'bg-green-50 text-green-700 ring-green-200'; label = 'Approved'; }
    else if (s === 'rejected' || s === 'reject') { cls += 'bg-red-50 text-red-700 ring-red-200'; label = 'Rejected'; }
    else { cls += 'bg-yellow-50 text-yellow-700 ring-yellow-200'; label = 'Pending'; }
    return `<span class="${cls}">${label}</span>`;
  }

  function formatWorkDate(s){
    if (!s) return '';
    try {
      const d = new Date(String(s).includes('T') ? s : `${s}T00:00:00`);
      if (isNaN(d.getTime())) return s;
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    } catch { return s; }
  }
  function formatTime12(timeStr){
    try {
      const parts = String(timeStr || '').split(':');
      if (parts.length < 2) return String(timeStr || '');
      let h = parseInt(parts[0], 10);
      const m = parseInt(parts[1], 10) || 0;
      if (!Number.isFinite(h)) return String(timeStr || '');
      const ampm = h >= 12 ? 'PM' : 'AM';
      h = h % 12; if (h === 0) h = 12;
      const mm = String(m).padStart(2, '0');
      return `${h}:${mm} ${ampm}`;
    } catch { return String(timeStr || ''); }
  }

  /**
   * RENDER EMPLOYEE SELECTION OPTIONS
   * Populates employee dropdown with search functionality
   */
  function renderEmpOptions(list, selected){
    const sel = document.getElementById('ut-emp');
    if (!sel) return;
    const cur = selected != null ? String(selected) : '';
    sel.innerHTML = '';
    list.forEach(e => {
      const opt = document.createElement('option');
      opt.value = e.employee_id;
      const nm = toTitleCase(`${e.first_name || ''} ${e.last_name || ''}`.trim());
      opt.textContent = nm;
      if (cur && String(cur) === String(e.employee_id)) opt.selected = true;
      sel.appendChild(opt);
    });
  }

  /**
   * WIRE EMPLOYEE SEARCH FUNCTIONALITY
   * Enables real-time filtering of employee dropdown options
   */
  function wireEmpSearch(){
    const input = document.getElementById('ut-emp-search');
    if (!input) return;
    input.oninput = () => {
      const q = (input.value || '').toLowerCase().trim();
      const selected = document.getElementById('ut-emp')?.value || '';
      const filtered = !q ? employees.slice() : employees.filter(e => `${(e.first_name||'').toLowerCase()} ${(e.last_name||'').toLowerCase()}`.includes(q) || String(e.email||'').toLowerCase().includes(q));
      renderEmpOptions(filtered, selected);
    };
  }

  /**
   * OPEN UNDERTIME REQUEST MODAL
   * Initializes modal with employee data and search capabilities
   */
  async function openUt(){
    await loadEmployees();
    renderEmpOptions(employees);
    wireEmpSearch();
    // reset fields and state for create mode
    editingUtId = null;
    const empSel = document.getElementById('ut-emp');
    const dateEl = document.getElementById('ut-date');
    const endEl = document.getElementById('ut-end');
    const reasonEl = document.getElementById('ut-reason');
    if (empSel) empSel.value = empSel.options[0]?.value || '';
    if (dateEl) dateEl.value = '';
    if (endEl) endEl.value = '';
    if (reasonEl) reasonEl.value = '';
    const modal = document.getElementById('adminUtModal');
    if (modal) {
      const title = modal.querySelector('h5');
      if (title) title.textContent = 'Request Undertime';
      const saveBtn = document.getElementById('ut-save');
      if (saveBtn) saveBtn.textContent = 'Submit';
      modal.classList.remove('hidden');
    }
  }

  function closeUt(){
    const modal = document.getElementById('adminUtModal');
    if (modal) modal.classList.add('hidden');
    // reset edit state after closing
    editingUtId = null;
    const saveBtn = document.getElementById('ut-save');
    if (saveBtn) saveBtn.textContent = 'Submit';
  }

  async function openUtEdit(it){
    // Ensure employees list is ready and options rendered
    await loadEmployees();
    renderEmpOptions(employees, it.employee_id);
    wireEmpSearch();
    // Set form values from row
    editingUtId = it.ut_id || it.id || null;
    const empSel = document.getElementById('ut-emp');
    const dateEl = document.getElementById('ut-date');
    const endEl = document.getElementById('ut-end');
    const reasonEl = document.getElementById('ut-reason');
    if (empSel && it.employee_id != null) empSel.value = String(it.employee_id);
    if (dateEl) dateEl.value = (it.work_date || '').slice(0,10);
    if (endEl) endEl.value = (it.end_time || '').slice(0,5);
    if (reasonEl) reasonEl.value = it.reason || '';
    // Update modal title and save button for edit mode
    const modal = document.getElementById('adminUtModal');
    if (modal) {
      const title = modal.querySelector('h5');
      if (title) title.textContent = 'Edit Undertime';
      const saveBtn = document.getElementById('ut-save');
      if (saveBtn) saveBtn.textContent = 'Update';
      modal.classList.remove('hidden');
    }
  }

  /**
   * SUBMIT UNDERTIME REQUEST
   * Validates form data and sends undertime request to API
   * Calculates hours based on shift end time difference
   */
  async function submitUndertime(){
    const employee_id = document.getElementById('ut-emp')?.value;
    const work_date = document.getElementById('ut-date')?.value;
    const end_time = document.getElementById('ut-end')?.value || '';
    const reason = document.getElementById('ut-reason')?.value || '';
    const toMinutes = (t) => { const parts = String(t).split(':').map(n => parseInt(n,10)); const h = parts[0]||0, m = parts[1]||0; return h*60 + m; };
    // Compute undertime hours as difference between shift end and selected time out
    const SHIFT_END = '20:00';
    let hours = 0;
    if (end_time) {
      const se = toMinutes(SHIFT_END);
      const b = toMinutes(end_time);
      const diff = se - b;
      hours = diff > 0 ? (diff / 60) : 0;
    }
    if (!employee_id || !work_date || !end_time || !Number.isFinite(hours) || hours <= 0){ alert('Select employee, date, and a valid time out'); return; }
    const fd = new FormData();
    const payload = { employee_id, work_date, hours, start_time: null, end_time, reason };
    if (editingUtId) { payload.ut_id = editingUtId; }
    fd.append('operation', editingUtId ? 'updateUndertime' : 'requestUndertime');
    fd.append('json', JSON.stringify(payload));
    try{
      await axios.post(`${baseApiUrl}/undertime.php`, fd);
      closeUt();
      alert(editingUtId ? 'Undertime request updated' : 'Undertime request submitted');
      await loadUndertime();
      page = 1;
      render();
    }catch{
      alert(editingUtId ? 'Failed to update undertime' : 'Failed to submit undertime');
    }
  }

  /**
   * SUBMIT APPROVAL/REJECTION DECISION
   * Processes admin decisions on undertime requests
   */
  async function submitDecision(it, op){
    try{
      const fd = new FormData();
      fd.append('operation', op === 'approve' ? 'approve' : 'reject');
      fd.append('json', JSON.stringify({ ut_id: it.ut_id || it.id }));
      await axios.post(`${baseApiUrl}/undertime.php`, fd);
    } catch {}
  }

  /**
   * GET FILTERED UNDERTIME REQUESTS
   * Applies search, status, and department filters to data
   * Returns filtered array for display
   */
  function getFiltered(){
    const q = (query || '').toLowerCase();
    const s = (statusFilter || 'pending').toLowerCase();
    let base = allItems.slice();
    // Only undertime items if API returns mixed kinds (safety)
    base = base.filter(it => (String(it.kind||'').toLowerCase() || 'undertime') === 'undertime' || it.ut_id != null);
    if (s !== 'all') {
      base = base.filter(it => {
        const st = String(it.status || '').toLowerCase();
        if (s === 'approved' || s === 'approve') return st === 'approved' || st === 'approve';
        if (s === 'rejected' || s === 'reject') return st === 'rejected' || st === 'reject';
        return st === 'pending';
      });
    }
    if (deptFilter) {
      base = base.filter(it => String(getRowDept(it) || '').toLowerCase() === deptFilter);
    }
    if (!q) return base;
    return base.filter(it => {
      const name = `${it.first_name || ''} ${it.last_name || ''}`.toLowerCase();
      const date = (it.work_date || '').toLowerCase();
      const reason = (it.reason || '').toLowerCase();
      const st = (it.status || '').toLowerCase();
      const dept = String(getRowDept(it) || '').toLowerCase();
      return name.includes(q) || date.includes(q) || reason.includes(q) || st.includes(q) || dept.includes(q);
    });
  }

  function render(){
    const tbody = document.getElementById('ut-requests-tbody');
    const pager = document.getElementById('ut-requests-pagination');
    if (!tbody) return;

    const rows = getFiltered();
    const total = rows.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (page > totalPages) page = totalPages;
    const startIdx = (page - 1) * pageSize;
    const endIdx = Math.min(startIdx + pageSize, total);
    const pageRows = rows.slice(startIdx, endIdx);

    tbody.innerHTML = '';
    if (!pageRows.length){
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="8" class="px-3 py-6 text-sm text-center text-gray-500">No undertime requests</td>`;
      tbody.appendChild(tr);
    } else {
      pageRows.forEach((it, idx) => {
        const tr = document.createElement('tr');
        const name = toTitleCase(`${it.first_name || ''} ${it.last_name || ''}`.trim());
        const dept = toTitleCase(getRowDept(it) || '');
        tr.innerHTML = `
          <td class="px-3 py-2 text-sm text-gray-700">${startIdx + idx + 1}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${name}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${dept}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${formatWorkDate(it.work_date) || ''}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${formatTime12(it.end_time) || ''}</td>
          <td class="px-3 py-2 text-sm text-gray-700 truncate max-w-[20rem]" title="${escapeHtml(it.reason || '')}">${escapeHtml(it.reason || '')}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${statusBadge(it.status)}</td>
          <td class="px-3 py-2 text-sm text-right">
            <div class="relative inline-block text-left" data-ut-menu-container>
              <button class="inline-flex items-center justify-center w-8 h-8 rounded hover:bg-gray-100" aria-label="Actions" data-action="menu-toggle">
                <span class="text-gray-600 font-bold text-lg">•••</span>
              </button>
              <div class="hidden origin-top-right absolute right-0 mt-2 w-36 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 z-10" role="menu" data-menu>
                <div class="py-1">
                  ${(() => {
                    const st = String((it.status||'')).toLowerCase();
                    if (st === 'pending') {
                      return `
                        <button class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50" data-menu-action="edit">Edit</button>
                        <button class="w-full text-left px-3 py-2 text-sm text-green-700 hover:bg-gray-50" data-menu-action="approve">Approve</button>
                        <button class="w-full text-left px-3 py-2 text-sm text-red-600 hover:bg-gray-50" data-menu-action="reject">Reject</button>
                      `;
                    } else if (st === 'approved' || st === 'approve') {
                      return `
                        <button class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50" data-menu-action="edit">Edit</button>
                      `;
                    }
                    // rejected or other: no actions
                    return '';
                  })()}
                </div>
              </div>
            </div>
          </td>`;
        const container = tr.querySelector('[data-ut-menu-container]');
        const toggle = container?.querySelector('[data-action="menu-toggle"]');
        const menu = container?.querySelector('[data-menu]');
        if (toggle && menu) {
          toggle.addEventListener('click', (ev) => {
            ev.preventDefault(); ev.stopPropagation();
            // Close other menus
            tbody.querySelectorAll('[data-ut-menu-container] [data-menu]').forEach(m => { if (m !== menu) m.classList.add('hidden'); });
            const wasHidden = menu.classList.contains('hidden');
            menu.classList.toggle('hidden');
            // When opening, temporarily disable scrollbars on the table wrapper (like Leave Requests)
            const wrap = container.closest('.overflow-x-auto');
            if (wasHidden) {
              if (wrap) {
                window.__utPrevScrollWrap = wrap;
                window.__utPrevOverflowX = wrap.style.overflowX;
                window.__utPrevOverflowY = wrap.style.overflowY;
                wrap.style.overflowX = 'visible';
                wrap.style.overflowY = 'visible';
              }
            } else {
              if (window.__utPrevScrollWrap) {
                window.__utPrevScrollWrap.style.overflowX = window.__utPrevOverflowX || '';
                window.__utPrevScrollWrap.style.overflowY = window.__utPrevOverflowY || '';
                window.__utPrevScrollWrap = null;
                window.__utPrevOverflowX = null;
                window.__utPrevOverflowY = null;
              }
            }
          });
          menu.querySelectorAll('[data-menu-action]').forEach(btn => {
            btn.addEventListener('click', async () => {
              const action = btn.getAttribute('data-menu-action');
              if (action === 'edit') {
                await openUtEdit(it);
              } else if (action === 'approve') {
                await submitDecision(it, 'approve');
                await loadUndertime();
                render();
              } else if (action === 'reject') {
                await submitDecision(it, 'reject');
                await loadUndertime();
                render();
              }
              menu.classList.add('hidden');
              // Restore scrollbars if we disabled them when opening
              if (window.__utPrevScrollWrap) {
                window.__utPrevScrollWrap.style.overflowX = window.__utPrevOverflowX || '';
                window.__utPrevScrollWrap.style.overflowY = window.__utPrevOverflowY || '';
                window.__utPrevScrollWrap = null;
                window.__utPrevOverflowX = null;
                window.__utPrevOverflowY = null;
              }
            });
          });
        }
        tbody.appendChild(tr);
      });
      // Wire global click close for UT menus
      if (!window.__utMenuGlobalClose) {
        window.__utMenuGlobalClose = true;
        document.addEventListener('click', () => {
          document.querySelectorAll('[data-ut-menu-container] [data-menu]').forEach(m => m.classList.add('hidden'));
          // Restore scroll state for table wrapper if modified
          if (window.__utPrevScrollWrap) {
            window.__utPrevScrollWrap.style.overflowX = window.__utPrevOverflowX || '';
            window.__utPrevScrollWrap.style.overflowY = window.__utPrevOverflowY || '';
            window.__utPrevScrollWrap = null;
            window.__utPrevOverflowX = null;
            window.__utPrevOverflowY = null;
          }
        });
      }
    }

    if (pager){
      const showingFrom = total === 0 ? 0 : (startIdx + 1);
      const showingTo = endIdx;
      pager.innerHTML = `
        <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${total}</span></div>
        <div class="flex items-center gap-2">
          <button id="ut-req-prev" class="px-1.5 py-0.5 text-xs rounded border ${page <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
          <span>Page ${page} of ${totalPages}</span>
          <button id="ut-req-next" class="px-1.5 py-0.5 text-xs rounded border ${page >= totalPages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
        </div>`;
      const prev = document.getElementById('ut-req-prev');
      const next = document.getElementById('ut-req-next');
      if (prev) prev.addEventListener('click', () => { if (page > 1) { page -= 1; render(); } });
      if (next) next.addEventListener('click', () => { if (page < totalPages) { page += 1; render(); } });
    }
  }

  async function init(){
    try {
      // Wire controls
      const searchInput = document.getElementById('ut-req-search-input');
      const pageSizeSelect = document.getElementById('ut-req-page-size');
      const statusSelect = document.getElementById('ut-req-status-filter');
      const deptSelect = document.getElementById('ut-req-dept-filter');

      if (searchInput) searchInput.addEventListener('input', () => { query = (searchInput.value || '').trim(); page = 1; render(); });
      if (pageSizeSelect) pageSizeSelect.addEventListener('change', () => {
        const n = Number(pageSizeSelect.value);
        pageSize = Number.isFinite(n) && n > 0 ? n : 10;
        page = 1;
        render();
      });
      if (statusSelect) statusSelect.addEventListener('change', () => {
        statusFilter = (statusSelect.value || 'pending').toLowerCase();
        page = 1;
        render();
      });
      if (deptSelect) deptSelect.addEventListener('change', () => {
        deptFilter = (deptSelect.value || '').toLowerCase();
        page = 1;
        render();
      });

      // Wire modal open/close and submit
      const openBtn = document.getElementById('ut-btn-file');
      const modal = document.getElementById('adminUtModal');
      const saveBtn = document.getElementById('ut-save');
      if (openBtn) openBtn.addEventListener('click', openUt);
      if (modal) modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeUt));
      if (saveBtn) saveBtn.addEventListener('click', submitUndertime);

      await Promise.all([loadEmployees(), loadDepartments(), loadUndertime()]);
      // Ensure deterministic order (newest first)
      allItems = allItems.slice().sort((a,b) => String(b.work_date||'').localeCompare(String(a.work_date||'')));
      render();
    } catch {
      render();
    }
  }

  document.addEventListener('DOMContentLoaded', init);
})();
