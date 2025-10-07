/**
 * DEPARTMENT MANAGEMENT INTERFACE
 * Handles CRUD operations for company departments and their positions
 * Provides paginated table view with search and filtering capabilities
 */
(function(){
  /**
   * TOAST NOTIFICATION HELPERS
   * Creates container and displays temporary success/error messages
   * Ensures single container instance with proper styling
   */
  function ensureToastContainer(){
    if (document.getElementById('toast-container')) return;
    const c = document.createElement('div');
    c.id = 'toast-container';
    c.className = 'fixed top-4 right-4 z-50 space-y-2';
    document.body.appendChild(c);
  }
  function showToast(msg, variant){
    ensureToastContainer();
    const container = document.getElementById('toast-container');
    const bg = variant === 'error' ? 'bg-red-600' : 'bg-green-600';
    const t = document.createElement('div');
    t.className = `${bg} text-white rounded shadow px-4 py-2 text-sm transition-opacity duration-300 opacity-0`;
    t.textContent = msg;
    container.appendChild(t);
    requestAnimationFrame(() => t.classList.remove('opacity-0'));
    setTimeout(() => { t.classList.add('opacity-0'); setTimeout(() => t.remove(), 300); }, 2200);
  }

  // Modal helpers
  function openModal(id){ const m = document.getElementById(id); if (m) m.classList.remove('hidden'); }
  function closeModal(id){ const m = document.getElementById(id); if (m) m.classList.add('hidden'); }

  function escapeHtml(str){ return String(str||'').replace(/[&<>\"]/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[s])); }
  function fmtDate(d){ if(!d) return ''; const dt = new Date(d); return isNaN(dt) ? '' : dt.toLocaleDateString(); }
  function toForm(map){ const fd = new FormData(); Object.entries(map).forEach(([k,v]) => fd.append(k, v)); return fd; }

  // State
  let allRows = [];
  let page = 1;
  let pageSize = 10;
  let query = '';

  /**
   * FILTER DEPARTMENTS BY SEARCH QUERY
   * Searches department names and descriptions for matching text
   * Returns filtered array based on current query string
   */
  function filtered(){
    let rows = allRows.slice();
    const q = (query||'').toLowerCase();
    if (q) rows = rows.filter(r => String(r.dept_name||'').toLowerCase().includes(q) || String(r.description||'').toLowerCase().includes(q));
    return rows;
  }

  /**
   * RENDER DEPARTMENT TABLE WITH PAGINATION
   * Updates table body with filtered data and pagination controls
   * Wires edit and delete button event handlers
   */
  function render(){
    const tbody = document.getElementById('dept-tbody');
    const pager = document.getElementById('dept-pagination');
    if (!tbody || !pager) return;

    const rows = filtered();
    const total = rows.length;
    const pages = Math.max(1, Math.ceil(total / pageSize));
    if (page > pages) page = pages;
    const start = (page - 1) * pageSize;
    const slice = rows.slice(start, start + pageSize);
    tbody.innerHTML = '';
    if (slice.length === 0){
      tbody.innerHTML = '<tr><td colspan="5" class="px-3 py-3 text-sm text-gray-500">No departments</td></tr>';
    } else {
      slice.forEach((r, i) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="px-3 py-2 text-sm text-gray-700">${start + i + 1}</td>
          <td class="px-3 py-2 text-sm text-gray-900 font-medium">${escapeHtml(r.dept_name || '')}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${escapeHtml(r.description || '')}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${fmtDate(r.created_at)}</td>
          <td class="px-3 py-2 text-sm text-right">
            <button class="px-2 py-1 text-xs rounded border hover:bg-gray-50" data-action="edit" data-id="${r.dept_id}">Edit</button>
            <button class="ml-1 px-2 py-1 text-xs rounded border border-red-600 text-red-700 hover:bg-red-50" data-action="delete" data-id="${r.dept_id}">Delete</button>
          </td>`;
        tbody.appendChild(tr);
      });
      tbody.querySelectorAll('[data-action="edit"]').forEach(btn => btn.addEventListener('click', onEdit));
      tbody.querySelectorAll('[data-action="delete"]').forEach(btn => btn.addEventListener('click', onDelete));
    }
    pager.innerHTML = `
      <div>Showing <span class="font-medium">${total === 0 ? 0 : (start + 1)}</span>–<span class="font-medium">${Math.min(start + pageSize, total)}</span> of <span class="font-medium">${total}</span></div>
      <div class="flex items-center gap-2">
        <button id="dept-prev" class="px-2 py-1 text-xs rounded border ${page <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
        <span>Page ${page} of ${pages}</span>
        <button id="dept-next" class="px-2 py-1 text-xs rounded border ${page >= pages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
      </div>`;
    const prev = document.getElementById('dept-prev');
    const next = document.getElementById('dept-next');
    if (prev) prev.addEventListener('click', () => { if (page > 1) { page -= 1; render(); } });
    if (next) next.addEventListener('click', () => { if (page < pages) { page += 1; render(); } });
  }

  /**
   * LOAD DEPARTMENTS FROM API
   * Fetches all department data and refreshes table display
   * Handles loading states and error conditions
   */
  async function load(){
    const tbody = document.getElementById('dept-tbody');
    if (tbody) tbody.innerHTML = '';
    try {
      const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getDepartmentsFull' } });
      allRows = Array.isArray(res.data) ? res.data : [];
    } catch { allRows = []; }
    render();
  }

  /**
   * OPEN ADD DEPARTMENT MODAL
   * Resets form fields and configures modal for new department creation
   * Hides position management section for new departments
   */
  function onAdd(){
    const inputId = document.getElementById('dept_id');
    const inputName = document.getElementById('dept_name');
    const inputDesc = document.getElementById('dept_desc');
    const modalTitle = document.getElementById('deptModalTitle');
    if (!inputId || !inputName || !inputDesc || !modalTitle) return;
    modalTitle.textContent = 'Add Department';
    inputId.value = '';
    inputName.value = '';
    inputDesc.value = '';
    const wrap = document.getElementById('dept_positions_wrap');
    const list = document.getElementById('dept_pos_list');
    const input = document.getElementById('dept_pos_input');
    if (wrap) wrap.classList.add('hidden');
    if (list) list.innerHTML = '';
    if (input) input.value = '';
    openModal('deptModal');
  }

  /**
   * OPEN EDIT DEPARTMENT MODAL
   * Populates form with existing department data and loads positions
   * Enables position management interface for existing departments
   */
  async function onEdit(e){
    const id = Number(e.currentTarget.getAttribute('data-id'));
    const row = allRows.find(r => Number(r.dept_id) === id);
    const inputId = document.getElementById('dept_id');
    const inputName = document.getElementById('dept_name');
    const inputDesc = document.getElementById('dept_desc');
    const modalTitle = document.getElementById('deptModalTitle');
    if (!row || !inputId || !inputName || !inputDesc || !modalTitle) return;
    modalTitle.textContent = 'Edit Department';
    inputId.value = row.dept_id;
    inputName.value = row.dept_name || '';
    inputDesc.value = row.description || '';
    // Show positions management panel
    const wrap = document.getElementById('dept_positions_wrap');
    const list = document.getElementById('dept_pos_list');
    const addBtn = document.getElementById('dept_pos_add');
    const input = document.getElementById('dept_pos_input');
    if (wrap && list && addBtn && input) {
      wrap.classList.remove('hidden');
      list.innerHTML = '';
      try {
        const res = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getDepartmentPositions', dept_name: row.dept_name } });
        const positions = Array.isArray(res.data) ? res.data : [];
        renderPositionList(list, id, positions);
      } catch { list.innerHTML = '<li class="py-2 text-red-600">Failed to load positions</li>'; }
      // Wire add
      addBtn.onclick = async () => {
        const name = (input.value || '').trim();
        if (!name) { input.focus(); return; }
        try {
          const fd = new FormData();
          fd.append('operation', 'addDepartmentPosition');
          fd.append('json', JSON.stringify({ dept_id: id, position_name: name }));
          const res = await axios.post(`${window.baseApiUrl}/employees.php`, fd);
          if (res.data && res.data.success){
            showToast('Position added', 'success');
            input.value = '';
            const reload = await axios.get(`${window.baseApiUrl}/employees.php`, { params: { operation: 'getDepartmentPositions', dept_name: row.dept_name } });
            renderPositionList(list, id, Array.isArray(reload.data) ? reload.data : []);
          } else {
            showToast(res.data && res.data.message ? res.data.message : 'Failed to add position', 'error');
          }
        } catch { showToast('Failed to add position', 'error'); }
      };
    }
    openModal('deptModal');
  }

  /**
   * RENDER DEPARTMENT POSITIONS LIST
   * Displays positions with delete functionality for each item
   * Handles empty states and position removal operations
   */
  function renderPositionList(listEl, deptId, positions){
    if (!listEl) return;
    const items = (positions || []).map(p => String(p));
    if (!items.length){ listEl.innerHTML = '<li class="py-2 text-gray-500">No positions yet</li>'; return; }
    listEl.innerHTML = '';
    items.forEach(name => {
      const li = document.createElement('li');
      li.className = 'py-1 flex items-center justify-between';
      li.innerHTML = `<span>${escapeHtml(name)}</span><button class="px-2 py-0.5 text-xs rounded border border-red-600 text-red-700" data-pos="${escapeHtml(name)}">Delete</button>`;
      li.querySelector('button').addEventListener('click', async () => {
        if (!confirm(`Delete position "${name}"?`)) return;
        try {
          const fd = new FormData();
          fd.append('operation', 'deleteDepartmentPosition');
          fd.append('json', JSON.stringify({ dept_id: deptId, position_name: name }));
          const res = await axios.post(`${window.baseApiUrl}/employees.php`, fd);
          if (res.data && res.data.success){
            showToast('Position deleted', 'success');
            li.remove();
            if (!listEl.children.length){ listEl.innerHTML = '<li class="py-2 text-gray-500">No positions yet</li>'; }
          } else { showToast('Failed to delete position', 'error'); }
        } catch { showToast('Failed to delete position', 'error'); }
      });
      listEl.appendChild(li);
    });
  }

  /**
   * DELETE DEPARTMENT WITH CONFIRMATION
   * Prompts user for confirmation before removing department
   * Refreshes table data after successful deletion
   */
  async function onDelete(e){
    const id = Number(e.currentTarget.getAttribute('data-id'));
    const row = allRows.find(r => Number(r.dept_id) === id);
    if (!row) return;
    if (!confirm(`Delete department "${row.dept_name}"?`)) return;
    try {
      const res = await axios.post(`${window.baseApiUrl}/employees.php`, toForm({ operation: 'deleteDepartment', json: JSON.stringify({ dept_id: id }) }));
      const ok = res && res.data && res.data.success;
      if (ok) { showToast('Department deleted', 'success'); await load(); }
      else { showToast('Failed to delete department', 'error'); }
    } catch { showToast('Failed to delete department', 'error'); }
  }

  function validate(){
    const inputName = document.getElementById('dept_name');
    if (!inputName) return false;
    inputName.classList.remove('border-red-500');
    if (!String(inputName.value||'').trim()){
      inputName.classList.add('border-red-500');
      inputName.focus();
      return false;
    }
    return true;
  }

  async function onSave(){
    if (!validate()) return;
    const inputId = document.getElementById('dept_id');
    const inputName = document.getElementById('dept_name');
    const inputDesc = document.getElementById('dept_desc');
    const editing = String(inputId.value||'').trim() !== '';
    const payload = { dept_name: inputName.value.trim(), description: (inputDesc.value||'').trim() };
    try {
      if (editing){ payload.dept_id = Number(inputId.value); }
      const op = editing ? 'updateDepartment' : 'createDepartment';
      const res = await axios.post(`${window.baseApiUrl}/employees.php`, toForm({ operation: op, json: JSON.stringify(payload) }));
      const data = res && res.data ? res.data : {};
      if (data.success){
        if (editing){
          closeModal('deptModal');
          showToast('Department updated', 'success');
          await load();
        } else {
          // New department created: keep modal open and switch to Edit mode to allow adding positions immediately
          const newId = Number(data.dept_id || 0);
          showToast('Department created', 'success');
          await load();
          if (newId > 0) {
            // Open edit flow for this department (shows positions panel)
            try {
              await onEdit({ currentTarget: { getAttribute: () => String(newId) } });
            } catch {}
          }
        }
      } else {
        showToast(data.message || 'Operation failed', 'error');
      }
    } catch {
      showToast('Operation failed', 'error');
    }
  }

  function init(){
    // Configure base API URL
    if (!window.baseApiUrl) {
      window.baseApiUrl = `${location.origin}/intro/api`;
    }

    const btnAdd = document.getElementById('btn-add-dept');
    const btnSave = document.getElementById('dept-save');
    const searchEl = document.getElementById('dept-search');
    const pageSizeEl = document.getElementById('dept-page-size');

    const modal = document.getElementById('deptModal');
    if (modal) modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => closeModal('deptModal')));

    if (btnAdd) btnAdd.addEventListener('click', onAdd);
    if (btnSave) btnSave.addEventListener('click', onSave);
    if (searchEl) searchEl.addEventListener('input', () => { query = (searchEl.value||'').trim(); page = 1; render(); });
    if (pageSizeEl) pageSizeEl.addEventListener('change', () => { const n = Number(pageSizeEl.value); pageSize = Number.isFinite(n) && n>0 ? n : 10; page = 1; render(); });

    load();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else { init(); }
})();
