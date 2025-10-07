/**
 * LEAVE TYPES MANAGEMENT INTERFACE
 * Handles CRUD operations for company leave type definitions
 * Provides paginated table view with search functionality
 */
(function(){
  /**
   * TOAST NOTIFICATION SYSTEM
   * Creates and displays temporary success/error messages
   * Manages container lifecycle and animation timing
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

  /**
   * API INTERFACE FOR LEAVE TYPES
   * Centralizes all HTTP requests for leave type operations
   * Provides create, read, update, delete functionality
   */
  const API = {
    base: (window.baseApiUrl || '../../api').replace(/\/$/, ''),
    list: () => axios.get(`${(window.baseApiUrl || '../../api').replace(/\/$/, '')}/leave-types.php`, { params: { operation: 'list' } }),
    create: (payload) => {
      const fd = new FormData();
      fd.append('operation', 'create');
      fd.append('json', JSON.stringify(payload));
      return axios.post(`${(window.baseApiUrl || '../../api').replace(/\/$/, '')}/leave-types.php`, fd);
    },
    update: (payload) => {
      const fd = new FormData();
      fd.append('operation', 'update');
      fd.append('json', JSON.stringify(payload));
      return axios.post(`${(window.baseApiUrl || '../../api').replace(/\/$/, '')}/leave-types.php`, fd);
    },
    delete: (id) => {
      const fd = new FormData();
      fd.append('operation', 'delete');
      fd.append('json', JSON.stringify({ id }));
      return axios.post(`${(window.baseApiUrl || '../../api').replace(/\/$/, '')}/leave-types.php`, fd);
    }
  };

  // State
  let allRows = [];
  let page = 1;
  let pageSize = 10;
  let query = '';

  /**
   * FETCH ALL LEAVE TYPES FROM API
   * Loads complete list of leave types into local state
   * Handles errors gracefully with empty fallback
   */
  async function fetchAll(){
    try {
      const res = await API.list();
      allRows = Array.isArray(res.data) ? res.data : [];
    } catch (e) {
      console.error('Failed to fetch leave types', e);
      allRows = [];
    }
  }

  /**
   * FILTER LEAVE TYPES BY SEARCH QUERY
   * Searches leave type names and descriptions for matches
   * Returns filtered array based on current search terms
   */
  function filtered(){
    let rows = allRows.slice();
    const q = (query||'').toLowerCase();
    if (q) rows = rows.filter(r => String(r.name||'').toLowerCase().includes(q) || String(r.description||'').toLowerCase().includes(q));
    return rows;
  }

  /**
   * RENDER LEAVE TYPES TABLE WITH PAGINATION
   * Updates table display with filtered data and controls
   * Wires event handlers for edit and delete actions
   */
  function render(){
    const tbody = document.getElementById('lt-tbody');
    const pager = document.getElementById('lt-pagination');
    if (!tbody || !pager) return;

    const rows = filtered();
    const total = rows.length;
    const pages = Math.max(1, Math.ceil(total / pageSize));
    if (page > pages) page = pages;
    const start = (page - 1) * pageSize;
    const slice = rows.slice(start, start + pageSize);
    tbody.innerHTML = '';
    if (slice.length === 0){
      tbody.innerHTML = '<tr><td colspan="5" class="px-3 py-3 text-sm text-gray-500">No leave types</td></tr>';
    } else {
      slice.forEach((r, i) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="px-3 py-2 text-sm text-gray-700">${start + i + 1}</td>
          <td class="px-3 py-2 text-sm text-gray-900 font-medium">${escapeHtml(r.name || '')}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${escapeHtml(r.description || '')}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${fmtDate(r.created_at)}</td>
          <td class="px-3 py-2 text-sm text-right">
            <button class="px-2 py-1 text-xs rounded border hover:bg-gray-50" data-action="edit" data-id="${r.id}">Edit</button>
            <button class="ml-1 px-2 py-1 text-xs rounded border border-red-600 text-red-700 hover:bg-red-50" data-action="delete" data-id="${r.id}">Delete</button>
          </td>`;
        tbody.appendChild(tr);
      });
      tbody.querySelectorAll('[data-action="edit"]').forEach(btn => btn.addEventListener('click', onEdit));
      tbody.querySelectorAll('[data-action="delete"]').forEach(btn => btn.addEventListener('click', onDelete));
    }
    pager.innerHTML = `
      <div>Showing <span class="font-medium">${total === 0 ? 0 : (start + 1)}</span>–<span class="font-medium">${Math.min(start + pageSize, total)}</span> of <span class="font-medium">${total}</span></div>
      <div class="flex items-center gap-2">
        <button id="lt-prev" class="px-2 py-1 text-xs rounded border ${page <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
        <span>Page ${page} of ${pages}</span>
        <button id="lt-next" class="px-2 py-1 text-xs rounded border ${page >= pages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
      </div>`;
    const prev = document.getElementById('lt-prev');
    const next = document.getElementById('lt-next');
    if (prev) prev.addEventListener('click', () => { if (page > 1) { page -= 1; render(); } });
    if (next) next.addEventListener('click', () => { if (page < pages) { page += 1; render(); } });
  }

  /**
   * OPEN ADD LEAVE TYPE MODAL
   * Resets form fields and configures modal for new entry
   * Sets appropriate modal title and clears inputs
   */
  function onAdd(){
    const inputId = document.getElementById('lt_id');
    const inputName = document.getElementById('lt_name');
    const inputDesc = document.getElementById('lt_desc');
    const modalTitle = document.getElementById('ltModalTitle');
    if (!inputId || !inputName || !inputDesc || !modalTitle) return;
    modalTitle.textContent = 'Add Leave Type';
    inputId.value = '';
    inputName.value = '';
    inputDesc.value = '';
    openModal('ltModal');
  }

  /**
   * OPEN EDIT LEAVE TYPE MODAL
   * Populates form with existing leave type data for editing
   * Configures modal title and pre-fills form fields
   */
  function onEdit(e){
    const id = String(e.currentTarget.getAttribute('data-id'));
    const row = allRows.find(r => String(r.id) === id);
    const inputId = document.getElementById('lt_id');
    const inputName = document.getElementById('lt_name');
    const inputDesc = document.getElementById('lt_desc');
    const modalTitle = document.getElementById('ltModalTitle');
    if (!row || !inputId || !inputName || !inputDesc || !modalTitle) return;
    modalTitle.textContent = 'Edit Leave Type';
    inputId.value = row.id;
    inputName.value = row.name || '';
    inputDesc.value = row.description || '';
    openModal('ltModal');
  }

  /**
   * DELETE LEAVE TYPE WITH CONFIRMATION
   * Prompts user for deletion confirmation before proceeding
   * Refreshes table data after successful removal
   */
  async function onDelete(e){
    const id = String(e.currentTarget.getAttribute('data-id'));
    const row = allRows.find(r => String(r.id) === id);
    if (!row) return;
    if (!confirm(`Delete leave type "${row.name}"?`)) return;
    try {
      await API.delete(id);
      showToast('Leave type deleted', 'success');
      await fetchAll();
      render();
    } catch(err) {
      console.error(err);
      showToast('Failed to delete leave type', 'error');
    }
  }

  /**
   * VALIDATE LEAVE TYPE FORM INPUT
   * Checks required fields and applies error styling
   * Returns boolean indicating validation success
   */
  function validate(){
    const inputName = document.getElementById('lt_name');
    if (!inputName) return false;
    inputName.classList.remove('border-red-500');
    if (!String(inputName.value||'').trim()){
      inputName.classList.add('border-red-500');
      inputName.focus();
      return false;
    }
    return true;
  }

  /**
   * SAVE LEAVE TYPE (CREATE OR UPDATE)
   * Determines operation mode and calls appropriate API endpoint
   * Handles validation, API calls, and success feedback
   */
  async function onSave(){
    if (!validate()) return;
    const inputId = document.getElementById('lt_id');
    const inputName = document.getElementById('lt_name');
    const inputDesc = document.getElementById('lt_desc');
    const editing = String(inputId.value||'').trim() !== '';
    const name = inputName.value.trim();
    const desc = (inputDesc.value||'').trim();

    try {
      if (editing){
        const id = String(inputId.value);
        await API.update({ id, name, description: desc });
      } else {
        await API.create({ name, description: desc, is_active: 1 });
      }
      closeModal('ltModal');
      showToast(editing ? 'Leave type updated' : 'Leave type created', 'success');
      await fetchAll();
      render();
    } catch(err) {
      console.error(err);
      const msg = err?.response?.data?.message || 'Operation failed';
      showToast(msg, 'error');
    }
  }

  function seedDefaultsIfEmpty(){ /* now handled by DB seed; no-op */ }

  function init(){
    // Wire controls
    const btnAdd = document.getElementById('btn-add-lt');
    const btnSave = document.getElementById('lt-save');
    const searchEl = document.getElementById('lt-search');
    const pageSizeEl = document.getElementById('lt-page-size');

    const modal = document.getElementById('ltModal');
    if (modal) modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => closeModal('ltModal')));

    if (btnAdd) btnAdd.addEventListener('click', onAdd);
    if (btnSave) btnSave.addEventListener('click', onSave);
    if (searchEl) searchEl.addEventListener('input', () => { query = (searchEl.value||'').trim(); page = 1; render(); });
    if (pageSizeEl) pageSizeEl.addEventListener('change', () => { const n = Number(pageSizeEl.value); pageSize = Number.isFinite(n) && n>0 ? n : 10; page = 1; render(); });

    fetchAll().then(() => { seedDefaultsIfEmpty(); render(); });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else { init(); }
})();
