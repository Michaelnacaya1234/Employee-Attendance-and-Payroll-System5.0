/**
 * RENDER AUDIT LOGS MANAGEMENT INTERFACE
 * Displays system audit trail with search, filtering, and pagination
 * Tracks user actions, timestamps, and IP addresses for security monitoring
 */
export async function render() {
  const app = document.getElementById('app');
  
  /**
   * STATE MANAGEMENT FOR AUDIT LOGS
   * Manages pagination, filtering, and data storage
   * Maintains current view state and user preferences
   */
  let allLogs = [];
  let currentPage = 1;
  let pageSize = 10;
  let totalPages = 1;
  let totalLogs = 0;
  
  app.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h4 class="text-xl font-semibold">Audit Logs</h4>
    </div>
    <div class="bg-white rounded-lg shadow p-4">
      <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div class="flex flex-wrap items-center gap-2">
          <div class="relative">
            <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
            <input id="audit-search-input" class="w-56 border rounded pl-9 pr-3 py-1.5 text-sm" placeholder="Search by username, action, details" />
          </div>
          <button id="audit-search-clear" aria-label="Clear search" class="inline-flex items-center gap-1.5 border border-gray-300 rounded px-2.5 py-1 text-sm text-gray-700 hover:bg-gray-50 active:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1">
            <svg class="w-4 h-4 text-gray-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
            <span>Clear</span>
          </button>
          <div class="flex items-center gap-2">
            <label class="text-sm text-gray-600">Date:</label>
            <input type="date" id="audit-date" class="border rounded px-2 py-1 text-sm" />
          </div>
        </div>
        <div class="flex items-center gap-2">
          <span class="text-sm text-gray-600">Rows per page</span>
          <select id="audit-page-size" class="border rounded px-2 py-1">
            <option value="10" selected>10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </div>
      </div>
      <div id="audit-logs-table"></div>
      <div id="audit-logs-pagination" class="mt-3 flex items-center justify-between text-sm text-gray-600"></div>
    </div>`;
  
  // Wire up event listeners
  const searchInput = document.getElementById('audit-search-input');
  const searchClear = document.getElementById('audit-search-clear');
  const pageSizeSelect = document.getElementById('audit-page-size');
  const dateInput = document.getElementById('audit-date');
  
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      currentPage = 1;
      loadAuditLogs();
    });
  }
  
  if (searchClear) {
    searchClear.addEventListener('click', () => {
      if (searchInput) searchInput.value = '';
      if (dateInput) dateInput.value = '';
      currentPage = 1;
      loadAuditLogs();
    });
  }
  
  if (pageSizeSelect) {
    pageSizeSelect.addEventListener('change', () => {
      const num = Number(pageSizeSelect.value);
      pageSize = Number.isFinite(num) && num > 0 ? num : 10;
      currentPage = 1;
      loadAuditLogs();
    });
  }
  if (dateInput) {
    dateInput.addEventListener('change', () => {
      currentPage = 1;
      loadAuditLogs();
    });
  }
  
    
  // Load initial data
  await loadAuditLogs();
  
  /**
   * LOAD AUDIT LOGS FROM API
   * Fetches audit log data with search and date filtering
   * Handles pagination and error states gracefully
   */
  async function loadAuditLogs() {
    const container = document.getElementById('audit-logs-table');
    if (!container) return;
    
    container.innerHTML = '<div class="text-gray-500">Loading...</div>';
    
    try {
      // Get filter values
      const searchQuery = searchInput ? searchInput.value.trim() : '';
      const onDate = dateInput ? dateInput.value : '';
      
      // Build query parameters
      const params = {
        operation: 'getAuditLogs',
        page: currentPage,
        limit: pageSize
      };
      
      if (searchQuery) {
        params.search = searchQuery;
      }
      
      if (onDate) {
        params.start_date = onDate;
        params.end_date = onDate;
      }
      
      const response = await axios.get(`${window.baseApiUrl}/reports.php`, { params });
      const data = response.data || {};
      
      allLogs = Array.isArray(data.logs) ? data.logs : [];
      totalLogs = data.total || 0;
      totalPages = data.pages || 1;
      
      renderAuditLogsTable();
    } catch (error) {
      container.innerHTML = '<div class="text-red-600">Failed to load audit logs</div>';
      console.error('Error loading audit logs:', error);
    }
  }
  
  /**
   * RENDER AUDIT LOGS TABLE
   * Creates formatted table with user data and action details
   * Handles empty states and provides pagination controls
   */
  function renderAuditLogsTable() {
    const container = document.getElementById('audit-logs-table');
    if (!container) return;
    
    if (!allLogs.length) {
      container.innerHTML = '<div class="text-gray-500">No audit logs found</div>';
      renderPagination();
      return;
    }
    
    const table = document.createElement('table');
    table.className = 'min-w-full divide-y divide-gray-200';
    table.innerHTML = `
      <thead class="bg-gray-50">
        <tr>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Timestamp</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">User</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Role</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Action</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">Details</th>
          <th class="px-3 py-2 text-left text-xs font-semibold text-gray-600">IP Address</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-200 bg-white"></tbody>`;
    
    const tbody = table.querySelector('tbody');
    allLogs.forEach(log => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="px-3 py-2 text-sm text-gray-700">${formatDateTime(log.created_at)}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${escapeHtml(log.username || 'Unknown')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${escapeHtml(log.role || 'Unknown')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${escapeHtml(log.action || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700 max-w-xs truncate" title="${escapeHtml(log.details || '')}">${escapeHtml(log.details || '')}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${escapeHtml(log.ip_address || '')}</td>`;
      tbody.appendChild(tr);
    });
    
    container.innerHTML = '';
    container.appendChild(table);
    
    renderPagination();
  }
  
  /**
   * RENDER PAGINATION CONTROLS
   * Creates previous/next buttons and page information display
   * Wires click handlers for navigation functionality
   */
  function renderPagination() {
    const footer = document.getElementById('audit-logs-pagination');
    if (!footer) return;
    
    const showingFrom = totalLogs === 0 ? 0 : ((currentPage - 1) * pageSize + 1);
    const showingTo = Math.min(currentPage * pageSize, totalLogs);
    
    footer.innerHTML = `
      <div>Showing <span class="font-medium">${showingFrom}</span>–<span class="font-medium">${showingTo}</span> of <span class="font-medium">${totalLogs}</span></div>
      <div class="flex items-center gap-2">
        <button id="audit-prev" class="px-2 py-1 text-xs rounded border ${currentPage <= 1 ? 'opacity-50 cursor-not-allowed' : ''}">Prev</button>
        <span>Page ${currentPage} of ${totalPages}</span>
        <button id="audit-next" class="px-2 py-1 text-xs rounded border ${currentPage >= totalPages ? 'opacity-50 cursor-not-allowed' : ''}">Next</button>
      </div>`;
    
    const prev = document.getElementById('audit-prev');
    const next = document.getElementById('audit-next');
    
    if (prev && currentPage > 1) {
      prev.addEventListener('click', () => {
        currentPage -= 1;
        loadAuditLogs();
      });
    }
    
    if (next && currentPage < totalPages) {
      next.addEventListener('click', () => {
        currentPage += 1;
        loadAuditLogs();
      });
    }
  }
  
  function formatDateTime(isoString) {
    if (!isoString) return '';
    try {
      const date = new Date(isoString);
      return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    } catch {
      return isoString;
    }
  }
  
  function escapeHtml(text) {
    return String(text || '')
      .replace(/&/g, '&')
      .replace(/</g, '<')
      .replace(/>/g, '>')
      .replace(/"/g, '"')
      .replace(/'/g, '&#039;');
  }
}