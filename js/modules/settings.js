/**
 * RENDER SETTINGS MANAGEMENT INTERFACE
 * Main function that renders the comprehensive settings dashboard
 * Includes user management, system config, security, backups, and audit logs
 */
export async function render() {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="mb-4">
      <h4 class="text-xl font-semibold">Settings</h4>
      <p class="text-sm text-gray-600">Manage users, system config, payroll rules, attendance rules, notifications, security, backups, and audit logs.</p>
    </div>
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div class="bg-white rounded-lg shadow p-4">
        <h5 class="font-semibold mb-2">Appearance</h5>
        <div class="text-sm text-gray-700 mb-2">Select a primary color theme:</div>
        <div class="flex items-center gap-2 flex-wrap" id="theme-swatches">
          <button type="button" class="w-7 h-7 rounded-full border ring-0" data-theme-pick="blue" style="background-color:#2563eb" aria-label="Blue"></button>
          <button type="button" class="w-7 h-7 rounded-full border ring-0" data-theme-pick="emerald" style="background-color:#059669" aria-label="Emerald"></button>
          <button type="button" class="w-7 h-7 rounded-full border ring-0" data-theme-pick="rose" style="background-color:#e11d48" aria-label="Rose"></button>
          <button type="button" class="w-7 h-7 rounded-full border ring-0" data-theme-pick="violet" style="background-color:#7c3aed" aria-label="Violet"></button>
          <button type="button" class="w-7 h-7 rounded-full border ring-0" data-theme-pick="amber" style="background-color:#d97706" aria-label="Amber"></button>
          <button type="button" class="w-7 h-7 rounded-full border ring-0" data-theme-pick="teal" style="background-color:#0d9488" aria-label="Teal"></button>
        </div>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <h5 class="font-semibold mb-2">User Management</h5>
        <ul class="list-disc list-inside text-sm text-gray-700 space-y-1">
          <li>Add, edit, deactivate, delete users</li>
          <li>Assign roles and permissions</li>
          <li>Reset passwords</li>
        </ul>
        <button id="open-user-mgmt" class="mt-3 px-3 py-2 text-sm rounded border">Open</button>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <h5 class="font-semibold mb-2">System Configuration</h5>
        <ul class="list-disc list-inside text-sm text-gray-700 space-y-1">
          <li>Company info, work days/hours</li>
          <li>Overtime rules</li>
          <li>Holidays and special days</li>
        </ul>
        <button id="open-system-config" class="mt-3 px-3 py-2 text-sm rounded border">Open</button>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <h5 class="font-semibold mb-2">Payroll Settings</h5>
        <ul class="list-disc list-inside text-sm text-gray-700 space-y-1">
          <li>Pay periods and salary rules</li>
          <li>Tax and deductions</li>
          <li>Loans</li>
        </ul>
        <button id="open-payroll-settings" class="mt-3 px-3 py-2 text-sm rounded border">Open</button>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <h5 class="font-semibold mb-2">Attendance Settings</h5>
        <ul class="list-disc list-inside text-sm text-gray-700 space-y-1">
          <li>Clock-in methods</li>
          <li>Late/early/absence rules</li>
          <li>Leave types and policies</li>
        </ul>
        <button id="open-attendance-settings" class="mt-3 px-3 py-2 text-sm rounded border">Open</button>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <h5 class="font-semibold mb-2">Notification Settings</h5>
        <ul class="list-disc list-inside text-sm text-gray-700 space-y-1">
          <li>Email/SMS templates</li>
          <li>Triggers and recipients</li>
        </ul>
        <button id="open-notification-settings" class="mt-3 px-3 py-2 text-sm rounded border">Open</button>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <h5 class="font-semibold mb-2">Security Settings</h5>
        <ul class="list-disc list-inside text-sm text-gray-700 space-y-1">
          <li>Password policy, 2FA</li>
          <li>Session timeouts, lockouts</li>
        </ul>
        <button id="open-security-settings" class="mt-3 px-3 py-2 text-sm rounded border">Open</button>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <h5 class="font-semibold mb-2">Backup & Data</h5>
        <ul class="list-disc list-inside text-sm text-gray-700 space-y-1">
          <li>Auto backups, manual backup/restore</li>
          <li>Import/export data</li>
        </ul>
        <button id="open-backup-settings" class="mt-3 px-3 py-2 text-sm rounded border">Open</button>
      </div>
      <div class="bg-white rounded-lg shadow p-4">
        <h5 class="font-semibold mb-2">Audit Logs</h5>
        <ul class="list-disc list-inside text-sm text-gray-700 space-y-1">
          <li>Logins, data changes</li>
          <li>Payroll runs and approvals</li>
        </ul>
        <button id="open-audit-logs" class="mt-3 px-3 py-2 text-sm rounded border">Open</button>
      </div>
    </div>

    <div id="settings-modal" class="fixed inset-0 z-50 hidden">
      <div class="absolute inset-0 bg-black/50" data-close="true"></div>
      <div class="relative mx-auto mt-20 w-full max-w-3xl">
        <div class="bg-white rounded-lg shadow max-h-[80vh] flex flex-col">
          <div class="flex items-center justify-between border-b px-4 py-3">
            <h5 class="font-semibold" id="settings-title">Settings</h5>
            <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
          </div>
          <div id="settings-body" class="p-4 text-sm text-gray-700 overflow-y-auto flex-1">
            <div class="text-gray-500">This is a placeholder. We can wire each section to backend endpoints as needed.</div>
          </div>
          <div class="flex justify-end gap-2 border-t px-4 py-3">
            <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
            <button id="settings-save" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
          </div>
        </div>
      </div>
    </div>`;

  // Minimal card animations with anime.js (no opacity changes)
  async function ensureAnime(){
    return new Promise((resolve, reject) => {
      if (window.anime) return resolve(window.anime);
      const s = document.createElement('script');
      s.src = 'https://cdnjs.cloudflare.com/ajax/libs/animejs/3.2.1/anime.min.js';
      s.async = true;
      s.onload = () => resolve(window.anime);
      s.onerror = () => reject(new Error('Failed to load anime.js'));
      document.head.appendChild(s);
    });
  }
  (async () => {
    try {
      const anime = await ensureAnime();
      const cards = Array.from(document.querySelectorAll('.grid > .bg-white.rounded-lg.shadow.p-4'));
      if (cards.length) {
        cards.forEach(c => { c.style.transformOrigin = '50% 50%'; });
        anime({
          targets: cards,
          translateY: [6, 0],
          scale: [0.98, 1],
          easing: 'easeOutQuad',
          duration: 360,
          delay: anime.stagger(50)
        });
        cards.forEach(card => {
          card.addEventListener('mouseenter', () => {
            anime.remove(card);
            anime({ targets: card, scale: 1.02, duration: 140, easing: 'easeOutQuad' });
          });
          card.addEventListener('mouseleave', () => {
            anime.remove(card);
            anime({ targets: card, scale: 1.0, duration: 160, easing: 'easeOutQuad' });
          });
        });
      }
    } catch {}
  })();

  const modalEl = document.getElementById('settings-modal');
  const openModal = () => modalEl.classList.remove('hidden');
  const closeModal = () => modalEl.classList.add('hidden');
  modalEl.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', closeModal));

  const sections = [
    ['open-user-mgmt', 'User Management'],
    ['open-system-config', 'System Configuration'],
    ['open-payroll-settings', 'Payroll Settings'],
    ['open-attendance-settings', 'Attendance Settings'],
    ['open-notification-settings', 'Notification Settings'],
    ['open-security-settings', 'Security Settings'],
    ['open-backup-settings', 'Backup & Data Management'],
    ['open-audit-logs', 'Audit Logs'],
  ];
  sections.forEach(([id, title]) => {
    const btn = document.getElementById(id);
    if (btn) btn.addEventListener('click', async () => {
      document.getElementById('settings-title').textContent = title;
      if (id === 'open-user-mgmt') {
        document.getElementById('settings-body').innerHTML = renderUserMgmtShell();
        wireUserMgmt();
      } else if (id === 'open-audit-logs') {
        document.getElementById('settings-body').innerHTML = renderAuditLogsShell();
        wireAuditLogs();
      } else if (id === 'open-security-settings') {
        document.getElementById('settings-body').innerHTML = renderSecuritySettingsShell();
        wireSecuritySettings();
      } else if (id === 'open-system-config') {
        document.getElementById('settings-body').innerHTML = renderSystemConfigShell();
        wireSystemConfig();
      } else if (id === 'open-notification-settings') {
        document.getElementById('settings-body').innerHTML = renderNotificationSettingsShell();
        wireNotificationSettings();
      } else if (id === 'open-attendance-settings') {
        document.getElementById('settings-body').innerHTML = renderAttendanceSettingsShell();
        wireAttendanceSettings();
      } else if (id === 'open-payroll-settings') {
        document.getElementById('settings-body').innerHTML = renderPayrollSettingsShell();
        wirePayrollSettings();
      } else if (id === 'open-backup-settings') {
        document.getElementById('settings-body').innerHTML = renderBackupSettingsShell();
        wireBackupSettings();
      } else {
        document.getElementById('settings-body').innerHTML = '<div class="text-gray-500">Coming soon – configurable options for ' + title + '.</div>';
      }
      openModal();
    });
  });

  document.getElementById('settings-save').addEventListener('click', () => {
    // Placeholder save (not used for User Management section)
    closeModal();
  });

  // User Management section
  function renderUserMgmtShell(){
    return `
      <div class="flex items-center justify-between mb-3">
        <div class="flex items-center gap-2">
          <div class="relative">
            <svg class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M10 18a8 8 0 100-16 8 8 0 000 16z"/></svg>
            <input id="um-search" class="w-48 border rounded pl-8 pr-2 py-1 text-xs" placeholder="Search username, name, email" />
          </div>
          <button id="um-refresh" class="px-2 py-1 text-xs rounded border">Refresh</button>
        </div>
        <div class="flex items-center gap-2">
          <button id="um-add" class="px-2 py-1 text-xs rounded bg-primary-600 text-white hover:bg-primary-700">Add User</button>
        </div>
      </div>
      <div class="overflow-x-auto border rounded">
        <table class="min-w-full text-sm">
          <thead class="bg-gray-50 text-xs text-gray-600">
            <tr>
              <th class="px-3 py-2 text-left">Username</th>
              <th class="px-3 py-2 text-left">Role</th>
              <th class="px-3 py-2 text-left">Employee</th>
              <th class="px-3 py-2 text-left">Status</th>
              <th class="px-3 py-2 text-left">Actions</th>
            </tr>
          </thead>
          <tbody id="um-tbody" class="divide-y"></tbody>
        </table>
      </div>
      <div id="um-empty" class="hidden p-4 text-center text-sm text-gray-500">No users found</div>

      <div id="um-form-modal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-24 w-full max-w-md">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3"><h5 class="font-semibold" id="um-form-title">Add User</h5><button class="text-gray-500 text-xl" data-close="true">×</button></div>
            <form id="um-form" class="p-4 space-y-2 text-sm">
              <input type="hidden" id="um-user-id" />
              <div>
                <label class="block text-xs text-gray-500 mb-1">Username (email)</label>
                <input id="um-username" class="w-full border rounded px-2 py-1" required />
              </div>
              <div>
                <label class="block text-xs text-gray-500 mb-1">Role</label>
                <select id="um-role" class="w-full border rounded px-2 py-1">
                  <option value="admin">Admin</option>
                  <option value="hr">HR</option>
                  <option value="manager">Manager</option>
                  <option value="employee">Employee</option>
                </select>
              </div>
              <div>
                <label class="block text-xs text-gray-500 mb-1">Link to Employee (optional)</label>
                <input id="um-employee-id" type="number" class="w-full border rounded px-2 py-1" placeholder="Employee ID" />
              </div>
              <div id="um-password-row">
                <label class="block text-xs text-gray-500 mb-1">Password (leave blank to auto-generate)</label>
                <input id="um-password" type="password" class="w-full border rounded px-2 py-1" />
              </div>
              <div class="pt-2 flex justify-end gap-2">
                <button type="button" class="px-3 py-2 text-sm rounded border" data-close="true">Cancel</button>
                <button id="um-save" type="submit" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    `;
  }

  function wireUserMgmt(){
    const tbody = document.getElementById('um-tbody');
    const empty = document.getElementById('um-empty');
    const search = document.getElementById('um-search');
    const refreshBtn = document.getElementById('um-refresh');
    const addBtn = document.getElementById('um-add');

    let rows = [];
    let q = '';

    const load = async () => {
      tbody.innerHTML = '<tr><td class="px-3 py-2 text-sm text-gray-500" colspan="5">Loading...</td></tr>';
      try {
        const res = await axios.get(`${window.baseApiUrl}/users.php`, { params: { operation: 'listUsers', q } });
        rows = Array.isArray(res.data) ? res.data : [];
      } catch { rows = []; }
      render();
    };

    const render = () => {
      const filtered = rows;
      if (!filtered.length){
        tbody.innerHTML = '';
        empty.classList.remove('hidden');
        return;
      }
      empty.classList.add('hidden');
      tbody.innerHTML = filtered.map(r => {
        const full = `${(r.first_name||'').trim()} ${(r.last_name||'').trim()}`.trim();
        const emp = r.employee_id ? `${full || 'Employee #'+r.employee_id}` : '';
        const status = r.emp_status ? r.emp_status : '';
        return `<tr>
          <td class="px-3 py-2">${r.username}</td>
          <td class="px-3 py-2 capitalize">${r.role}</td>
          <td class="px-3 py-2">${emp}</td>
          <td class="px-3 py-2 capitalize">${status}</td>
          <td class="px-3 py-2">
            <div class="flex items-center gap-1 text-xs">
              <button class="px-2 py-1 rounded border" data-um-act="edit" data-id="${r.user_id}">Edit</button>
              <button class="px-2 py-1 rounded border" data-um-act="pwd" data-id="${r.user_id}">Reset Password</button>
              ${r.user_id !== (window.__me && window.__me.user_id) ? `<button class="px-2 py-1 rounded border text-red-600" data-um-act="del" data-id="${r.user_id}">Delete</button>` : ''}
              ${r.employee_id ? `<button class="px-2 py-1 rounded border" data-um-act="toggle" data-id="${r.user_id}" data-status="${status==='active'?'inactive':'active'}">${status==='active'?'Deactivate':'Activate'}</button>` : ''}
            </div>
          </td>
        </tr>`;
      }).join('');
      tbody.querySelectorAll('[data-um-act]')?.forEach(btn => btn.addEventListener('click', onRowAction));
    };

    const openForm = (mode, row) => {
      const modal = document.getElementById('um-form-modal');
      const title = document.getElementById('um-form-title');
      const idEl = document.getElementById('um-user-id');
      const userEl = document.getElementById('um-username');
      const roleEl = document.getElementById('um-role');
      const empEl = document.getElementById('um-employee-id');
      const pwdRow = document.getElementById('um-password-row');
      const form = document.getElementById('um-form');

      title.textContent = mode === 'add' ? 'Add User' : 'Edit User';
      idEl.value = row?.user_id || '';
      userEl.value = row?.username || '';
      roleEl.value = row?.role || 'employee';
      empEl.value = row?.employee_id || '';
      pwdRow.style.display = mode === 'add' ? 'block' : 'none';

      modal.classList.remove('hidden');
      modal.querySelectorAll('[data-close="true"]').forEach(el => el.addEventListener('click', () => modal.classList.add('hidden')));
      form.onsubmit = async (e) => {
        e.preventDefault();
        try {
          if (mode === 'add'){
            const fd = new FormData();
            fd.append('operation', 'createUser');
            fd.append('json', JSON.stringify({ username: userEl.value.trim(), role: roleEl.value, employee_id: empEl.value ? Number(empEl.value) : null, password: document.getElementById('um-password').value }));
            const res = await axios.post(`${window.baseApiUrl}/users.php`, fd);
            if (!(res.data && res.data.success)) throw new Error();
          } else {
            const fd = new FormData();
            fd.append('operation', 'updateUser');
            fd.append('json', JSON.stringify({ user_id: Number(idEl.value), username: userEl.value.trim(), role: roleEl.value, employee_id: empEl.value ? Number(empEl.value) : null }));
            const res = await axios.post(`${window.baseApiUrl}/users.php`, fd);
            if (!(res.data && res.data.success)) throw new Error();
          }
          await load();
          modal.classList.add('hidden');
        } catch { alert('Failed to save user'); }
      };
    };

    function onRowAction(e){
      const act = e.currentTarget.getAttribute('data-um-act');
      const id = Number(e.currentTarget.getAttribute('data-id'));
      const row = rows.find(r => Number(r.user_id) === id);
      if (act === 'edit') return openForm('edit', row);
      if (act === 'del') return onDelete(id);
      if (act === 'pwd') return onResetPwd(id);
      if (act === 'toggle') {
        const status = e.currentTarget.getAttribute('data-status');
        return onToggleStatus(id, status);
      }
    }

    async function onDelete(id){
      if (!confirm('Delete this user?')) return;
      try {
        const fd = new FormData();
        fd.append('operation', 'deleteUser');
        fd.append('json', JSON.stringify({ user_id: id }));
        const res = await axios.post(`${window.baseApiUrl}/users.php`, fd);
        if (!(res.data && res.data.success)) throw new Error();
        await load();
      } catch { alert('Failed to delete user'); }
    }

    async function onResetPwd(id){
      const pwd = prompt('Enter new password (leave blank to auto-generate):', '');
      try {
        const fd = new FormData();
        fd.append('operation', 'adminResetPassword');
        fd.append('json', JSON.stringify({ user_id: id, password: (pwd || '') }));
        const res = await axios.post(`${window.baseApiUrl}/users.php`, fd);
        if (!(res.data && res.data.success)) throw new Error();
        if (res.data.generated_password) alert('Generated password: ' + res.data.generated_password);
      } catch { alert('Failed to reset password'); }
    }

    async function onToggleStatus(id, status){
      try {
        const fd = new FormData();
        fd.append('operation', 'setMappedEmployeeStatus');
        fd.append('json', JSON.stringify({ user_id: id, status }));
        const res = await axios.post(`${window.baseApiUrl}/users.php`, fd);
        if (!(res.data && res.data.success)) throw new Error();
        await load();
      } catch { alert('Failed to update status'); }
    }

    if (search) search.addEventListener('input', () => { q = search.value.trim(); load(); });
    if (refreshBtn) refreshBtn.addEventListener('click', load);
    if (addBtn) addBtn.addEventListener('click', () => openForm('add'));

    load();
  }

  // Backup & Data section (rendered inside Settings modal)
  function renderBackupSettingsShell(){
    return `
      <div class="flex items-center justify-between mb-3">
        <div class="text-sm text-gray-600">Create full database backup, download/restore SQL files, and manage stored backups.</div>
        <div class="flex items-center gap-2">
          <button id="backup-create" class="px-3 py-1.5 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Create Backup</button>
          <label class="px-3 py-1.5 text-sm rounded border cursor-pointer">
            <input id="backup-upload" type="file" accept=".sql" class="hidden" />
            Restore from file
          </label>
        </div>
      </div>
      <div id="backup-status" class="text-sm text-gray-600"></div>
      <div class="overflow-x-auto border rounded mt-3">
        <table class="min-w-full text-sm">
          <thead class="bg-gray-50 text-xs text-gray-600">
            <tr>
              <th class="px-3 py-2 text-left">File</th>
              <th class="px-3 py-2 text-left">Size</th>
              <th class="px-3 py-2 text-left">Created</th>
              <th class="px-3 py-2 text-left">Actions</th>
            </tr>
          </thead>
          <tbody id="backup-tbody" class="divide-y"></tbody>
        </table>
      </div>
      <div id="backup-empty" class="hidden p-4 text-center text-sm text-gray-500">No backups found</div>
    `;
  }

  function wireBackupSettings(){
    const tbody = document.getElementById('backup-tbody');
    const empty = document.getElementById('backup-empty');
    const status = document.getElementById('backup-status');
    const createBtn = document.getElementById('backup-create');
    const upload = document.getElementById('backup-upload');

    function setStatus(msg, type = 'info'){
      if (!status) return;
      status.textContent = msg || '';
      status.className = `text-sm ${type === 'error' ? 'text-red-600' : (type === 'success' ? 'text-green-600' : 'text-gray-600')}`;
    }

    function escapeHtml(text){
      return String(text || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    async function load(){
      setStatus('Loading...');
      try {
        const res = await axios.get(`${window.baseApiUrl}/backup.php`, { params: { operation: 'listBackups' }, withCredentials: true });
        const rows = Array.isArray(res.data) ? res.data : [];
        if (!rows.length){
          tbody.innerHTML = '';
          empty.classList.remove('hidden');
        } else {
          empty.classList.add('hidden');
          tbody.innerHTML = rows.map(r => `
            <tr>
              <td class="px-3 py-2">${escapeHtml(r.file)}</td>
              <td class="px-3 py-2">${formatSize(r.size)}</td>
              <td class="px-3 py-2">${escapeHtml(r.created_at)}</td>
              <td class="px-3 py-2">
                <div class="flex items-center gap-2">
                  <a class="px-2 py-1 text-xs rounded border" href="${window.baseApiUrl}/backup.php?operation=downloadBackup&file=${encodeURIComponent(r.file)}" target="_blank" rel="noopener">Download</a>
                  <button class="px-2 py-1 text-xs rounded border" data-bu-act="restore" data-file="${r.file}">Restore</button>
                  <button class="px-2 py-1 text-xs rounded border text-red-600" data-bu-act="delete" data-file="${r.file}">Delete</button>
                </div>
              </td>
            </tr>`).join('');
          tbody.querySelectorAll('[data-bu-act]')?.forEach(btn => btn.addEventListener('click', onRowAction));
        }
        setStatus('');
      } catch (e) {
        setStatus('Failed to load backups', 'error');
      }
    }

    function onRowAction(e){
      const act = e.currentTarget.getAttribute('data-bu-act');
      const file = e.currentTarget.getAttribute('data-file');
      if (act === 'restore') return restore(file);
      if (act === 'delete') return del(file);
    }

    async function create(){
      setStatus('Creating backup...');
      try {
        const fd = new FormData(); fd.append('operation', 'createBackup');
        const res = await axios.post(`${window.baseApiUrl}/backup.php`, fd, { withCredentials: true });
        if (res && res.data && res.data.success) {
          setStatus('Backup created', 'success');
          await load();
        } else { setStatus('Failed to create backup', 'error'); }
      } catch { setStatus('Failed to create backup', 'error'); }
    }

    async function restore(file){
      if (!confirm('Restore this backup? This will overwrite current data.')) return;
      setStatus('Restoring...');
      try {
        const fd = new FormData();
        fd.append('operation', 'restoreFromFile');
        fd.append('json', JSON.stringify({ file }));
        const res = await axios.post(`${window.baseApiUrl}/backup.php`, fd, { withCredentials: true });
        if (res && res.data && res.data.success) {
          setStatus('Restore completed', 'success');
        } else { setStatus('Restore failed', 'error'); }
      } catch { setStatus('Restore failed', 'error'); }
    }

    async function del(file){
      if (!confirm('Delete this backup file?')) return;
      setStatus('Deleting...');
      try {
        const fd = new FormData();
        fd.append('operation', 'deleteBackup');
        fd.append('json', JSON.stringify({ file }));
        const res = await axios.post(`${window.baseApiUrl}/backup.php`, fd, { withCredentials: true });
        if (res && res.data && res.data.success) {
          setStatus('Backup deleted', 'success');
          await load();
        } else { setStatus('Failed to delete backup', 'error'); }
      } catch { setStatus('Failed to delete backup', 'error'); }
    }

    function formatSize(bytes){
      const units = ['B','KB','MB','GB'];
      let i = 0; let s = Number(bytes) || 0;
      while (s >= 1024 && i < units.length - 1) { s /= 1024; i++; }
      return `${s.toFixed(1)} ${units[i]}`;
    }

    if (createBtn) createBtn.addEventListener('click', create);
    if (upload) upload.addEventListener('change', async (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      setStatus('Uploading and restoring...');
      try {
        const fd = new FormData();
        fd.append('operation', 'restoreUpload');
        fd.append('file', file);
        const res = await axios.post(`${window.baseApiUrl}/backup.php`, fd, { withCredentials: true });
        if (res && res.data && res.data.success) {
          setStatus('Restore completed', 'success');
          await load();
        } else {
          const errorMsg = (res && res.data && res.data.message) ? res.data.message : 'Restore failed';
          setStatus(errorMsg, 'error');
        }
      } catch (error) {
        // Check if it's a network error or server error with response
        if (error.response && error.response.data && error.response.data.message) {
          setStatus(error.response.data.message, 'error');
        } else {
          setStatus('Restore failed', 'error');
        }
      }
      e.target.value = '';
    });

    load();
  }

  // Security Settings section (rendered inside Settings modal)
  function renderSecuritySettingsShell(){
    return `
      <form id="security-settings-form" class="space-y-4">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label class="block text-xs text-gray-500 mb-1">Minimum password length</label>
            <input type="number" min="6" max="128" id="sec-password_min_length" class="w-full border rounded px-2 py-1" />
          </div>
          <div class="flex items-center gap-2 mt-6">
            <input type="checkbox" id="sec-password_require_uppercase" class="border rounded" />
            <label for="sec-password_require_uppercase" class="text-sm text-gray-700">Require uppercase</label>
          </div>
          <div class="flex items-center gap-2">
            <input type="checkbox" id="sec-password_require_number" class="border rounded" />
            <label for="sec-password_require_number" class="text-sm text-gray-700">Require number</label>
          </div>
          <div class="flex items-center gap-2">
            <input type="checkbox" id="sec-password_require_special" class="border rounded" />
            <label for="sec-password_require_special" class="text-sm text-gray-700">Require special character</label>
          </div>
          <div>
            <label class="block text-xs text-gray-500 mb-1">Password expiry (days)</label>
            <input type="number" min="0" max="3650" id="sec-password_expiry_days" class="w-full border rounded px-2 py-1" />
            <div class="text-xs text-gray-500 mt-1">0 = never expire</div>
          </div>
          <div class="flex items-center gap-2">
            <input type="checkbox" id="sec-two_factor_enabled" class="border rounded" />
            <label for="sec-two_factor_enabled" class="text-sm text-gray-700">Enable 2FA (TOTP)</label>
          </div>
          <div>
            <label class="block text-xs text-gray-500 mb-1">Session timeout (minutes)</label>
            <input type="number" min="5" max="1440" id="sec-session_timeout_minutes" class="w-full border rounded px-2 py-1" />
          </div>
          <div class="flex items-center gap-2">
            <input type="checkbox" id="sec-remember_me_enabled" class="border rounded" />
            <label for="sec-remember_me_enabled" class="text-sm text-gray-700">Allow remember me</label>
          </div>
          <div>
            <label class="block text-xs text-gray-500 mb-1">Lockout after failed attempts</label>
            <input type="number" min="0" max="20" id="sec-account_lockout_threshold" class="w-full border rounded px-2 py-1" />
            <div class="mt-3 p-2 border rounded bg-gray-50">
              <label class="flex items-center gap-2 text-sm">
                <input type="checkbox" id="sec-account_lockout_escalation_attempts_enabled" class="rounded" />
                <span>Enable escalating lockouts (attempts)</span>
              </label>
              <div class="grid grid-cols-1 md:grid-cols-3 gap-3 mt-2">
                <div>
                  <label class="block text-xs text-gray-500 mb-1">First lockout (attempts)</label>
                  <input type="number" min="1" max="50" id="sec-account_lockout_first_attempts" class="w-full border rounded px-2 py-1" />
                </div>
                <div>
                  <label class="block text-xs text-gray-500 mb-1">Second lockout (attempts)</label>
                  <input type="number" min="1" max="50" id="sec-account_lockout_second_attempts" class="w-full border rounded px-2 py-1" />
                </div>
                <div>
                  <label class="block text-xs text-gray-500 mb-1">Third+ lockout (attempts)</label>
                  <input type="number" min="1" max="50" id="sec-account_lockout_third_attempts" class="w-full border rounded px-2 py-1" />
                </div>
              </div>
              <div class="mt-1 text-xs text-gray-600">Example: First lockout = 5 attempts, second = 4 attempts, third = 3 attempts → escalates after repeated failures.</div>
            </div>
          </div>
          <div>
            <label class="block text-xs text-gray-500 mb-1">Lockout duration (minutes)</label>
            <input type="number" min="1" max="1440" id="sec-account_lockout_duration_minutes" class="w-full border rounded px-2 py-1" />
                        <div class="mt-3 p-2 border rounded bg-gray-50">
              <label class="flex items-center gap-2 text-sm">
                <input type="checkbox" id="sec-account_lockout_escalation_enabled" class="rounded" />
                <span>Enable escalating lockouts</span>
              </label>
              <div class="grid grid-cols-1 md:grid-cols-3 gap-3 mt-2">
                <div>
                  <label class="block text-xs text-gray-500 mb-1">First lockout (minutes)</label>
                  <input type="number" min="1" max="1440" id="sec-account_lockout_first_minutes" class="w-full border rounded px-2 py-1" />
                </div>
                <div>
                  <label class="block text-xs text-gray-500 mb-1">Second lockout (minutes)</label>
                  <input type="number" min="1" max="1440" id="sec-account_lockout_second_minutes" class="w-full border rounded px-2 py-1" />
                </div>
                <div>
                  <label class="block text-xs text-gray-500 mb-1">Third+ lockout (minutes)</label>
                  <input type="number" min="1" max="1440" id="sec-account_lockout_third_minutes" class="w-full border rounded px-2 py-1" />
                </div>
              </div>
              <div class="mt-1 text-xs text-gray-600">Example: First lockout = 5 min, second = 15 min, third = 30 min → escalates after repeated failures.</div>
            </div>
          </div>
        </div>
        <div class="pt-2 flex justify-end">
          <button id="security-settings-save" type="button" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save Security Settings</button>
        </div>
      </form>
      <div id="security-settings-status" class="text-sm"></div>
      <div class="mt-6 border-t pt-4">
        <div class="flex items-center justify-between mb-2">
          <h6 class="font-semibold">Blocked Accounts</h6>
          <button id="sec-refresh-blocked" class="px-2 py-1 text-xs rounded border">Refresh</button>
        </div>
        <div id="sec-blocked-status" class="text-sm text-gray-600"></div>
        <div class="overflow-x-auto border rounded mt-2">
          <table class="min-w-full text-sm">
            <thead class="bg-gray-50 text-xs text-gray-600">
              <tr>
                <th class="px-3 py-2 text-left">User</th>
                <th class="px-3 py-2 text-left">Role</th>
                <th class="px-3 py-2 text-left">Email</th>
                <th class="px-3 py-2 text-left">Blocked At</th>
                <th class="px-3 py-2 text-left">Actions</th>
              </tr>
            </thead>
            <tbody id="sec-blocked-tbody" class="divide-y"></tbody>
          </table>
        </div>
        <div id="sec-blocked-empty" class="hidden p-3 text-center text-sm text-gray-500">No blocked accounts</div>
      </div>
    `;
  }

  function wireSecuritySettings(){
    const apiBase = window.baseApiUrl || 'api';
    const status = (msg, type = 'info') => {
      const el = document.getElementById('security-settings-status');
      if (!el) return;
      el.textContent = msg || '';
      el.className = `text-sm ${type === 'error' ? 'text-red-600' : (type === 'success' ? 'text-green-600' : 'text-gray-600')}`;
    };

    const ids = [
      'password_min_length',
      'password_require_uppercase',
      'password_require_number',
      'password_require_special',
      'password_expiry_days',
      'two_factor_enabled',
      'session_timeout_minutes',
      'remember_me_enabled',
      'account_lockout_threshold',
      'account_lockout_duration_minutes',
      'account_lockout_escalation_enabled',
      'account_lockout_first_minutes',
      'account_lockout_second_minutes',
      'account_lockout_third_minutes',
      'account_lockout_escalation_attempts_enabled',
      'account_lockout_first_attempts',
      'account_lockout_second_attempts',
      'account_lockout_third_attempts'
    ];

    const getEl = (k) => document.getElementById(`sec-${k}`);

    // Helpers used by Blocked Accounts rendering
    function escapeHtml(text){
      return String(text || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }
    function formatTimestamp(iso){
      if (!iso) return '';
      try {
        const d = new Date(iso);
        if (isNaN(d.getTime())) return String(iso || '');
        const pad = (n) => String(n).padStart(2, '0');
        const y = d.getFullYear();
        const m = pad(d.getMonth() + 1);
        const day = pad(d.getDate());
        const hh = pad(d.getHours());
        const mm = pad(d.getMinutes());
        const ss = pad(d.getSeconds());
        return `${y}-${m}-${day} ${hh}:${mm}:${ss}`;
      } catch { return String(iso || ''); }
    }

    async function load(){
      status('Loading...');
      try {
        const res = await axios.get(`${apiBase}/security.php`, { params: { operation: 'getSecuritySettings' } });
        const cfg = res.data || {};
        ids.forEach(k => {
          const el = getEl(k);
          if (!el) return;
          if (el.type === 'checkbox') el.checked = String(cfg[k] || '0') === '1';
          else el.value = cfg[k] ?? '';
        });
        status('');
      } catch {
        status('Failed to load settings', 'error');
      }
      await loadBlocked();
    }

    async function save(){
      const payload = {};
      ids.forEach(k => {
        const el = getEl(k);
        if (!el) return;
        if (el.type === 'checkbox') payload[k] = el.checked ? 1 : 0;
        else payload[k] = Number(el.value);
      });
      try {
        const fd = new FormData();
        fd.append('operation', 'updateSecuritySettings');
        fd.append('json', JSON.stringify(payload));
        const res = await axios.post(`${apiBase}/security.php`, fd);
        if (res && res.data && res.data.success) {
          status('Security settings updated', 'success');
        } else {
          status('Failed to update settings', 'error');
        }
      } catch {
        status('Failed to update settings', 'error');
      }
    }

    async function loadBlocked(){
      const tbody = document.getElementById('sec-blocked-tbody');
      const empty = document.getElementById('sec-blocked-empty');
      const sEl = document.getElementById('sec-blocked-status');
      if (!tbody || !empty) return;
      sEl.textContent = 'Loading blocked accounts...';
      try {
        const res = await axios.get(`${apiBase}/security.php`, { params: { operation: 'listBlockedAccounts' } });
        const rows = Array.isArray(res.data) ? res.data : [];
        if (!rows.length){
          tbody.innerHTML = '';
          empty.classList.remove('hidden');
        } else {
          empty.classList.add('hidden');
          tbody.innerHTML = rows.map(r => `
            <tr>
              <td class="px-3 py-2">${escapeHtml(r.username)}${r.full_name ? ` <span class="text-gray-500">(${escapeHtml(r.full_name)})</span>` : ''}</td>
              <td class="px-3 py-2">${escapeHtml(r.role || '')}</td>
              <td class="px-3 py-2">${escapeHtml(r.email || '')}</td>
              <td class="px-3 py-2">${formatTimestamp(r.blocked_at)}</td>
              <td class="px-3 py-2"><button class="px-2 py-1 text-xs rounded border" data-unblock-id="${r.user_id}">Unblock</button></td>
            </tr>
          `).join('');
          tbody.querySelectorAll('[data-unblock-id]')?.forEach(btn => btn.addEventListener('click', async (e) => {
            const id = Number(e.currentTarget.getAttribute('data-unblock-id'));
            if (!id) return;
            if (!confirm('Unblock this account?')) return;
            try {
              const fd = new FormData();
              fd.append('operation', 'unblockAccount');
              fd.append('json', JSON.stringify({ user_id: id }));
              const resp = await axios.post(`${apiBase}/security.php`, fd);
              if (!(resp && resp.data && resp.data.success)) throw new Error();
              await loadBlocked();
            } catch { alert('Failed to unblock account'); }
          }));
        }
        sEl.textContent = '';
      } catch {
        sEl.textContent = 'Failed to load blocked accounts';
        sEl.className = 'text-sm text-red-600';
      }
    }

    const btn = document.getElementById('security-settings-save');
    if (btn) btn.addEventListener('click', save);
    const refreshBlocked = document.getElementById('sec-refresh-blocked');
    if (refreshBlocked) refreshBlocked.addEventListener('click', loadBlocked);
    load();
  }

  // Audit Logs section (rendered inside Settings modal)
  function renderAuditLogsShell(){
    return `
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
    `;
  }

  function wireAuditLogs(){
    let currentPage = 1;
    let pageSize = 10;
    let totalPages = 1;
    let totalLogs = 0;
    let allLogs = [];
    let sortDir = 'desc';

    const searchInput = document.getElementById('audit-search-input');
    const searchClear = document.getElementById('audit-search-clear');
    const pageSizeSelect = document.getElementById('audit-page-size');
    const dateInput = document.getElementById('audit-date');

    if (searchInput) searchInput.addEventListener('input', () => { currentPage = 1; loadAuditLogs(); });
    if (searchClear) searchClear.addEventListener('click', () => { if (searchInput) searchInput.value = ''; if (dateInput) dateInput.value = ''; currentPage = 1; loadAuditLogs(); });
    if (pageSizeSelect) pageSizeSelect.addEventListener('change', () => { const n = Number(pageSizeSelect.value); pageSize = Number.isFinite(n) && n > 0 ? n : 10; currentPage = 1; loadAuditLogs(); });
    if (dateInput) dateInput.addEventListener('change', () => { currentPage = 1; loadAuditLogs(); });

    loadAuditLogs();

    async function loadAuditLogs(){
      const container = document.getElementById('audit-logs-table');
      if (!container) return;
      container.innerHTML = '<div class="text-gray-500">Loading...</div>';
      try {
        const params = { operation: 'getAuditLogs', page: currentPage, limit: pageSize };
        const searchQuery = searchInput ? searchInput.value.trim() : '';
        const onDate = dateInput ? dateInput.value : '';
        if (searchQuery) params.search = searchQuery;
        if (onDate) { params.start_date = onDate; params.end_date = onDate; }
        const response = await axios.get(`${window.baseApiUrl}/reports.php`, { params });
        const data = response.data || {};
        allLogs = Array.isArray(data.logs) ? data.logs : [];
        totalLogs = data.total || 0;
        totalPages = data.pages || 1;
        sortLogs();
        renderAuditLogsTable();
      } catch (error) {
        const container2 = document.getElementById('audit-logs-table');
        if (container2) container2.innerHTML = '<div class="text-red-600">Failed to load audit logs</div>';
      }
    }

    function sortLogs(){
      const toTime = (x) => {
        const d = new Date(x && x.created_at !== undefined ? x.created_at : x);
        const t = d.getTime();
        return Number.isFinite(t) ? t : -Infinity;
      };
      allLogs.sort((a,b) => sortDir === 'asc' ? (toTime(a) - toTime(b)) : (toTime(b) - toTime(a)));
    }

    function renderAuditLogsTable(){
      const container = document.getElementById('audit-logs-table');
      if (!container) return;
      if (!allLogs.length){
        container.innerHTML = '<div class="text-gray-500">No audit logs found</div>';
        renderPagination();
        return;
      }
      const table = document.createElement('table');
      table.className = 'min-w-full divide-y divide-gray-200';
      table.innerHTML = `
        <thead class="bg-gray-50">
          <tr>
            <th id="audit-sort-ts" class="px-3 py-2 text-left text-xs font-semibold text-gray-600 cursor-pointer select-none">Timestamp <span id="audit-sort-ts-icon">↓</span></th>
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
          <td class="px-3 py-2 text-sm text-gray-700 font-mono">${formatTimestamp(log.created_at)}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${escapeHtml(log.username || 'Unknown')}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${escapeHtml(log.role || 'Unknown')}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${escapeHtml(log.action || '')}</td>
          <td class="px-3 py-2 text-sm text-gray-700 max-w-xs truncate" title="${escapeHtml(log.details || '')}">${escapeHtml(log.details || '')}</td>
          <td class="px-3 py-2 text-sm text-gray-700">${escapeHtml(log.ip_address || '')}</td>`;
        tbody.appendChild(tr);
      });
      container.innerHTML = '';
      container.appendChild(table);
      try {
        const th = table.querySelector('#audit-sort-ts');
        const icon = table.querySelector('#audit-sort-ts-icon');
        if (icon) icon.textContent = sortDir === 'asc' ? '↑' : '↓';
        if (th) th.addEventListener('click', () => {
          sortDir = sortDir === 'asc' ? 'desc' : 'asc';
          sortLogs();
          renderAuditLogsTable();
        });
      } catch {}
      renderPagination();
    }

    function renderPagination(){
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
      if (prev && currentPage > 1) prev.addEventListener('click', () => { currentPage -= 1; loadAuditLogs(); });
      if (next && currentPage < totalPages) next.addEventListener('click', () => { currentPage += 1; loadAuditLogs(); });
    }

    function formatTimestamp(iso){
      if (!iso) return '';
      try {
        const d = new Date(iso);
        if (isNaN(d.getTime())) return String(iso || '');
        const pad = (n) => String(n).padStart(2, '0');
        const y = d.getFullYear();
        const m = pad(d.getMonth() + 1);
        const day = pad(d.getDate());
        const hh = pad(d.getHours());
        const mm = pad(d.getMinutes());
        const ss = pad(d.getSeconds());
        return `${y}-${m}-${day} ${hh}:${mm}:${ss}`;
      } catch { return String(iso || ''); }
    }

    function escapeHtml(text){
      return String(text || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }
  }

  // System Configuration section (rendered inside Settings modal)
  function renderSystemConfigShell(){
    return `
      <form id="syscfg-form" class="space-y-4">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="p-3 border rounded">
            <h6 class="font-semibold mb-2">General</h6>
            <div class="space-y-3">
              <div>
                <label class="block text-xs text-gray-500 mb-1">Company name</label>
                <input id="syscfg-company_name" class="w-full border rounded px-2 py-1 text-sm" />
              </div>
              <div>
                <label class="block text-xs text-gray-500 mb-1">Company address</label>
                <input id="syscfg-company_address" class="w-full border rounded px-2 py-1 text-sm" />
              </div>
              <div>
                <label class="block text-xs text-gray-500 mb-1">System Profile</label>
                <select id="syscfg-system_profile" class="w-full border rounded px-2 py-1 text-sm">
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                </select>
              </div>
              <div>
                <label class="block text-xs text-gray-500 mb-1">Developed By</label>
                <input id="syscfg-developed_by" class="w-full border rounded px-2 py-1 text-sm" />
              </div>
                          </div>
          </div>
          <div class="p-3 border rounded">
            <h6 class="font-semibold mb-2">Work Schedule</h6>
            <div class="space-y-3">
              <div>
                <label class="block text-xs text-gray-500 mb-1">Work week</label>
                <div class="flex flex-wrap gap-3 text-sm">
                  <label class="inline-flex items-center gap-2"><input type="checkbox" id="syscfg-ww-mon" class="rounded"/>Mon</label>
                  <label class="inline-flex items-center gap-2"><input type="checkbox" id="syscfg-ww-tue" class="rounded"/>Tue</label>
                  <label class="inline-flex items-center gap-2"><input type="checkbox" id="syscfg-ww-wed" class="rounded"/>Wed</label>
                  <label class="inline-flex items-center gap-2"><input type="checkbox" id="syscfg-ww-thu" class="rounded"/>Thu</label>
                  <label class="inline-flex items-center gap-2"><input type="checkbox" id="syscfg-ww-fri" class="rounded"/>Fri</label>
                  <label class="inline-flex items-center gap-2"><input type="checkbox" id="syscfg-ww-sat" class="rounded"/>Sat</label>
                  <label class="inline-flex items-center gap-2"><input type="checkbox" id="syscfg-ww-sun" class="rounded"/>Sun</label>
                </div>
              </div>
              <div>
                <label class="block text-xs text-gray-500 mb-1">Total work hours (per day)</label>
                <input type="number" min="0" max="24" step="0.25" id="syscfg-work_hours_per_day" class="w-full border rounded px-2 py-1 text-sm" />
              </div>
                          </div>
          </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="p-3 border rounded">
            <h6 class="font-semibold mb-2">Overtime Rules</h6>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label class="block text-xs text-gray-500 mb-1">Regular Overtime (%)</label>
                <div class="flex items-center">
                  <input type="number" min="100" step="0.01" id="syscfg-ot-regular" class="w-full border rounded px-2 py-1 text-sm" />
                  <span class="ml-1 text-sm text-gray-600">%</span>
                </div>
              </div>
              <div>
                <label class="block text-xs text-gray-500 mb-1">Rest day Overtime (%)</label>
                <div class="flex items-center">
                  <input type="number" min="100" step="0.01" id="syscfg-ot-rest" class="w-full border rounded px-2 py-1 text-sm" />
                  <span class="ml-1 text-sm text-gray-600">%</span>
                </div>
              </div>
              <div>
                <label class="block text-xs text-gray-500 mb-1">Special Holiday Overtime (%)</label>
                <div class="flex items-center">
                  <input type="number" min="100" step="0.01" id="syscfg-ot-special" class="w-full border rounded px-2 py-1 text-sm" />
                  <span class="ml-1 text-sm text-gray-600">%</span>
                </div>
              </div>
              <div>
                <label class="block text-xs text-gray-500 mb-1">Regular Holiday Overtime (%)</label>
                <div class="flex items-center">
                  <input type="number" min="100" step="0.01" id="syscfg-ot-regular-holiday" class="w-full border rounded px-2 py-1 text-sm" />
                  <span class="ml-1 text-sm text-gray-600">%</span>
                </div>
              </div>
            </div>
          </div>
          <div class="p-3 border rounded">
            <h6 class="font-semibold mb-2">Undertime Rules</h6>
            <label class="flex items-center gap-2 text-sm">
              <input type="checkbox" id="syscfg-undertime-enabled" class="rounded" />
              <span>Enable undertime deduction</span>
            </label>
            <div class="mt-2">
              <label class="block text-xs text-gray-500 mb-1">Undertime grace period (minutes)</label>
              <input type="number" min="0" max="120" id="syscfg-undertime-grace-minutes" class="w-full border rounded px-2 py-1 text-sm" />
            </div>
            <div class="mt-2">
              <label class="block text-xs text-gray-500 mb-1">Undertime deduction (per hour)</label>
              <input type="number" min="0" step="0.01" id="syscfg-undertime-per-hour" class="w-full border rounded px-2 py-1 text-sm" />
            </div>
          </div>
        </div>
        <div class="pt-2 flex justify-end">
          <button id="syscfg-save" type="button" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save System Settings</button>
        </div>
        <div id="syscfg-status" class="text-sm"></div>
        <div class="mt-6 border-t pt-4">
          <div class="flex items-center justify-between mb-2">
            <h6 class="font-semibold">Holidays & Special Days</h6>
            <div class="flex items-center gap-2">
              <button id="syscfg-hol-auto-generate" type="button" class="px-2 py-1 text-xs rounded bg-purple-600 text-white hover:bg-purple-700">Auto-Generate All Years</button>
              <button id="syscfg-hol-refresh" type="button" class="px-2 py-1 text-xs rounded border">Refresh</button>
            </div>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-2 mb-2">
            <input type="date" id="syscfg-hol-date" class="border rounded px-2 py-1 text-sm" />
            <input type="text" id="syscfg-hol-name" class="border rounded px-2 py-1 text-sm" placeholder="Name" />
            <input type="text" id="syscfg-hol-desc" class="border rounded px-2 py-1 text-sm" placeholder="Description (optional)" />
          </div>
          <div class="flex items-center gap-2 mb-2">
            <input type="checkbox" id="syscfg-hol-recurring" class="rounded border-gray-300 text-primary-600 focus:ring-primary-500" />
            <label for="syscfg-hol-recurring" class="text-sm text-gray-700">Repeat every year (e.g., New Year, Christmas)</label>
          </div>
          <div class="flex items-center gap-2 mb-3">
            <button id="syscfg-hol-add" type="button" class="px-2 py-1 text-xs rounded bg-primary-600 text-white hover:bg-primary-700">Add Holiday</button>
            <div class="flex items-center gap-1">
              <input type="number" id="syscfg-hol-year" class="w-20 border rounded px-2 py-1 text-sm" placeholder="2024" min="2020" max="2030" />
              <button id="syscfg-hol-generate" type="button" class="px-2 py-1 text-xs rounded bg-green-600 text-white hover:bg-green-700">Generate Recurring</button>
            </div>
            <span id="syscfg-hol-status" class="text-sm text-gray-600"></span>
          </div>
          <div class="overflow-x-auto border rounded">
            <table class="min-w-full text-sm">
              <thead class="bg-gray-50 text-xs text-gray-600">
                <tr>
                  <th class="px-3 py-2 text-left">Date</th>
                  <th class="px-3 py-2 text-left">Name</th>
                  <th class="px-3 py-2 text-left">Description</th>
                  <th class="px-3 py-2 text-left">Type</th>
                  <th class="px-3 py-2 text-left">Actions</th>
                </tr>
              </thead>
              <tbody id="syscfg-hol-tbody" class="divide-y"></tbody>
            </table>
          </div>
          <div id="syscfg-hol-empty" class="hidden p-3 text-center text-sm text-gray-500">No holidays added</div>
        </div>
      </form>
    `;
  }

  function wireSystemConfig(){
    const apiBase = window.baseApiUrl || 'api';

    function setStatus(msg, type = 'info'){
      const el = document.getElementById('syscfg-status');
      if (!el) return;
      el.textContent = msg || '';
      el.className = `text-sm ${type === 'error' ? 'text-red-600' : (type === 'success' ? 'text-green-600' : 'text-gray-600')}`;
    }
    function setHolStatus(msg, type = 'info'){
      const el = document.getElementById('syscfg-hol-status');
      if (!el) return;
      el.textContent = msg || '';
      el.className = `text-sm ${type === 'error' ? 'text-red-600' : (type === 'success' ? 'text-green-600' : 'text-gray-600')}`;
    }
    function escapeHtml(text){
      return String(text || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    const wwIds = ['mon','tue','wed','thu','fri','sat','sun'];
    const toPercent = (m) => {
      const x = parseFloat(m);
      if (!Number.isFinite(x)) return '';
      const pct = x * 100;
      return Number.isInteger(pct) ? String(pct) : pct.toFixed(2);
    };
    const toMultiplier = (p) => {
      const x = parseFloat(p);
      if (!Number.isFinite(x)) return '';
      return (x / 100).toFixed(2);
    };

    async function loadSettings(){
      setStatus('Loading...');
      try {
        const res = await axios.get(`${apiBase}/system.php`, { params: { operation: 'getSystemSettings' } });
        const s = res.data || {};
        const val = (k, d = '') => s[k] ?? d;
        const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
        const setChk = (id, v) => { const el = document.getElementById(id); if (el) el.checked = String(v) === '1' || v === 1 || v === true; };

        setVal('syscfg-company_name', val('company_name', ''));
        setVal('syscfg-company_address', val('company_address', ''));
        setVal('syscfg-system_profile', val('system_profile', 'production'));
        setVal('syscfg-developed_by', val('developed_by', ''));
        setVal('syscfg-work_hours_per_day', val('work_hours_per_day', '8'));

        // Overtime multipliers -> UI percent
        setVal('syscfg-ot-regular', toPercent(val('ot_regular_multiplier', '1.25')));
        setVal('syscfg-ot-rest', toPercent(val('ot_rest_day_multiplier', '1.30')));
        setVal('syscfg-ot-special', toPercent(val('ot_special_holiday_multiplier', '1.50')));
        setVal('syscfg-ot-regular-holiday', toPercent(val('ot_regular_holiday_multiplier', '2.00')));

        // Undertime rules
        setChk('syscfg-undertime-enabled', val('undertime_deduction_enabled', '1'));
        setVal('syscfg-undertime-grace-minutes', val('undertime_grace_minutes', '0'));
        setVal('syscfg-undertime-per-hour', val('undertime_deduction_per_hour', '0.00'));

        // Work week
        let ww = [];
        try { ww = JSON.parse(val('work_week', '["mon","tue","wed","thu","fri"]')); if (!Array.isArray(ww)) ww = []; } catch { ww = ['mon','tue','wed','thu','fri']; }
        wwIds.forEach(d => {
          const el = document.getElementById(`syscfg-ww-${d}`);
          if (el) el.checked = ww.includes(d);
        });
        setStatus('');
      } catch {
        setStatus('Failed to load settings', 'error');
      }
      await loadHolidays();
    }

    async function saveSettings(){
      const getVal = (id) => { const el = document.getElementById(id); return el ? el.value : ''; };
      const getChk = (id) => { const el = document.getElementById(id); return el && el.checked ? 1 : 0; };
      const ww = wwIds.filter(d => { const el = document.getElementById(`syscfg-ww-${d}`); return el && el.checked; });
      const payload = {
        company_name: getVal('syscfg-company_name').trim(),
        company_address: getVal('syscfg-company_address').trim(),
        system_profile: getVal('syscfg-system_profile'),
        developed_by: getVal('syscfg-developed_by').trim(),
        work_hours_per_day: getVal('syscfg-work_hours_per_day'),
        // Overtime multipliers (store as multipliers)
        ot_regular_multiplier: toMultiplier(getVal('syscfg-ot-regular') || '125'),
        ot_rest_day_multiplier: toMultiplier(getVal('syscfg-ot-rest') || '130'),
        ot_special_holiday_multiplier: toMultiplier(getVal('syscfg-ot-special') || '150'),
        ot_regular_holiday_multiplier: toMultiplier(getVal('syscfg-ot-regular-holiday') || '200'),
        // Undertime rules
        undertime_deduction_enabled: getChk('syscfg-undertime-enabled'),
        undertime_grace_minutes: getVal('syscfg-undertime-grace-minutes'),
        undertime_deduction_per_hour: getVal('syscfg-undertime-per-hour'),
        work_week: JSON.stringify(ww)
      };
      setStatus('Saving...');
      try {
        const fd = new FormData();
        fd.append('operation', 'updateSystemSettings');
        fd.append('json', JSON.stringify(payload));
        const res = await axios.post(`${apiBase}/system.php`, fd);
        if (res && res.data && res.data.success) setStatus('System settings updated', 'success');
        else setStatus('Failed to update settings', 'error');
      } catch { setStatus('Failed to update settings', 'error'); }
    }

    async function loadHolidays(){
      const tbody = document.getElementById('syscfg-hol-tbody');
      const empty = document.getElementById('syscfg-hol-empty');
      if (!tbody || !empty) return;
      setHolStatus('Loading...');
      try {
        // Load holidays for a wider range to show all holidays including recurring ones
        const currentYear = new Date().getFullYear();
        const startDate = `${currentYear - 1}-01-01`;
        const endDate = `${currentYear + 5}-12-31`;
        
        const res = await axios.get(`${apiBase}/holidays.php`, { 
          params: { 
            operation: 'list',
            start_date: startDate,
            end_date: endDate
          } 
        });
        const rows = Array.isArray(res.data) ? res.data : [];
        if (!rows.length){
          tbody.innerHTML = '';
          empty.classList.remove('hidden');
        } else {
          empty.classList.add('hidden');
          tbody.innerHTML = rows.map(r => {
            const isGenerated = r.is_generated || (typeof r.id === 'string' && r.id.startsWith('recurring_'));
            const isRecurring = r.is_recurring == 1;
            
            let typeBadge = '';
            if (isGenerated) {
              typeBadge = '<span class="px-2 py-1 text-xs rounded bg-green-100 text-green-800">Generated</span>';
            } else if (isRecurring) {
              typeBadge = '<span class="px-2 py-1 text-xs rounded bg-blue-100 text-blue-800">Recurring</span>';
            } else {
              typeBadge = '<span class="px-2 py-1 text-xs rounded bg-gray-100 text-gray-600">One-time</span>';
            }
            
            const deleteButton = isGenerated ? 
              '<span class="px-2 py-1 text-xs rounded bg-gray-100 text-gray-400">Auto</span>' :
              `<button class="px-2 py-1 text-xs rounded border text-red-600" data-hol-del-id="${r.id}">Delete</button>`;
            
            return `
              <tr class="${isGenerated ? 'bg-green-50' : ''}">
                <td class="px-3 py-2">${escapeHtml(r.holiday_date || r.date || '')}</td>
                <td class="px-3 py-2">${escapeHtml(r.holiday_name || r.name || '')}</td>
                <td class="px-3 py-2">${escapeHtml(r.description || '')}</td>
                <td class="px-3 py-2">${typeBadge}</td>
                <td class="px-3 py-2">${deleteButton}</td>
              </tr>
            `;
          }).join('');
          tbody.querySelectorAll('[data-hol-del-id]')?.forEach(btn => btn.addEventListener('click', async (e) => {
            const id = Number(e.currentTarget.getAttribute('data-hol-del-id'));
            if (!id) return;
            if (!confirm('Delete this holiday?')) return;
            try {
              const fd = new FormData();
              fd.append('operation', 'delete');
              fd.append('json', JSON.stringify({ id }));
              const resp = await axios.post(`${apiBase}/holidays.php`, fd);
              if (!(resp && resp.data && resp.data.success)) throw new Error();
              await loadHolidays();
            } catch { alert('Failed to delete holiday'); }
          }));
        }
        setHolStatus('');
      } catch {
        setHolStatus('Failed to load holidays', 'error');
      }
    }

    async function addHoliday(){
      const date = (document.getElementById('syscfg-hol-date')?.value || '').trim();
      const name = (document.getElementById('syscfg-hol-name')?.value || '').trim();
      const desc = (document.getElementById('syscfg-hol-desc')?.value || '').trim();
      const isRecurring = document.getElementById('syscfg-hol-recurring')?.checked || false;
      
      if (!date || !name){ setHolStatus('Date and Name are required', 'error'); return; }
      setHolStatus('Adding...');
      try {
        const fd = new FormData();
        fd.append('operation', 'create');
        fd.append('json', JSON.stringify({ 
          holiday_date: date, 
          holiday_name: name, 
          description: desc,
          is_recurring: isRecurring
        }));
        const res = await axios.post(`${apiBase}/holidays.php`, fd);
        if (res && res.data && res.data.success) {
          setHolStatus('Holiday added', 'success');
          try { document.getElementById('syscfg-hol-date').value = ''; } catch {}
          try { document.getElementById('syscfg-hol-name').value = ''; } catch {}
          try { document.getElementById('syscfg-hol-desc').value = ''; } catch {}
          try { document.getElementById('syscfg-hol-recurring').checked = false; } catch {}
          await loadHolidays();
        } else {
          setHolStatus(res.data?.message || 'Failed to add holiday', 'error');
        }
      } catch (error) { 
        setHolStatus('Failed to add holiday', 'error'); 
      }
    }

    async function generateRecurringHolidays(){
      const year = document.getElementById('syscfg-hol-year')?.value;
      if (!year || year < 2020 || year > 2030) {
        setHolStatus('Please enter a valid year (2020-2030)', 'error');
        return;
      }
      
      if (!confirm(`Generate recurring holidays for ${year}? This will create holidays like New Year, Christmas, etc. for the specified year.`)) {
        return;
      }
      
      setHolStatus('Generating recurring holidays...');
      try {
        const fd = new FormData();
        fd.append('operation', 'generate_recurring');
        fd.append('json', JSON.stringify({ year: parseInt(year) }));
        const res = await axios.post(`${apiBase}/holidays.php`, fd);
        
        if (res && res.data && res.data.success) {
          const message = res.data.message || `Generated ${res.data.created || 0} holidays for ${year}`;
          setHolStatus(message, 'success');
          await loadHolidays();
        } else {
          setHolStatus(res.data?.message || 'Failed to generate recurring holidays', 'error');
        }
      } catch (error) { 
        setHolStatus('Failed to generate recurring holidays', 'error'); 
      }
    }

    async function autoGenerateAllYears(){
      const currentYear = new Date().getFullYear();
      const years = [currentYear, currentYear + 1, currentYear + 2, currentYear + 3, currentYear + 4];
      
      if (!confirm(`Generate recurring holidays for years ${years.join(', ')}? This will create holidays like New Year, Christmas, etc. for all these years.`)) {
        return;
      }
      
      setHolStatus('Generating recurring holidays for multiple years...');
      let totalCreated = 0;
      let totalSkipped = 0;
      
      try {
        for (const year of years) {
          const fd = new FormData();
          fd.append('operation', 'generate_recurring');
          fd.append('json', JSON.stringify({ year: year }));
          const res = await axios.post(`${apiBase}/holidays.php`, fd);
          
          if (res && res.data && res.data.success) {
            totalCreated += res.data.created || 0;
            totalSkipped += res.data.skipped || 0;
          }
        }
        
        setHolStatus(`Generated ${totalCreated} holidays across ${years.length} years (${totalSkipped} already existed)`, 'success');
        await loadHolidays();
      } catch (error) { 
        setHolStatus('Failed to generate recurring holidays', 'error'); 
      }
    }

    const saveBtn = document.getElementById('syscfg-save');
    if (saveBtn) saveBtn.addEventListener('click', saveSettings);
    const addHolBtn = document.getElementById('syscfg-hol-add');
    if (addHolBtn) addHolBtn.addEventListener('click', addHoliday);
    const refreshHolBtn = document.getElementById('syscfg-hol-refresh');
    if (refreshHolBtn) refreshHolBtn.addEventListener('click', loadHolidays);
    const generateHolBtn = document.getElementById('syscfg-hol-generate');
    if (generateHolBtn) generateHolBtn.addEventListener('click', generateRecurringHolidays);
    const autoGenerateBtn = document.getElementById('syscfg-hol-auto-generate');
    if (autoGenerateBtn) autoGenerateBtn.addEventListener('click', autoGenerateAllYears);

    // Set default year to current year
    const yearInput = document.getElementById('syscfg-hol-year');
    if (yearInput) yearInput.value = new Date().getFullYear();

    loadSettings();
  }

  // Attendance Settings section (rendered inside Settings modal)
  function renderAttendanceSettingsShell(){
    return `
      <form id="att-settings-form" class="space-y-4">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="p-3 border rounded">
            <h6 class="font-semibold mb-2">Clock-in</h6>
            <div>
              <label class="block text-xs text-gray-500 mb-1">Clock-in method</label>
              <select id="att-clock_in_method" class="w-full border rounded px-2 py-1 text-sm">
                <option value="qr">QR Code</option>
                <option value="pin">PIN</option>
                <option value="manual">Manual</option>
                <option value="rfid">RFID</option>
              </select>
            </div>
          </div>
          <div class="p-3 border rounded">
            <h6 class="font-semibold mb-2">Work Hours</h6>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-xs text-gray-500 mb-1">Standard start time</label>
                <input type="time" id="att-standard_start" class="w-full border rounded px-2 py-1 text-sm" />
              </div>
              <div>
                <label class="block text-xs text-gray-500 mb-1">Standard end time</label>
                <input type="time" id="att-standard_end" class="w-full border rounded px-2 py-1 text-sm" />
              </div>
            </div>
            <div class="mt-3">
              <label class="block text-xs text-gray-500 mb-1">Late grace period (minutes)</label>
              <input type="number" min="0" max="120" id="att-grace_period_minutes" class="w-full border rounded px-2 py-1 text-sm" />
            </div>
          </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="p-3 border rounded">
            <h6 class="font-semibold mb-2">Break & Overtime</h6>
            <div class="flex items-center gap-2">
              <input type="checkbox" id="att-allow_break_scans" class="rounded" />
              <label for="att-allow_break_scans" class="text-sm text-gray-700">Allow break scans?</label>
            </div>
            <div class="flex items-center gap-2 mt-2">
              <input type="checkbox" id="att-overtime_tracking_enabled" class="rounded" />
              <label for="att-overtime_tracking_enabled" class="text-sm text-gray-700">Enable overtime tracking</label>
            </div>
          </div>
        </div>
        <div class="pt-2 flex justify-end">
          <button id="att-settings-save" type="button" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save Attendance Settings</button>
        </div>
      </form>
      <div id="att-settings-status" class="text-sm"></div>
    `;
  }

  function wireAttendanceSettings(){
    const apiBase = window.baseApiUrl || 'api';
    const status = (msg, type = 'info') => {
      const el = document.getElementById('att-settings-status');
      if (!el) return;
      el.textContent = msg || '';
      el.className = `text-sm ${type === 'error' ? 'text-red-600' : (type === 'success' ? 'text-green-600' : 'text-gray-600')}`;
    };
    function getVal(id){ const el = document.getElementById(id); return el ? el.value : ''; }
    function setVal(id, v){ const el = document.getElementById(id); if (el) el.value = v; }
    function getChk(id){ const el = document.getElementById(id); return el && el.checked ? 1 : 0; }
    function setChk(id, v){ const el = document.getElementById(id); if (el) el.checked = String(v) === '1' || v === 1 || v === true; }

    async function load(){
      status('Loading...');
      try {
        const res = await axios.get(`${apiBase}/system.php`, { params: { operation: 'getSystemSettings' } });
        const s = res.data || {};
        setVal('att-clock_in_method', s.clock_in_method ?? 'qr');
        setVal('att-standard_start', s.standard_work_start_time ?? '08:00');
        setVal('att-standard_end', s.standard_work_end_time ?? '17:00');
        setVal('att-grace_period_minutes', s.grace_period_minutes ?? '0');
        setChk('att-allow_break_scans', s.allow_break_scans ?? '0');
        setChk('att-overtime_tracking_enabled', s.overtime_tracking_enabled ?? '1');
        status('');
      } catch {
        status('Failed to load settings', 'error');
      }
    }

    async function save(){
      status('Saving...');
      const payload = {
        clock_in_method: getVal('att-clock_in_method'),
        standard_work_start_time: getVal('att-standard_start'),
        standard_work_end_time: getVal('att-standard_end'),
        grace_period_minutes: getVal('att-grace_period_minutes'),
        allow_break_scans: getChk('att-allow_break_scans'),
        overtime_tracking_enabled: getChk('att-overtime_tracking_enabled')
      };
      try {
        const fd = new FormData();
        fd.append('operation', 'updateSystemSettings');
        fd.append('json', JSON.stringify(payload));
        const res = await axios.post(`${apiBase}/system.php`, fd);
        if (res && res.data && res.data.success) status('Attendance settings updated', 'success');
        else status('Failed to update settings', 'error');
      } catch {
        status('Failed to update settings', 'error');
      }
    }

    const btn = document.getElementById('att-settings-save');
    if (btn) btn.addEventListener('click', save);
    load();
  }

  // Notification Settings section (rendered inside Settings modal)
  function renderNotificationSettingsShell(){
    return `
      <div class="space-y-6">
        <!-- Notification Configuration -->
        <div class="border rounded-lg p-4">
          <h6 class="font-semibold mb-4">Create New Notification</h6>
          <form id="notif-settings-form" class="space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label class="block text-xs text-gray-500 mb-1">Notification Type</label>
                <div class="relative">
                  <button type="button" id="notif-type-dropdown" class="w-full border rounded px-3 py-2 text-sm text-left bg-white flex items-center justify-between hover:border-gray-400 focus:border-primary-500 focus:ring-1 focus:ring-primary-500">
                    <span id="notif-type-selected">Select Notification Type</span>
                    <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                    </svg>
                  </button>
                  <div id="notif-type-options" class="hidden absolute z-10 w-full mt-1 bg-white border rounded-md shadow-lg">
                    <div class="py-1">
                      <button type="button" class="w-full px-3 py-2 text-sm text-left hover:bg-gray-100" data-value="general">General</button>
                      <button type="button" class="w-full px-3 py-2 text-sm text-left hover:bg-gray-100" data-value="alert">Alert</button>
                      <button type="button" class="w-full px-3 py-2 text-sm text-left hover:bg-gray-100" data-value="payroll">Payroll</button>
                      <button type="button" class="w-full px-3 py-2 text-sm text-left hover:bg-gray-100" data-value="attendance">Attendance</button>
                      <button type="button" class="w-full px-3 py-2 text-sm text-left hover:bg-gray-100" data-value="leave">Leave</button>
                      <button type="button" class="w-full px-3 py-2 text-sm text-left hover:bg-gray-100" data-value="system">System</button>
                      <button type="button" class="w-full px-3 py-2 text-sm text-left hover:bg-gray-100" data-value="reminder">Reminder</button>
                    </div>
                  </div>
                </div>
                <input type="hidden" id="notif-type" value="" />
              </div>
              <div>
                <label class="block text-xs text-gray-500 mb-1">Recipients</label>
                <div class="relative">
                  <button type="button" id="notif-recipients-dropdown" class="w-full border rounded px-3 py-2 text-sm text-left bg-white flex items-center justify-between hover:border-gray-400 focus:border-primary-500 focus:ring-1 focus:ring-primary-500">
                    <span id="notif-recipients-selected">Select Recipients</span>
                    <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                    </svg>
                  </button>
                  <div id="notif-recipients-options" class="hidden absolute z-10 w-full mt-1 bg-white border rounded-md shadow-lg">
                    <div class="py-1">
                      <button type="button" class="w-full px-3 py-2 text-sm text-left hover:bg-gray-100" data-value="all">All Users</button>
                      <button type="button" class="w-full px-3 py-2 text-sm text-left hover:bg-gray-100" data-value="hr">HR Department</button>
                      <button type="button" class="w-full px-3 py-2 text-sm text-left hover:bg-gray-100" data-value="manager">Managers</button>
                      <button type="button" class="w-full px-3 py-2 text-sm text-left hover:bg-gray-100" data-value="employee">Employees</button>
                      <button type="button" class="w-full px-3 py-2 text-sm text-left hover:bg-gray-100" data-value="specific">Specific Users</button>
                    </div>
                  </div>
                </div>
                <input type="hidden" id="notif-recipients" value="" />
              </div>
            </div>
            <div id="specific-users-section" class="hidden">
              <label class="block text-xs text-gray-500 mb-1">Specific User IDs (comma-separated)</label>
              <input id="notif-specific-users" class="w-full border rounded px-2 py-1 text-sm" placeholder="e.g., 12, 34, 56" />
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label class="block text-xs text-gray-500 mb-1">Delivery Method</label>
                <select id="notif-delivery" class="w-full border rounded px-2 py-1 text-sm">
                  <option value="in_app" selected>In-app</option>
                  <option value="email">Email</option>
                  <option value="sms">SMS</option>
                  <option value="all">All Methods</option>
                </select>
              </div>
            </div>
            <div>
              <label class="block text-xs text-gray-500 mb-1">Subject/Title</label>
              <input id="notif-subject" class="w-full border rounded px-2 py-1 text-sm" placeholder="Notification subject or title" />
            </div>
            <div>
              <label class="block text-xs text-gray-500 mb-1">Message Content</label>
              <textarea id="notif-message" rows="4" class="w-full border rounded px-2 py-1 text-sm" placeholder="Enter your notification message here..."></textarea>
            </div>
            <div class="flex items-center gap-4">
              <label class="flex items-center gap-2 text-sm">
                <input type="checkbox" id="notif-send-immediately" class="rounded" checked />
                <span>Send Immediately</span>
              </label>
              <label class="flex items-center gap-2 text-sm">
                <input type="checkbox" id="notif-save-template" class="rounded" />
                <span>Save as Template</span>
              </label>
            </div>
            <div class="pt-2 flex justify-between">
              <button type="button" id="notif-preview" class="px-3 py-2 text-sm rounded border border-gray-300 hover:bg-gray-50">Preview</button>
              <div class="flex gap-2">
                <button type="button" id="notif-send" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Send Notification</button>
              </div>
            </div>
          </form>
          <div id="notif-settings-status" class="text-sm mt-2"></div>
        </div>

        <!-- Notification Templates -->
        <div class="border rounded-lg p-4">
          <div class="flex items-center justify-between mb-4">
            <h6 class="font-semibold">Notification Templates</h6>
          </div>
          <div class="overflow-x-auto border rounded">
            <table class="min-w-full text-sm">
              <thead class="bg-gray-50 text-xs text-gray-600">
                <tr>
                  <th class="px-3 py-2 text-left">Template Name</th>
                  <th class="px-3 py-2 text-left">Type</th>
                  <th class="px-3 py-2 text-left">Recipients</th>
                  <th class="px-3 py-2 text-left">Created</th>
                  <th class="px-3 py-2 text-left">Actions</th>
                </tr>
              </thead>
              <tbody id="notif-templates-tbody" class="divide-y"></tbody>
            </table>
          </div>
          <div id="notif-templates-empty" class="hidden p-4 text-center text-sm text-gray-500">No templates found. Create templates by checking 'Save as Template' when sending notifications.</div>
        </div>

        <!-- Notification History -->
        <div class="border rounded-lg p-4">
          <div class="flex items-center justify-between mb-4">
            <h6 class="font-semibold">Recent Notifications</h6>
            <div class="flex items-center gap-2">
              <select id="notif-history-filter" class="border rounded px-2 py-1 text-xs">
                <option value="all">All Types</option>
                <option value="general">General</option>
                <option value="alert">Alert</option>
                <option value="payroll">Payroll</option>
                <option value="attendance">Attendance</option>
                <option value="leave">Leave</option>
                <option value="system">System</option>
                <option value="reminder">Reminder</option>
              </select>
              <button id="notif-refresh-history" class="px-2 py-1 text-xs rounded border hover:bg-gray-50">Refresh</button>
            </div>
          </div>
          <div class="overflow-x-auto border rounded">
            <table class="min-w-full text-sm">
              <thead class="bg-gray-50 text-xs text-gray-600">
                <tr>
                  <th class="px-3 py-2 text-left">Subject</th>
                  <th class="px-3 py-2 text-left">Type</th>
                  <th class="px-3 py-2 text-left">Recipients</th>
                  <th class="px-3 py-2 text-left">Status</th>
                  <th class="px-3 py-2 text-left">Sent</th>
                  <th class="px-3 py-2 text-left">Actions</th>
                </tr>
              </thead>
              <tbody id="notif-history-tbody" class="divide-y"></tbody>
            </table>
          </div>
          <div id="notif-history-empty" class="hidden p-4 text-center text-sm text-gray-500">No notifications sent yet</div>
        </div>
      </div>

      <!-- Preview Modal -->
      <div id="notif-preview-modal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/50" data-close="true"></div>
        <div class="relative mx-auto mt-20 w-full max-w-lg">
          <div class="bg-white rounded-lg shadow">
            <div class="flex items-center justify-between border-b px-4 py-3">
              <h5 class="font-semibold">Notification Preview</h5>
              <button class="text-gray-500 hover:text-gray-700 text-xl leading-none" data-close="true">×</button>
            </div>
            <div class="p-4">
              <div class="space-y-3">
                <div>
                  <span class="text-xs text-gray-500">Type:</span>
                  <span id="preview-type" class="ml-2 text-sm font-medium"></span>
                </div>
                <div>
                  <span class="text-xs text-gray-500">Recipients:</span>
                  <span id="preview-recipients" class="ml-2 text-sm"></span>
                </div>
                <div>
                  <span class="text-xs text-gray-500">Priority:</span>
                  <span id="preview-priority" class="ml-2 text-sm"></span>
                </div>
                <div>
                  <span class="text-xs text-gray-500">Subject:</span>
                  <div id="preview-subject" class="mt-1 text-sm font-medium"></div>
                </div>
                <div>
                  <span class="text-xs text-gray-500">Message:</span>
                  <div id="preview-message" class="mt-1 text-sm whitespace-pre-wrap"></div>
                </div>
              </div>
            </div>
            <div class="flex justify-end gap-2 border-t px-4 py-3">
              <button class="px-3 py-2 text-sm rounded border" data-close="true">Close</button>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  function wireNotificationSettings(){
    const apiBase = window.baseApiUrl || 'api';
    // Hide Priority UI in Notification Settings
    try {
      const prSel = document.getElementById('notif-priority');
      if (prSel) {
        const prWrap = prSel.closest('div');
        if (prWrap) prWrap.style.display = 'none';
        const label = prWrap ? prWrap.previousElementSibling : null;
        if (label && /Priority Level/i.test(label.textContent || '')) label.style.display = 'none';
      }
      const prevPr = document.getElementById('preview-priority');
      if (prevPr) {
        const prevWrap = prevPr.closest('div');
        if (prevWrap) prevWrap.style.display = 'none';
      }
    } catch {}
    const status = (msg, type = 'info') => {
      const el = document.getElementById('notif-settings-status');
      if (!el) return;
      el.textContent = msg || '';
      el.className = `text-sm ${type === 'error' ? 'text-red-600' : (type === 'success' ? 'text-green-600' : 'text-gray-600')}`;
    };
    
    function escapeHtml(text){
      return String(text || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    // Dropdown functionality
    function setupDropdown(dropdownId, optionsId, hiddenInputId, selectedId) {
      const dropdown = document.getElementById(dropdownId);
      const options = document.getElementById(optionsId);
      const hiddenInput = document.getElementById(hiddenInputId);
      const selected = document.getElementById(selectedId);
      
      if (!dropdown || !options || !hiddenInput || !selected) return;
      
      dropdown.addEventListener('click', (e) => {
        e.preventDefault();
        options.classList.toggle('hidden');
      });
      
      options.addEventListener('click', (e) => {
        if (e.target.tagName === 'BUTTON') {
          const value = e.target.getAttribute('data-value');
          const text = e.target.textContent;
          
          hiddenInput.value = value;
          selected.textContent = text;
          options.classList.add('hidden');
          
          // Handle specific users section visibility
          if (hiddenInputId === 'notif-recipients' && value === 'specific') {
            document.getElementById('specific-users-section').classList.remove('hidden');
          } else if (hiddenInputId === 'notif-recipients') {
            document.getElementById('specific-users-section').classList.add('hidden');
          }
        }
      });
      
      // Close dropdown when clicking outside
      document.addEventListener('click', (e) => {
        if (!dropdown.contains(e.target) && !options.contains(e.target)) {
          options.classList.add('hidden');
        }
      });
    }
    
    // Setup dropdowns
    setupDropdown('notif-type-dropdown', 'notif-type-options', 'notif-type', 'notif-type-selected');
    setupDropdown('notif-recipients-dropdown', 'notif-recipients-options', 'notif-recipients', 'notif-recipients-selected');
    
    // Schedule section toggle
    // Remove unwanted sections (Recent Notifications, Schedule Date/Time, Save as Draft)
    (function(){
      try {
        // Remove Schedule Date/Time section
        document.getElementById('schedule-section')?.remove();
        // Remove Save as Draft button
        document.getElementById('notif-save-draft')?.remove();
        // Remove Recent Notifications block (find by heading text and remove its bordered container)
        const recentHeader = Array.from(document.querySelectorAll('h6.font-semibold')).find(h => h.textContent && h.textContent.trim() === 'Recent Notifications');
        const recentContainer = recentHeader ? recentHeader.closest('.border') : null;
        if (recentContainer) recentContainer.remove();
        // Fallback: remove history table wrapper and empty-state if still present
        document.getElementById('notif-history-tbody')?.closest('.overflow-x-auto')?.remove();
        document.getElementById('notif-history-empty')?.remove();
      } catch {}
    })();

    const sendImmediately = document.getElementById('notif-send-immediately');
    const scheduleSection = document.getElementById('schedule-section');
    if (sendImmediately && scheduleSection) {
      sendImmediately.addEventListener('change', () => {
        if (sendImmediately.checked) {
          scheduleSection.classList.add('hidden');
        } else {
          scheduleSection.classList.remove('hidden');
        }
      });
    }
    
    // Preview functionality
    const previewBtn = document.getElementById('notif-preview');
    const previewModal = document.getElementById('notif-preview-modal');
    if (previewBtn && previewModal) {
      previewBtn.addEventListener('click', () => {
        showPreview();
      });
      
      previewModal.querySelectorAll('[data-close="true"]').forEach(el => {
        el.addEventListener('click', () => previewModal.classList.add('hidden'));
      });
    }
    
    function showPreview() {
      const type = document.getElementById('notif-type-selected').textContent;
      const recipients = document.getElementById('notif-recipients-selected').textContent;
      const subject = document.getElementById('notif-subject').value;
      const message = document.getElementById('notif-message').value;
      
      document.getElementById('preview-type').textContent = type;
      document.getElementById('preview-recipients').textContent = recipients;
      document.getElementById('preview-subject').textContent = subject || 'No subject';
      document.getElementById('preview-message').textContent = message || 'No message content';
      
      previewModal.classList.remove('hidden');
    }
    
    // Send notification
    const sendBtn = document.getElementById('notif-send');
    if (sendBtn) {
      sendBtn.addEventListener('click', async () => {
        // Lazy-load SweetAlert2 if not present
        if (!window.Swal) {
          await new Promise((resolve, reject) => {
            const s = document.createElement('script');
            s.src = 'https://cdn.jsdelivr.net/npm/sweetalert2@11';
            s.async = true;
            s.onload = resolve;
            s.onerror = reject;
            document.head.appendChild(s);
          });
        }
        // Confirm before sending notification
        const result = await Swal.fire({
          title: 'Are you sure?',
          text: "You won't be able to revert this!",
          icon: 'warning',
          showCancelButton: true,
          confirmButtonColor: '#3085d6',
          cancelButtonColor: '#d33',
          confirmButtonText: 'Yes, send it!'
        });
        if (result.isConfirmed) {
          await sendNotification();
          try {
            await Swal.fire({
              title: 'Sent!',
              text: 'Notification has been sent.',
              icon: 'success'
            });
          } catch {}
        }
      });
    }
    
    // Save draft
    const saveDraftBtn = document.getElementById('notif-save-draft');
    if (saveDraftBtn) {
      saveDraftBtn.addEventListener('click', async () => {
        await saveDraft();
      });
    }
    
    async function sendNotification() {
      const type = document.getElementById('notif-type').value;
      const recipients = document.getElementById('notif-recipients').value;
      const specificUsers = document.getElementById('notif-specific-users')?.value || '';
      const delivery = document.getElementById('notif-delivery').value;
      const subject = document.getElementById('notif-subject').value;
      const message = document.getElementById('notif-message').value;
      const sendImmediately = document.getElementById('notif-send-immediately').checked;
      const saveTemplate = document.getElementById('notif-save-template').checked;
      const scheduleDate = document.getElementById('notif-schedule-date')?.value || '';
      const scheduleTime = document.getElementById('notif-schedule-time')?.value || '';
      
      if (!type || !recipients || !subject || !message) {
        status('Please fill in all required fields', 'error');
        return;
      }
      
      status('Sending notification...');
      
      try {
        const payload = {
          type,
          recipients: recipients === 'specific' ? specificUsers : recipients,
          delivery_method: delivery,
          subject,
          message,
          send_immediately: sendImmediately,
          save_as_template: saveTemplate,
          schedule_date: scheduleDate,
          schedule_time: scheduleTime
        };
        
        const fd = new FormData();
        fd.append('operation', 'sendNotification');
        fd.append('json', JSON.stringify(payload));
        
        const res = await axios.post(`${apiBase}/notifications.php`, fd);
        
        if (res && res.data && res.data.success) {
          status('Notification sent successfully', 'success');
          clearForm();
          try { if (typeof loadNotificationHistory === 'function') loadNotificationHistory(); } catch {}
          try {
            const filterSel = document.getElementById('notif-history-filter');
            if (filterSel) filterSel.value = 'all';
          } catch {}
          // Also refresh again shortly after to account for any backend processing delay
          setTimeout(() => {
            try { if (typeof loadNotificationHistory === 'function') loadNotificationHistory(); } catch {}
          }, 600);
          // Immediately refresh the notification history to show the sent notification
          setTimeout(() => {
            loadNotificationHistory();
          }, 500);
          if (saveTemplate) {
            await loadNotificationTemplates();
          }
        } else {
          status(res.data?.message || '', 'error');
        }
      } catch (error) {
        status('', 'error');
      }
    }
    
    async function saveDraft() {
      status('Saving draft...');
      // Implementation for saving draft
      status('Draft saved', 'success');
    }
    
    function clearForm() {
      document.getElementById('notif-type').value = '';
      document.getElementById('notif-type-selected').textContent = 'Select Notification Type';
      document.getElementById('notif-recipients').value = '';
      document.getElementById('notif-recipients-selected').textContent = 'Select Recipients';
      document.getElementById('notif-specific-users').value = '';
      document.getElementById('notif-delivery').value = 'in_app';
      document.getElementById('notif-subject').value = '';
      document.getElementById('notif-message').value = '';
      document.getElementById('notif-send-immediately').checked = true;
      document.getElementById('notif-save-template').checked = false;
      document.getElementById('specific-users-section').classList.add('hidden');
      document.getElementById('schedule-section').classList.add('hidden');
    }
    
    // Load notification templates
    async function loadNotificationTemplates() {
      const tbody = document.getElementById('notif-templates-tbody');
      const empty = document.getElementById('notif-templates-empty');
      if (!tbody || !empty) return;
      
      try {
        const res = await axios.get(`${apiBase}/notifications.php`, { 
          params: { operation: 'getTemplates' } 
        });
        
        const templates = Array.isArray(res.data) ? res.data : [];
        
        if (!templates.length) {
          tbody.innerHTML = '';
          empty.classList.remove('hidden');
        } else {
          empty.classList.add('hidden');
          tbody.innerHTML = templates.map(t => `
            <tr>
              <td class="px-3 py-2">${escapeHtml(t.name || t.subject)}</td>
              <td class="px-3 py-2 capitalize">${escapeHtml(t.type)}</td>
              <td class="px-3 py-2 capitalize">${escapeHtml(t.recipients)}</td>
              <td class="px-3 py-2">${formatTimestamp(t.created_at)}</td>
              <td class="px-3 py-2">
                <div class="flex items-center gap-1 text-xs">
                  <button class="px-2 py-1 rounded border hover:bg-gray-50" data-template-use="${t.id}">Use</button>
                  <button class="px-2 py-1 rounded border text-red-600 hover:bg-red-50" data-template-delete="${t.id}">Delete</button>
                </div>
              </td>
            </tr>
          `).join('');
          
          // Wire template actions
          tbody.querySelectorAll('[data-template-use]').forEach(btn => {
            btn.addEventListener('click', () => {
              const templateId = btn.getAttribute('data-template-use');
              const template = templates.find(t => t.id == templateId);
              if (template) {
                loadTemplate(template);
              }
            });
          });
          
          tbody.querySelectorAll('[data-template-delete]').forEach(btn => {
            btn.addEventListener('click', async () => {
              const templateId = btn.getAttribute('data-template-delete');
              if (confirm('Delete this template?')) {
                await deleteTemplate(templateId);
                await loadNotificationTemplates();
              }
            });
          });
        }
      } catch (error) {
        console.error('Failed to load templates:', error);
      }
    }
    
    function loadTemplate(template) {
      // Populate form with template data
      document.getElementById('notif-type').value = template.type;
      document.getElementById('notif-type-selected').textContent = template.type.charAt(0).toUpperCase() + template.type.slice(1);
      document.getElementById('notif-recipients').value = template.recipients;
      document.getElementById('notif-recipients-selected').textContent = getRecipientsDisplayText(template.recipients);
      document.getElementById('notif-delivery').value = template.delivery_method || 'in_app';
      document.getElementById('notif-subject').value = template.subject || '';
      document.getElementById('notif-message').value = template.message || '';
    }
    
    function getRecipientsDisplayText(value) {
      const mapping = {
        'all': 'All Users',
        'admin': 'Admin Only',
        'hr': 'HR Department',
        'manager': 'Managers',
        'employee': 'Employees',
        'specific': 'Specific Users'
      };
      return mapping[value] || value;
    }
    
    async function deleteTemplate(templateId) {
      try {
        const fd = new FormData();
        fd.append('operation', 'deleteTemplate');
        fd.append('json', JSON.stringify({ template_id: templateId }));
        
        await axios.post(`${apiBase}/notifications.php`, fd);
      } catch (error) {
        console.error('Failed to delete template:', error);
      }
    }
    
    // Load notification history
    async function loadNotificationHistory() {
      const tbody = document.getElementById('notif-history-tbody');
      const empty = document.getElementById('notif-history-empty');
      const filter = document.getElementById('notif-history-filter')?.value || 'all';
      
      if (!tbody || !empty) return;
      
      try {
        const res = await axios.get(`${apiBase}/notifications.php`, { 
          params: { 
            operation: 'getNotificationHistory',
            filter: filter !== 'all' ? filter : undefined
          } 
        });
        
        const history = Array.isArray(res.data) ? res.data : [];
        
        if (!history.length) {
          tbody.innerHTML = '';
          empty.classList.remove('hidden');
        } else {
          empty.classList.add('hidden');
          tbody.innerHTML = history.map(h => {
            const statusBadge = getStatusBadge(h.status);
            // Handle subject extraction from message
            let displaySubject = h.subject || 'Notification';
            if (h.message && h.message.includes('\n\n')) {
              const parts = h.message.split('\n\n', 2);
              displaySubject = parts[0] || 'Notification';
            }
            
            return `
              <tr>
                <td class="px-3 py-2">${escapeHtml(displaySubject)}</td>
                <td class="px-3 py-2 capitalize">${escapeHtml(h.type)}</td>
                <td class="px-3 py-2">${escapeHtml(h.recipients || (h.recipient_count ? h.recipient_count + ' recipients' : 'Employee'))}</td>
                <td class="px-3 py-2">${statusBadge}</td>
                <td class="px-3 py-2">${formatTimestamp(h.sent_at || h.created_at)}</td>
                <td class="px-3 py-2">
                  <div class="flex items-center gap-1 text-xs">
                    <button class="px-2 py-1 rounded border hover:bg-gray-50" data-history-view="${h.id}" title="View details">View</button>
                    <button class="px-2 py-1 rounded border hover:bg-gray-50" data-history-resend="${h.id}" title="Send again">Resend</button>
                  </div>
                </td>
              </tr>
            `;
          }).join('');
          
          // Wire history actions
          tbody.querySelectorAll('[data-history-view]').forEach(btn => {
            btn.addEventListener('click', () => {
              const historyId = btn.getAttribute('data-history-view');
              // Implementation for viewing notification details
            });
          });
          
          tbody.querySelectorAll('[data-history-resend]').forEach(btn => {
            btn.addEventListener('click', () => {
              const historyId = btn.getAttribute('data-history-resend');
              // Implementation for resending notification
            });
          });
        }
      } catch (error) {
        console.error('Failed to load notification history:', error);
      }
    }
    
    function getStatusBadge(status) {
      const badges = {
        'sent': '<span class="px-2 py-1 text-xs rounded bg-green-100 text-green-800">Sent</span>',
        'pending': '<span class="px-2 py-1 text-xs rounded bg-yellow-100 text-yellow-800">Pending</span>',
        'failed': '<span class="px-2 py-1 text-xs rounded bg-red-100 text-red-800">Failed</span>',
        'draft': '<span class="px-2 py-1 text-xs rounded bg-gray-100 text-gray-800">Draft</span>'
      };
      return badges[status] || '<span class="px-2 py-1 text-xs rounded bg-gray-100 text-gray-600">Unknown</span>';
    }
    
    function formatTimestamp(iso) {
      if (!iso) return '';
      try {
        const d = new Date(iso);
        if (isNaN(d.getTime())) return String(iso || '');
        return d.toLocaleString();
      } catch {
        return String(iso || '');
      }
    }
    
    // Refresh buttons
    const refreshTemplatesBtn = document.getElementById('notif-refresh-templates');
    if (refreshTemplatesBtn) {
      refreshTemplatesBtn.addEventListener('click', loadNotificationTemplates);
    }
    
    const refreshHistoryBtn = document.getElementById('notif-refresh-history');
    if (refreshHistoryBtn) {
      refreshHistoryBtn.addEventListener('click', loadNotificationHistory);
    }
    
    const historyFilterSelect = document.getElementById('notif-history-filter');
    if (historyFilterSelect) {
      historyFilterSelect.addEventListener('change', loadNotificationHistory);
    }
    
    // Initial load
    loadNotificationTemplates();
    loadNotificationHistory();
  }

  // Payroll Settings section (rendered inside Settings modal)
  function renderPayrollSettingsShell(){
    return `
      <form id="pay-settings-form" class="space-y-4">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="p-3 border rounded">
            <h6 class="font-semibold mb-2">Pay Structure</h6>
            <div>
              <label class="block text-xs text-gray-500 mb-1">Pay period</label>
              <select id="pay-pay_period" class="w-full border rounded px-2 py-1 text-sm">
                <option value="monthly">Monthly</option>
                <option value="semi_monthly">Semi-monthly</option>
                <option value="bi_weekly">Bi-weekly</option>
                <option value="weekly">Weekly</option>
              </select>
            </div>
            <div class="mt-3">
              <label class="block text-xs text-gray-500 mb-1">Salary basis</label>
              <select id="pay-salary_basis" class="w-full border rounded px-2 py-1 text-sm">
                <option value="monthly">Monthly</option>
                <option value="daily">Daily</option>
                <option value="hourly">Hourly</option>
              </select>
            </div>
          </div>
          <div class="p-3 border rounded">
            <h6 class="font-semibold mb-2">Government Deductions</h6>
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" id="pay-sss_enabled" class="rounded"/> <span>SSS</span></label>
            <label class="flex items-center gap-2 text-sm mt-1"><input type="checkbox" id="pay-philhealth_enabled" class="rounded"/> <span>PhilHealth</span></label>
            <label class="flex items-center gap-2 text-sm mt-1"><input type="checkbox" id="pay-pagibig_enabled" class="rounded"/> <span>Pag-IBIG</span></label>
            <label class="flex items-center gap-2 text-sm mt-1"><input type="checkbox" id="pay-tax_enabled" class="rounded"/> <span>Tax (Withholding)</span></label>
          </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="p-3 border rounded">
            <h6 class="font-semibold mb-2">Late & Absent Rules</h6>
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" id="pay-late_deduction_enabled" class="rounded"/> <span>Enable late deduction</span></label>
            <div class="mt-2">
              <label class="block text-xs text-gray-500 mb-1">Late deduction (per minute)</label>
              <input type="number" min="0" step="0.01" id="pay-late_deduction_per_minute" class="w-full border rounded px-2 py-1 text-sm" />
            </div>
            <label class="flex items-center gap-2 text-sm mt-3"><input type="checkbox" id="pay-absent_deduction_enabled" class="rounded"/> <span>Enable absent deduction</span></label>
            <div class="mt-2">
              <label class="block text-xs text-gray-500 mb-1">Absent deduction (per day)</label>
              <input type="number" min="0" step="0.01" id="pay-absent_deduction_per_day" class="w-full border rounded px-2 py-1 text-sm" />
            </div>
          </div>
          <div class="p-3 border rounded">
            <h6 class="font-semibold mb-2">Loans</h6>
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" id="pay-loans_enabled" class="rounded"/> <span>Enable employee loans</span></label>
            <div class="text-xs text-gray-500 mt-2">When enabled, loan deductions can be configured per employee.</div>
          </div>
        </div>
        <div class="pt-2 flex justify-end">
          <button id="pay-settings-save" type="button" class="px-3 py-2 text-sm rounded bg-primary-600 text-white hover:bg-primary-700">Save Payroll Settings</button>
        </div>
      </form>
      <div id="pay-settings-status" class="text-sm"></div>
    `;
  }

  function wirePayrollSettings(){
    const apiBase = window.baseApiUrl || 'api';
    const status = (msg, type = 'info') => {
      const el = document.getElementById('pay-settings-status');
      if (!el) return;
      el.textContent = msg || '';
      el.className = `text-sm ${type === 'error' ? 'text-red-600' : (type === 'success' ? 'text-green-600' : 'text-gray-600')}`;
    };
    const getVal = (id) => { const el = document.getElementById(id); return el ? el.value : ''; };
    const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
    const getChk = (id) => { const el = document.getElementById(id); return el && el.checked ? 1 : 0; };
    const setChk = (id, v) => { const el = document.getElementById(id); if (el) el.checked = String(v) === '1' || v === 1 || v === true; };

    async function load(){
      status('Loading...');
      try {
        const res = await axios.get(`${apiBase}/system.php`, { params: { operation: 'getSystemSettings' } });
        const s = res.data || {};
        setVal('pay-pay_period', s.pay_period ?? 'semi_monthly');
        setVal('pay-salary_basis', s.salary_basis ?? 'monthly');
        setChk('pay-sss_enabled', s.sss_enabled ?? '1');
        setChk('pay-philhealth_enabled', s.philhealth_enabled ?? '1');
        setChk('pay-pagibig_enabled', s.pagibig_enabled ?? '1');
        setChk('pay-tax_enabled', s.tax_enabled ?? '1');
        setChk('pay-late_deduction_enabled', s.late_deduction_enabled ?? '1');
        setVal('pay-late_deduction_per_minute', s.late_deduction_per_minute ?? '0');
        setChk('pay-absent_deduction_enabled', s.absent_deduction_enabled ?? '1');
        setVal('pay-absent_deduction_per_day', s.absent_deduction_per_day ?? '0');
        setChk('pay-loans_enabled', s.loans_enabled ?? '1');
        status('');
      } catch { status('Failed to load settings', 'error'); }
    }

    async function save(){
      status('Saving...');
      const payload = {
        pay_period: getVal('pay-pay_period'),
        salary_basis: getVal('pay-salary_basis'),
        sss_enabled: getChk('pay-sss_enabled'),
        philhealth_enabled: getChk('pay-philhealth_enabled'),
        pagibig_enabled: getChk('pay-pagibig_enabled'),
        tax_enabled: getChk('pay-tax_enabled'),
        late_deduction_enabled: getChk('pay-late_deduction_enabled'),
        late_deduction_per_minute: getVal('pay-late_deduction_per_minute'),
        absent_deduction_enabled: getChk('pay-absent_deduction_enabled'),
        absent_deduction_per_day: getVal('pay-absent_deduction_per_day'),
        loans_enabled: getChk('pay-loans_enabled')
      };
      try {
        const fd = new FormData();
        fd.append('operation', 'updateSystemSettings');
        fd.append('json', JSON.stringify(payload));
        const res = await axios.post(`${apiBase}/system.php`, fd);
        if (res && res.data && res.data.success) status('Payroll settings updated', 'success');
        else status('Failed to update settings', 'error');
      } catch { status('Failed to update settings', 'error'); }
    }

    const btn = document.getElementById('pay-settings-save');
    if (btn) btn.addEventListener('click', save);
    load();
  }

  // Theme selection logic
  const themes = {
    blue:   { 600: '#2563eb', 700: '#1d4ed8' },
    emerald:{ 600: '#059669', 700: '#047857' },
    rose:   { 600: '#e11d48', 700: '#be123c' },
    violet: { 600: '#7c3aed', 700: '#6d28d9' },
    amber:  { 600: '#d97706', 700: '#b45309' },
    teal:   { 600: '#0d9488', 700: '#0f766e' }
  };

  function ensureThemeStyle(theme){
    const t = themes[theme] || themes.blue;
    const css = `
:root { --primary-600: ${t[600]}; --primary-700: ${t[700]}; }
.bg-primary-600, .hover\\:bg-primary-600:hover { background-color: var(--primary-600) !important; }
.bg-primary-700, .hover\\:bg-primary-700:hover { background-color: var(--primary-700) !important; }
.text-primary-700 { color: var(--primary-700) !important; }
.text-primary-600 { color: var(--primary-600) !important; }
.border-primary-600 { border-color: var(--primary-600) !important; }
.ring-primary-600 { --tw-ring-color: var(--primary-600) !important; }
.from-primary-700 { --tw-gradient-from: var(--primary-700) !important; }
.to-primary-600 { --tw-gradient-to: var(--primary-600) !important; }
`;
    let el = document.getElementById('theme-overrides');
    if (!el){ el = document.createElement('style'); el.id = 'theme-overrides'; document.head.appendChild(el); }
    el.textContent = css;
  }

  function applyTheme(theme){ ensureThemeStyle(theme); }

  function updateSwatchUI(active){
    document.querySelectorAll('[data-theme-pick]').forEach(btn => {
      const on = btn.getAttribute('data-theme-pick') === active;
      btn.classList.toggle('ring-2', on);
      btn.classList.toggle('ring-offset-2', on);
      btn.classList.toggle('ring-gray-800', on);
    });
  }

  function setTheme(theme){
    try {
      if (window.__setTheme && window.__setTheme !== setTheme) {
        window.__setTheme(theme);
        updateSwatchUI(theme);
        return;
      }
    } catch(e){}
    try { localStorage.setItem('introTheme', theme); } catch(e){}
    updateSwatchUI(theme);
  }

  // Expose for other modules (e.g., profile menu quick picker)
  // Use global theme handlers from admin-inline.js

  const savedTheme = localStorage.getItem('introTheme') || 'blue';
  updateSwatchUI(savedTheme);

  document.querySelectorAll('[data-theme-pick]').forEach(btn => {
    btn.addEventListener('click', () => setTheme(btn.getAttribute('data-theme-pick')));
  });
}


