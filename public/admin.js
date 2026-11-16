// admin.js – PRiVY Security Administration Console Logic
document.addEventListener('DOMContentLoaded', () => {
  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');

  // Strict role check: Ordinary users cannot access admin dashboard
  if (!token || role !== 'admin') {
    window.location.href = 'login.html';
    return;
  }

  // Profile
  let currentAdminId = null;
  const adminUsernameEl = document.getElementById('admin-username');
  const logoutBtn = document.getElementById('admin-logout-btn');
  const refreshAllBtn = document.getElementById('refresh-all-btn');

  // Stats Elements
  const statUsersCount = document.getElementById('stat-users-count');
  const statScansCount = document.getElementById('stat-scans-count');
  const statSafeCount = document.getElementById('stat-safe-count');
  const statSafePct = document.getElementById('stat-safe-pct');
  const statThreatCount = document.getElementById('stat-threat-count');
  const statThreatPct = document.getElementById('stat-threat-pct');
  const statAvgScore = document.getElementById('stat-avg-score');

  // Distribution Bar
  const distSafeBar = document.getElementById('dist-safe-bar');
  const distThreatBar = document.getElementById('dist-threat-bar');
  const distSafeLabel = document.getElementById('dist-safe-label');
  const distThreatLabel = document.getElementById('dist-threat-label');

  // User Management Elements
  const usersTableBody = document.getElementById('users-table-body');
  const usersEmpty = document.getElementById('users-empty');
  const userSearchInput = document.getElementById('user-search-input');
  const openAddUserBtn = document.getElementById('open-add-user-btn');
  const closeAddUserBtn = document.getElementById('close-add-user-btn');
  const addUserPanel = document.getElementById('add-user-panel');
  const addUserForm = document.getElementById('add-user-form');
  const addUserAlert = document.getElementById('add-user-alert');
  const addUserSuccess = document.getElementById('add-user-success');

  // Scan Telemetry Elements
  const scansTableBody = document.getElementById('scans-table-body');
  const scansEmpty = document.getElementById('scans-empty');
  const scanFilterBtns = document.querySelectorAll('.scan-filter-btn');
  let currentScanFilter = 'all';

  // Decode admin token
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    currentAdminId = payload.id;
    adminUsernameEl.textContent = payload.username || 'Admin';
  } catch (e) {
    console.warn('Token parse error:', e);
  }

  // Escape HTML helper
  const escapeHtml = (str) => {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };

  // Safe fetch wrapper with JSON checking
  const apiFetch = async (url, options = {}) => {
    const defaultHeaders = {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    };
    options.headers = { ...defaultHeaders, ...(options.headers || {}) };

    const resp = await fetch(url, options);

    if (resp.status === 401 || resp.status === 403) {
      localStorage.clear();
      window.location.href = 'login.html';
      throw new Error('Administrative session expired. Please sign in again.');
    }

    const contentType = resp.headers.get('content-type') || '';
    let data;
    if (contentType.includes('application/json')) {
      data = await resp.json();
    } else {
      const text = await resp.text();
      throw new Error(text || 'Non-JSON server response');
    }

    if (!resp.ok) {
      throw new Error(data.error || 'Request failed');
    }

    return data;
  };

  // 1. Load System Telemetry Stats
  const loadStats = async () => {
    try {
      const stats = await apiFetch('/api/admin/stats');

      statUsersCount.textContent = stats.totalUsers;
      statScansCount.textContent = stats.totalScans;
      statSafeCount.textContent = stats.safeScans;
      statSafePct.textContent = `${stats.safePercentage}% safe ratio`;
      statThreatCount.textContent = stats.phishingScans;
      statThreatPct.textContent = `${stats.phishingPercentage}% threat ratio`;
      statAvgScore.textContent = stats.averageSecurityScore;

      // Distribution Bar
      distSafeBar.style.width = `${stats.safePercentage}%`;
      distThreatBar.style.width = `${stats.phishingPercentage}%`;
      distSafeLabel.textContent = `${stats.safePercentage}%`;
      distThreatLabel.textContent = `${stats.phishingPercentage}%`;
    } catch (err) {
      console.error('Stats loading error:', err);
    }
  };

  // 2. Load User Registry
  const loadUsers = async (searchQuery = '') => {
    try {
      const url = searchQuery
        ? `/api/admin/users?search=${encodeURIComponent(searchQuery)}`
        : '/api/admin/users';
      const users = await apiFetch(url);

      usersTableBody.innerHTML = '';
      if (!users || users.length === 0) {
        usersEmpty.classList.remove('hidden');
        return;
      }
      usersEmpty.classList.add('hidden');

      users.forEach(u => {
        const tr = document.createElement('tr');
        const isSelf = u.id === currentAdminId;
        const roleBadgeClass = u.role === 'admin' ? 'admin' : 'user';
        const roleLabel = u.role.toUpperCase();
        const dateStr = u.created_at ? new Date(u.created_at).toLocaleDateString() : 'N/A';

        let actionHtml = '';
        if (isSelf) {
          actionHtml = `<span style="font-size:0.75rem; color:var(--brand-light); font-weight:600;">Active Session</span>`;
        } else {
          const toggleRoleTarget = u.role === 'admin' ? 'user' : 'admin';
          const toggleRoleText = u.role === 'admin' ? 'Demote to User' : 'Promote to Admin';
          const toggleRoleBtnClass = u.role === 'admin' ? 'btn-secondary' : 'btn-primary';

          actionHtml = `
            <div style="display:flex; gap:0.4rem; align-items:center;">
              <button class="btn ${toggleRoleBtnClass} btn-sm toggle-role-btn" data-id="${u.id}" data-role="${toggleRoleTarget}">
                ${toggleRoleText}
              </button>
              <button class="btn btn-danger btn-sm delete-user-btn" data-id="${u.id}" data-username="${escapeHtml(u.username)}">
                Delete
              </button>
            </div>
          `;
        }

        tr.innerHTML = `
          <td style="font-weight:600; color:var(--text-main);">#${u.id}</td>
          <td style="color:var(--text-main); font-weight:600;">${escapeHtml(u.username)}</td>
          <td>${escapeHtml(u.email || 'None')}</td>
          <td><span class="role-badge ${roleBadgeClass}">${roleLabel}</span></td>
          <td style="color:var(--brand-sky); font-weight:600;">${u.scan_count || 0}</td>
          <td style="font-size:0.8rem; color:var(--text-muted);">${dateStr}</td>
          <td>${actionHtml}</td>
        `;

        usersTableBody.appendChild(tr);
      });

      // Role toggle event listeners
      document.querySelectorAll('.toggle-role-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          const userId = e.currentTarget.getAttribute('data-id');
          const newRole = e.currentTarget.getAttribute('data-role');
          if (confirm(`Change this user's role to ${newRole.toUpperCase()}?`)) {
            try {
              await apiFetch(`/api/admin/users/${userId}/role`, {
                method: 'PATCH',
                body: JSON.stringify({ role: newRole })
              });
              await loadUsers(userSearchInput.value.trim());
              await loadStats();
            } catch (err) {
              alert(err.message);
            }
          }
        });
      });

      // Delete user event listeners
      document.querySelectorAll('.delete-user-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          const userId = e.currentTarget.getAttribute('data-id');
          const username = e.currentTarget.getAttribute('data-username');
          if (confirm(`Permanently remove user "${username}" and all their associated scan records?`)) {
            try {
              await apiFetch(`/api/admin/users/${userId}`, { method: 'DELETE' });
              await loadUsers(userSearchInput.value.trim());
              await loadStats();
              await loadScans(currentScanFilter);
            } catch (err) {
              alert(err.message);
            }
          }
        });
      });
    } catch (err) {
      console.error('Users loading error:', err);
    }
  };

  // 3. Load System-Wide Scans Feed
  const loadScans = async (filter = 'all') => {
    try {
      const url = filter === 'all' ? '/api/admin/scans' : `/api/admin/scans?filter=${filter}`;
      const scans = await apiFetch(url);

      scansTableBody.innerHTML = '';
      if (!scans || scans.length === 0) {
        scansEmpty.classList.remove('hidden');
        return;
      }
      scansEmpty.classList.add('hidden');

      scans.forEach(s => {
        const tr = document.createElement('tr');
        const isPhish = s.isPhishing;
        const verdictClass = isPhish ? 'phishing' : 'safe';
        const verdictText = isPhish ? 'Threat' : 'Safe';
        const dateStr = s.timestamp ? new Date(s.timestamp).toLocaleString() : 'Recent';

        const reasonsHtml = s.reasons && s.reasons.length > 0
          ? s.reasons.map(r => `&bull; ${escapeHtml(r)}`).join('<br>')
          : '<span style="color:var(--safe-primary);">Clean pattern</span>';

        tr.innerHTML = `
          <td style="font-size:0.8rem; color:var(--text-muted);">#${s.id}</td>
          <td style="font-size:0.8rem; color:var(--text-muted);">${dateStr}</td>
          <td style="font-weight:600; color:var(--text-main);">${escapeHtml(s.username)}</td>
          <td class="url-cell" title="${escapeHtml(s.url)}">${escapeHtml(s.url)}</td>
          <td><span class="verdict-tag ${verdictClass}" style="font-size:0.75rem; padding:0.2rem 0.5rem;">${verdictText}</span></td>
          <td style="font-weight:700; color:${isPhish ? 'var(--threat-primary)' : 'var(--safe-primary)'};">${s.securityScore}/100</td>
          <td style="font-size:0.8rem; max-width:280px;">${reasonsHtml}</td>
        `;

        scansTableBody.appendChild(tr);
      });
    } catch (err) {
      console.error('Scans loading error:', err);
    }
  };

  // Search input handler with debounce
  let searchTimeout = null;
  userSearchInput.addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      loadUsers(userSearchInput.value.trim());
    }, 250);
  });

  // Add User Form Handling
  openAddUserBtn.addEventListener('click', () => {
    addUserPanel.classList.toggle('hidden');
    addUserAlert.classList.add('hidden');
    addUserSuccess.classList.add('hidden');
  });

  closeAddUserBtn.addEventListener('click', () => {
    addUserPanel.classList.add('hidden');
  });

  addUserForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    addUserAlert.classList.add('hidden');
    addUserSuccess.classList.add('hidden');

    const username = document.getElementById('new-username').value.trim();
    const email = document.getElementById('new-email').value.trim();
    const password = document.getElementById('new-password').value;
    const userRole = document.getElementById('new-role').value;

    try {
      await apiFetch('/api/admin/users', {
        method: 'POST',
        body: JSON.stringify({ username, email, password, role: userRole })
      });

      addUserSuccess.textContent = `Account "${username}" created successfully with role ${userRole.toUpperCase()}.`;
      addUserSuccess.classList.remove('hidden');
      addUserForm.reset();

      await loadUsers();
      await loadStats();

      setTimeout(() => {
        addUserPanel.classList.add('hidden');
      }, 1500);
    } catch (err) {
      addUserAlert.textContent = err.message;
      addUserAlert.classList.remove('hidden');
    }
  });

  // Filter scan buttons
  scanFilterBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      scanFilterBtns.forEach(b => b.classList.remove('active'));
      e.currentTarget.classList.add('active');
      currentScanFilter = e.currentTarget.getAttribute('data-filter');
      loadScans(currentScanFilter);
    });
  });

  // Refresh Telemetry Button
  refreshAllBtn.addEventListener('click', async () => {
    await loadStats();
    await loadUsers(userSearchInput.value.trim());
    await loadScans(currentScanFilter);
  });

  // Logout
  logoutBtn.addEventListener('click', () => {
    localStorage.clear();
    window.location.href = 'login.html';
  });

  // Initial Data Fetch
  loadStats();
  loadUsers();
  loadScans('all');
});
