// dashboard.js – PRiVY User Dashboard Logic
document.addEventListener('DOMContentLoaded', () => {
  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');

  if (!token) {
    window.location.href = 'login.html';
    return;
  }

  // Admin access rule: Admin must not access ordinary user dashboard
  if (role === 'admin') {
    window.location.href = 'admin.html';
    return;
  }

  // Navigation & User Profile Elements
  const navUsername = document.getElementById('nav-username');
  const navRole = document.getElementById('nav-role');
  const profileUsername = document.getElementById('profile-username');
  const profileEmail = document.getElementById('profile-email');
  const profileRole = document.getElementById('profile-role');
  const profileId = document.getElementById('profile-id');
  const logoutBtn = document.getElementById('logout-btn');

  // Scanner Elements
  const urlInput = document.getElementById('url-input');
  const analyzeBtn = document.getElementById('analyze-btn');
  const btnText = document.getElementById('btn-text');
  const btnSpinner = document.getElementById('btn-spinner');
  const resultCard = document.getElementById('result');
  const statusText = document.getElementById('status-text');
  const verdictBadge = document.getElementById('verdict-badge');
  const scoreEl = document.getElementById('score');
  const scoreBar = document.getElementById('score-bar');
  const inspectedUrlEl = document.getElementById('inspected-url');
  const reasonsEl = document.getElementById('reasons');
  const quickPills = document.querySelectorAll('.quick-pill');

  // Stats Elements
  const statTotalScans = document.getElementById('stat-total-scans');
  const statSafeScans = document.getElementById('stat-safe-scans');
  const statSafePct = document.getElementById('stat-safe-pct');
  const statThreatScans = document.getElementById('stat-threat-scans');
  const statThreatPct = document.getElementById('stat-threat-pct');
  const statAvgScore = document.getElementById('stat-avg-score');

  // History Elements
  const historyTableBody = document.getElementById('history-table-body');
  const historyEmpty = document.getElementById('history-empty');
  const clearBtn = document.getElementById('clear-history');

  // Decode Token / Fetch /api/me
  const initUserProfile = async () => {
    try {
      const resp = await fetch('/api/me', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (resp.ok) {
        const data = await resp.json();
        const u = data.user;
        navUsername.textContent = u.username;
        profileUsername.textContent = u.username;
        profileEmail.textContent = u.email || 'Not specified';
        profileRole.textContent = u.role.toUpperCase();
        profileId.textContent = `#${u.id}`;
        navRole.textContent = u.role.toUpperCase();
      } else {
        // Fallback to token payload
        const payload = JSON.parse(atob(token.split('.')[1]));
        navUsername.textContent = payload.username || 'User';
        profileUsername.textContent = payload.username || 'User';
        profileRole.textContent = (payload.role || 'user').toUpperCase();
        profileId.textContent = `#${payload.id || '?'}`;
      }
    } catch (e) {
      console.warn('Profile sync fallback:', e);
    }
  };
  initUserProfile();

  // Load History from SQLite Backend
  const loadHistory = async () => {
    try {
      const resp = await fetch('/api/history', {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (resp.status === 401 || resp.status === 403) {
        localStorage.clear();
        window.location.href = 'login.html';
        return;
      }

      if (!resp.ok) throw new Error('Failed to retrieve history');
      const history = await resp.json();

      updateStats(history);
      renderHistoryTable(history);
    } catch (err) {
      console.error('History load error:', err);
    }
  };

  // Update Top Stats from Actual History Records
  const updateStats = (history) => {
    const total = history.length;
    const threats = history.filter(h => h.isPhishing).length;
    const safe = total - threats;

    let avg = 100;
    if (total > 0) {
      const totalScore = history.reduce((acc, h) => acc + (typeof h.securityScore === 'number' ? h.securityScore : 100), 0);
      avg = Math.round(totalScore / total);
    }

    statTotalScans.textContent = total;
    statSafeScans.textContent = safe;
    statThreatScans.textContent = threats;
    statAvgScore.textContent = avg;

    const safeRatio = total > 0 ? Math.round((safe / total) * 100) : 100;
    const threatRatio = total > 0 ? Math.round((threats / total) * 100) : 0;
    statSafePct.textContent = `${safeRatio}% of scans`;
    statThreatPct.textContent = `${threatRatio}% of scans`;
  };

  // Render History Table
  const renderHistoryTable = (history) => {
    historyTableBody.innerHTML = '';
    if (history.length === 0) {
      historyEmpty.classList.remove('hidden');
      return;
    }
    historyEmpty.classList.add('hidden');

    history.forEach(item => {
      const tr = document.createElement('tr');
      const isPhish = item.isPhishing;
      const verdictClass = isPhish ? 'phishing' : 'safe';
      const verdictLabel = isPhish ? 'Threat' : 'Safe';

      const reasonsPreview = item.reasons && item.reasons.length > 0
        ? item.reasons.map(r => `&bull; ${escapeHtml(r)}`).join('<br>')
        : '<span style="color:var(--safe-primary);">Clean pattern</span>';

      const dateStr = item.timestamp ? new Date(item.timestamp).toLocaleString() : 'Just now';

      tr.innerHTML = `
        <td style="font-size:0.8rem; color:var(--text-muted);">${dateStr}</td>
        <td class="url-cell" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</td>
        <td><span class="verdict-tag ${verdictClass}" style="font-size:0.75rem; padding:0.2rem 0.5rem;">${verdictLabel}</span></td>
        <td style="font-weight:700; color:${isPhish ? 'var(--threat-primary)' : 'var(--safe-primary)'};">${item.securityScore}/100</td>
        <td style="font-size:0.82rem; max-width:280px;">${reasonsPreview}</td>
        <td>
          <button class="btn btn-danger btn-sm delete-btn" data-id="${item.id}" title="Delete record">
            Delete
          </button>
        </td>
      `;

      historyTableBody.appendChild(tr);
    });

    // Attach delete handlers
    document.querySelectorAll('.delete-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const scanId = e.currentTarget.getAttribute('data-id');
        if (confirm('Delete this scan entry from your history?')) {
          await deleteScanItem(scanId);
        }
      });
    });
  };

  // Delete Individual History Item
  const deleteScanItem = async (id) => {
    try {
      const resp = await fetch(`/api/history/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!resp.ok) throw new Error('Failed to delete scan record');
      await loadHistory();
    } catch (err) {
      alert(err.message);
    }
  };

  // Clear Entire User History
  clearBtn.addEventListener('click', async () => {
    if (confirm('Are you sure you want to permanently clear all your scan records?')) {
      try {
        const resp = await fetch('/api/history', {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!resp.ok) throw new Error('Failed to clear history');
        await loadHistory();
      } catch (err) {
        alert(err.message);
      }
    }
  });

  // Display Result Card
  const showResult = (data) => {
    inspectedUrlEl.textContent = data.url;
    scoreEl.textContent = data.securityScore;

    resultCard.className = 'result-box';
    verdictBadge.className = 'verdict-tag';
    scoreEl.className = 'score-number';

    if (data.isPhishing) {
      resultCard.classList.add('phishing');
      verdictBadge.classList.add('phishing');
      statusText.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        Phishing Threat Detected
      `;
      if (data.securityScore <= 50) {
        scoreEl.classList.add('danger');
        scoreBar.style.backgroundColor = 'var(--threat-primary)';
      } else {
        scoreEl.classList.add('warning');
        scoreBar.style.backgroundColor = 'var(--warning-primary)';
      }
    } else {
      resultCard.classList.add('safe');
      verdictBadge.classList.add('safe');
      statusText.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="m9 12 2 2 4-4"/>
        </svg>
        Verified Safe URL
      `;
      scoreEl.classList.add('safe');
      scoreBar.style.backgroundColor = 'var(--safe-primary)';
    }

    scoreBar.style.width = `${Math.max(5, data.securityScore)}%`;

    reasonsEl.innerHTML = '';
    if (!data.reasons || data.reasons.length === 0) {
      const li = document.createElement('li');
      li.className = 'reason-item';
      li.innerHTML = `
        <svg class="reason-icon safe" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="20 6 9 17 4 12"></polyline>
        </svg>
        <span>No malicious signatures detected. Structural syntax and host validation passed.</span>
      `;
      reasonsEl.appendChild(li);
    } else {
      data.reasons.forEach(r => {
        const li = document.createElement('li');
        li.className = 'reason-item';
        li.innerHTML = `
          <svg class="reason-icon danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="15" y1="9" x2="9" y2="15"></line>
            <line x1="9" y1="9" x2="15" y2="15"></line>
          </svg>
          <span>${escapeHtml(r)}</span>
        `;
        reasonsEl.appendChild(li);
      });
    }

    resultCard.classList.remove('hidden');
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  };

  const escapeHtml = (str) => {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };

  // Perform Scan via Backend /api/scan (Protected, invokes C++ engine)
  const scanUrl = async (url) => {
    btnText.textContent = 'Scanning...';
    btnSpinner.classList.remove('hidden');
    analyzeBtn.disabled = true;

    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ url })
      });

      const contentType = resp.headers.get('content-type') || '';
      let data;
      if (contentType.includes('application/json')) {
        data = await resp.json();
      } else {
        const text = await resp.text();
        throw new Error(text || 'Server returned non-JSON error');
      }

      if (!resp.ok) {
        throw new Error(data.error || 'Scan failed');
      }

      showResult(data);
      await loadHistory();
    } catch (err) {
      alert(`Scan Failure: ${err.message}`);
    } finally {
      btnText.textContent = 'Execute Scan';
      btnSpinner.classList.add('hidden');
      analyzeBtn.disabled = false;
    }
  };

  analyzeBtn.addEventListener('click', () => {
    const url = urlInput.value.trim();
    if (!url) {
      urlInput.focus();
      return;
    }
    scanUrl(url);
  });

  urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const url = urlInput.value.trim();
      if (url) scanUrl(url);
    }
  });

  // Quick pills
  quickPills.forEach(pill => {
    pill.addEventListener('click', () => {
      const sampleUrl = pill.getAttribute('data-url');
      if (sampleUrl) {
        urlInput.value = sampleUrl;
        scanUrl(sampleUrl);
      }
    });
  });

  // Logout
  logoutBtn.addEventListener('click', () => {
    localStorage.clear();
    window.location.href = 'login.html';
  });

  // Initial History Load
  loadHistory();
});
