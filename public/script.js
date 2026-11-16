// script.js – PRiVY Landing Page Logic
document.addEventListener('DOMContentLoaded', () => {
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
  const navAuthGroup = document.getElementById('nav-auth-buttons');
  const quickPills = document.querySelectorAll('.quick-pill');

  // Check login state to update nav buttons
  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');

  if (token) {
    const dashboardTarget = role === 'admin' ? 'admin.html' : 'dashboard.html';
    const dashboardLabel = role === 'admin' ? 'Admin Console' : 'Dashboard';
    navAuthGroup.innerHTML = `
      <a href="${dashboardTarget}" class="btn btn-secondary btn-sm">${dashboardLabel}</a>
      <button id="nav-logout-btn" class="btn btn-danger btn-sm">Sign Out</button>
    `;
    const logoutBtn = document.getElementById('nav-logout-btn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', () => {
        localStorage.clear();
        window.location.reload();
      });
    }
  }

  // Quick test sample pills
  quickPills.forEach(pill => {
    pill.addEventListener('click', () => {
      const sampleUrl = pill.getAttribute('data-url');
      if (sampleUrl) {
        urlInput.value = sampleUrl;
        analyse(sampleUrl);
      }
    });
  });

  const showResult = (data) => {
    inspectedUrlEl.textContent = data.url;
    scoreEl.textContent = data.securityScore;

    // Reset classes
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
        Potential Phishing Threat
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
        <span>No suspicious heuristic patterns detected. Standard domain syntax and security flags verified.</span>
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

  const analyse = async (url) => {
    btnText.textContent = 'Inspecting...';
    btnSpinner.classList.remove('hidden');
    analyzeBtn.disabled = true;

    try {
      const headers = { 'Content-Type': 'application/json' };
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers,
        body: JSON.stringify({ url })
      });

      const contentType = response.headers.get('content-type') || '';
      let data;
      if (contentType.includes('application/json')) {
        data = await response.json();
      } else {
        const text = await response.text();
        throw new Error(text || 'Received non-JSON response from server');
      }

      if (!response.ok) {
        throw new Error(data.error || 'URL analysis failed');
      }

      showResult(data);
    } catch (err) {
      alert(`Scan Notice: ${err.message}`);
    } finally {
      btnText.textContent = 'Analyze URL';
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
    analyse(url);
  });

  urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const url = urlInput.value.trim();
      if (url) analyse(url);
    }
  });
});
