/**
 * Universal Session & Cookie Manager Pro v3.0
 * Advanced cookie & storage inspection, session snapshots, security audit, and encrypted backup.
 */

// Application State
const state = {
  currentTab: null,
  activeDomain: '',
  isInternalPage: false,
  cookies: [],
  localStorageData: {},
  sessionStorageData: {},
  activeStorageSubtab: 'local', // 'local' or 'session'
  snapshots: [],
  editingCookie: null,
  editingStorage: null
};

// ==========================================
// Toast & UI Helpers
// ==========================================
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = 'toast';
  
  let icon = 'ℹ️';
  if (type === 'success') icon = '✅';
  if (type === 'error') icon = '❌';
  if (type === 'warn') icon = '⚠️';
  
  toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(8px)';
    toast.style.transition = 'all 0.2s ease';
    setTimeout(() => toast.remove(), 200);
  }, 2600);
}

function updateStatus(text) {
  const el = document.getElementById('statusBarText');
  if (el) el.textContent = text;
}

function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  return (bytes / 1024).toFixed(1) + ' KB';
}

function formatExpiry(expirationDate) {
  if (!expirationDate) return { text: 'Session', isSession: true, isExpired: false };
  const now = Date.now() / 1000;
  const isExpired = expirationDate < now;
  const date = new Date(expirationDate * 1000);
  const diffDays = Math.round((expirationDate - now) / 86400);
  
  if (isExpired) return { text: 'Expired', isSession: false, isExpired: true };
  if (diffDays < 1) return { text: '< 1 day', isSession: false, isExpired: false };
  if (diffDays < 30) return { text: `${diffDays}d`, isSession: false, isExpired: false };
  if (diffDays < 365) return { text: `${Math.round(diffDays / 30)}mo`, isSession: false, isExpired: false };
  return { text: `${(diffDays / 365).toFixed(1)}y`, isSession: false, isExpired: false };
}

// ==========================================
// Theme Management
// ==========================================
function initTheme() {
  chrome.storage.local.get(['theme'], (result) => {
    const savedTheme = result.theme || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', savedTheme);
  });

  document.getElementById('themeToggleBtn').addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') || 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    chrome.storage.local.set({ theme: next });
    showToast(`Switched to ${next} mode`, 'info');
  });
}

// ==========================================
// Initialization & Tab Detection
// ==========================================
document.addEventListener('DOMContentLoaded', async () => {
  initTheme();
  setupNavTabs();
  setupModals();
  setupHubActions();
  setupGlobalActions();

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      showEmptyPageState("No active browser tab found.");
      return;
    }

    state.currentTab = tab;

    // Check for internal Chrome pages
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('edge://') || tab.url.startsWith('about:')) {
      state.isInternalPage = true;
      renderSiteInfo(tab, true);
      showEmptyPageState("Internal browser pages do not support cookie or storage manipulation. Please test on an external website.");
      return;
    }

    renderSiteInfo(tab, false);
    await refreshAllData();
  } catch (err) {
    console.error("Initialization error:", err);
    showToast("Error loading tab: " + err.message, "error");
  }
});

function renderSiteInfo(tab, isInternal) {
  const pill = document.getElementById('sitePill');
  const favicon = document.getElementById('siteFavicon');
  const hostnameEl = document.getElementById('siteHostname');
  const protocolBadge = document.getElementById('siteProtocol');

  if (isInternal) {
    hostnameEl.textContent = "Internal Page";
    protocolBadge.textContent = "SYSTEM";
    protocolBadge.className = "protocol-badge insecure";
    return;
  }

  try {
    const urlObj = new URL(tab.url);
    state.activeDomain = urlObj.hostname;
    hostnameEl.textContent = urlObj.hostname;
    
    if (tab.favIconUrl) {
      favicon.src = tab.favIconUrl;
      favicon.style.display = 'inline-block';
    } else {
      favicon.style.display = 'none';
    }

    const isSecure = urlObj.protocol === 'https:';
    protocolBadge.textContent = isSecure ? 'HTTPS' : 'HTTP';
    protocolBadge.className = `protocol-badge ${isSecure ? 'secure' : 'insecure'}`;
  } catch (e) {
    hostnameEl.textContent = tab.url;
  }
}

function showEmptyPageState(msg) {
  const container = document.getElementById('cookiesList');
  container.innerHTML = `
    <div class="empty-state">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
      <h4>Restricted Access</h4>
      <p>${msg}</p>
    </div>
  `;
  document.getElementById('storageTableBody').innerHTML = `
    <tr><td colspan="3" style="text-align:center; padding: 24px; color: var(--text-muted);">${msg}</td></tr>
  `;
}

// ==========================================
// Nav Tabs Controller
// ==========================================
function setupNavTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPane = document.getElementById(btn.getAttribute('data-tab'));
      if (targetPane) targetPane.classList.add('active');

      if (btn.getAttribute('data-tab') === 'tab-snapshots') {
        loadSnapshots();
      } else if (btn.getAttribute('data-tab') === 'tab-audit') {
        runSecurityAudit();
      }
    });
  });

  // Storage Subtabs
  document.getElementById('lsSubtabBtn').addEventListener('click', () => {
    state.activeStorageSubtab = 'local';
    document.getElementById('lsSubtabBtn').className = 'btn btn-primary btn-sm';
    document.getElementById('ssSubtabBtn').className = 'btn btn-secondary btn-sm';
    renderStorageItems();
  });

  document.getElementById('ssSubtabBtn').addEventListener('click', () => {
    state.activeStorageSubtab = 'session';
    document.getElementById('ssSubtabBtn').className = 'btn btn-primary btn-sm';
    document.getElementById('lsSubtabBtn').className = 'btn btn-secondary btn-sm';
    renderStorageItems();
  });
}

// ==========================================
// Core Data Fetchers
// ==========================================
async function refreshAllData() {
  if (state.isInternalPage || !state.currentTab) return;
  updateStatus("Refreshing cookies & storage...");
  await Promise.all([loadCookies(), loadStorage()]);
  loadSnapshots();
  runSecurityAudit();
  updateStatus(`Loaded ${state.cookies.length} cookies, ${Object.keys(state.localStorageData).length} local storage keys`);
}

async function loadCookies() {
  if (!state.currentTab || !state.currentTab.url) return;

  return new Promise((resolve) => {
    chrome.cookies.getAll({ url: state.currentTab.url }, (cookies) => {
      state.cookies = cookies || [];
      document.getElementById('cookieCountBadge').textContent = state.cookies.length;
      document.getElementById('auditTotalCookies').textContent = state.cookies.length;
      renderCookies();
      resolve(state.cookies);
    });
  });
}

async function loadStorage() {
  if (!state.currentTab || !state.currentTab.id) return;

  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: state.currentTab.id },
      func: () => {
        const ls = {};
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i);
          ls[k] = localStorage.getItem(k);
        }
        const ss = {};
        for (let i = 0; i < sessionStorage.length; i++) {
          const k = sessionStorage.key(i);
          ss[k] = sessionStorage.getItem(k);
        }
        return { localStorage: ls, sessionStorage: ss };
      }
    });

    if (results && results[0] && results[0].result) {
      state.localStorageData = results[0].result.localStorage || {};
      state.sessionStorageData = results[0].result.sessionStorage || {};
    }
  } catch (err) {
    console.warn("Storage inspection skipped:", err);
    state.localStorageData = {};
    state.sessionStorageData = {};
  }

  const lsCount = Object.keys(state.localStorageData).length;
  const ssCount = Object.keys(state.sessionStorageData).length;
  document.getElementById('lsCount').textContent = lsCount;
  document.getElementById('ssCount').textContent = ssCount;
  document.getElementById('storageCountBadge').textContent = lsCount + ssCount;

  renderStorageItems();
}

// ==========================================
// Cookies Tab Rendering & Actions
// ==========================================
function renderCookies() {
  const container = document.getElementById('cookiesList');
  const search = document.getElementById('cookieSearch').value.toLowerCase().trim();
  const filter = document.getElementById('cookieFilter').value;

  let filtered = state.cookies.filter(c => {
    // Search match
    const matchSearch = !search ||
      c.name.toLowerCase().includes(search) ||
      c.value.toLowerCase().includes(search) ||
      c.domain.toLowerCase().includes(search);
    if (!matchSearch) return false;

    // Filter match
    if (filter === 'session') return c.session;
    if (filter === 'persistent') return !c.session;
    if (filter === 'secure') return c.secure;
    if (filter === 'httponly') return c.httpOnly;
    if (filter === 'samesite-none') return c.sameSite === 'no_restriction';

    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"></circle><line x1="8" y1="12" x2="16" y2="12"></line></svg>
        <h4>No Cookies Found</h4>
        <p>${state.cookies.length === 0 ? 'No cookies are stored for this website.' : 'No cookies match your search criteria.'}</p>
      </div>
    `;
    return;
  }

  container.innerHTML = '';
  filtered.forEach(cookie => {
    const card = document.createElement('div');
    card.className = 'cookie-card';

    const expiryInfo = formatExpiry(cookie.expirationDate);
    const size = (cookie.name + cookie.value).length;

    card.innerHTML = `
      <div class="cookie-header">
        <div class="cookie-name-group">
          <span class="cookie-name" title="${escapeHtml(cookie.name)}">${escapeHtml(cookie.name)}</span>
          <span class="cookie-domain-path">${escapeHtml(cookie.domain)}${escapeHtml(cookie.path)}</span>
        </div>
        <div class="cookie-actions">
          <button class="icon-btn copy-pair-btn" title="Copy name=value">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
          </button>
          <button class="icon-btn edit-cookie-btn" title="Edit Cookie">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
          </button>
          <button class="icon-btn danger delete-cookie-btn" title="Delete Cookie">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
          </button>
        </div>
      </div>
      <div class="cookie-value-box" title="Click to copy raw value">${escapeHtml(cookie.value || '<empty>')}</div>
      <div class="badges-row">
        ${cookie.secure ? '<span class="badge badge-green">🔒 Secure</span>' : '<span class="badge badge-neutral">🔓 Insecure</span>'}
        ${cookie.httpOnly ? '<span class="badge badge-amber">🛡️ HttpOnly</span>' : ''}
        ${cookie.sameSite && cookie.sameSite !== 'unspecified' ? `<span class="badge badge-blue">SameSite: ${cookie.sameSite}</span>` : ''}
        <span class="badge ${expiryInfo.isExpired ? 'badge-red' : (expiryInfo.isSession ? 'badge-neutral' : 'badge-purple')}">
          ⌛ ${expiryInfo.text}
        </span>
        <span class="badge badge-neutral">${formatBytes(size)}</span>
      </div>
    `;

    // Action handlers
    card.querySelector('.cookie-value-box').addEventListener('click', () => {
      copyToClipboard(cookie.value, "Cookie value copied!");
    });

    card.querySelector('.copy-pair-btn').addEventListener('click', () => {
      copyToClipboard(`${cookie.name}=${cookie.value}`, `Copied ${cookie.name}=${cookie.value.substring(0, 10)}...`);
    });

    card.querySelector('.edit-cookie-btn').addEventListener('click', () => {
      openCookieModal(cookie);
    });

    card.querySelector('.delete-cookie-btn').addEventListener('click', () => {
      deleteCookie(cookie);
    });

    container.appendChild(card);
  });
}

document.getElementById('cookieSearch').addEventListener('input', renderCookies);
document.getElementById('cookieFilter').addEventListener('change', renderCookies);

// Copy All Filtered Header
document.getElementById('copyAllCookiesHeaderBtn').addEventListener('click', () => {
  if (state.cookies.length === 0) {
    showToast("No cookies to copy", "warn");
    return;
  }
  const headerStr = state.cookies.map(c => `${c.name}=${c.value}`).join('; ');
  copyToClipboard(headerStr, `Copied ${state.cookies.length} cookies as HTTP Header!`);
});

// Delete Filtered
document.getElementById('clearCookiesBtn').addEventListener('click', async () => {
  if (state.cookies.length === 0) return;
  if (!confirm(`Are you sure you want to delete all cookies currently shown?`)) return;

  let count = 0;
  for (const c of state.cookies) {
    const isHostOnlyPrefix = c.name.startsWith("__Host-");
    const protocol = (c.secure || isHostOnlyPrefix) ? "https://" : "http://";
    const cleanDomain = c.domain.startsWith('.') ? c.domain.substring(1) : c.domain;
    const url = protocol + cleanDomain + (c.path || "/");

    try {
      await chrome.cookies.remove({ url: url, name: c.name });
      count++;
    } catch (e) {
      console.warn("Could not delete cookie", c.name, e);
    }
  }

  showToast(`Deleted ${count} cookies!`, 'success');
  await loadCookies();
  runSecurityAudit();
});

async function deleteCookie(cookie) {
  const isHostOnlyPrefix = cookie.name.startsWith("__Host-");
  const protocol = (cookie.secure || isHostOnlyPrefix) ? "https://" : "http://";
  const cleanDomain = cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain;
  const url = protocol + cleanDomain + (cookie.path || "/");

  try {
    await chrome.cookies.remove({ url: url, name: cookie.name });
    showToast(`Deleted "${cookie.name}"`, 'success');
    await loadCookies();
    runSecurityAudit();
  } catch (err) {
    showToast(`Failed to delete cookie: ${err.message}`, 'error');
  }
}

// ==========================================
// Storage Tab Rendering & Actions
// ==========================================
function renderStorageItems() {
  const tbody = document.getElementById('storageTableBody');
  const search = document.getElementById('storageSearch').value.toLowerCase().trim();
  const dataSource = state.activeStorageSubtab === 'local' ? state.localStorageData : state.sessionStorageData;
  const keys = Object.keys(dataSource);

  const filteredKeys = keys.filter(k => {
    if (!search) return true;
    const val = String(dataSource[k] || '').toLowerCase();
    return k.toLowerCase().includes(search) || val.includes(search);
  });

  if (filteredKeys.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="3" style="text-align: center; padding: 30px; color: var(--text-muted);">
          No items found in ${state.activeStorageSubtab === 'local' ? 'LocalStorage' : 'SessionStorage'}.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = '';
  filteredKeys.forEach(key => {
    const val = dataSource[key];
    const tr = document.createElement('tr');

    tr.innerHTML = `
      <td class="storage-key">${escapeHtml(key)}</td>
      <td>
        <div class="storage-val" title="Click to view/copy">${escapeHtml(val)}</div>
      </td>
      <td style="text-align: right;">
        <div style="display: inline-flex; gap: 4px;">
          <button class="icon-btn edit-storage-btn" title="Edit Item">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
          </button>
          <button class="icon-btn danger delete-storage-btn" title="Delete Item">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
          </button>
        </div>
      </td>
    `;

    tr.querySelector('.storage-val').addEventListener('click', () => {
      copyToClipboard(val, `Copied value for key "${key}"!`);
    });

    tr.querySelector('.edit-storage-btn').addEventListener('click', () => {
      openStorageModal({ target: state.activeStorageSubtab, key: key, value: val });
    });

    tr.querySelector('.delete-storage-btn').addEventListener('click', () => {
      deleteStorageItem(state.activeStorageSubtab, key);
    });

    tbody.appendChild(tr);
  });
}

document.getElementById('storageSearch').addEventListener('input', renderStorageItems);

async function deleteStorageItem(target, key) {
  if (!state.currentTab || !state.currentTab.id) return;
  try {
    await chrome.scripting.executeScript({
      target: { tabId: state.currentTab.id },
      func: (t, k) => {
        if (t === 'local') localStorage.removeItem(k);
        else sessionStorage.removeItem(k);
      },
      args: [target, key]
    });
    showToast(`Removed "${key}"`, 'success');
    await loadStorage();
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
  }
}

document.getElementById('clearActiveStorageBtn').addEventListener('click', async () => {
  const target = state.activeStorageSubtab;
  const name = target === 'local' ? 'LocalStorage' : 'SessionStorage';
  if (!confirm(`Are you sure you want to clear ALL ${name} keys on this page?`)) return;

  try {
    await chrome.scripting.executeScript({
      target: { tabId: state.currentTab.id },
      func: (t) => {
        if (t === 'local') localStorage.clear();
        else sessionStorage.clear();
      },
      args: [target]
    });
    showToast(`Cleared ${name}!`, 'success');
    await loadStorage();
  } catch (err) {
    showToast(`Failed to clear: ${err.message}`, 'error');
  }
});

// ==========================================
// Multi-Account Session Snapshots Engine
// ==========================================
async function loadSnapshots() {
  chrome.storage.local.get(['session_snapshots'], (result) => {
    state.snapshots = result.session_snapshots || [];
    const container = document.getElementById('snapshotsList');
    document.getElementById('snapshotCountBadge').textContent = state.snapshots.length;

    if (state.snapshots.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
          <h4>No Session Profiles Saved</h4>
          <p>Create a snapshot above to save your logged-in state and switch accounts anytime.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = '';
    state.snapshots.forEach(snapshot => {
      const card = document.createElement('div');
      card.className = 'snapshot-card';

      const isCurrentDomain = snapshot.domain === state.activeDomain;
      const dateStr = new Date(snapshot.timestamp).toLocaleString();
      const cookieCount = snapshot.cookies ? snapshot.cookies.length : 0;
      const lsCount = snapshot.localStorage ? Object.keys(snapshot.localStorage).length : 0;

      card.innerHTML = `
        <div class="snapshot-info">
          <div class="snapshot-title">
            <span>⚡ ${escapeHtml(snapshot.name)}</span>
            ${isCurrentDomain ? '<span class="badge badge-green">Current Site</span>' : `<span class="badge badge-neutral">${escapeHtml(snapshot.domain)}</span>`}
          </div>
          <div class="snapshot-meta">
            Saved on ${dateStr} • <b>${cookieCount}</b> cookies • <b>${lsCount}</b> storage keys
          </div>
        </div>
        <div class="snapshot-actions">
          <button class="btn btn-primary btn-sm restore-snap-btn" title="Restore this session state">
            Switch / Activate
          </button>
          <button class="icon-btn export-snap-btn" title="Download Snapshot JSON">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
          </button>
          <button class="icon-btn danger delete-snap-btn" title="Delete Profile">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
          </button>
        </div>
      `;

      card.querySelector('.restore-snap-btn').addEventListener('click', () => {
        applySnapshot(snapshot);
      });

      card.querySelector('.export-snap-btn').addEventListener('click', () => {
        downloadJsonFile(snapshot, `${snapshot.domain}_snapshot_${snapshot.name}.json`);
      });

      card.querySelector('.delete-snap-btn').addEventListener('click', () => {
        deleteSnapshot(snapshot.id);
      });

      container.appendChild(card);
    });
  });
}

document.getElementById('saveSnapshotBtn').addEventListener('click', async () => {
  const nameInput = document.getElementById('snapshotNameInput');
  const name = nameInput.value.trim();
  if (!name) {
    showToast("Please enter a profile name!", "warn");
    return;
  }

  updateStatus(`Capturing snapshot "${name}"...`);

  await loadCookies();
  await loadStorage();

  const newSnapshot = {
    id: 'snap_' + Date.now(),
    name: name,
    domain: state.activeDomain,
    url: state.currentTab ? state.currentTab.url : '',
    timestamp: new Date().toISOString(),
    cookies: state.cookies,
    localStorage: state.localStorageData,
    sessionStorage: state.sessionStorageData
  };

  chrome.storage.local.get(['session_snapshots'], (result) => {
    const list = result.session_snapshots || [];
    list.unshift(newSnapshot);
    chrome.storage.local.set({ session_snapshots: list }, () => {
      nameInput.value = '';
      showToast(`Profile "${name}" saved!`, 'success');
      loadSnapshots();
    });
  });
});

async function applySnapshot(snapshot) {
  if (!confirm(`Switch to profile "${snapshot.name}"? This will overwrite the current session and reload the page.`)) {
    return;
  }

  updateStatus(`Activating profile "${snapshot.name}"...`);
  await restoreSessionPayload(snapshot);
}

function deleteSnapshot(id) {
  chrome.storage.local.get(['session_snapshots'], (result) => {
    let list = result.session_snapshots || [];
    list = list.filter(s => s.id !== id);
    chrome.storage.local.set({ session_snapshots: list }, () => {
      showToast("Profile removed", 'info');
      loadSnapshots();
    });
  });
}

// ==========================================
// Security & Privacy Audit Engine
// ==========================================
function runSecurityAudit() {
  const total = state.cookies.length;
  let insecureCount = 0;
  let trackerCount = 0;
  let missingHttpOnly = 0;
  let sameSiteNone = 0;

  const findings = [];
  const sensitiveKeywords = ['sess', 'token', 'auth', 'jwt', 'id', 'login', 'key', 'admin', 'user'];

  state.cookies.forEach(c => {
    const isSensitive = sensitiveKeywords.some(k => c.name.toLowerCase().includes(k));
    const now = Date.now() / 1000;

    // Check Secure flag
    if (!c.secure) {
      insecureCount++;
    }

    // Check HttpOnly on sensitive cookies
    if (isSensitive && !c.httpOnly) {
      missingHttpOnly++;
    }

    // Check SameSite
    if (c.sameSite === 'no_restriction' || !c.sameSite || c.sameSite === 'unspecified') {
      sameSiteNone++;
    }

    // Check Long-lived trackers (> 365 days)
    if (c.expirationDate && (c.expirationDate - now) > 365 * 86400) {
      trackerCount++;
    }
  });

  // Score Calculation
  let grade = 'A+';
  let gradeClass = 'score-great';

  if (insecureCount > 3 || missingHttpOnly > 2) {
    grade = 'C';
    gradeClass = 'score-warn';
  }
  if (insecureCount > 8 || missingHttpOnly > 5) {
    grade = 'F';
    gradeClass = 'score-danger';
  } else if (insecureCount > 0 || missingHttpOnly > 0) {
    grade = 'B+';
    gradeClass = 'score-blue';
  }

  const gradeEl = document.getElementById('auditGrade');
  gradeEl.textContent = grade;
  gradeEl.className = `score ${gradeClass}`;
  document.getElementById('auditScoreBadge').textContent = grade;
  document.getElementById('auditInsecureCount').textContent = insecureCount;
  document.getElementById('auditTrackerCount').textContent = trackerCount;

  // Render Findings
  const findingsList = document.getElementById('auditFindingsList');
  findingsList.innerHTML = '';

  if (insecureCount > 0) {
    findings.push({
      type: 'danger',
      title: `${insecureCount} Cookie(s) Missing "Secure" Flag`,
      desc: 'Cookies transmitted without the Secure flag can be intercepted over unencrypted connections (Man-in-the-Middle attacks).'
    });
  }

  if (missingHttpOnly > 0) {
    findings.push({
      type: 'warn',
      title: `${missingHttpOnly} Sensitive Cookie(s) Accessible to JavaScript`,
      desc: 'Authentication or session tokens missing the HttpOnly flag can be stolen by malicious scripts in Cross-Site Scripting (XSS) attacks.'
    });
  }

  if (trackerCount > 0) {
    findings.push({
      type: 'warn',
      title: `${trackerCount} Long-Lived Persistent Tracker(s) Detected`,
      desc: 'Cookies set with lifespans greater than 1 year track browsing activity across sessions.'
    });
  }

  if (findings.length === 0) {
    findingsList.innerHTML = `
      <div class="finding-card success">
        <div class="finding-icon">✅</div>
        <div class="finding-text">
          <h5>No Major Cookie Security Vulnerabilities Detected</h5>
          <p>Cookies for this domain follow current security and privacy best practices (Secure flags, HttpOnly, and strict/lax boundaries).</p>
        </div>
      </div>
    `;
    return;
  }

  findings.forEach(f => {
    const el = document.createElement('div');
    el.className = `finding-card ${f.type}`;
    el.innerHTML = `
      <div class="finding-icon">${f.type === 'danger' ? '⚠️' : '🛡️'}</div>
      <div class="finding-text">
        <h5>${escapeHtml(f.title)}</h5>
        <p>${escapeHtml(f.desc)}</p>
      </div>
    `;
    findingsList.appendChild(el);
  });
}

// One-Click Security Harden
document.getElementById('hardenSecurityBtn').addEventListener('click', async () => {
  if (state.cookies.length === 0) {
    showToast("No cookies to harden", "warn");
    return;
  }

  let hardenedCount = 0;
  for (const cookie of state.cookies) {
    if (!cookie.secure || cookie.sameSite === 'unspecified' || !cookie.sameSite) {
      const isHostOnlyPrefix = cookie.name.startsWith("__Host-");
      const cleanDomain = cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain;
      const url = "https://" + cleanDomain + (cookie.path || "/");

      const updateObj = {
        url: url,
        name: cookie.name,
        value: cookie.value,
        path: cookie.path || "/",
        secure: true,
        httpOnly: cookie.httpOnly,
        sameSite: 'lax'
      };

      if (!isHostOnlyPrefix && cookie.domain) {
        updateObj.domain = cookie.domain;
      }
      if (cookie.expirationDate) {
        updateObj.expirationDate = cookie.expirationDate;
      }

      try {
        await chrome.cookies.set(updateObj);
        hardenedCount++;
      } catch (e) {
        console.warn("Could not harden cookie:", cookie.name, e);
      }
    }
  }

  showToast(`Security hardened on ${hardenedCount} cookies!`, 'success');
  await loadCookies();
  runSecurityAudit();
});

// ==========================================
// Backup & Restore Hub (Multi-Format & Encryption)
// ==========================================
function setupHubActions() {
  // Export button
  document.getElementById('hubDownloadBtn').addEventListener('click', async () => {
    await exportBackup(false);
  });

  // Copy raw export button
  document.getElementById('hubCopyBtn').addEventListener('click', async () => {
    await exportBackup(true);
  });

  // File Dropzone
  const dropzone = document.getElementById('fileDropzone');
  const fileInput = document.getElementById('hubFileInput');
  const fileNameDisplay = document.getElementById('selectedFileName');

  dropzone.addEventListener('click', () => fileInput.click());

  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.style.borderColor = 'var(--primary)';
  });

  dropzone.addEventListener('dragleave', () => {
    dropzone.style.borderColor = 'var(--border-color)';
  });

  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.style.borderColor = 'var(--border-color)';
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      fileNameDisplay.textContent = fileInput.files[0].name;
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      fileNameDisplay.textContent = fileInput.files[0].name;
    }
  });

  // Restore button
  document.getElementById('hubRestoreBtn').addEventListener('click', async () => {
    if (!fileInput.files || fileInput.files.length === 0) {
      showToast("Please select a session file to restore!", "warn");
      return;
    }

    const file = fileInput.files[0];
    const passphrase = document.getElementById('importPassphrase').value.trim();
    const reader = new FileReader();

    reader.onload = async (e) => {
      try {
        let content = e.target.result;

        // Check if content is Netscape format
        if (content.startsWith('# Netscape HTTP Cookie File') || content.includes('\tTRUE\t') || content.includes('\tFALSE\t')) {
          const parsedCookies = parseNetscapeFormat(content);
          await restoreSessionPayload({ cookies: parsedCookies });
          return;
        }

        // Try JSON parse
        let data = JSON.parse(content);

        // Check if encrypted container
        if (data && data.__encrypted && data.cipherText) {
          if (!passphrase) {
            showToast("This backup is encrypted! Enter the passphrase above.", "error");
            return;
          }
          data = await decryptData(data, passphrase);
        }

        await restoreSessionPayload(data);
      } catch (err) {
        console.error("Restore failed:", err);
        showToast("Restore failed: " + err.message, "error");
      }
    };

    reader.readAsText(file);
  });
}

async function exportBackup(copyOnly = false) {
  await loadCookies();
  await loadStorage();

  const format = document.getElementById('exportFormat').value;
  const passphrase = document.getElementById('exportPassphrase').value.trim();
  let exportContent = '';
  let filename = `${state.activeDomain || 'session'}_backup_${Date.now()}`;

  if (format === 'netscape') {
    exportContent = generateNetscapeFormat(state.cookies);
    filename += '.txt';
  } else {
    let payload = {};
    if (format === 'cookies-json') {
      payload = { cookies: state.cookies };
      filename += '_cookies.json';
    } else {
      payload = {
        generator: "Universal Session Manager Pro v3.0",
        domain: state.activeDomain,
        exportDate: new Date().toISOString(),
        cookies: state.cookies,
        localStorage: state.localStorageData,
        sessionStorage: state.sessionStorageData
      };
      filename += '.json';
    }

    if (passphrase) {
      payload = await encryptData(payload, passphrase);
    }
    exportContent = JSON.stringify(payload, null, 2);
  }

  if (copyOnly) {
    copyToClipboard(exportContent, "Export data copied to clipboard!");
  } else {
    downloadTextFile(exportContent, filename, format === 'netscape' ? 'text/plain' : 'application/json');
    showToast(`Backup downloaded successfully!`, 'success');
  }
}

// Restore generic payload (cookies + local + session)
async function restoreSessionPayload(payload) {
  updateStatus("Applying session data...");
  let cookiesRestored = 0;
  let lsCount = 0;

  // 1. Restore Cookies
  const cookies = payload.cookies || (Array.isArray(payload) ? payload : []);
  for (const cookie of cookies) {
    const isHostOnlyPrefix = cookie.name.startsWith("__Host-");
    const protocol = (cookie.secure || isHostOnlyPrefix) ? "https://" : "http://";
    const cleanDomain = cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain;
    const url = protocol + cleanDomain + (cookie.path || "/");

    const cookieDetails = {
      url: url,
      name: cookie.name,
      value: cookie.value,
      path: isHostOnlyPrefix ? "/" : (cookie.path || "/"),
      secure: isHostOnlyPrefix ? true : Boolean(cookie.secure),
      httpOnly: Boolean(cookie.httpOnly)
    };

    if (!isHostOnlyPrefix && cookie.domain) {
      cookieDetails.domain = cookie.domain;
    }
    if (cookie.sameSite && ["no_restriction", "lax", "strict"].includes(cookie.sameSite)) {
      cookieDetails.sameSite = cookie.sameSite;
    }
    if (cookie.expirationDate && typeof cookie.expirationDate === 'number') {
      cookieDetails.expirationDate = cookie.expirationDate;
    }

    try {
      await chrome.cookies.set(cookieDetails);
      cookiesRestored++;
    } catch (e) {
      console.warn("Could not restore cookie:", cookie.name, e);
    }
  }

  // 2. Restore LocalStorage & SessionStorage
  const lsData = payload.localStorage || {};
  const ssData = payload.sessionStorage || {};

  if (state.currentTab && state.currentTab.id) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId: state.currentTab.id },
        func: (ls, ss) => {
          for (const k in ls) localStorage.setItem(k, ls[k]);
          for (const k in ss) sessionStorage.setItem(k, ss[k]);
        },
        args: [lsData, ssData]
      });
      lsCount = Object.keys(lsData).length;
    } catch (e) {
      console.warn("Storage restore script failed:", e);
    }
  }

  showToast(`Restored ${cookiesRestored} cookies & ${lsCount} storage items! Reloading...`, 'success');

  setTimeout(() => {
    if (state.currentTab && state.currentTab.id) {
      chrome.tabs.reload(state.currentTab.id);
    }
  }, 1000);
}

// Netscape Format Converters
function generateNetscapeFormat(cookies) {
  let lines = [
    "# Netscape HTTP Cookie File",
    "# http://curl.haxx.se/rfc/cookie_spec.html",
    "# This file was generated by Raiyan Universal Session & Cookie Manager Pro v3.0\n"
  ];

  cookies.forEach(c => {
    const domain = c.domain;
    const includeSubdomains = domain.startsWith('.') ? 'TRUE' : 'FALSE';
    const path = c.path || '/';
    const secure = c.secure ? 'TRUE' : 'FALSE';
    const expiry = c.expirationDate ? Math.round(c.expirationDate) : '0';
    const name = c.name;
    const value = c.value;
    lines.push(`${domain}\t${includeSubdomains}\t${path}\t${secure}\t${expiry}\t${name}\t${value}`);
  });

  return lines.join('\n');
}

function parseNetscapeFormat(text) {
  const lines = text.split('\n');
  const cookies = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const parts = trimmed.split('\t');
    if (parts.length >= 7) {
      cookies.push({
        domain: parts[0],
        path: parts[2],
        secure: parts[3].toUpperCase() === 'TRUE',
        expirationDate: parseInt(parts[4]) || 0,
        name: parts[5],
        value: parts[6]
      });
    }
  }
  return cookies;
}

// ==========================================
// WebCrypto AES-GCM Encryption / Decryption
// ==========================================
async function getKeyFromPassphrase(passphrase, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Safe Uint8Array <-> Base64 helpers (prevents RangeError: Maximum call stack size exceeded on large sessions)
function uint8ArrayToBase64(bytes) {
  let binary = '';
  const len = bytes.byteLength;
  const chunkSize = 8192;
  for (let i = 0; i < len; i += chunkSize) {
    binary += String.fromCharCode.apply(
      null,
      bytes.subarray(i, Math.min(i + chunkSize, len))
    );
  }
  return btoa(binary);
}

function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function encryptData(objectData, passphrase) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await getKeyFromPassphrase(passphrase, salt);

  const encoded = enc.encode(JSON.stringify(objectData));
  const cipherBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, encoded);

  return {
    __encrypted: true,
    salt: uint8ArrayToBase64(salt),
    iv: uint8ArrayToBase64(iv),
    cipherText: uint8ArrayToBase64(new Uint8Array(cipherBuffer))
  };
}

async function decryptData(encryptedContainer, passphrase) {
  const salt = base64ToUint8Array(encryptedContainer.salt);
  const iv = base64ToUint8Array(encryptedContainer.iv);
  const cipherBytes = base64ToUint8Array(encryptedContainer.cipherText);

  const key = await getKeyFromPassphrase(passphrase, salt);
  const decryptedBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, cipherBytes);

  const dec = new TextDecoder();
  return JSON.parse(dec.decode(decryptedBuffer));
}

// ==========================================
// Modals Controller (Add / Edit)
// ==========================================
function setupModals() {
  // Cookie Modal
  document.getElementById('openAddCookieBtn').addEventListener('click', () => {
    openCookieModal(null);
  });

  document.getElementById('closeCookieModalBtn').addEventListener('click', closeCookieModal);
  document.getElementById('cancelCookieModalBtn').addEventListener('click', closeCookieModal);

  document.getElementById('saveCookieModalBtn').addEventListener('click', saveCookieFromModal);

  // Storage Modal
  document.getElementById('openAddStorageBtn').addEventListener('click', () => {
    openStorageModal(null);
  });

  document.getElementById('closeStorageModalBtn').addEventListener('click', closeStorageModal);
  document.getElementById('cancelStorageModalBtn').addEventListener('click', closeStorageModal);

  document.getElementById('saveStorageModalBtn').addEventListener('click', saveStorageFromModal);

  document.getElementById('modalFormatJsonBtn').addEventListener('click', () => {
    const valEl = document.getElementById('modalStorageValue');
    try {
      const parsed = JSON.parse(valEl.value);
      valEl.value = JSON.stringify(parsed, null, 2);
      showToast("JSON formatted!", "success");
    } catch (e) {
      showToast("Value is not valid JSON", "warn");
    }
  });
}

function openCookieModal(cookie) {
  state.editingCookie = cookie;
  const modal = document.getElementById('cookieModal');
  const title = document.getElementById('cookieModalTitle');

  if (cookie) {
    title.textContent = `Edit Cookie: ${cookie.name}`;
    document.getElementById('modalCookieName').value = cookie.name;
    document.getElementById('modalCookieName').disabled = true;
    document.getElementById('modalCookieValue').value = cookie.value;
    document.getElementById('modalCookieDomain').value = cookie.domain;
    document.getElementById('modalCookiePath').value = cookie.path || '/';
    document.getElementById('modalCookieSameSite').value = cookie.sameSite || 'unspecified';
    document.getElementById('modalCookieSecure').checked = Boolean(cookie.secure);
    document.getElementById('modalCookieHttpOnly').checked = Boolean(cookie.httpOnly);

    if (cookie.expirationDate) {
      const days = Math.round((cookie.expirationDate - (Date.now() / 1000)) / 86400);
      document.getElementById('modalCookieExpiryDays').value = Math.max(0, days);
    } else {
      document.getElementById('modalCookieExpiryDays').value = '';
    }
  } else {
    title.textContent = "Add New Cookie";
    document.getElementById('modalCookieName').value = '';
    document.getElementById('modalCookieName').disabled = false;
    document.getElementById('modalCookieValue').value = '';
    document.getElementById('modalCookieDomain').value = state.activeDomain ? `.${state.activeDomain}` : '';
    document.getElementById('modalCookiePath').value = '/';
    document.getElementById('modalCookieSameSite').value = 'lax';
    document.getElementById('modalCookieSecure').checked = true;
    document.getElementById('modalCookieHttpOnly').checked = false;
    document.getElementById('modalCookieExpiryDays').value = '30';
  }

  modal.classList.add('open');
}

function closeCookieModal() {
  document.getElementById('cookieModal').classList.remove('open');
  state.editingCookie = null;
}

async function saveCookieFromModal() {
  const name = document.getElementById('modalCookieName').value.trim();
  const value = document.getElementById('modalCookieValue').value;
  let domain = document.getElementById('modalCookieDomain').value.trim();
  const path = document.getElementById('modalCookiePath').value.trim() || '/';
  const sameSite = document.getElementById('modalCookieSameSite').value;
  const secure = document.getElementById('modalCookieSecure').checked;
  const httpOnly = document.getElementById('modalCookieHttpOnly').checked;
  const expiryDays = parseFloat(document.getElementById('modalCookieExpiryDays').value);

  if (!name) {
    showToast("Cookie name is required!", "error");
    return;
  }

  const isHostOnlyPrefix = name.startsWith("__Host-");
  const protocol = (secure || isHostOnlyPrefix) ? "https://" : "http://";
  const cleanDomain = domain.startsWith('.') ? domain.substring(1) : (domain || state.activeDomain);
  const url = protocol + cleanDomain + path;

  const cookieObj = {
    url: url,
    name: name,
    value: value,
    path: isHostOnlyPrefix ? "/" : path,
    secure: isHostOnlyPrefix ? true : secure,
    httpOnly: httpOnly
  };

  if (!isHostOnlyPrefix && domain) {
    cookieObj.domain = domain;
  }

  if (sameSite && sameSite !== 'unspecified') {
    cookieObj.sameSite = sameSite;
  }

  if (!isNaN(expiryDays) && expiryDays > 0) {
    cookieObj.expirationDate = Math.round((Date.now() / 1000) + (expiryDays * 86400));
  }

  try {
    await chrome.cookies.set(cookieObj);
    showToast(`Saved cookie "${name}"`, 'success');
    closeCookieModal();
    await loadCookies();
    runSecurityAudit();
  } catch (err) {
    showToast(`Error saving cookie: ${err.message}`, 'error');
  }
}

function openStorageModal(item) {
  state.editingStorage = item;
  const modal = document.getElementById('storageModal');
  const title = document.getElementById('storageModalTitle');

  if (item) {
    title.textContent = `Edit ${item.target === 'local' ? 'LocalStorage' : 'SessionStorage'} Key`;
    document.getElementById('modalStorageTarget').value = item.target;
    document.getElementById('modalStorageKey').value = item.key;
    document.getElementById('modalStorageKey').disabled = true;
    document.getElementById('modalStorageValue').value = item.value;
  } else {
    title.textContent = "Add Storage Item";
    document.getElementById('modalStorageTarget').value = state.activeStorageSubtab;
    document.getElementById('modalStorageKey').value = '';
    document.getElementById('modalStorageKey').disabled = false;
    document.getElementById('modalStorageValue').value = '';
  }

  modal.classList.add('open');
}

function closeStorageModal() {
  document.getElementById('storageModal').classList.remove('open');
  state.editingStorage = null;
}

async function saveStorageFromModal() {
  const target = document.getElementById('modalStorageTarget').value;
  const key = document.getElementById('modalStorageKey').value.trim();
  const value = document.getElementById('modalStorageValue').value;

  if (!key) {
    showToast("Storage key name is required!", "error");
    return;
  }

  if (!state.currentTab || !state.currentTab.id) return;

  try {
    await chrome.scripting.executeScript({
      target: { tabId: state.currentTab.id },
      func: (t, k, v) => {
        if (t === 'local') localStorage.setItem(k, v);
        else sessionStorage.setItem(k, v);
      },
      args: [target, key, value]
    });

    showToast(`Saved ${key} to ${target === 'local' ? 'LocalStorage' : 'SessionStorage'}`, 'success');
    closeStorageModal();
    await loadStorage();
  } catch (err) {
    showToast(`Error saving storage: ${err.message}`, 'error');
  }
}

// ==========================================
// Global Action Buttons (Nuke, Reload)
// ==========================================
function setupGlobalActions() {
  // Reload Active Tab
  document.getElementById('reloadTabBtn').addEventListener('click', () => {
    if (state.currentTab && state.currentTab.id) {
      chrome.tabs.reload(state.currentTab.id);
      showToast("Tab reloaded", "info");
      setTimeout(() => refreshAllData(), 800);
    }
  });

  // Nuke All Site Data
  document.getElementById('nukeSiteBtn').addEventListener('click', async () => {
    if (!confirm(`⚠️ NUKE ALL DATA for ${state.activeDomain || 'this site'}?\n\nThis will permanently delete all cookies, localStorage, and sessionStorage, and reload the page.`)) {
      return;
    }

    // 1. Remove all cookies for tab
    for (const c of state.cookies) {
      const isHostOnlyPrefix = c.name.startsWith("__Host-");
      const protocol = (c.secure || isHostOnlyPrefix) ? "https://" : "http://";
      const cleanDomain = c.domain.startsWith('.') ? c.domain.substring(1) : c.domain;
      const url = protocol + cleanDomain + (c.path || "/");
      try {
        await chrome.cookies.remove({ url: url, name: c.name });
      } catch (e) {}
    }

    // 2. Clear storage in tab
    if (state.currentTab && state.currentTab.id) {
      try {
        await chrome.scripting.executeScript({
          target: { tabId: state.currentTab.id },
          func: () => {
            localStorage.clear();
            sessionStorage.clear();
          }
        });
      } catch (e) {}
    }

    showToast("All site data wiped! Reloading...", "warn");
    setTimeout(() => {
      if (state.currentTab && state.currentTab.id) {
        chrome.tabs.reload(state.currentTab.id);
      }
    }, 600);
  });
}

// ==========================================
// Utilities
// ==========================================
function escapeHtml(str) {
  if (typeof str !== 'string') return String(str || '');
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function copyToClipboard(text, successToast = "Copied to clipboard!") {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    showToast(successToast, "success");
  }).catch(() => {
    // Fallback
    const input = document.createElement('textarea');
    input.value = text;
    document.body.appendChild(input);
    input.select();
    document.execCommand('copy');
    input.remove();
    showToast(successToast, "success");
  });
}

function downloadTextFile(content, filename, mimeType = 'text/plain') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function downloadJsonFile(obj, filename) {
  downloadTextFile(JSON.stringify(obj, null, 2), filename, 'application/json');
}