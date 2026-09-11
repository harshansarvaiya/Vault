import {
  deriveMasterKeys,
  generateVek,
  encryptVek,
  decryptVek,
  encryptPayload,
  decryptPayload,
  createDefaultDecoyItems,
  generateRecoveryPhrase,
  getRandomHex,
} from './crypto.js';

import { generateTotp } from './totp.js';
import { generatePassword, generatePassphrase, calculatePasswordEntropy } from './password-generator.js';
import { isWebAuthnSupported, registerPasskey, authenticatePasskey } from './webauthn-client.js';
import { generateQrSvg } from './qr-code.js';

// Application State
const state = {
  currentUser: null,
  sessionToken: null,
  mek: null, // Master Encryption Key (AES-GCM CryptoKey)
  vek: null, // Vault Encryption Key (AES-GCM CryptoKey)
  isDuress: false,
  vaultItems: [], // Decrypted credentials array
  activeFilter: 'all',
  searchQuery: '',
  inactivityTimeoutMinutes: 5,
  inactivityTimer: null,
  clipboardTimer: null,
};

// Register PWA Service Worker for offline resilience
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch((err) => {
      console.warn('PWA ServiceWorker registration failed:', err);
    });
  });
}

// =========================================================================
// UI HELPERS & NOTIFICATIONS
// =========================================================================

export function showToast(message, type = 'info', duration = 3500) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 200);
  }, duration);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.add('active');
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.remove('active');
}

document.querySelectorAll('.close-modal').forEach((btn) => {
  btn.addEventListener('click', (e) => {
    const modal = e.target.closest('.modal-backdrop');
    if (modal) modal.classList.remove('active');
  });
});

// =========================================================================
// INACTIVITY TIMER & PRIVACY SHIELD
// =========================================================================

function resetInactivityTimer() {
  if (!state.sessionToken) return;

  if (state.inactivityTimer) clearTimeout(state.inactivityTimer);

  state.inactivityTimer = setTimeout(() => {
    lockVault('Inactivity lock engaged for security.');
  }, state.inactivityTimeoutMinutes * 60 * 1000);
}

['mousemove', 'keydown', 'touchstart', 'scroll', 'click'].forEach((event) => {
  window.addEventListener(event, resetInactivityTimer, { passive: true });
});

// Tab blur privacy shield (blurs vault when switching tabs/windows)
const privacyShield = document.getElementById('privacyShield');
window.addEventListener('blur', () => {
  if (state.sessionToken && privacyShield) {
    privacyShield.classList.add('active');
  }
});

window.addEventListener('focus', () => {
  if (privacyShield) {
    privacyShield.classList.remove('active');
  }
});

if (privacyShield) {
  privacyShield.addEventListener('click', () => {
    privacyShield.classList.remove('active');
  });
}

// Clipboard auto-clear (sanitizes system clipboard after 30 seconds)
function copyWithAutoClear(text, label = 'Secret') {
  navigator.clipboard.writeText(text).then(() => {
    showToast(`${label} copied. Auto-clearing clipboard in 30s.`, 'info');

    if (state.clipboardTimer) clearTimeout(state.clipboardTimer);

    state.clipboardTimer = setTimeout(async () => {
      try {
        // Overwrite clipboard with empty string
        await navigator.clipboard.writeText('');
        showToast('Clipboard sanitized.', 'success');
      } catch {
        // Background write might be restricted by browser if not focused
      }
    }, 30000);
  }).catch((err) => {
    showToast('Failed to copy to clipboard', 'error');
  });
}

// =========================================================================
// AUTHENTICATION LOGIC (Master Password, Passkeys, Duress)
// =========================================================================

async function handleLogin(username, password) {
  try {
    showToast('Deriving cryptographic keys (600,000 PBKDF2 rounds)...', 'info', 2000);

    // 1. Pre-login to retrieve user salts
    const preRes = await fetch(`/api/auth/pre-login?username=${encodeURIComponent(username)}`);
    if (!preRes.ok) throw new Error('Pre-login handshake failed');
    const salts = await preRes.json();

    // 2. Derive MEK and MAH
    const { mek, authHash } = await deriveMasterKeys(password, salts.kdfSalt, salts.kdfIterations);

    // 3. Authenticate with server
    const authRes = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, authHash }),
    });

    if (!authRes.ok) {
      const err = await authRes.json();
      throw new Error(err.error || 'Authentication rejected');
    }

    const authData = await authRes.json();
    state.currentUser = authData.user;
    state.sessionToken = authData.sessionToken;
    state.isDuress = authData.isDuress;
    state.mek = mek;

    // 4. Decrypt Vault Encryption Key (VEK)
    state.vek = await decryptVek(authData.encryptedVek, mek);

    // 5. Update Status Banner
    updateStatusBadge();

    // 6. Transition to Unlocked Vault
    await loadVaultItems();
    showUnlockedView();
    showToast(state.isDuress ? 'Decoy Sector Initialized.' : 'Vault decrypted successfully.', 'success');
  } catch (err) {
    console.error('Login error:', err);
    showToast(err.message, 'error');
  }
}

async function handlePasskeyLogin() {
  try {
    showToast('Engaging biometric passkey sensor...', 'info');
    const result = await authenticatePasskey();
    if (!result || !result.success) throw new Error('Passkey verification failed');

    state.currentUser = result.user;
    state.sessionToken = result.sessionToken;
    state.isDuress = result.isDuress;

    // To decrypt vault items, prompt operator for Master Password or use session key
    const masterPass = prompt('Passkey verified! Enter Master Password to decrypt vault data:');
    if (!masterPass) {
      showToast('Master password required for zero-knowledge decryption', 'error');
      return;
    }

    const preRes = await fetch(`/api/auth/pre-login?username=${encodeURIComponent(result.user.username)}`);
    const salts = await preRes.json();
    const { mek } = await deriveMasterKeys(masterPass, salts.kdfSalt, salts.kdfIterations);
    state.mek = mek;
    state.vek = await decryptVek(result.encryptedVek, mek);

    updateStatusBadge();
    await loadVaultItems();
    showUnlockedView();
    showToast('Biometric unlock successful.', 'success');
  } catch (err) {
    console.error('Passkey login error:', err);
    showToast(err.message, 'error');
  }
}

async function handleRegister(username, password, duressPin) {
  try {
    showToast('Generating military-grade encryption keys...', 'info', 2500);

    const kdfSalt = getRandomHex(16);
    const authSalt = getRandomHex(16);
    const kdfIterations = 600000;

    // 1. Derive primary Master Keys
    const { mek, authHash } = await deriveMasterKeys(password, kdfSalt, kdfIterations);

    // 2. Generate random 256-bit Vault Encryption Key (VEK)
    const { key: vekKey } = await generateVek();
    const encryptedVek = await encryptVek(vekKey, mek);

    // 3. Setup Duress Decoy Sector (Option A)
    let duressSalt = null;
    let duressHash = null;
    let duressEncryptedVek = null;
    let decoyItems = [];

    if (duressPin) {
      duressSalt = getRandomHex(16);
      const duressKeys = await deriveMasterKeys(duressPin, duressSalt, kdfIterations);
      const { key: duressVek } = await generateVek();
      duressEncryptedVek = await encryptVek(duressVek, duressKeys.mek);
      duressHash = duressKeys.authHash;

      // Populate default decoy credentials
      decoyItems = await createDefaultDecoyItems(duressVek);
    }

    // 4. Send zero-knowledge registration to server
    const regRes = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        authSalt,
        authHash,
        kdfSalt,
        kdfIterations,
        encryptedVek,
        duressSalt,
        duressHash,
        duressEncryptedVek,
        decoyItems,
      }),
    });

    if (!regRes.ok) {
      const err = await regRes.json();
      throw new Error(err.error || 'Registration failed');
    }

    const regData = await regRes.json();
    state.currentUser = regData.user;
    state.sessionToken = regData.sessionToken;
    state.mek = mek;
    state.vek = vekKey;
    state.isDuress = false;

    closeModal('registerModal');
    updateStatusBadge();
    await loadVaultItems();
    showUnlockedView();
    showToast('AegisVault initialized and encrypted.', 'success');
  } catch (err) {
    console.error('Registration error:', err);
    showToast(err.message, 'error');
  }
}

function lockVault(reason = 'Vault locked.') {
  // Wipe sensitive encryption keys from memory
  state.currentUser = null;
  state.sessionToken = null;
  state.mek = null;
  state.vek = null;
  state.isDuress = false;
  state.vaultItems = [];

  if (state.inactivityTimer) clearTimeout(state.inactivityTimer);

  document.getElementById('authSection').style.display = 'flex';
  document.getElementById('vaultSection').style.display = 'none';
  document.getElementById('unlockedHeaderActions').style.display = 'none';

  const badge = document.getElementById('statusBadge');
  badge.className = 'status-badge';
  document.getElementById('statusText').innerText = 'E2EE ACTIVE';

  showToast(reason, 'info');
}

function updateStatusBadge() {
  const badge = document.getElementById('statusBadge');
  const text = document.getElementById('statusText');

  if (state.isDuress) {
    badge.className = 'status-badge duress-banner';
    text.innerText = 'SECTOR: DECOY';
  } else {
    badge.className = 'status-badge';
    text.innerText = 'E2EE ENCRYPTED';
  }
}

function showUnlockedView() {
  document.getElementById('authSection').style.display = 'none';
  document.getElementById('vaultSection').style.display = 'flex';
  document.getElementById('unlockedHeaderActions').style.display = 'flex';
  resetInactivityTimer();
}

// =========================================================================
// VAULT CRUD OPERATIONS (Zero-Knowledge AES-256-GCM)
// =========================================================================

async function loadVaultItems() {
  if (!state.sessionToken || !state.vek) return;

  try {
    const res = await fetch('/api/vault', {
      headers: { Authorization: `Bearer ${state.sessionToken}` },
    });

    if (!res.ok) throw new Error('Failed to load encrypted items');

    const encryptedItems = await res.json();
    const decryptedItems = [];

    for (const item of encryptedItems) {
      try {
        const payload = await decryptPayload(item.encrypted_payload, state.vek);
        decryptedItems.push({
          id: item.id,
          title: payload.title || 'Untitled Entity',
          category: item.category || payload.category || 'General',
          username: payload.username || '',
          password: payload.password || '',
          url: payload.url || '',
          totpSecret: payload.totpSecret || '',
          notes: payload.notes || '',
          tags: payload.tags || [],
          is_favorite: item.is_favorite === 1,
          created_at: item.created_at,
          updated_at: item.updated_at,
        });
      } catch (decErr) {
        console.warn('Failed to decrypt individual item:', item.id, decErr);
      }
    }

    state.vaultItems = decryptedItems;
    renderVaultGrid();
    updateSidebarCounts();
  } catch (err) {
    console.error('Error loading vault:', err);
    showToast('Failed to load vault items', 'error');
  }
}

async function saveItem(itemData) {
  if (!state.sessionToken || !state.vek) return;

  try {
    const payload = {
      title: itemData.title,
      category: itemData.category,
      username: itemData.username,
      password: itemData.password,
      url: itemData.url,
      totpSecret: itemData.totpSecret,
      notes: itemData.notes,
      tags: itemData.tags,
    };

    // Client-side Zero-Knowledge Encryption
    const encryptedTitle = await encryptPayload({ title: itemData.title }, state.vek);
    const encryptedPayload = await encryptPayload(payload, state.vek);

    const isEdit = !!itemData.id;
    const endpoint = isEdit ? `/api/vault/${itemData.id}` : '/api/vault';
    const method = isEdit ? 'PUT' : 'POST';

    const res = await fetch(endpoint, {
      method,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${state.sessionToken}`,
      },
      body: JSON.stringify({
        encryptedTitle,
        category: itemData.category,
        encryptedPayload,
        isFavorite: itemData.is_favorite,
      }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to save entity');
    }

    closeModal('itemModal');
    showToast(isEdit ? 'Entity updated and re-encrypted.' : 'Entity securely stored.', 'success');
    await loadVaultItems();
  } catch (err) {
    console.error('Save error:', err);
    showToast(err.message, 'error');
  }
}

async function deleteItem(id) {
  if (!confirm('Permanently shred this encrypted credential?')) return;

  try {
    const res = await fetch(`/api/vault/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${state.sessionToken}` },
    });

    if (!res.ok) throw new Error('Failed to delete item');

    showToast('Entity purged from vault.', 'success');
    await loadVaultItems();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// =========================================================================
// UI RENDERING (Cards, TOTP Ticker, Filters)
// =========================================================================

function renderVaultGrid() {
  const grid = document.getElementById('vaultGrid');
  const emptyState = document.getElementById('emptyVault');
  if (!grid) return;

  let items = state.vaultItems;

  // Filter by category or priority
  if (state.activeFilter === 'favorite') {
    items = items.filter((i) => i.is_favorite);
  } else if (state.activeFilter === 'totp') {
    items = items.filter((i) => !!i.totpSecret);
  } else if (state.activeFilter !== 'all') {
    items = items.filter((i) => i.category.toLowerCase() === state.activeFilter.toLowerCase());
  }

  // Filter by search query
  if (state.searchQuery.trim()) {
    const q = state.searchQuery.toLowerCase();
    items = items.filter((i) =>
      i.title.toLowerCase().includes(q) ||
      i.username.toLowerCase().includes(q) ||
      i.notes.toLowerCase().includes(q) ||
      i.category.toLowerCase().includes(q) ||
      (i.tags && i.tags.some((t) => t.toLowerCase().includes(q)))
    );
  }

  if (items.length === 0) {
    grid.innerHTML = '';
    emptyState.style.display = 'flex';
    return;
  }

  emptyState.style.display = 'none';

  grid.innerHTML = items
    .map((item) => {
      const initial = (item.title || 'U').charAt(0).toUpperCase();
      const hasTotp = !!item.totpSecret;

      return `
        <div class="vault-card" data-id="${item.id}">
          <div class="card-header">
            <div class="card-title-wrap">
              <div class="card-avatar">${initial}</div>
              <div>
                <div class="card-title">${escapeHtml(item.title)}</div>
                <div class="card-category">${escapeHtml(item.category)}</div>
              </div>
            </div>
            <div style="display: flex; gap: 4px;">
              ${item.is_favorite ? '<span style="color: var(--amber-warn); font-size: 14px;" title="Priority">★</span>' : ''}
              <button class="btn-icon copy-btn btn-edit-item" data-id="${item.id}" title="Edit Entity">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>
              </button>
              <button class="btn-icon copy-btn btn-delete-item" data-id="${item.id}" title="Delete Entity">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--red-alert)" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
              </button>
            </div>
          </div>

          <!-- Username Field -->
          ${item.username ? `
            <div class="card-field">
              <div class="field-label">Identifier</div>
              <div class="field-value-box">
                <span class="field-value">${escapeHtml(item.username)}</span>
                <button class="copy-btn btn-copy" data-copy="${escapeHtml(item.username)}" data-label="Identifier" title="Copy Identifier">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                </button>
              </div>
            </div>
          ` : ''}

          <!-- Password Field -->
          <div class="card-field">
            <div class="field-label">Secret Password</div>
            <div class="field-value-box">
              <span class="field-value pass-text" data-revealed="false" data-pass="${escapeHtml(item.password)}">••••••••••••</span>
              <div class="field-actions">
                <button class="copy-btn btn-toggle-pass" title="Reveal Password">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                </button>
                <button class="copy-btn btn-copy" data-copy="${escapeHtml(item.password)}" data-label="Password" title="Copy Secret (Auto-clear 30s)">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                </button>
              </div>
            </div>
          </div>

          <!-- TOTP 2FA Widget -->
          ${hasTotp ? `
            <div class="totp-container" data-secret="${escapeHtml(item.totpSecret)}">
              <div>
                <div style="font-size: 10px; color: var(--cyan-core); font-family: var(--font-mono); letter-spacing: 1px;">2FA ROLLING CODE</div>
                <div class="totp-digits">------</div>
              </div>
              <div class="totp-timer">
                <svg class="timer-circle">
                  <circle class="timer-bg" cx="11" cy="11" r="8"></circle>
                  <circle class="timer-progress" cx="11" cy="11" r="8" stroke-dasharray="50.2" stroke-dashoffset="0"></circle>
                </svg>
                <span class="totp-seconds">30</span>
                <button class="copy-btn btn-copy-totp" title="Copy 2FA Code">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                </button>
              </div>
            </div>
          ` : ''}

          <!-- Website URL Launch -->
          ${item.url ? `
            <div style="display: flex; justify-content: flex-end;">
              <a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer" style="color: var(--cyan-core); font-size: 11px; font-family: var(--font-mono); text-decoration: none; display: flex; align-items: center; gap: 4px;">
                <span>Launch Service</span>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
              </a>
            </div>
          ` : ''}
        </div>
      `;
    })
    .join('');

  attachCardEvents();
  updateTotpCodes();
}

function attachCardEvents() {
  // Copy buttons
  document.querySelectorAll('.btn-copy').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const text = btn.getAttribute('data-copy');
      const label = btn.getAttribute('data-label') || 'Data';
      copyWithAutoClear(text, label);
    });
  });

  // Toggle password eye
  document.querySelectorAll('.btn-toggle-pass').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const card = btn.closest('.vault-card');
      const textSpan = card.querySelector('.pass-text');
      const isRevealed = textSpan.getAttribute('data-revealed') === 'true';
      const actualPass = textSpan.getAttribute('data-pass');

      if (isRevealed) {
        textSpan.innerText = '••••••••••••';
        textSpan.setAttribute('data-revealed', 'false');
      } else {
        textSpan.innerText = actualPass;
        textSpan.setAttribute('data-revealed', 'true');
      }
    });
  });

  // Edit item
  document.querySelectorAll('.btn-edit-item').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.getAttribute('data-id');
      const item = state.vaultItems.find((i) => i.id === id);
      if (item) populateItemModal(item);
    });
  });

  // Delete item
  document.querySelectorAll('.btn-delete-item').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.getAttribute('data-id');
      deleteItem(id);
    });
  });

  // Copy TOTP
  document.querySelectorAll('.btn-copy-totp').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const container = btn.closest('.totp-container');
      const digits = container.querySelector('.totp-digits').innerText.replace(/\s+/g, '');
      if (digits && digits !== '------') {
        copyWithAutoClear(digits, '2FA Code');
      }
    });
  });
}

function populateItemModal(item = null) {
  document.getElementById('itemModalTitle').innerText = item ? 'MODIFY ENCRYPTED ENTITY' : 'STORE ENCRYPTED ENTITY';
  document.getElementById('itemId').value = item ? item.id : '';
  document.getElementById('itemTitle').value = item ? item.title : '';
  document.getElementById('itemCategory').value = item ? item.category : 'General';
  document.getElementById('itemFavorite').checked = item ? item.is_favorite : false;
  document.getElementById('itemUsername').value = item ? item.username : '';
  document.getElementById('itemPassword').value = item ? item.password : '';
  document.getElementById('itemUrl').value = item ? item.url : '';
  document.getElementById('itemTotpSecret').value = item ? item.totpSecret : '';
  document.getElementById('itemNotes').value = item ? item.notes : '';
  document.getElementById('itemTags').value = item && item.tags ? item.tags.join(', ') : '';

  openModal('itemModal');
}

function updateSidebarCounts() {
  const items = state.vaultItems;
  const setTxt = (id, txt) => {
    const el = document.getElementById(id);
    if (el) el.innerText = txt;
  };

  setTxt('countAll', items.length);
  setTxt('countFavorites', items.filter((i) => i.is_favorite).length);
  setTxt('countTotp', items.filter((i) => !!i.totpSecret).length);
  setTxt('countCatGeneral', items.filter((i) => i.category.toLowerCase() === 'general').length);
  setTxt('countCatFinance', items.filter((i) => i.category.toLowerCase() === 'finance').length);
  setTxt('countCatInfra', items.filter((i) => i.category.toLowerCase() === 'infrastructure').length);
  setTxt('countCatWork', items.filter((i) => i.category.toLowerCase() === 'work').length);
}

// Live TOTP Refresh Ticker
async function updateTotpCodes() {
  const containers = document.querySelectorAll('.totp-container');
  if (containers.length === 0) return;

  const circumference = 2 * Math.PI * 8; // ~50.26

  for (const container of containers) {
    const secret = container.getAttribute('data-secret');
    if (!secret) continue;

    const result = await generateTotp(secret);
    if (result) {
      const digitsEl = container.querySelector('.totp-digits');
      const secEl = container.querySelector('.totp-seconds');
      const progressEl = container.querySelector('.timer-progress');

      if (digitsEl) {
        digitsEl.innerText = `${result.token.slice(0, 3)} ${result.token.slice(3)}`;
      }
      if (secEl) {
        secEl.innerText = result.remainingSeconds;
      }
      if (progressEl) {
        const offset = circumference * (1 - result.percentage / 100);
        progressEl.style.strokeDashoffset = offset;
        if (result.remainingSeconds <= 5) {
          progressEl.style.stroke = 'var(--red-alert)';
        } else {
          progressEl.style.stroke = 'var(--cyan-core)';
        }
      }
    }
  }
}

setInterval(updateTotpCodes, 1000);

// =========================================================================
// PASSWORD GENERATOR CONTROLLER
// =========================================================================

function refreshPasswordGenerator() {
  const length = parseInt(document.getElementById('genLength').value, 10);
  const useUpper = document.getElementById('genUpper').checked;
  const useLower = document.getElementById('genLower').checked;
  const useNumbers = document.getElementById('genNumbers').checked;
  const useSymbols = document.getElementById('genSymbols').checked;
  const excludeAmbiguous = document.getElementById('genAvoidAmbiguous').checked;
  const isDiceware = document.getElementById('genDiceware').checked;

  document.getElementById('genLengthVal').innerText = length;

  let pwd = '';
  if (isDiceware) {
    const wordCount = Math.max(4, Math.round(length / 5));
    pwd = generatePassphrase(wordCount, '-', true);
  } else {
    pwd = generatePassword({ length, useUpper, useLower, useNumbers, useSymbols, excludeAmbiguous });
  }

  document.getElementById('genResult').value = pwd;

  const entropy = calculatePasswordEntropy(pwd);
  document.getElementById('genEntropyBits').innerText = `Entropy: ${entropy.bits} bits (${entropy.rating})`;
  document.getElementById('genCrackTime').innerText = `Crack Time: ${entropy.crackTime}`;
  document.getElementById('genCrackTime').style.color = entropy.color;

  const bar = document.getElementById('genEntropyBar');
  bar.style.width = `${Math.min(100, (entropy.bits / 100) * 100)}%`;
  bar.style.backgroundColor = entropy.color;
}

// =========================================================================
// SECURITY AUDIT SCANNER
// =========================================================================

function runSecurityAudit() {
  const items = state.vaultItems;
  let weakCount = 0;
  let reusedCount = 0;
  let no2faCount = 0;

  const passwordCounts = {};
  for (const item of items) {
    if (item.password) {
      passwordCounts[item.password] = (passwordCounts[item.password] || 0) + 1;
    }
  }

  const findingsList = document.getElementById('auditFindings');
  findingsList.innerHTML = '';

  for (const item of items) {
    const entropy = calculatePasswordEntropy(item.password);
    const isReused = item.password && passwordCounts[item.password] > 1;
    const isWeak = entropy.bits < 55;
    const has2fa = !!item.totpSecret;

    if (isWeak) weakCount++;
    if (isReused) reusedCount++;
    if (!has2fa) no2faCount++;

    if (isWeak || isReused || !has2fa) {
      const issueDiv = document.createElement('div');
      issueDiv.style.cssText = 'background: var(--bg-surface); padding: 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-dim); font-size: 12px; font-family: var(--font-mono);';
      issueDiv.innerHTML = `
        <div style="font-weight: 700; color: #fff; margin-bottom: 4px;">${escapeHtml(item.title)}</div>
        <div style="display: flex; flex-wrap: wrap; gap: 6px;">
          ${isWeak ? `<span style="color: var(--red-alert); background: var(--red-dim); padding: 2px 6px; border-radius: 4px;">Weak (${entropy.bits}b)</span>` : ''}
          ${isReused ? `<span style="color: var(--amber-warn); background: var(--amber-glow); padding: 2px 6px; border-radius: 4px;">Reused Password</span>` : ''}
          ${!has2fa ? `<span style="color: var(--cyan-core); background: var(--cyan-dim); padding: 2px 6px; border-radius: 4px;">No 2FA</span>` : ''}
        </div>
      `;
      findingsList.appendChild(issueDiv);
    }
  }

  document.getElementById('auditTotal').innerText = items.length;
  document.getElementById('auditWeak').innerText = weakCount;
  document.getElementById('auditReused').innerText = reusedCount;
  document.getElementById('auditNo2fa').innerText = no2faCount;

  openModal('auditModal');
}

// =========================================================================
// PASSKEYS / WEBAUTHN DEVICE MANAGER
// =========================================================================

async function loadPasskeysList() {
  if (!state.sessionToken) return;

  try {
    const res = await fetch('/api/webauthn/list', {
      headers: { Authorization: `Bearer ${state.sessionToken}` },
    });
    if (!res.ok) throw new Error('Failed to load passkeys');

    const passkeys = await res.json();
    const list = document.getElementById('passkeysList');
    list.innerHTML = '';

    if (passkeys.length === 0) {
      list.innerHTML = '<div style="font-size: 12px; color: var(--text-muted); font-family: var(--font-mono);">No passkeys registered on this account yet.</div>';
      return;
    }

    passkeys.forEach((pk) => {
      const item = document.createElement('div');
      item.style.cssText = 'display: flex; align-items: center; justify-content: space-between; background: var(--bg-surface); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-dim);';
      item.innerHTML = `
        <div>
          <div style="font-weight: 600; font-size: 13px; color: #fff;">${escapeHtml(pk.device_name || 'Passkey Device')}</div>
          <div style="font-size: 10px; color: var(--text-muted); font-family: var(--font-mono);">Created: ${new Date(pk.created_at).toLocaleDateString()}</div>
        </div>
        <button class="btn-icon btn-del-pk" data-id="${pk.id}" style="color: var(--red-alert); background: transparent; border: none; cursor: pointer;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
        </button>
      `;
      list.appendChild(item);
    });

    list.querySelectorAll('.btn-del-pk').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        if (confirm('Revoke this passkey credential?')) {
          await fetch(`/api/webauthn/${id}`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${state.sessionToken}` },
          });
          showToast('Passkey revoked.', 'info');
          loadPasskeysList();
        }
      });
    });
  } catch (err) {
    console.error('Passkeys load error:', err);
  }
}

// =========================================================================
// MOBILE QR CODE CONNECTION
// =========================================================================

async function showMobilePairModal() {
  try {
    const res = await fetch('/api/info');
    const info = await res.json();

    const mobileUrl = info.mobileUrl;
    document.getElementById('mobileUrlDisplay').innerText = mobileUrl;

    const qrContainer = document.getElementById('qrCodeContainer');
    qrContainer.innerHTML = generateQrSvg(mobileUrl, 5);

    openModal('mobilePairModal');
  } catch (err) {
    showToast('Failed to fetch mobile pairing info', 'error');
  }
}

// =========================================================================
// EVENT LISTENERS INITIALIZATION
// =========================================================================

document.addEventListener('DOMContentLoaded', () => {
  // Login Form
  document.getElementById('loginForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const u = document.getElementById('loginUsername').value.trim();
    const p = document.getElementById('loginPassword').value;
    if (u && p) handleLogin(u, p);
  });

  // Biometric Passkey Hero Login Button
  document.getElementById('btnPasskeyLogin').addEventListener('click', () => {
    const username = document.getElementById('loginUsername').value.trim() || null;
    handlePasskeyLogin(username);
  });

  // Open Registration Modal
  document.getElementById('btnShowRegister').addEventListener('click', () => {
    document.getElementById('recoveryPhraseBox').innerText = generateRecoveryPhrase();
    openModal('registerModal');
  });

  // Registration Form
  document.getElementById('registerForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const u = document.getElementById('regUsername').value.trim();
    const p = document.getElementById('regPassword').value;
    const pConfirm = document.getElementById('regPasswordConfirm').value;
    const duressPin = document.getElementById('regDuressPin').value.trim();

    if (p !== pConfirm) {
      showToast('Master passwords do not match', 'error');
      return;
    }
    if (p.length < 8) {
      showToast('Master password must be at least 8 characters', 'error');
      return;
    }

    handleRegister(u, p, duressPin);
  });

  // Lock Vault Button
  document.getElementById('btnLockVault').addEventListener('click', () => {
    lockVault('Vault securely locked and cryptographic keys wiped.');
  });

  // Open Item Modal
  document.getElementById('btnNewItem').addEventListener('click', () => populateItemModal());
  document.getElementById('btnEmptyNew').addEventListener('click', () => populateItemModal());
  document.getElementById('mobNavAdd').addEventListener('click', () => populateItemModal());

  // Save Item Form
  document.getElementById('itemForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const id = document.getElementById('itemId').value;
    const title = document.getElementById('itemTitle').value.trim();
    const category = document.getElementById('itemCategory').value;
    const is_favorite = document.getElementById('itemFavorite').checked;
    const username = document.getElementById('itemUsername').value.trim();
    const password = document.getElementById('itemPassword').value;
    const url = document.getElementById('itemUrl').value.trim();
    const totpSecret = document.getElementById('itemTotpSecret').value.trim();
    const notes = document.getElementById('itemNotes').value;
    const tagsRaw = document.getElementById('itemTags').value;
    const tags = tagsRaw ? tagsRaw.split(',').map((t) => t.trim()).filter(Boolean) : [];

    saveItem({ id, title, category, is_favorite, username, password, url, totpSecret, notes, tags });
  });

  // Quick Generate Button in Item Modal
  document.getElementById('btnQuickGenPass').addEventListener('click', () => {
    const pwd = generatePassword({ length: 22, useUpper: true, useLower: true, useNumbers: true, useSymbols: true });
    document.getElementById('itemPassword').value = pwd;
    showToast('Strong password generated', 'success');
  });

  // Search Input
  document.getElementById('searchInput').addEventListener('input', (e) => {
    state.searchQuery = e.target.value;
    renderVaultGrid();
  });

  // Filter Pills
  document.querySelectorAll('.pill').forEach((pill) => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.pill').forEach((p) => p.classList.remove('active'));
      pill.classList.add('active');
      state.activeFilter = pill.getAttribute('data-pill');
      renderVaultGrid();
    });
  });

  // Sidebar Filter Items
  document.querySelectorAll('.nav-item[data-filter], .nav-item[data-category]').forEach((item) => {
    item.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach((i) => i.classList.remove('active'));
      item.classList.add('active');

      const filter = item.getAttribute('data-filter');
      const category = item.getAttribute('data-category');
      state.activeFilter = filter || category;
      renderVaultGrid();
    });
  });

  // Password Generator Modal & Triggers
  document.getElementById('btnOpenGenerator').addEventListener('click', () => {
    refreshPasswordGenerator();
    openModal('genModal');
  });

  document.getElementById('mobNavGen').addEventListener('click', () => {
    refreshPasswordGenerator();
    openModal('genModal');
  });

  ['genLength', 'genUpper', 'genLower', 'genNumbers', 'genSymbols', 'genAvoidAmbiguous', 'genDiceware'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', refreshPasswordGenerator);
  });

  document.getElementById('btnRerollGen').addEventListener('click', refreshPasswordGenerator);
  document.getElementById('btnCopyGen').addEventListener('click', () => {
    const pwd = document.getElementById('genResult').value;
    copyWithAutoClear(pwd, 'Generated Password');
  });

  // Audit Triggers
  document.getElementById('btnAudit').addEventListener('click', runSecurityAudit);
  document.getElementById('mobNavAudit').addEventListener('click', runSecurityAudit);

  // Mobile Connect QR Trigger
  document.getElementById('btnMobileConnect').addEventListener('click', showMobilePairModal);

  // Passkey Devices Manager Modal
  const openPasskeys = () => {
    loadPasskeysList();
    openModal('passkeysModal');
  };
  document.getElementById('navPasskeysManager').addEventListener('click', openPasskeys);
  document.getElementById('mobNavDevices').addEventListener('click', openPasskeys);

  // Register New Passkey Button
  document.getElementById('btnRegisterNewPasskey').addEventListener('click', async () => {
    const name = document.getElementById('passkeyDeviceName').value.trim() || 'My Biometric Device';
    try {
      showToast('Engaging biometric passkey enrollment...', 'info');
      await registerPasskey(state.sessionToken, name);
      showToast('Passkey registered successfully!', 'success');
      document.getElementById('passkeyDeviceName').value = '';
      loadPasskeysList();
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Mobile Bottom Nav: Vault Tab
  document.getElementById('mobNavVault').addEventListener('click', () => {
    document.querySelectorAll('.mobile-nav-item').forEach((i) => i.classList.remove('active'));
    document.getElementById('mobNavVault').classList.add('active');
    state.activeFilter = 'all';
    renderVaultGrid();
  });

  // Encrypted Backup Export
  document.getElementById('navExportBackup').addEventListener('click', () => {
    if (state.vaultItems.length === 0) {
      showToast('No items to backup', 'info');
      return;
    }
    const backupJson = JSON.stringify({
      version: '1.0',
      exportedAt: new Date().toISOString(),
      items: state.vaultItems,
    }, null, 2);

    const blob = new Blob([backupJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `AegisVault_Backup_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Encrypted backup exported.', 'success');
  });
});
