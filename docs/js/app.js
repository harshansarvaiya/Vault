import {
  deriveMasterKeys,
  generateVek,
  encryptVek,
  decryptVek,
  encryptPayload,
  decryptPayload,
  generateRecoveryPhrase,
  getRandomHex,
} from './crypto.js';

import { isWebAuthnSupported, registerPasskey, authenticatePasskey } from './webauthn-client.js';

// Application State
const isStaticHosting = window.location.hostname.endsWith('github.io') || window.location.protocol === 'file:';

// Local storage zero-knowledge client store for static hosting / offline PWA
const localStore = {
  getUser(username) {
    const data = localStorage.getItem(`aegis_user_${username.toLowerCase()}`);
    return data ? JSON.parse(data) : null;
  },
  saveUser(userData) {
    localStorage.setItem(`aegis_user_${userData.username.toLowerCase()}`, JSON.stringify(userData));
  },
  getItems(username) {
    const key = `aegis_vault_${username.toLowerCase()}`;
    const data = localStorage.getItem(key);
    return data ? JSON.parse(data) : [];
  },
  saveItems(username, items) {
    const key = `aegis_vault_${username.toLowerCase()}`;
    localStorage.setItem(key, JSON.stringify(items));
  },
};

const state = {
  currentUser: null,
  sessionToken: null,
  mek: null, // Master Encryption Key (AES-GCM CryptoKey)
  vek: null, // Vault Encryption Key (AES-GCM CryptoKey)
  vaultItems: [], // Decrypted credentials array
  searchQuery: '',
  inactivityTimeoutMinutes: 5,
  inactivityTimer: null,
  clipboardTimer: null,
};

// Register PWA Service Worker
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  });
}

// =========================================================================
// UI HELPERS & NOTIFICATIONS
// =========================================================================

export function showToast(message, type = 'info', duration = 3000) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerText = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 250);
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
    lockVault('Vault auto-locked due to inactivity.');
  }, state.inactivityTimeoutMinutes * 60 * 1000);
}

['mousemove', 'keydown', 'touchstart', 'scroll', 'click'].forEach((evt) => {
  window.addEventListener(evt, resetInactivityTimer, { passive: true });
});

// Tab blur privacy shield
const privacyShield = document.getElementById('privacyShield');
window.addEventListener('blur', () => {
  if (state.sessionToken && privacyShield) privacyShield.classList.add('active');
});

window.addEventListener('focus', () => {
  if (privacyShield) privacyShield.classList.remove('active');
});

if (privacyShield) {
  privacyShield.addEventListener('click', () => privacyShield.classList.remove('active'));
}

// Clipboard auto-wipe after 30 seconds
function copyWithAutoClear(text, label = 'Secret') {
  navigator.clipboard.writeText(text).then(() => {
    showToast(`${label} copied. Clipboard wipes in 30s.`, 'info');

    if (state.clipboardTimer) clearTimeout(state.clipboardTimer);

    state.clipboardTimer = setTimeout(async () => {
      try {
        await navigator.clipboard.writeText('');
        showToast('Clipboard sanitized.', 'success');
      } catch {}
    }, 30000);
  }).catch(() => {
    showToast('Failed to copy to clipboard', 'error');
  });
}

// Single-click strong password generator (24 characters, high entropy)
function generateStrongPassword(length = 24) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
  const randomValues = new Uint32Array(length);
  crypto.getRandomValues(randomValues);

  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i] % chars.length];
  }
  return result;
}

// =========================================================================
// AUTHENTICATION (Master Password & Biometric Passkeys)
// =========================================================================

async function handleLogin(username, password) {
  try {
    showToast('Deriving keys (600,000 PBKDF2 rounds)...', 'info', 2000);

    // 1. Fetch salts
    let salts = null;
    try {
      if (!isStaticHosting) {
        const preRes = await fetch(`./api/auth/pre-login?username=${encodeURIComponent(username)}`);
        if (preRes.ok) salts = await preRes.json();
      }
    } catch {}

    if (!salts) {
      const localUser = localStore.getUser(username);
      if (localUser) {
        salts = {
          kdfSalt: localUser.kdfSalt,
          kdfIterations: localUser.kdfIterations,
          authSalt: localUser.authSalt,
        };
      } else {
        throw new Error('Identifier not found. Please create a new vault.');
      }
    }

    // 2. Derive Master Keys
    const { mek, authHash } = await deriveMasterKeys(password, salts.kdfSalt, salts.kdfIterations);

    // 3. Authenticate
    let authData = null;
    try {
      if (!isStaticHosting) {
        const authRes = await fetch('./api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, authHash }),
        });
        if (authRes.ok) authData = await authRes.json();
      }
    } catch {}

    if (!authData) {
      const localUser = localStore.getUser(username);
      if (!localUser || localUser.authHash !== authHash) {
        throw new Error('Invalid credentials');
      }
      authData = {
        user: { id: localUser.username, username: localUser.username },
        sessionToken: `session_${Date.now()}`,
        encryptedVek: localUser.encryptedVek,
      };
    }

    state.currentUser = authData.user;
    state.sessionToken = authData.sessionToken;
    state.mek = mek;

    // Cache user credentials and salts in localStore for offline & backup usage
    localStore.saveUser({
      username: authData.user.username,
      authSalt: salts ? salts.authSalt : null,
      authHash: authHash,
      kdfSalt: salts ? salts.kdfSalt : null,
      kdfIterations: salts ? (salts.kdfIterations || 600000) : 600000,
      encryptedVek: authData.encryptedVek,
    });

    // 4. Decrypt VEK
    state.vek = await decryptVek(authData.encryptedVek, mek);

    // 5. Unlock UI
    await loadVaultItems();
    showUnlockedView();
    showToast('Vault decrypted successfully.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function handlePasskeyLogin() {
  try {
    const enteredUsername = document.getElementById('loginUsername').value.trim();
    const username = enteredUsername || localStorage.getItem('aegis_active_bio_user');

    if (!username) {
      showToast('Enter your Account Identifier first, or register biometrics after logging in.', 'info', 4000);
      return;
    }

    const bioDataStr = localStorage.getItem(`aegis_bio_${username.toLowerCase()}`);
    if (!bioDataStr) {
      showToast('Face ID not enrolled on this device yet. Log in with your Master Password first, then tap "Register This Device\'s Biometrics" in Backup settings.', 'info', 6000);
      return;
    }

    showToast('Engaging Face ID / Biometric sensor...', 'info', 2000);
    const result = await authenticatePasskey(username);
    if (!result || !result.success) throw new Error('Biometric verification failed');

    state.currentUser = result.user;
    state.sessionToken = result.sessionToken;
    state.vek = result.vek;

    await loadVaultItems();
    showUnlockedView();
    showToast('Vault unlocked with Face ID!', 'success');
  } catch (err) {
    if (err.name === 'NotAllowedError' || err.message?.includes('cancelled')) {
      showToast('Biometric scan cancelled.', 'info');
    } else {
      showToast(err.message || 'Biometric authentication failed', 'error');
    }
  }
}

async function handleRegister(username, password) {
  try {
    showToast('Generating military-grade encryption keys...', 'info', 2000);

    const kdfSalt = getRandomHex(16);
    const authSalt = getRandomHex(16);
    const kdfIterations = 600000;

    const { mek, authHash } = await deriveMasterKeys(password, kdfSalt, kdfIterations);
    const { key: vekKey } = await generateVek();
    const encryptedVek = await encryptVek(vekKey, mek);

    let regData = null;
    try {
      if (!isStaticHosting) {
        const regRes = await fetch('./api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username,
            authSalt,
            authHash,
            kdfSalt,
            kdfIterations,
            encryptedVek,
          }),
        });
        if (regRes.ok) regData = await regRes.json();
      }
    } catch {}

    localStore.saveUser({
      username,
      authSalt,
      authHash,
      kdfSalt,
      kdfIterations,
      encryptedVek,
    });

    if (!regData) {
      regData = {
        user: { id: username, username },
        sessionToken: `session_${Date.now()}`,
      };
    }

    state.currentUser = regData.user;
    state.sessionToken = regData.sessionToken;
    state.mek = mek;
    state.vek = vekKey;

    closeModal('registerModal');
    await loadVaultItems();
    showUnlockedView();
    showToast('Vault created & encrypted.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function lockVault(reason = 'Vault locked.') {
  state.currentUser = null;
  state.sessionToken = null;
  state.mek = null;
  state.vek = null;
  state.vaultItems = [];

  if (state.inactivityTimer) clearTimeout(state.inactivityTimer);

  document.getElementById('authSection').style.display = 'flex';
  document.getElementById('vaultSection').style.display = 'none';
  document.getElementById('unlockedHeaderActions').style.display = 'none';

  showToast(reason, 'info');
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
    let encryptedItems = null;
    try {
      if (!isStaticHosting) {
        const res = await fetch('./api/vault', {
          headers: { Authorization: `Bearer ${state.sessionToken}` },
        });
        if (res.ok) encryptedItems = await res.json();
      }
    } catch {}

    if (!encryptedItems) {
      encryptedItems = localStore.getItems(state.currentUser.username);
    } else if (Array.isArray(encryptedItems)) {
      localStore.saveItems(state.currentUser.username, encryptedItems);
    }

    const decryptedItems = [];
    for (const item of encryptedItems) {
      try {
        const payload = await decryptPayload(item.encrypted_payload, state.vek);
        decryptedItems.push({
          id: item.id,
          title: payload.title || 'Untitled',
          username: payload.username || '',
          password: payload.password || '',
          url: payload.url || '',
          notes: payload.notes || '',
          created_at: item.created_at,
          updated_at: item.updated_at,
        });
      } catch (e) {
        console.warn('Decryption error on item:', item.id);
      }
    }

    state.vaultItems = decryptedItems;
    renderVaultGrid();
  } catch (err) {
    showToast('Failed to load vault items', 'error');
  }
}

async function saveItem(itemData) {
  if (!state.sessionToken || !state.vek) return;

  try {
    const payload = {
      title: itemData.title,
      username: itemData.username,
      password: itemData.password,
      url: itemData.url,
      notes: itemData.notes,
    };

    const encryptedTitle = await encryptPayload({ title: itemData.title }, state.vek);
    const encryptedPayload = await encryptPayload(payload, state.vek);

    const isEdit = !!itemData.id;
    const itemId = itemData.id || `item_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date().toISOString();

    try {
      if (!isStaticHosting) {
        const endpoint = isEdit ? `./api/vault/${itemData.id}` : './api/vault';
        const method = isEdit ? 'PUT' : 'POST';
        await fetch(endpoint, {
          method,
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${state.sessionToken}`,
          },
          body: JSON.stringify({
            encryptedTitle,
            category: 'General',
            encryptedPayload,
            isFavorite: false,
          }),
        });
      }
    } catch {}

    // Always update localStore
    const localItems = localStore.getItems(state.currentUser.username);
    const existingIdx = localItems.findIndex((i) => i.id === itemId);
    const itemRecord = {
      id: itemId,
      encrypted_title: encryptedTitle,
      category: 'General',
      encrypted_payload: encryptedPayload,
      is_favorite: 0,
      created_at: isEdit && existingIdx >= 0 ? localItems[existingIdx].created_at : now,
      updated_at: now,
    };

    if (existingIdx >= 0) {
      localItems[existingIdx] = itemRecord;
    } else {
      localItems.unshift(itemRecord);
    }
    localStore.saveItems(state.currentUser.username, localItems);

    closeModal('itemModal');
    showToast(isEdit ? 'Password updated.' : 'Password securely stored.', 'success');
    await loadVaultItems();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function deleteItem(id) {
  if (!confirm('Permanently delete this password?')) return;

  try {
    try {
      if (!isStaticHosting) {
        await fetch(`./api/vault/${id}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${state.sessionToken}` },
        });
      }
    } catch {}

    const localItems = localStore.getItems(state.currentUser.username).filter((i) => i.id !== id);
    localStore.saveItems(state.currentUser.username, localItems);

    showToast('Password deleted.', 'success');
    await loadVaultItems();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// =========================================================================
// UI RENDERING
// =========================================================================

function renderVaultGrid() {
  const grid = document.getElementById('vaultGrid');
  const emptyState = document.getElementById('emptyVault');
  const countEl = document.getElementById('vaultItemCount');
  if (!grid) return;

  let items = state.vaultItems;

  if (state.searchQuery.trim()) {
    const q = state.searchQuery.toLowerCase();
    items = items.filter((i) =>
      i.title.toLowerCase().includes(q) ||
      i.username.toLowerCase().includes(q) ||
      i.url.toLowerCase().includes(q) ||
      i.notes.toLowerCase().includes(q)
    );
  }

  if (countEl) countEl.innerText = `${items.length} ${items.length === 1 ? 'account' : 'accounts'}`;

  if (items.length === 0) {
    grid.innerHTML = '';
    emptyState.style.display = 'flex';
    return;
  }

  emptyState.style.display = 'none';

  grid.innerHTML = items
    .map((item) => {
      const initial = (item.title || 'U').charAt(0).toUpperCase();

      return `
        <div class="vault-card" data-id="${item.id}">
          <div class="card-top">
            <div class="card-title-wrap">
              <div class="card-avatar">${initial}</div>
              <div class="card-title">${escapeHtml(item.title)}</div>
            </div>
            <div class="card-actions">
              <button class="icon-action-btn btn-edit-item" data-id="${item.id}" title="Edit Account">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>
              </button>
              <button class="icon-action-btn btn-delete-item" data-id="${item.id}" title="Delete Account">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--red-alert)" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
              </button>
            </div>
          </div>

          <!-- Username Row -->
          <div class="card-row">
            <div class="row-label">Username / ID</div>
            <div class="row-content">
              <span class="row-val">${escapeHtml(item.username)}</span>
              <button class="icon-action-btn btn-copy" data-copy="${escapeHtml(item.username)}" data-label="Username" title="Copy Username">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              </button>
            </div>
          </div>

          <!-- Password Row -->
          <div class="card-row">
            <div class="row-label">Password</div>
            <div class="row-content">
              <span class="row-val pass-text" data-revealed="false" data-pass="${escapeHtml(item.password)}">••••••••••••</span>
              <div class="row-btns">
                <button class="icon-action-btn btn-toggle-pass" title="Reveal Password">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                </button>
                <button class="icon-action-btn btn-copy" data-copy="${escapeHtml(item.password)}" data-label="Password" title="Copy Password (Auto-clear 30s)">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                </button>
              </div>
            </div>
          </div>

          ${item.notes ? `<div class="card-notes">${escapeHtml(item.notes)}</div>` : ''}

          ${item.url ? `
            <div style="display: flex; justify-content: flex-end; margin-top: 2px;">
              <a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer" style="color: var(--cyan-core); font-size: 11px; font-family: var(--font-mono); text-decoration: none; display: flex; align-items: center; gap: 4px;">
                <span>Visit site &rarr;</span>
              </a>
            </div>
          ` : ''}
        </div>
      `;
    })
    .join('');

  attachCardEvents();
}

function attachCardEvents() {
  document.querySelectorAll('.btn-copy').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      copyWithAutoClear(btn.getAttribute('data-copy'), btn.getAttribute('data-label'));
    });
  });

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

  document.querySelectorAll('.btn-edit-item').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.getAttribute('data-id');
      const item = state.vaultItems.find((i) => i.id === id);
      if (item) populateItemModal(item);
    });
  });

  document.querySelectorAll('.btn-delete-item').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      deleteItem(btn.getAttribute('data-id'));
    });
  });
}

function populateItemModal(item = null) {
  document.getElementById('itemModalTitle').innerText = item ? 'EDIT CREDENTIAL' : 'ADD NEW PASSWORD';
  document.getElementById('itemId').value = item ? item.id : '';
  document.getElementById('itemTitle').value = item ? item.title : '';
  document.getElementById('itemUsername').value = item ? item.username : '';
  document.getElementById('itemPassword').value = item ? item.password : '';
  document.getElementById('itemUrl').value = item ? item.url : '';
  document.getElementById('itemNotes').value = item ? item.notes : '';

  openModal('itemModal');
}

// =========================================================================
// BACKUP, EXPORT & THEFT RECOVERY
// =========================================================================

function buildBackupPackage() {
  if (!state.currentUser) return null;
  const encryptedItems = localStore.getItems(state.currentUser.username);
  const user = localStore.getUser(state.currentUser.username);

  return {
    format: 'aegis-encrypted-vault',
    version: '1.0',
    username: state.currentUser.username,
    kdfSalt: user ? user.kdfSalt : null,
    kdfIterations: user ? (user.kdfIterations || 600000) : 600000,
    authSalt: user ? user.authSalt : null,
    authHash: user ? user.authHash : null,
    encryptedVek: user ? user.encryptedVek : null,
    items: encryptedItems || [],
    exportedAt: new Date().toISOString(),
  };
}

function exportEncryptedBackup() {
  const backupPackage = buildBackupPackage();
  if (!backupPackage) {
    showToast('Vault must be unlocked to export', 'error');
    return;
  }

  const blob = new Blob([JSON.stringify(backupPackage, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `AegisVault_Backup_${state.currentUser.username}_${Date.now()}.vault`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('Encrypted backup downloaded.', 'success');
}

async function emailEncryptedBackup() {
  const backupPackage = buildBackupPackage();
  if (!backupPackage) {
    showToast('Vault must be unlocked to email backup', 'error');
    return;
  }

  const filename = `AegisVault_Backup_${state.currentUser.username}_${Date.now()}.vault`;
  const jsonStr = JSON.stringify(backupPackage, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const file = new File([blob], filename, { type: 'application/json' });

  // 1. Mobile & Web Share API support: share directly via Mail / Gmail app
  if (navigator.canShare && navigator.canShare({ files: [file] })) {
    try {
      await navigator.share({
        title: `Vault Encrypted Backup - ${state.currentUser.username}`,
        text: `Encrypted Aegis Vault Backup (${filename}). Protected with zero-knowledge AES-256-GCM. Decrypt using your Master Password.`,
        files: [file],
      });
      showToast('Backup shared successfully!', 'success');
      return;
    } catch (err) {
      if (err.name === 'AbortError') return; // User closed share dialog
      console.warn('Native file share failed, falling back to download + mailto:', err);
    }
  }

  // 2. Desktop fallback: Trigger direct file download and open mailto draft
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);

  const subject = encodeURIComponent(`Aegis Vault Encrypted Backup - ${state.currentUser.username}`);
  const body = encodeURIComponent(
    `Hello,\n\nYour encrypted Aegis Vault backup file ("${filename}") has been saved to your downloads.\n\nPlease attach that .vault file to this email to safely keep a copy in your inbox for disaster recovery.\n\nSECURITY NOTE:\nThis file is encrypted with zero-knowledge military-grade AES-256-GCM. No one (not even email providers or attackers) can open it without your Master Password.\n\nTo restore on any phone or computer, open Aegis Vault and use the Emergency .vault Decryptor.`
  );

  window.location.href = `mailto:?subject=${subject}&body=${body}`;
  showToast('Backup file downloaded & email draft opened.', 'success', 5000);
}

function importBackupFile(file) {
  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const data = JSON.parse(e.target.result);
      if (data.format !== 'aegis-encrypted-vault' || !data.username) {
        throw new Error('Invalid vault backup format');
      }

      // Save user and items to localStore
      localStore.saveUser({
        username: data.username,
        authSalt: data.authSalt,
        authHash: data.authHash,
        kdfSalt: data.kdfSalt,
        kdfIterations: data.kdfIterations || 600000,
        encryptedVek: data.encryptedVek,
      });

      if (data.items && Array.isArray(data.items)) {
        localStore.saveItems(data.username, data.items);
      }

      showToast(`Restored backup for ${data.username}! You can now login.`, 'success', 4000);
      closeModal('backupModal');
      document.getElementById('loginUsername').value = data.username;
    } catch (err) {
      showToast('Import failed: ' + err.message, 'error');
    }
  };
  reader.readAsText(file);
}

// =========================================================================
// EMERGENCY .VAULT DECRYPTOR (Disaster & Theft Recovery)
// =========================================================================

let emergencyState = {
  data: null,
  decryptedItems: [],
  mek: null,
  vek: null,
  searchQuery: '',
};

function openEmergencyDecryptModal() {
  emergencyState = {
    data: null,
    decryptedItems: [],
    mek: null,
    vek: null,
    searchQuery: '',
  };

  const fileInput = document.getElementById('emergencyVaultFileInput');
  if (fileInput) fileInput.value = '';
  const passInput = document.getElementById('emergencyMasterPassword');
  if (passInput) passInput.value = '';
  const searchInput = document.getElementById('emergencySearchInput');
  if (searchInput) searchInput.value = '';

  const inputSec = document.getElementById('emergencyInputSection');
  const outputSec = document.getElementById('emergencyOutputSection');
  if (inputSec) inputSec.style.display = 'flex';
  if (outputSec) outputSec.style.display = 'none';

  openModal('emergencyDecryptModal');
}

async function runEmergencyDecrypt() {
  const fileInput = document.getElementById('emergencyVaultFileInput');
  const passInput = document.getElementById('emergencyMasterPassword');

  if (!fileInput.files || !fileInput.files[0]) {
    showToast('Please select your .vault backup file first', 'error');
    return;
  }

  const password = passInput.value;
  if (!password) {
    showToast('Please enter your Master Password', 'error');
    return;
  }

  const file = fileInput.files[0];

  try {
    showToast('Deriving keys & verifying Master Password (600,000 rounds)...', 'info', 2500);

    const fileText = await file.text();
    let data;
    try {
      data = JSON.parse(fileText);
    } catch {
      throw new Error('Corrupted file: Not valid JSON');
    }

    if (data.format !== 'aegis-encrypted-vault' || !data.encryptedVek || !data.kdfSalt) {
      throw new Error('Unrecognized backup format. Expected Aegis .vault file.');
    }

    // Derive Master Keys using the salt & iterations embedded in the backup
    const { mek, authHash } = await deriveMasterKeys(
      password,
      data.kdfSalt,
      data.kdfIterations || 600000
    );

    // If backup recorded authHash, verify it
    if (data.authHash && data.authHash !== authHash) {
      throw new Error('Incorrect Master Password. Verification failed.');
    }

    // Decrypt Vault Encryption Key (VEK) - AES-GCM tag verification
    let vek;
    try {
      vek = await decryptVek(data.encryptedVek, mek);
    } catch {
      throw new Error('Incorrect Master Password or authentication tag failed.');
    }

    // Decrypt all items
    const decryptedItems = [];
    const itemsToDecrypt = data.items || [];
    for (const item of itemsToDecrypt) {
      try {
        const payload = await decryptPayload(item.encrypted_payload, vek);
        decryptedItems.push({
          id: item.id || `item_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
          title: payload.title || 'Untitled',
          username: payload.username || '',
          password: payload.password || '',
          url: payload.url || '',
          notes: payload.notes || '',
          created_at: item.created_at,
          updated_at: item.updated_at,
        });
      } catch (e) {
        console.warn('Decryption failed on item:', item.id, e);
      }
    }

    emergencyState.data = data;
    emergencyState.decryptedItems = decryptedItems;
    emergencyState.mek = mek;
    emergencyState.vek = vek;
    emergencyState.searchQuery = '';

    // Switch view to results
    document.getElementById('emergencyInputSection').style.display = 'none';
    const outputSec = document.getElementById('emergencyOutputSection');
    outputSec.style.display = 'flex';

    document.getElementById('emergencyDecryptedTitle').innerText =
      `✓ Decrypted ${decryptedItems.length} accounts for [${data.username || 'user'}]`;

    renderEmergencyItems();
    showToast(`Emergency decryption successful! (${decryptedItems.length} accounts found)`, 'success', 4000);
  } catch (err) {
    showToast(err.message, 'error', 4000);
  }
}

function renderEmergencyItems() {
  const listEl = document.getElementById('emergencyResultsList');
  if (!listEl) return;

  let items = emergencyState.decryptedItems;
  const q = emergencyState.searchQuery.trim().toLowerCase();
  if (q) {
    items = items.filter(
      (i) =>
        i.title.toLowerCase().includes(q) ||
        i.username.toLowerCase().includes(q) ||
        i.url.toLowerCase().includes(q) ||
        i.notes.toLowerCase().includes(q)
    );
  }

  if (items.length === 0) {
    listEl.innerHTML = `
      <div style="text-align: center; padding: 24px; color: var(--text-muted); font-size: 13px; font-family: var(--font-mono);">
        ${q ? 'No accounts matched your search.' : 'This vault contains no accounts.'}
      </div>
    `;
    return;
  }

  listEl.innerHTML = items
    .map((item) => {
      const initial = (item.title || 'U').charAt(0).toUpperCase();

      return `
        <div class="emergency-card" style="background: var(--bg-surface); border: 1px solid var(--border-bright); border-radius: var(--radius-sm); padding: 12px; display: flex; flex-direction: column; gap: 8px;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div style="font-weight: 700; font-size: 14px; color: #fff; display: flex; align-items: center; gap: 8px;">
              <span style="display: inline-block; width: 26px; height: 26px; line-height: 26px; text-align: center; background: var(--bg-primary); border-radius: 4px; font-family: var(--font-mono); font-size: 12px; color: var(--cyan-core); border: 1px solid var(--border-dim);">${initial}</span>
              <span>${escapeHtml(item.title)}</span>
            </div>
            ${item.url ? `
              <a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer" style="font-size: 11px; color: var(--cyan-core); text-decoration: none; font-family: var(--font-mono); display: flex; align-items: center; gap: 3px;">
                <span>Visit &rarr;</span>
              </a>
            ` : ''}
          </div>

          <div style="display: flex; justify-content: space-between; align-items: center; background: var(--bg-primary); border: 1px solid var(--border-dim); border-radius: 4px; padding: 6px 10px; font-family: var(--font-mono); font-size: 12px;">
            <span style="color: var(--text-muted); font-size: 10px; text-transform: uppercase;">User / ID</span>
            <span style="color: #fff; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 200px;">${escapeHtml(item.username)}</span>
            <button class="icon-action-btn btn-emg-copy" data-copy="${escapeHtml(item.username)}" data-label="Username" title="Copy Username">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
            </button>
          </div>

          <div style="display: flex; justify-content: space-between; align-items: center; background: var(--bg-primary); border: 1px solid var(--border-dim); border-radius: 4px; padding: 6px 10px; font-family: var(--font-mono); font-size: 12px;">
            <span style="color: var(--text-muted); font-size: 10px; text-transform: uppercase;">Password</span>
            <span class="emg-pass-text" data-revealed="false" data-pass="${escapeHtml(item.password)}" style="color: var(--cyan-core); font-family: var(--font-mono);">••••••••••••</span>
            <div style="display: flex; gap: 4px;">
              <button class="icon-action-btn btn-emg-toggle-pass" title="Reveal Password">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
              </button>
              <button class="icon-action-btn btn-emg-copy" data-copy="${escapeHtml(item.password)}" data-label="Password" title="Copy Password (Auto-clear 30s)">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              </button>
            </div>
          </div>

          ${item.notes ? `
            <div style="font-size: 11px; color: var(--text-secondary); background: var(--bg-primary); border-radius: 4px; padding: 6px 8px; border-left: 2px solid var(--border-bright); font-family: var(--font-mono); white-space: pre-wrap;">${escapeHtml(item.notes)}</div>
          ` : ''}
        </div>
      `;
    })
    .join('');

  listEl.querySelectorAll('.btn-emg-copy').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      copyWithAutoClear(btn.getAttribute('data-copy'), btn.getAttribute('data-label'));
    });
  });

  listEl.querySelectorAll('.btn-emg-toggle-pass').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const card = btn.closest('.emergency-card');
      const textSpan = card.querySelector('.emg-pass-text');
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
}

function restoreEmergencyToDevice() {
  if (!emergencyState.data || !emergencyState.data.username) {
    showToast('No decrypted vault to restore', 'error');
    return;
  }

  const d = emergencyState.data;

  // Persist to localStore
  localStore.saveUser({
    username: d.username,
    authSalt: d.authSalt,
    authHash: d.authHash,
    kdfSalt: d.kdfSalt,
    kdfIterations: d.kdfIterations || 600000,
    encryptedVek: d.encryptedVek,
  });

  if (d.items && Array.isArray(d.items)) {
    localStore.saveItems(d.username, d.items);
  }

  // Activate session and load state
  state.currentUser = { id: d.username, username: d.username };
  state.sessionToken = `session_${Date.now()}`;
  state.mek = emergencyState.mek;
  state.vek = emergencyState.vek;
  state.vaultItems = emergencyState.decryptedItems;

  closeModal('emergencyDecryptModal');
  renderVaultGrid();
  showUnlockedView();
  showToast(`Vault successfully restored & unlocked for ${d.username}!`, 'success', 4000);
}

// =========================================================================
// INITIALIZATION
// =========================================================================

document.addEventListener('DOMContentLoaded', () => {
  // Login Form
  document.getElementById('loginForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const u = document.getElementById('loginUsername').value.trim();
    const p = document.getElementById('loginPassword').value;
    if (u && p) handleLogin(u, p);
  });

  // Passkey Login
  document.getElementById('btnPasskeyLogin').addEventListener('click', () => {
    handlePasskeyLogin();
  });

  // Show Registration
  document.getElementById('btnShowRegister').addEventListener('click', () => {
    document.getElementById('recoveryPhraseBox').innerText = generateRecoveryPhrase();
    openModal('registerModal');
  });

  // Register Form
  document.getElementById('registerForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const u = document.getElementById('regUsername').value.trim();
    const p = document.getElementById('regPassword').value;
    const pConfirm = document.getElementById('regPasswordConfirm').value;

    if (p !== pConfirm) {
      showToast('Master passwords do not match', 'error');
      return;
    }
    if (p.length < 8) {
      showToast('Master password must be at least 8 characters', 'error');
      return;
    }

    handleRegister(u, p);
  });

  // Lock Vault
  document.getElementById('btnLockVault').addEventListener('click', () => {
    lockVault('Vault locked.');
  });

  // Add Item Buttons
  document.getElementById('btnNewItem').addEventListener('click', () => populateItemModal());
  document.getElementById('btnEmptyNew').addEventListener('click', () => populateItemModal());

  // Save Item Form
  document.getElementById('itemForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const id = document.getElementById('itemId').value;
    const title = document.getElementById('itemTitle').value.trim();
    const username = document.getElementById('itemUsername').value.trim();
    const password = document.getElementById('itemPassword').value;
    const url = document.getElementById('itemUrl').value.trim();
    const notes = document.getElementById('itemNotes').value;

    saveItem({ id, title, username, password, url, notes });
  });

  // 1-Click Generate Password button inside Add Item form
  document.getElementById('btnQuickGenPass').addEventListener('click', () => {
    const pwd = generateStrongPassword(24);
    document.getElementById('itemPassword').value = pwd;
    showToast('Strong 24-character password generated', 'success');
  });

  // Search input
  document.getElementById('searchInput').addEventListener('input', (e) => {
    state.searchQuery = e.target.value;
    renderVaultGrid();
  });

  // Backup & Recovery Modal
  document.getElementById('btnBackup').addEventListener('click', () => openModal('backupModal'));

  // Export Encrypted Backup
  document.getElementById('btnExportFile').addEventListener('click', exportEncryptedBackup);

  // Email Encrypted Backup
  document.getElementById('btnEmailBackup').addEventListener('click', emailEncryptedBackup);

  // Emergency Decrypt Trigger from Login Screen
  document.getElementById('btnOpenEmergencyDecrypt').addEventListener('click', openEmergencyDecryptModal);

  // Emergency Decrypt Action
  document.getElementById('btnRunEmergencyDecrypt').addEventListener('click', runEmergencyDecrypt);

  // Emergency Filter Search
  document.getElementById('emergencySearchInput').addEventListener('input', (e) => {
    emergencyState.searchQuery = e.target.value;
    renderEmergencyItems();
  });

  // Emergency Restore to Device
  document.getElementById('btnRestoreToDevice').addEventListener('click', restoreEmergencyToDevice);

  // Import Backup Trigger
  const importInput = document.getElementById('importFileInput');
  document.getElementById('btnTriggerImport').addEventListener('click', () => importInput.click());
  importInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      importBackupFile(e.target.files[0]);
    }
  });

  // Register Passkey
  document.getElementById('btnRegisterPasskey').addEventListener('click', async () => {
    try {
      if (!state.currentUser || !state.vek) {
        showToast('Please open and unlock your vault first to enroll Face ID', 'error');
        return;
      }
      showToast('Enrolling device biometrics (Face ID / Touch ID)...', 'info');
      await registerPasskey(state.currentUser, state.vek, state.sessionToken);
      showToast('Face ID / Biometrics successfully enrolled on this device!', 'success', 4000);
    } catch (err) {
      if (err.name === 'NotAllowedError' || err.message?.includes('cancelled')) {
        showToast('Biometric enrollment cancelled.', 'info');
      } else {
        showToast(err.message || 'Failed to register biometrics', 'error');
      }
    }
  });
});
