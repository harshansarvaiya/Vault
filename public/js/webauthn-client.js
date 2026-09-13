// AegisVault Client-side WebAuthn / Passkeys Engine (FIDO2)
// Enables Passwordless Biometric Login with Face ID, Touch ID, Windows Hello & Hardware Keys

export function base64urlToBuffer(base64url) {
  if (!base64url) return new ArrayBuffer(0);
  if (base64url instanceof ArrayBuffer) return base64url;
  if (base64url instanceof Uint8Array) return base64url.buffer;

  let base64 = String(base64url).replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  try {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (e) {
    console.warn('base64urlToBuffer decode error:', e);
    return new ArrayBuffer(0);
  }
}

export function bufferToBase64url(buffer) {
  if (!buffer) return '';
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function isWebAuthnSupported() {
  return window.PublicKeyCredential !== undefined && typeof window.PublicKeyCredential === 'function';
}

export async function isPlatformAuthenticatorAvailable() {
  if (!isWebAuthnSupported()) return false;
  if (PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
    try {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      return false;
    }
  }
  return false;
}

// Enroll Device Biometrics (Face ID / Touch ID / Windows Hello)
export async function registerDeviceBiometrics(user, vekKey, sessionToken = null, deviceName = 'Personal Device') {
  if (!isWebAuthnSupported()) {
    throw new Error('Biometrics / WebAuthn is not supported in this browser or context.');
  }

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = new TextEncoder().encode(user.username);
  const hostname = window.location.hostname || 'localhost';

  // 1. Invoke native browser authenticator (Face ID / Touch ID)
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: {
        name: 'AegisVault',
        id: hostname,
      },
      user: {
        id: userId,
        name: user.username,
        displayName: user.username,
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256 (Apple Secure Enclave standard)
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'preferred',
      },
      timeout: 60000,
    },
  });

  if (!credential) {
    throw new Error('Authenticator creation was cancelled or returned no credentials');
  }

  // 2. Wrap Vault Encryption Key (VEK) for this device
  const rawVek = await crypto.subtle.exportKey('raw', vekKey);
  const deviceWrapKeyBytes = crypto.getRandomValues(new Uint8Array(32));
  const deviceKey = await crypto.subtle.importKey(
    'raw',
    deviceWrapKeyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedVekBytes = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    deviceKey,
    rawVek
  );

  // 3. Store biometric record in localStorage for instant local unlock
  const bioRecord = {
    username: user.username,
    credentialId: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    deviceWrapKey: bufferToBase64url(deviceWrapKeyBytes),
    encryptedVek: bufferToBase64url(encryptedVekBytes),
    iv: bufferToBase64url(iv),
    enrolledAt: new Date().toISOString(),
  };

  localStorage.setItem(`aegis_bio_${user.username.toLowerCase()}`, JSON.stringify(bioRecord));
  localStorage.setItem('aegis_active_bio_user', user.username.toLowerCase());

  // 4. Optionally sync with backend if running in server mode
  const isStaticHosting = window.location.hostname.endsWith('github.io') || window.location.protocol === 'file:';
  if (!isStaticHosting && sessionToken) {
    try {
      await fetch('./api/webauthn/register-verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({
          id: credential.id,
          rawId: bufferToBase64url(credential.rawId),
          type: credential.type,
          deviceName,
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          attestationObject: bufferToBase64url(credential.response.attestationObject),
          transports: credential.response.getTransports ? credential.response.getTransports() : [],
        }),
      });
    } catch {}
  }

  return { success: true };
}

// Authenticate via Device Biometrics (1-Touch Face ID / Touch ID Unlock)
export async function authenticateDeviceBiometrics(username) {
  if (!isWebAuthnSupported()) {
    throw new Error('Biometrics / WebAuthn is not supported in this browser or context.');
  }

  const bioDataStr = localStorage.getItem(`aegis_bio_${username.toLowerCase()}`);
  if (!bioDataStr) {
    throw new Error('Face ID not enrolled on this device. Please log in with your Master Password first, then tap "Register This Device\'s Biometrics" in Backup & Recovery.');
  }

  const bioData = JSON.parse(bioDataStr);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const hostname = window.location.hostname || 'localhost';

  // 1. Invoke native Face ID / Touch ID check
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: hostname,
      allowCredentials: [
        {
          id: base64urlToBuffer(bioData.rawId || bioData.credentialId),
          type: 'public-key',
        },
      ],
      userVerification: 'required',
      timeout: 60000,
    },
  });

  if (!assertion) {
    throw new Error('Biometric authentication cancelled');
  }

  // 2. Face ID passed! Decrypt the device-wrapped Vault Encryption Key (VEK)
  const deviceKey = await crypto.subtle.importKey(
    'raw',
    base64urlToBuffer(bioData.deviceWrapKey),
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const rawVek = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(base64urlToBuffer(bioData.iv)) },
    deviceKey,
    base64urlToBuffer(bioData.encryptedVek)
  );

  const vek = await crypto.subtle.importKey(
    'raw',
    rawVek,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  return {
    success: true,
    user: { id: bioData.username, username: bioData.username },
    sessionToken: `bio_session_${Date.now()}`,
    vek,
  };
}

// Backward compatibility aliases
export const registerPasskey = registerDeviceBiometrics;
export const authenticatePasskey = authenticateDeviceBiometrics;
