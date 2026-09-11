// AegisVault Client-side WebAuthn / Passkeys Engine (FIDO2)
// Enables Passwordless Biometric Login with Face ID, Touch ID, Windows Hello & Hardware Keys

function base64urlToBuffer(base64url) {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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

// Register a new Passkey / Biometric Authenticator
export async function registerPasskey(sessionToken, deviceName = 'Biometric Authenticator') {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn / Passkeys are not supported in this browser or context.');
  }

  // 1. Fetch registration options from server
  const optRes = await fetch('/api/webauthn/register-options', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${sessionToken}`,
    },
  });

  if (!optRes.ok) {
    const err = await optRes.json();
    throw new Error(err.error || 'Failed to initialize passkey registration');
  }

  const options = await optRes.json();

  // 2. Decode binary fields for WebAuthn API
  options.challenge = base64urlToBuffer(options.challenge);
  options.user.id = base64urlToBuffer(options.user.id);
  if (options.excludeCredentials) {
    options.excludeCredentials = options.excludeCredentials.map((c) => ({
      ...c,
      id: base64urlToBuffer(c.id),
    }));
  }

  // 3. Invoke native browser authenticator (Face ID, Touch ID, Windows Hello, Security Key)
  const credential = await navigator.credentials.create({
    publicKey: options,
  });

  if (!credential) {
    throw new Error('Authenticator creation was cancelled or returned no credentials');
  }

  // 4. Encode response to base64url for verification
  const responseData = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    deviceName,
    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
    attestationObject: bufferToBase64url(credential.response.attestationObject),
    transports: credential.response.getTransports ? credential.response.getTransports() : [],
  };

  // 5. Send to server for cryptographic validation & storage
  const verifyRes = await fetch('/api/webauthn/register-verify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${sessionToken}`,
    },
    body: JSON.stringify(responseData),
  });

  if (!verifyRes.ok) {
    const err = await verifyRes.json();
    throw new Error(err.error || 'Failed to verify passkey on server');
  }

  return await verifyRes.json();
}

// Authenticate via Passkey (Passwordless Biometric Login)
export async function authenticatePasskey(username = null) {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn / Passkeys are not supported in this browser or context.');
  }

  // 1. Fetch challenge and options
  const optRes = await fetch('/api/webauthn/auth-options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
  });

  if (!optRes.ok) {
    const err = await optRes.json();
    throw new Error(err.error || 'Failed to get authentication options');
  }

  const options = await optRes.json();
  options.challenge = base64urlToBuffer(options.challenge);

  if (options.allowCredentials) {
    options.allowCredentials = options.allowCredentials.map((c) => ({
      ...c,
      id: base64urlToBuffer(c.id),
    }));
  }

  // 2. Invoke browser authenticator
  const assertion = await navigator.credentials.get({
    publicKey: options,
  });

  if (!assertion) {
    throw new Error('Passkey authentication cancelled');
  }

  // 3. Format response
  const responseData = {
    id: assertion.id,
    rawId: bufferToBase64url(assertion.rawId),
    type: assertion.type,
    clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
    authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
    signature: bufferToBase64url(assertion.response.signature),
    userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null,
  };

  // 4. Verify on server
  const verifyRes = await fetch('/api/webauthn/auth-verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(responseData),
  });

  if (!verifyRes.ok) {
    const err = await verifyRes.json();
    throw new Error(err.error || 'Passkey verification failed');
  }

  return await verifyRes.json();
}
