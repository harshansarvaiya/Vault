// AegisVault Cross-Device QR Handshake Engine
// End-to-End Encrypted (ECDH P-256 + AES-256-GCM) over ephemeral relay

import { base64urlToBuffer, bufferToBase64url } from './webauthn-client.js';

export function getRandomHex(byteLength = 16) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// -------------------------------------------------------------------------
// TARGET DEVICE (e.g. Laptop/Desktop requesting unlock)
// -------------------------------------------------------------------------

export async function createPairingSession(onStatusUpdate) {
  // 1. Generate ephemeral ECDH keypair (P-256)
  const targetKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  const rawPublicKey = await crypto.subtle.exportKey('raw', targetKeyPair.publicKey);
  const targetPubKeyBase64 = bufferToBase64url(rawPublicKey);
  const sessionId = getRandomHex(16);

  // 2. Build pairing URL
  const baseUrl = window.location.origin + window.location.pathname;
  const pairingUrl = `${baseUrl}?pair=${sessionId}#${targetPubKeyBase64}`;

  // 3. Setup real-time listener via Server-Sent Events (SSE)
  let eventSource = null;
  let isClosed = false;

  const promise = new Promise((resolve, reject) => {
    const topic = `aegis_pair_${sessionId}`;
    eventSource = new EventSource(`https://ntfy.sh/${topic}/sse`);

    if (onStatusUpdate) onStatusUpdate('Waiting for phone camera scan...');

    eventSource.onmessage = async (event) => {
      try {
        const data = JSON.parse(event.data);
        // Ignore ntfy ping/open events
        if (data.event !== 'message' || !data.message) return;

        let packet;
        try {
          packet = JSON.parse(data.message);
        } catch {
          return;
        }

        if (!packet.phonePublicKey || !packet.iv || !packet.ct) return;

        if (onStatusUpdate) onStatusUpdate('Phone verified Face ID! Decrypting vault keys...');

        // 4. Import Phone's public key
        const phoneKey = await crypto.subtle.importKey(
          'raw',
          base64urlToBuffer(packet.phonePublicKey),
          { name: 'ECDH', namedCurve: 'P-256' },
          false,
          []
        );

        // 5. Derive shared AES-256-GCM key
        const sharedKey = await crypto.subtle.deriveKey(
          { name: 'ECDH', public: phoneKey },
          targetKeyPair.privateKey,
          { name: 'AES-GCM', length: 256 },
          false,
          ['decrypt']
        );

        // 6. Decrypt vault credentials payload
        const decryptedBytes = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: new Uint8Array(base64urlToBuffer(packet.iv)) },
          sharedKey,
          base64urlToBuffer(packet.ct)
        );

        const payload = JSON.parse(new TextDecoder().decode(decryptedBytes));

        // 7. Import raw VEK key into CryptoKey
        const vek = await crypto.subtle.importKey(
          'raw',
          base64urlToBuffer(payload.rawVek),
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt', 'decrypt']
        );

        cleanup();
        resolve({
          username: payload.username,
          vek,
          authSalt: payload.authSalt,
          authHash: payload.authHash,
          kdfSalt: payload.kdfSalt,
          kdfIterations: payload.kdfIterations || 600000,
          encryptedVek: payload.encryptedVek,
          items: payload.items || [],
        });
      } catch (err) {
        cleanup();
        reject(new Error('Failed to decrypt paired vault: ' + err.message));
      }
    };

    eventSource.onerror = (err) => {
      // EventSource reconnects automatically on temporary drop
      console.warn('Pairing stream reconnecting...', err);
    };

    // Auto-expire after 3 minutes
    setTimeout(() => {
      if (!isClosed) {
        cleanup();
        reject(new Error('Pairing session timed out. Please try again.'));
      }
    }, 180000);
  });

  function cleanup() {
    isClosed = true;
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
  }

  return {
    sessionId,
    targetPubKeyBase64,
    pairingUrl,
    promise,
    cancel: cleanup,
  };
}

// -------------------------------------------------------------------------
// PRIMARY DEVICE (Phone authorizing login via Face ID)
// -------------------------------------------------------------------------

export async function authorizePairingRequest(sessionId, targetPubKeyBase64, username, vekKey, localStore) {
  // 1. Generate phone's ephemeral ECDH keypair
  const phoneKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  // 2. Import target device's public key
  const targetKey = await crypto.subtle.importKey(
    'raw',
    base64urlToBuffer(targetPubKeyBase64),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  // 3. Derive matching shared secret
  const sharedKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: targetKey },
    phoneKeyPair.privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  // 4. Export VEK and package vault credentials
  const rawVek = await crypto.subtle.exportKey('raw', vekKey);
  const user = localStore.getUser(username);
  const items = localStore.getItems(username);

  const payload = {
    username,
    rawVek: bufferToBase64url(rawVek),
    authSalt: user ? user.authSalt : null,
    authHash: user ? user.authHash : null,
    kdfSalt: user ? user.kdfSalt : null,
    kdfIterations: user ? user.kdfIterations : 600000,
    encryptedVek: user ? user.encryptedVek : null,
    items: items || [],
    authorizedAt: new Date().toISOString(),
  };

  // 5. Encrypt with AES-256-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    sharedKey,
    plaintext
  );

  // 6. Export phone's public key
  const phonePubKeyRaw = await crypto.subtle.exportKey('raw', phoneKeyPair.publicKey);

  // 7. Post encrypted payload to ephemeral relay
  const messageBody = JSON.stringify({
    phonePublicKey: bufferToBase64url(phonePubKeyRaw),
    iv: bufferToBase64url(iv),
    ct: bufferToBase64url(ciphertext),
  });

  const res = await fetch(`https://ntfy.sh/aegis_pair_${sessionId}`, {
    method: 'POST',
    body: messageBody,
  });

  if (!res.ok) {
    throw new Error('Failed to transmit authorization payload');
  }

  return { success: true };
}
