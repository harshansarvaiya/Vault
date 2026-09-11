import crypto from 'node:crypto';
import db from './db.mjs';

// Clean expired challenges periodically
function cleanupChallenges() {
  const now = Date.now();
  db.prepare('DELETE FROM challenges WHERE expires_at < ?').run(now);
}

// Lightweight RFC 8949 CBOR decoder tailored for WebAuthn attestation & COSE
export function decodeCbor(buffer) {
  let offset = 0;

  function read() {
    if (offset >= buffer.length) {
      throw new Error('Unexpected end of CBOR buffer');
    }
    const initialByte = buffer[offset++];
    const majorType = initialByte >> 5;
    const additionalInfo = initialByte & 0x1f;

    let length;
    if (additionalInfo < 24) {
      length = additionalInfo;
    } else if (additionalInfo === 24) {
      length = buffer[offset++];
    } else if (additionalInfo === 25) {
      length = buffer.readUInt16BE(offset);
      offset += 2;
    } else if (additionalInfo === 26) {
      length = buffer.readUInt32BE(offset);
      offset += 4;
    } else if (additionalInfo === 27) {
      // 64-bit integer
      const hi = buffer.readUInt32BE(offset);
      const lo = buffer.readUInt32BE(offset + 4);
      offset += 8;
      length = (BigInt(hi) << 32n) + BigInt(lo);
    } else {
      throw new Error(`Unsupported additional info: ${additionalInfo}`);
    }

    switch (majorType) {
      case 0: // unsigned integer
        return typeof length === 'bigint' ? Number(length) : length;
      case 1: // negative integer
        return typeof length === 'bigint' ? Number(-1n - length) : -1 - length;
      case 2: { // byte string
        const len = Number(length);
        const slice = buffer.subarray(offset, offset + len);
        offset += len;
        return slice;
      }
      case 3: { // text string
        const len = Number(length);
        const str = buffer.toString('utf8', offset, offset + len);
        offset += len;
        return str;
      }
      case 4: { // array
        const len = Number(length);
        const arr = [];
        for (let i = 0; i < len; i++) {
          arr.push(read());
        }
        return arr;
      }
      case 5: { // map
        const len = Number(length);
        const map = new Map();
        for (let i = 0; i < len; i++) {
          const key = read();
          const val = read();
          map.set(key, val);
        }
        return map;
      }
      case 6: // tag
        return read();
      case 7: { // float / simple
        if (additionalInfo === 20) return false;
        if (additionalInfo === 21) return true;
        if (additionalInfo === 22) return null;
        if (additionalInfo === 23) return undefined;
        return undefined;
      }
      default:
        throw new Error(`Unsupported major type: ${majorType}`);
    }
  }

  const value = read();
  return { value, bytesRead: offset };
}

// Convert COSE key map to standard JWK format
export function coseToJwk(coseMap) {
  const kty = coseMap.get(1); // 1 = kty
  if (kty === 2) {
    // EC2
    const crv = coseMap.get(-1); // -1 = crv (1 = P-256)
    const x = coseMap.get(-2);   // -2 = x
    const y = coseMap.get(-3);   // -3 = y

    if (crv !== 1) {
      throw new Error(`Unsupported EC curve: ${crv}`);
    }
    return {
      kty: 'EC',
      crv: 'P-256',
      x: Buffer.from(x).toString('base64url'),
      y: Buffer.from(y).toString('base64url'),
    };
  } else if (kty === 3) {
    // RSA
    const n = coseMap.get(-1);
    const e = coseMap.get(-2);
    return {
      kty: 'RSA',
      n: Buffer.from(n).toString('base64url'),
      e: Buffer.from(e).toString('base64url'),
    };
  }
  throw new Error(`Unsupported COSE kty: ${kty}`);
}

// Parse authData from attestation or authentication
export function parseAuthData(buffer) {
  if (buffer.length < 37) {
    throw new Error('authData too short');
  }
  const rpIdHash = buffer.subarray(0, 32);
  const flags = buffer[32];
  const signCount = buffer.readUInt32BE(33);

  const userPresent = (flags & 0x01) !== 0;
  const userVerified = (flags & 0x04) !== 0;
  const attestedCredentialDataPresent = (flags & 0x40) !== 0;
  const extensionDataPresent = (flags & 0x80) !== 0;

  let credential = null;
  let offset = 37;

  if (attestedCredentialDataPresent) {
    if (buffer.length < offset + 18) {
      throw new Error('Attested credential data incomplete');
    }
    const aaguid = buffer.subarray(offset, offset + 16);
    offset += 16;
    const credIdLen = buffer.readUInt16BE(offset);
    offset += 2;
    const credentialId = buffer.subarray(offset, offset + credIdLen);
    offset += credIdLen;

    const remaining = buffer.subarray(offset);
    const { value: coseMap, bytesRead } = decodeCbor(remaining);
    offset += bytesRead;

    const jwk = coseToJwk(coseMap);
    credential = {
      aaguid: aaguid.toString('hex'),
      credentialId: credentialId.toString('base64url'),
      jwk,
    };
  }

  return {
    rpIdHash,
    flags,
    signCount,
    userPresent,
    userVerified,
    attestedCredentialDataPresent,
    extensionDataPresent,
    credential,
    remainingOffset: offset,
  };
}

// Generate registration options for FIDO2 Passkey
export function generateRegistrationOptions(user, rpId, rpName = 'AegisVault Military Security') {
  cleanupChallenges();
  const challenge = crypto.randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + 120000; // 2 minutes

  db.prepare('INSERT OR REPLACE INTO challenges (challenge, user_id, type, expires_at) VALUES (?, ?, ?, ?)').run(
    challenge,
    user.id,
    'register',
    expiresAt
  );

  // Retrieve user's existing passkeys to exclude re-registration
  const existing = db.prepare('SELECT id FROM passkeys WHERE user_id = ?').all(user.id);
  const excludeCredentials = existing.map((row) => ({
    id: row.id,
    type: 'public-key',
  }));

  return {
    challenge,
    rp: { name: rpName, id: rpId },
    user: {
      id: Buffer.from(user.id).toString('base64url'),
      name: user.username,
      displayName: user.username,
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' },   // ES256 (ECDSA P-256)
      { alg: -257, type: 'public-key' }, // RS256 (RSA 2048)
    ],
    timeout: 60000,
    attestation: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
    excludeCredentials,
  };
}

// Verify registration response from client
export function verifyRegistrationResponse({ response, userId, expectedOrigin }) {
  cleanupChallenges();
  const { id, rawId, clientDataJSON, attestationObject, transports, deviceName } = response;

  const clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'));
  if (clientData.type !== 'webauthn.create') {
    throw new Error('Invalid clientData type');
  }

  // Verify challenge
  const challengeRow = db.prepare('SELECT * FROM challenges WHERE challenge = ? AND type = ?').get(
    clientData.challenge,
    'register'
  );
  if (!challengeRow) {
    throw new Error('Registration challenge not found or expired');
  }
  if (challengeRow.user_id !== userId) {
    throw new Error('Challenge user mismatch');
  }
  db.prepare('DELETE FROM challenges WHERE challenge = ?').run(clientData.challenge);

  // Verify origin
  if (expectedOrigin && !clientData.origin.startsWith(expectedOrigin)) {
    // Allow localhost/127.0.0.1 or exact origin match
    const originHost = new URL(clientData.origin).host;
    const expectedHost = new URL(expectedOrigin).host;
    if (originHost !== expectedHost && !originHost.startsWith('localhost') && !originHost.startsWith('127.0.0.1')) {
      throw new Error(`Origin mismatch: ${clientData.origin} vs ${expectedOrigin}`);
    }
  }

  // Decode attestation object
  const attestationBuffer = Buffer.from(attestationObject, 'base64url');
  const { value: attestationMap } = decodeCbor(attestationBuffer);
  const authDataBuffer = attestationMap.get('authData');

  const parsedAuthData = parseAuthData(authDataBuffer);
  if (!parsedAuthData.credential) {
    throw new Error('No credential extracted from attestation');
  }

  const credId = id || parsedAuthData.credential.credentialId;
  const jwk = parsedAuthData.credential.jwk;

  // Store in passkeys table
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO passkeys (id, user_id, public_key, counter, transports, device_name, created_at, last_used_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    credId,
    userId,
    JSON.stringify(jwk),
    parsedAuthData.signCount,
    JSON.stringify(transports || []),
    deviceName || 'Biometric Security Key / Passkey',
    now,
    now
  );

  return { verified: true, credentialId: credId };
}

// Generate authentication options for FIDO2 login
export function generateAuthenticationOptions(userId = null, rpId) {
  cleanupChallenges();
  const challenge = crypto.randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + 120000;

  db.prepare('INSERT OR REPLACE INTO challenges (challenge, user_id, type, expires_at) VALUES (?, ?, ?, ?)').run(
    challenge,
    userId,
    'auth',
    expiresAt
  );

  let allowCredentials = [];
  if (userId) {
    const keys = db.prepare('SELECT id, transports FROM passkeys WHERE user_id = ?').all(userId);
    allowCredentials = keys.map((k) => ({
      id: k.id,
      type: 'public-key',
      transports: k.transports ? JSON.parse(k.transports) : undefined,
    }));
  }

  return {
    challenge,
    timeout: 60000,
    rpId,
    userVerification: 'preferred',
    allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
  };
}

// Verify authentication assertion response
export function verifyAuthenticationResponse({ response, expectedOrigin }) {
  cleanupChallenges();
  const { id, clientDataJSON, authenticatorData, signature, userHandle } = response;

  const clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'));
  if (clientData.type !== 'webauthn.get') {
    throw new Error('Invalid clientData type for authentication');
  }

  const challengeRow = db.prepare('SELECT * FROM challenges WHERE challenge = ? AND type = ?').get(
    clientData.challenge,
    'auth'
  );
  if (!challengeRow) {
    throw new Error('Authentication challenge invalid or expired');
  }
  db.prepare('DELETE FROM challenges WHERE challenge = ?').run(clientData.challenge);

  // Retrieve passkey from database
  const passkey = db.prepare('SELECT * FROM passkeys WHERE id = ?').get(id);
  if (!passkey) {
    throw new Error('Passkey credential not found');
  }

  const jwk = JSON.parse(passkey.public_key);
  const publicKey = crypto.createPublicKey({ format: 'jwk', key: jwk });

  const authDataBuffer = Buffer.from(authenticatorData, 'base64url');
  const clientDataHash = crypto.createHash('sha256').update(Buffer.from(clientDataJSON, 'base64url')).digest();
  const verifyBuffer = Buffer.concat([authDataBuffer, clientDataHash]);

  const signatureBuffer = Buffer.from(signature, 'base64url');
  const isValid = crypto.verify('SHA256', verifyBuffer, publicKey, signatureBuffer);

  if (!isValid) {
    throw new Error('Passkey cryptographic signature verification failed');
  }

  // Update sign count
  const newSignCount = authDataBuffer.readUInt32BE(33);
  const now = new Date().toISOString();
  db.prepare('UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?').run(
    newSignCount,
    now,
    id
  );

  return {
    verified: true,
    userId: passkey.user_id,
  };
}
