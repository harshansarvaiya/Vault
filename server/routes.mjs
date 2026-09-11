import crypto from 'node:crypto';
import db, { randomUUID } from './db.mjs';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from './webauthn.mjs';

// In-memory rate limiting map: ip -> { count, lockedUntil }
const rateLimitMap = new Map();

export function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry) return true;
  if (entry.lockedUntil && now < entry.lockedUntil) {
    return false;
  }
  if (entry.lockedUntil && now >= entry.lockedUntil) {
    rateLimitMap.delete(ip);
    return true;
  }
  return entry.count < 15; // Max 15 sensitive requests per minute
}

export function recordFailedAttempt(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, firstAttempt: now, lockedUntil: null };
  entry.count++;
  if (entry.count >= 6) {
    entry.lockedUntil = now + 5 * 60 * 1000; // 5 minute progressive lock
  }
  rateLimitMap.set(ip, entry);
}

export function clearRateLimit(ip) {
  rateLimitMap.delete(ip);
}

// Helper: server-side secondary hash for auth verifier
function hashVerifier(clientHash, salt) {
  return crypto.scryptSync(clientHash, salt, 32).toString('hex');
}

// Log security audit event
export function logSecurityEvent(userId, eventType, req, metadata = '') {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const ua = req.headers['user-agent'] || 'unknown';
  const now = new Date().toISOString();
  try {
    db.prepare(`
      INSERT INTO audit_logs (user_id, event_type, ip_address, user_agent, metadata, timestamp)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(userId, eventType, ip, ua, typeof metadata === 'object' ? JSON.stringify(metadata) : String(metadata), now);
  } catch (err) {
    console.error('Failed to log audit event:', err.message);
  }
}

// Session validation
export function authenticateSession(req) {
  const authHeader = req.headers['authorization'];
  let token = null;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else if (req.headers['cookie']) {
    const match = req.headers['cookie'].match(/vault_session=([^;]+)/);
    if (match) token = match[1];
  }

  if (!token) return null;

  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(token);
  if (!session) return null;

  if (new Date(session.expires_at).getTime() < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(token);
    return null;
  }

  const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(session.user_id);
  if (!user) return null;

  return {
    user,
    sessionId: session.id,
    isDuress: session.is_duress === 1,
  };
}

// API router
export async function handleApiRequest(req, res, pathname, searchParams) {
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const origin = req.headers['origin'] || `${req.socket.encrypted ? 'https' : 'http'}://${req.headers.host}`;
  const host = req.headers.host ? req.headers.host.split(':')[0] : 'localhost';

  // Read body helper
  const getBody = async () => {
    return new Promise((resolve, reject) => {
      let data = '';
      req.on('data', (chunk) => {
        data += chunk;
        if (data.length > 5 * 1024 * 1024) { // 5MB limit
          reject(new Error('Payload too large'));
        }
      });
      req.on('end', () => {
        if (!data) return resolve({});
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error('Invalid JSON'));
        }
      });
      req.on('error', reject);
    });
  };

  const json = (data, status = 200) => {
    res.writeHead(status, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Pragma': 'no-cache',
    });
    res.end(JSON.stringify(data));
  };

  const error = (message, status = 400) => {
    json({ error: message }, status);
  };

  // Pre-flight CORS for development/mobile access
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    });
    res.end();
    return;
  }

  try {
    // -------------------------------------------------------------
    // AUTHENTICATION ROUTES
    // -------------------------------------------------------------

    // Pre-login: Fetch salts for username
    if (pathname === '/api/auth/pre-login' && req.method === 'GET') {
      const username = searchParams.get('username')?.trim();
      if (!username) return error('Username is required');

      const user = db.prepare('SELECT kdf_salt, kdf_iterations, auth_salt, duress_salt FROM users WHERE username = ?').get(username);
      if (user) {
        return json({
          kdfSalt: user.kdf_salt,
          kdfIterations: user.kdf_iterations,
          authSalt: user.auth_salt,
          duressSalt: user.duress_salt,
        });
      } else {
        // Return deterministic dummy salt to thwart username enumeration
        const dummySalt = crypto.createHash('sha256').update(`salt:${username}:dummy`).digest('hex').substring(0, 32);
        return json({
          kdfSalt: dummySalt,
          kdfIterations: 600000,
          authSalt: dummySalt,
          duressSalt: dummySalt,
        });
      }
    }

    // User Registration
    if (pathname === '/api/auth/register' && req.method === 'POST') {
      const body = await getBody();
      const {
        username,
        authSalt,
        authHash,
        kdfSalt,
        kdfIterations,
        encryptedVek,
        duressSalt,
        duressHash,
        duressEncryptedVek,
        recoveryHash,
      } = body;

      if (!username || !authSalt || !authHash || !kdfSalt || !encryptedVek) {
        return error('Missing required registration parameters');
      }

      const cleanUsername = username.trim();
      if (cleanUsername.length < 3 || cleanUsername.length > 50) {
        return error('Username must be between 3 and 50 characters');
      }

      const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(cleanUsername);
      if (existing) {
        return error('Username is already registered');
      }

      const userId = randomUUID();
      const serverAuthSalt = crypto.randomBytes(16).toString('hex');
      const serverAuthHash = hashVerifier(authHash, serverAuthSalt);

      let serverDuressHash = null;
      if (duressHash && duressSalt) {
        serverDuressHash = hashVerifier(duressHash, duressSalt);
      }

      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO users (
          id, username, auth_salt, auth_hash, kdf_salt, kdf_iterations,
          encrypted_vek, duress_salt, duress_hash, duress_encrypted_vek,
          recovery_hash, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        userId,
        cleanUsername,
        serverAuthSalt,
        serverAuthHash,
        kdfSalt,
        kdfIterations || 600000,
        encryptedVek,
        duressSalt || null,
        serverDuressHash,
        duressEncryptedVek || null,
        recoveryHash || null,
        now,
        now
      );

      // Populate realistic decoy entries for Duress Mode
      if (duressEncryptedVek && body.decoyItems && Array.isArray(body.decoyItems)) {
        for (const item of body.decoyItems) {
          db.prepare(`
            INSERT INTO vault_items (id, user_id, is_duress, encrypted_title, category, encrypted_payload, is_favorite, created_at, updated_at)
            VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)
          `).run(
            randomUUID(),
            userId,
            item.encryptedTitle,
            item.category || 'General',
            item.encryptedPayload,
            0,
            now,
            now
          );
        }
      }

      // Create session
      const sessionToken = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      db.prepare('INSERT INTO sessions (id, user_id, is_duress, created_at, expires_at) VALUES (?, ?, 0, ?, ?)').run(
        sessionToken,
        userId,
        now,
        expiresAt
      );

      logSecurityEvent(userId, 'REGISTER_SUCCESS', req);

      return json({
        success: true,
        user: { id: userId, username: cleanUsername },
        sessionToken,
        encryptedVek,
        isDuress: false,
      });
    }

    // User Login (Master Password or Duress PIN)
    if (pathname === '/api/auth/login' && req.method === 'POST') {
      if (!checkRateLimit(clientIp)) {
        return error('Too many failed attempts. Temporary security lockout active.', 429);
      }

      const body = await getBody();
      const { username, authHash, duressAttempt } = body;

      if (!username || !authHash) {
        return error('Username and authentication proof required');
      }

      const cleanUsername = username.trim();
      const user = db.prepare('SELECT * FROM users WHERE username = ?').get(cleanUsername);

      if (!user) {
        recordFailedAttempt(clientIp);
        return error('Invalid credentials', 401);
      }

      // Check Master Password
      const testServerHash = hashVerifier(authHash, user.auth_salt);
      const isMasterMatch = crypto.timingSafeEqual(
        Buffer.from(testServerHash),
        Buffer.from(user.auth_hash)
      );

      // Check Duress PIN
      let isDuressMatch = false;
      if (user.duress_hash && user.duress_salt) {
        const testDuressHash = hashVerifier(authHash, user.duress_salt);
        if (testDuressHash.length === user.duress_hash.length) {
          isDuressMatch = crypto.timingSafeEqual(
            Buffer.from(testDuressHash),
            Buffer.from(user.duress_hash)
          );
        }
      }

      if (!isMasterMatch && !isDuressMatch) {
        recordFailedAttempt(clientIp);
        logSecurityEvent(user.id, 'LOGIN_FAILED', req);
        return error('Invalid credentials', 401);
      }

      clearRateLimit(clientIp);

      const sessionToken = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      const now = new Date().toISOString();
      const isDuressActive = isDuressMatch;

      db.prepare('INSERT INTO sessions (id, user_id, is_duress, created_at, expires_at) VALUES (?, ?, ?, ?, ?)').run(
        sessionToken,
        user.id,
        isDuressActive ? 1 : 0,
        now,
        expiresAt
      );

      if (isDuressActive) {
        logSecurityEvent(user.id, 'DURESS_TRIGGERED', req, { note: 'Decoy vault engaged under duress PIN' });
      } else {
        logSecurityEvent(user.id, 'LOGIN_SUCCESS', req);
      }

      return json({
        success: true,
        user: { id: user.id, username: user.username },
        sessionToken,
        encryptedVek: isDuressActive ? user.duress_encrypted_vek : user.encrypted_vek,
        isDuress: isDuressActive,
      });
    }

    // Current Session / Me
    if (pathname === '/api/auth/me' && req.method === 'GET') {
      const auth = authenticateSession(req);
      if (!auth) return error('Unauthorized', 401);

      const user = db.prepare('SELECT id, username, encrypted_vek, duress_encrypted_vek FROM users WHERE id = ?').get(auth.user.id);
      const passkeyCount = db.prepare('SELECT COUNT(*) as count FROM passkeys WHERE user_id = ?').get(auth.user.id).count;

      return json({
        user: { id: user.id, username: user.username },
        isDuress: auth.isDuress,
        hasPasskeys: passkeyCount > 0,
        passkeyCount,
        encryptedVek: auth.isDuress ? user.duress_encrypted_vek : user.encrypted_vek,
      });
    }

    // Logout
    if (pathname === '/api/auth/logout' && req.method === 'POST') {
      const auth = authenticateSession(req);
      if (auth) {
        db.prepare('DELETE FROM sessions WHERE id = ?').run(auth.sessionId);
        logSecurityEvent(auth.user.id, 'LOGOUT', req);
      }
      return json({ success: true });
    }

    // -------------------------------------------------------------
    // WEBAUTHN / PASSKEYS ROUTES
    // -------------------------------------------------------------

    // Register Passkey Options
    if (pathname === '/api/webauthn/register-options' && req.method === 'POST') {
      const auth = authenticateSession(req);
      if (!auth) return error('Unauthorized', 401);
      if (auth.isDuress) return error('Action disabled in restricted mode', 403);

      const options = generateRegistrationOptions(auth.user, host);
      return json(options);
    }

    // Register Passkey Verification
    if (pathname === '/api/webauthn/register-verify' && req.method === 'POST') {
      const auth = authenticateSession(req);
      if (!auth) return error('Unauthorized', 401);
      if (auth.isDuress) return error('Action disabled in restricted mode', 403);

      const body = await getBody();
      try {
        const result = verifyRegistrationResponse({
          response: body,
          userId: auth.user.id,
          expectedOrigin: origin,
        });
        logSecurityEvent(auth.user.id, 'PASSKEY_REGISTERED', req, { credId: result.credentialId });
        return json({ success: true, credentialId: result.credentialId });
      } catch (err) {
        return error(err.message, 400);
      }
    }

    // Passkey Login Options
    if (pathname === '/api/webauthn/auth-options' && req.method === 'POST') {
      const body = await getBody();
      const username = body.username?.trim();
      let userId = null;

      if (username) {
        const user = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
        if (user) userId = user.id;
      }

      const options = generateAuthenticationOptions(userId, host);
      return json(options);
    }

    // Passkey Login Verification
    if (pathname === '/api/webauthn/auth-verify' && req.method === 'POST') {
      const body = await getBody();
      try {
        const result = verifyAuthenticationResponse({
          response: body,
          expectedOrigin: origin,
        });

        const user = db.prepare('SELECT id, username, encrypted_vek FROM users WHERE id = ?').get(result.userId);
        const sessionToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        const now = new Date().toISOString();

        db.prepare('INSERT INTO sessions (id, user_id, is_duress, created_at, expires_at) VALUES (?, ?, 0, ?, ?)').run(
          sessionToken,
          user.id,
          now,
          expiresAt
        );

        logSecurityEvent(user.id, 'PASSKEY_LOGIN_SUCCESS', req, { credId: body.id });

        return json({
          success: true,
          user: { id: user.id, username: user.username },
          sessionToken,
          encryptedVek: user.encrypted_vek,
          isDuress: false,
        });
      } catch (err) {
        return error(err.message, 401);
      }
    }

    // List registered passkeys
    if (pathname === '/api/webauthn/list' && req.method === 'GET') {
      const auth = authenticateSession(req);
      if (!auth) return error('Unauthorized', 401);
      if (auth.isDuress) return json([]);

      const keys = db.prepare('SELECT id, device_name, created_at, last_used_at FROM passkeys WHERE user_id = ?').all(auth.user.id);
      return json(keys);
    }

    // Delete passkey
    if (pathname.startsWith('/api/webauthn/') && req.method === 'DELETE') {
      const auth = authenticateSession(req);
      if (!auth) return error('Unauthorized', 401);
      const credId = pathname.substring('/api/webauthn/'.length);

      db.prepare('DELETE FROM passkeys WHERE id = ? AND user_id = ?').run(credId, auth.user.id);
      logSecurityEvent(auth.user.id, 'PASSKEY_REMOVED', req, { credId });
      return json({ success: true });
    }

    // -------------------------------------------------------------
    // VAULT CRUD OPERATIONS (Zero-Knowledge Ciphertexts)
    // -------------------------------------------------------------

    // Read all vault items (filtered by duress context)
    if (pathname === '/api/vault' && req.method === 'GET') {
      const auth = authenticateSession(req);
      if (!auth) return error('Unauthorized', 401);

      const isDuress = auth.isDuress ? 1 : 0;
      const items = db.prepare(`
        SELECT id, encrypted_title, category, encrypted_payload, is_favorite, created_at, updated_at
        FROM vault_items
        WHERE user_id = ? AND is_duress = ?
        ORDER BY is_favorite DESC, updated_at DESC
      `).all(auth.user.id, isDuress);

      return json(items);
    }

    // Create a new vault item
    if (pathname === '/api/vault' && req.method === 'POST') {
      const auth = authenticateSession(req);
      if (!auth) return error('Unauthorized', 401);

      const body = await getBody();
      const { encryptedTitle, category, encryptedPayload, isFavorite } = body;

      if (!encryptedTitle || !encryptedPayload) {
        return error('Encrypted title and encrypted payload are required');
      }

      const itemId = randomUUID();
      const now = new Date().toISOString();
      const isDuress = auth.isDuress ? 1 : 0;

      db.prepare(`
        INSERT INTO vault_items (id, user_id, is_duress, encrypted_title, category, encrypted_payload, is_favorite, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        itemId,
        auth.user.id,
        isDuress,
        encryptedTitle,
        category || 'General',
        encryptedPayload,
        isFavorite ? 1 : 0,
        now,
        now
      );

      logSecurityEvent(auth.user.id, 'ITEM_CREATED', req, { itemId, duress: auth.isDuress });

      return json({
        id: itemId,
        encrypted_title: encryptedTitle,
        category: category || 'General',
        encrypted_payload: encryptedPayload,
        is_favorite: isFavorite ? 1 : 0,
        created_at: now,
        updated_at: now,
      }, 201);
    }

    // Update an existing vault item
    if (pathname.startsWith('/api/vault/') && req.method === 'PUT') {
      const auth = authenticateSession(req);
      if (!auth) return error('Unauthorized', 401);

      const itemId = pathname.substring('/api/vault/'.length);
      const body = await getBody();
      const { encryptedTitle, category, encryptedPayload, isFavorite } = body;

      const isDuress = auth.isDuress ? 1 : 0;
      const item = db.prepare('SELECT id FROM vault_items WHERE id = ? AND user_id = ? AND is_duress = ?').get(
        itemId,
        auth.user.id,
        isDuress
      );

      if (!item) {
        return error('Vault item not found', 404);
      }

      const now = new Date().toISOString();
      db.prepare(`
        UPDATE vault_items
        SET encrypted_title = COALESCE(?, encrypted_title),
            category = COALESCE(?, category),
            encrypted_payload = COALESCE(?, encrypted_payload),
            is_favorite = COALESCE(?, is_favorite),
            updated_at = ?
        WHERE id = ? AND user_id = ? AND is_duress = ?
      `).run(
        encryptedTitle,
        category,
        encryptedPayload,
        isFavorite !== undefined ? (isFavorite ? 1 : 0) : null,
        now,
        itemId,
        auth.user.id,
        isDuress
      );

      logSecurityEvent(auth.user.id, 'ITEM_UPDATED', req, { itemId, duress: auth.isDuress });

      return json({ success: true, updated_at: now });
    }

    // Delete a vault item
    if (pathname.startsWith('/api/vault/') && req.method === 'DELETE') {
      const auth = authenticateSession(req);
      if (!auth) return error('Unauthorized', 401);

      const itemId = pathname.substring('/api/vault/'.length);
      const isDuress = auth.isDuress ? 1 : 0;

      const result = db.prepare('DELETE FROM vault_items WHERE id = ? AND user_id = ? AND is_duress = ?').run(
        itemId,
        auth.user.id,
        isDuress
      );

      if (result.changes === 0) {
        return error('Vault item not found', 404);
      }

      logSecurityEvent(auth.user.id, 'ITEM_DELETED', req, { itemId, duress: auth.isDuress });

      return json({ success: true });
    }

    // Batch import items
    if (pathname === '/api/vault/batch' && req.method === 'POST') {
      const auth = authenticateSession(req);
      if (!auth) return error('Unauthorized', 401);

      const body = await getBody();
      if (!body.items || !Array.isArray(body.items)) {
        return error('Array of items required');
      }

      const now = new Date().toISOString();
      const isDuress = auth.isDuress ? 1 : 0;
      let count = 0;

      for (const item of body.items) {
        if (!item.encryptedTitle || !item.encryptedPayload) continue;
        db.prepare(`
          INSERT INTO vault_items (id, user_id, is_duress, encrypted_title, category, encrypted_payload, is_favorite, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          randomUUID(),
          auth.user.id,
          isDuress,
          item.encryptedTitle,
          item.category || 'General',
          item.encryptedPayload,
          item.isFavorite ? 1 : 0,
          now,
          now
        );
        count++;
      }

      logSecurityEvent(auth.user.id, 'BATCH_IMPORT', req, { count });
      return json({ success: true, imported: count });
    }

    // Audit log
    if (pathname === '/api/audit-log' && req.method === 'GET') {
      const auth = authenticateSession(req);
      if (!auth) return error('Unauthorized', 401);

      const logs = db.prepare(`
        SELECT id, event_type, ip_address, timestamp, metadata
        FROM audit_logs
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 50
      `).all(auth.user.id);

      return json(logs);
    }

    // Fallback 404 for unmatched API routes
    return error('API endpoint not found', 404);

  } catch (err) {
    console.error('API Error:', err);
    return error(err.message || 'Internal Server Error', 500);
  }
}
