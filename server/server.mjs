import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { getOrCreateCert } from './cert.mjs';
import { handleApiRequest } from './routes.mjs';

const HTTP_PORT = process.env.HTTP_PORT ? parseInt(process.env.HTTP_PORT, 10) : 3000;
const HTTPS_PORT = process.env.HTTPS_PORT ? parseInt(process.env.HTTPS_PORT, 10) : 8443;
const PUBLIC_DIR = path.resolve(process.cwd(), 'public');

// Discover LAN IP addresses for mobile pairing
function getLanIps() {
  const interfaces = os.networkInterfaces();
  const ips = [];
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name] || []) {
      if (iface.family === 'IPv4' && !iface.internal) {
        ips.push(iface.address);
      }
    }
  }
  return ips;
}

const lanIps = getLanIps();
const primaryLanIp = lanIps[0] || '127.0.0.1';

// Initialize or load TLS certificates
const { key, cert } = getOrCreateCert(lanIps);

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

// Main request dispatcher
async function requestListener(req, res) {
  const url = new URL(req.url, `${req.socket.encrypted ? 'https' : 'http'}://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // Handle API routes
  if (pathname.startsWith('/api/')) {
    // Mobile pairing info route
    if (pathname === '/api/info') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        httpPort: HTTP_PORT,
        httpsPort: HTTPS_PORT,
        lanIps,
        primaryLanIp,
        mobileUrl: `https://${primaryLanIp}:${HTTPS_PORT}`,
      }));
      return;
    }

    return handleApiRequest(req, res, pathname, url.searchParams);
  }

  // Static file serving from /public
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);

  // Security check: prevent path traversal outside public dir
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Access Denied');
    return;
  }

  // Check if file exists; fallback to index.html for SPA routing
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    filePath = path.join(PUBLIC_DIR, 'index.html');
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  try {
    const fileContent = fs.readFileSync(filePath);

    // Apply strict military-grade security headers
    res.writeHead(200, {
      'Content-Type': contentType,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
      // CSP allowing self and inline styles for UI accents, WebAuthn & Web Crypto native APIs
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https:; worker-src 'self';",
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600',
    });
    res.end(fileContent);
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Server Error');
  }
}

// Start HTTP Server (for local desktop convenience)
const httpServer = http.createServer(requestListener);
httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
  // HTTP server listening
});

// Start HTTPS Server (Required for WebAuthn, Passkeys & Secure Context on Mobile Phones)
const httpsServer = https.createServer({ key, cert }, requestListener);
httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
  printBanner();
});

function printBanner() {
  console.log(`
\x1b[36m========================================================================\x1b[0m
\x1b[1m\x1b[32m [AEGIS-VAULT] MILITARY-GRADE ZERO-KNOWLEDGE DEFENSE CORE ONLINE\x1b[0m
\x1b[36m========================================================================\x1b[0m

  \x1b[1m\x1b[37m[>] Desktop Browser Access:\x1b[0m
      Secure (Passkeys Ready): \x1b[32mhttps://localhost:${HTTPS_PORT}\x1b[0m
      Local Standard:          \x1b[33mhttp://localhost:${HTTP_PORT}\x1b[0m

  \x1b[1m\x1b[37m[>] Mobile Smartphone Access (iOS Safari / Android Chrome):\x1b[0m
      LAN URL:                 \x1b[1m\x1b[36mhttps://${primaryLanIp}:${HTTPS_PORT}\x1b[0m
      (Open this link on your phone connected to the same Wi-Fi)

  \x1b[1m\x1b[35m[i] Security Features Active:\x1b[0m
      - Client-Side AES-256-GCM Zero-Knowledge Encryption
      - 600,000 PBKDF2-SHA256 Derivation Rounds
      - FIDO2 / WebAuthn Biometric Passkeys (Face ID, Touch ID, Windows Hello)
      - Duress Coercion Decoy Vault System
      - Live RFC 6238 TOTP 2FA Authenticator Engine
      - Auto-Lock, Tab Privacy Shield & 30s Clipboard Sanitization

\x1b[36m========================================================================\x1b[0m
`);
}

export { httpServer, httpsServer };
