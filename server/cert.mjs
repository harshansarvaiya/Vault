import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const CERT_DIR = path.resolve(process.cwd(), 'data');
const KEY_PATH = path.join(CERT_DIR, 'server.key');
const CERT_PATH = path.join(CERT_DIR, 'server.cert');

function encodeLen(len) {
  if (len < 128) return Buffer.from([len]);
  const arr = [];
  let temp = len;
  while (temp > 0) {
    arr.unshift(temp & 0xff);
    temp >>= 8;
  }
  return Buffer.from([0x80 | arr.length, ...arr]);
}

function seq(...items) {
  const b = Buffer.concat(items);
  return Buffer.concat([Buffer.from([0x30]), encodeLen(b.length), b]);
}

function int(buf) {
  if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0x00]), buf]);
  return Buffer.concat([Buffer.from([0x02]), encodeLen(buf.length), buf]);
}

function oid(bytes) {
  return Buffer.concat([Buffer.from([0x06]), encodeLen(bytes.length), Buffer.from(bytes)]);
}

function bitString(buf) {
  return Buffer.concat([Buffer.from([0x03]), encodeLen(buf.length + 1), Buffer.from([0x00]), buf]);
}

function printableString(str) {
  const b = Buffer.from(str, 'ascii');
  return Buffer.concat([Buffer.from([0x13]), encodeLen(b.length), b]);
}

function utcTime(d) {
  const pad = (n) => String(n).padStart(2, '0');
  const yy = String(d.getUTCFullYear()).slice(-2);
  const mm = pad(d.getUTCMonth() + 1);
  const dd = pad(d.getUTCDate());
  const hh = pad(d.getUTCHours());
  const min = pad(d.getUTCMinutes());
  const ss = pad(d.getUTCSeconds());
  const str = yy + mm + dd + hh + min + ss + 'Z';
  const b = Buffer.from(str, 'ascii');
  return Buffer.concat([Buffer.from([0x17]), encodeLen(b.length), b]);
}

// Generate valid self-signed X.509 v3 certificate with dynamic SAN
export function generateCert(hosts = ['localhost', '127.0.0.1']) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spki = publicKey.export({ type: 'spki', format: 'der' });

  // sha256WithRSAEncryption: 1.2.840.113549.1.1.11
  const algOid = oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
  const sigAlg = seq(algOid, Buffer.from([0x05, 0x00]));

  const cn = seq(oid([0x55, 0x04, 0x03]), printableString('AegisVault Defense Core'));
  const rdn = Buffer.concat([Buffer.from([0x31]), encodeLen(cn.length), cn]);
  const name = seq(rdn);

  const now = new Date();
  const notBefore = utcTime(new Date(now.getTime() - 86400000));
  const notAfter = utcTime(new Date(now.getTime() + 10 * 365 * 86400000));
  const validity = seq(notBefore, notAfter);

  const serial = int(crypto.randomBytes(8));
  const version = Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x02]); // [0] EXPLICIT INTEGER 2 (v3)

  // Subject Alternative Names (SAN)
  const sanOid = oid([0x55, 0x1d, 0x11]);
  const sanEntries = [];

  for (const host of hosts) {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      // IP Address: tag [7] (0x87)
      const parts = host.split('.').map(Number);
      sanEntries.push(Buffer.from([0x87, 0x04, ...parts]));
    } else {
      // DNS name: tag [2] (0x82)
      const b = Buffer.from(host, 'ascii');
      sanEntries.push(Buffer.concat([Buffer.from([0x82]), encodeLen(b.length), b]));
    }
  }

  const sanSeq = seq(...sanEntries);
  const sanExt = seq(sanOid, Buffer.concat([Buffer.from([0x04]), encodeLen(sanSeq.length), sanSeq]));

  // Basic Constraints (CA: TRUE)
  const bcOid = oid([0x55, 0x1d, 0x13]);
  const bcVal = seq(Buffer.from([0x01, 0x01, 0xff]));
  const bcExt = seq(bcOid, Buffer.from([0x01, 0x01, 0xff]), Buffer.concat([Buffer.from([0x04]), encodeLen(bcVal.length), bcVal]));

  const extSeq = seq(bcExt, sanExt);
  const extExplicit = Buffer.concat([Buffer.from([0xa3]), encodeLen(extSeq.length), extSeq]);

  const tbsCert = seq(version, serial, sigAlg, name, validity, name, spki, extExplicit);

  const sign = crypto.createSign('SHA256');
  sign.update(tbsCert);
  const signature = sign.sign(privateKey);

  const certDer = seq(tbsCert, sigAlg, bitString(signature));
  const certPem =
    '-----BEGIN CERTIFICATE-----\n' +
    certDer.toString('base64').match(/.{1,64}/g).join('\n') +
    '\n-----END CERTIFICATE-----\n';

  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

  return { key: keyPem, cert: certPem };
}

export function getOrCreateCert(additionalIps = []) {
  if (!fs.existsSync(CERT_DIR)) {
    fs.mkdirSync(CERT_DIR, { recursive: true });
  }

  // Check if existing cert files exist
  if (fs.existsSync(KEY_PATH) && fs.existsSync(CERT_PATH)) {
    try {
      const key = fs.readFileSync(KEY_PATH, 'utf8');
      const cert = fs.readFileSync(CERT_PATH, 'utf8');
      return { key, cert };
    } catch (e) {
      console.warn('Could not read existing TLS certificates, re-generating...', e.message);
    }
  }

  const hosts = ['localhost', '127.0.0.1', ...additionalIps];
  const { key, cert } = generateCert(hosts);

  fs.writeFileSync(KEY_PATH, key, { encoding: 'utf8', mode: 0o600 });
  fs.writeFileSync(CERT_PATH, cert, { encoding: 'utf8', mode: 0o644 });

  return { key, cert };
}
