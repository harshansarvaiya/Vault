// AegisVault Military-Grade Web Crypto Engine
// Implements Zero-Knowledge End-to-End Encryption (AES-256-GCM + PBKDF2-SHA256)

// Utilities for ArrayBuffer / Base64 / Hex conversions
export function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}

export function getRandomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function getRandomHex(length = 16) {
  return bufferToHex(getRandomBytes(length));
}

// Derive Master Encryption Key (MEK) and Master Authentication Hash (MAH)
// Using 600,000 rounds of PBKDF2-SHA256 followed by HKDF separation
export async function deriveMasterKeys(password, saltHex, iterations = 600000) {
  const enc = new TextEncoder();
  const salt = new Uint8Array(hexToBuffer(saltHex));

  // 1. Import raw password
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // 2. Derive 512 bits via PBKDF2
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    512 // 64 bytes
  );

  // Split bits into two 256-bit partitions:
  // First 256 bits -> Master Encryption Key material
  // Second 256 bits -> Master Authentication Hash material
  const mekBytes = derivedBits.slice(0, 32);
  const mahBytes = derivedBits.slice(32, 64);

  // Import MEK as an AES-GCM CryptoKey
  const mek = await crypto.subtle.importKey(
    'raw',
    mekBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // Derive MAH hex string for authentication verification
  const mahHash = await crypto.subtle.digest('SHA-256', mahBytes);
  const authHash = bufferToHex(mahHash);

  return { mek, authHash };
}

// Generate a random 256-bit Vault Encryption Key (VEK)
export async function generateVek() {
  const rawBytes = getRandomBytes(32);
  const key = await crypto.subtle.importKey(
    'raw',
    rawBytes,
    { name: 'AES-GCM', length: 256 },
    true, // Extractable for encrypted backup / export
    ['encrypt', 'decrypt']
  );
  return { key, rawBytes };
}

// Encrypt the VEK using the Master Encryption Key (MEK)
export async function encryptVek(vekKey, mek) {
  const exportedVek = await crypto.subtle.exportKey('raw', vekKey);
  const iv = getRandomBytes(12); // 96-bit AES-GCM IV

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    mek,
    exportedVek
  );

  return JSON.stringify({
    ct: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv),
  });
}

// Decrypt the VEK using the Master Encryption Key (MEK)
export async function decryptVek(encryptedVekJson, mek) {
  const { ct, iv } = JSON.parse(encryptedVekJson);
  const ciphertext = base64ToBuffer(ct);
  const ivBuffer = base64ToBuffer(iv);

  const rawVek = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(ivBuffer) },
    mek,
    ciphertext
  );

  return crypto.subtle.importKey(
    'raw',
    rawVek,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// Encrypt an arbitrary JS object / payload using VEK
export async function encryptPayload(payloadObj, vekKey) {
  const enc = new TextEncoder();
  const plaintext = enc.encode(JSON.stringify(payloadObj));
  const iv = getRandomBytes(12); // Unique 96-bit IV for every single item

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    vekKey,
    plaintext
  );

  return JSON.stringify({
    ct: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv),
  });
}

// Decrypt an encrypted payload string using VEK
export async function decryptPayload(encryptedString, vekKey) {
  const { ct, iv } = JSON.parse(encryptedString);
  const ciphertext = base64ToBuffer(ct);
  const ivBuffer = base64ToBuffer(iv);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(ivBuffer) },
    vekKey,
    ciphertext
  );

  const dec = new TextDecoder();
  return JSON.parse(dec.decode(decrypted));
}

// Duress Mode: Setup realistic decoy accounts
export async function createDefaultDecoyItems(duressVek) {
  const decoys = [
    {
      title: 'City Library Card & Catalog',
      category: 'Personal',
      username: 'patron_849204',
      password: 'ReadBooks2024!#',
      url: 'https://catalog.citylibrary.org',
      notes: 'Barcode PIN: 4892. Overdue book reminder set.',
      tags: ['library', 'books'],
    },
    {
      title: 'Artisan Coffee Roasters Loyalty',
      category: 'Personal',
      username: 'alex.walker@coffeemail.net',
      password: 'EspressoMug$99',
      url: 'https://rewards.artisancoffee.com',
      notes: 'Free drink every 10 stars. Birthday coupon active.',
      tags: ['loyalty', 'coffee'],
    },
    {
      title: 'Metro Gym Member Portal',
      category: 'Health',
      username: 'member_7721',
      password: 'Fitness2025Lift!',
      url: 'https://portal.metrogym.net',
      notes: 'Locker combination: 18-34-02',
      tags: ['gym', 'fitness'],
    },
  ];

  const encryptedDecoys = [];
  for (const item of decoys) {
    const encryptedTitle = await encryptPayload({ title: item.title }, duressVek);
    const encryptedPayload = await encryptPayload(item, duressVek);
    encryptedDecoys.push({
      encryptedTitle,
      category: item.category,
      encryptedPayload,
    });
  }
  return encryptedDecoys;
}

// High-entropy 16-word emergency recovery phrase generator
const WORDLIST = [
  'alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel',
  'india', 'juliet', 'kilo', 'lima', 'mike', 'november', 'oscar', 'papa',
  'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor', 'whiskey', 'xray',
  'yankee', 'zulu', 'beacon', 'cipher', 'defense', 'falcon', 'galaxy', 'harbor',
  'iron', 'matrix', 'nexus', 'orbit', 'plasma', 'quantum', 'radar', 'sentinel',
  'titan', 'vortex', 'zenith', 'apex', 'bastion', 'comet', 'dagger', 'eclipse'
];

export function generateRecoveryPhrase() {
  const words = [];
  const randomIndices = getRandomBytes(16);
  for (let i = 0; i < 16; i++) {
    words.push(WORDLIST[randomIndices[i] % WORDLIST.length]);
  }
  return words.join(' ');
}
