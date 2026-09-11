// AegisVault RFC 6238 TOTP (Time-based One-Time Password) Authenticator Engine
// Client-side implementation using Web Crypto API (crypto.subtle HMAC-SHA1)

const RFC4648_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// Base32 decode
export function base32Decode(base32Str) {
  const clean = base32Str.toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0;
  let value = 0;
  const output = [];

  for (let i = 0; i < clean.length; i++) {
    const val = RFC4648_ALPHABET.indexOf(clean.charAt(i));
    if (val === -1) continue;

    value = (value << 5) | val;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

// Generate TOTP token for given secret and timestamp
export async function generateTotp(secretBase32, timeMs = Date.now(), stepSeconds = 30, digits = 6) {
  if (!secretBase32 || typeof secretBase32 !== 'string') return null;

  try {
    const keyBytes = base32Decode(secretBase32);
    if (keyBytes.length === 0) return null;

    const epochSeconds = Math.floor(timeMs / 1000);
    const counter = Math.floor(epochSeconds / stepSeconds);

    // 8-byte big-endian counter buffer
    const counterBuffer = new ArrayBuffer(8);
    const view = new DataView(counterBuffer);
    view.setBigUint64(0, BigInt(counter), false);

    // Import HMAC key
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: { name: 'SHA-1' } },
      false,
      ['sign']
    );

    // Compute HMAC
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, counterBuffer);
    const hmacBytes = new Uint8Array(signature);

    // Dynamic Truncation
    const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
    const binary =
      ((hmacBytes[offset] & 0x7f) << 24) |
      ((hmacBytes[offset + 1] & 0xff) << 16) |
      ((hmacBytes[offset + 2] & 0xff) << 8) |
      (hmacBytes[offset + 3] & 0xff);

    const token = (binary % Math.pow(10, digits)).toString().padStart(digits, '0');
    const remainingSeconds = stepSeconds - (epochSeconds % stepSeconds);

    return {
      token,
      remainingSeconds,
      percentage: (remainingSeconds / stepSeconds) * 100,
    };
  } catch (err) {
    console.error('TOTP generation error:', err);
    return null;
  }
}
