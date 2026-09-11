// AegisVault Military-Grade Password & Passphrase Generator with Entropy Analytics

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const NUMBERS = '0123456789';
const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';
const AMBIGUOUS = '1lI0O';

const PASSPHRASE_WORDS = [
  'cipher', 'quantum', 'titan', 'plasma', 'sentinel', 'falcon', 'matrix', 'nexus',
  'bastion', 'vortex', 'zenith', 'harbor', 'shadow', 'cobalt', 'vector', 'beacon',
  'iron', 'radar', 'eclipse', 'comet', 'hazard', 'hyper', 'orbit', 'solaris',
  'vertex', 'radiant', 'shield', 'phantom', 'sentry', 'aurora', 'tempest', 'valiant',
  'obsidian', 'neutron', 'cyber', 'kryptex', 'apex', 'delta', 'omega', 'stealth'
];

export function generatePassword(options = {}) {
  const {
    length = 20,
    useUpper = true,
    useLower = true,
    useNumbers = true,
    useSymbols = true,
    excludeAmbiguous = false,
  } = options;

  let pool = '';
  if (useUpper) pool += UPPERCASE;
  if (useLower) pool += LOWERCASE;
  if (useNumbers) pool += NUMBERS;
  if (useSymbols) pool += SYMBOLS;

  if (excludeAmbiguous) {
    pool = pool.split('').filter((ch) => !AMBIGUOUS.includes(ch)).join('');
  }

  if (pool.length === 0) {
    pool = LOWERCASE + NUMBERS;
  }

  const randomBytes = new Uint32Array(length);
  crypto.getRandomValues(randomBytes);

  let password = '';
  for (let i = 0; i < length; i++) {
    password += pool.charAt(randomBytes[i] % pool.length);
  }

  return password;
}

export function generatePassphrase(wordCount = 5, separator = '-', includeNumber = true) {
  const randomIndices = new Uint32Array(wordCount);
  crypto.getRandomValues(randomIndices);

  const words = [];
  for (let i = 0; i < wordCount; i++) {
    let word = PASSPHRASE_WORDS[randomIndices[i] % PASSPHRASE_WORDS.length];
    // Capitalize first letter
    word = word.charAt(0).toUpperCase() + word.slice(1);
    words.push(word);
  }

  if (includeNumber) {
    const randomNum = (new Uint8Array(1))[0] % 100;
    words[words.length - 1] += randomNum;
  }

  return words.join(separator);
}

export function calculatePasswordEntropy(password) {
  if (!password) return { bits: 0, rating: 'Empty', crackTime: 'Instant', color: '#ff3366' };

  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;

  if (poolSize === 0) poolSize = 1;

  const bits = Math.round(password.length * Math.log2(poolSize));

  let rating = 'Weak';
  let color = '#ff3366';
  let crackTime = '< 1 second';

  if (bits < 40) {
    rating = 'Vulnerable';
    color = '#ff3366';
    crackTime = 'Few seconds';
  } else if (bits < 60) {
    rating = 'Moderate';
    color = '#ffaa00';
    crackTime = 'Several weeks';
  } else if (bits < 80) {
    rating = 'Strong';
    color = '#00f0ff';
    crackTime = 'Several centuries';
  } else if (bits < 100) {
    rating = 'Very Strong';
    color = '#00ff88';
    crackTime = 'Millions of years';
  } else {
    rating = 'Military-Grade';
    color = '#00ff88';
    crackTime = 'Trillions of years (Quantum-Proof)';
  }

  return { bits, rating, crackTime, color };
}
