import assert from 'node:assert';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import db, { randomUUID } from '../server/db.mjs';
import {
  deriveMasterKeys,
  generateVek,
  encryptVek,
  decryptVek,
  encryptPayload,
  decryptPayload,
  createDefaultDecoyItems,
  getRandomHex,
} from '../public/js/crypto.js';
import { generateTotp } from '../public/js/totp.js';
import { generatePassword, calculatePasswordEntropy } from '../public/js/password-generator.js';
import { handleApiRequest } from '../server/routes.mjs';

console.log('\n================================================================');
console.log('       RUNNING AEGISVAULT MILITARY DEFENSE TEST SUITE           ');
console.log('================================================================\n');

async function runTests() {
  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      process.stdout.write(`[*] Testing: ${name}... `);
      await fn();
      console.log('\x1b[32mPASSED\x1b[0m');
      passed++;
    } catch (err) {
      console.log('\x1b[31mFAILED\x1b[0m');
      console.error(err);
      failed++;
    }
  }

  // TEST 1: Key Derivation Function (PBKDF2-SHA256)
  await test('Master Key Derivation (MEK & MAH Separation)', async () => {
    const password = 'TopSecretCommanderKey#2026!';
    const saltHex = getRandomHex(16);
    const { mek, authHash } = await deriveMasterKeys(password, saltHex, 10000); // 10k for test speed

    assert.ok(mek, 'MEK CryptoKey must be defined');
    assert.strictEqual(mek.type, 'secret', 'MEK must be a secret key');
    assert.strictEqual(mek.algorithm.name, 'AES-GCM', 'MEK algorithm must be AES-GCM');
    assert.ok(typeof authHash === 'string' && authHash.length === 64, 'MAH must be a 64-character SHA-256 hex string');
  });

  // TEST 2: VEK Generation, Encryption, and Decryption
  await test('Vault Encryption Key (VEK) Two-Tier Wrapping', async () => {
    const saltHex = getRandomHex(16);
    const { mek } = await deriveMasterKeys('MasterPass123$', saltHex, 5000);
    const { key: originalVek } = await generateVek();

    const encryptedVekJson = await encryptVek(originalVek, mek);
    const decryptedVek = await decryptVek(encryptedVekJson, mek);

    // Export raw bytes to verify identity
    const rawOriginal = await crypto.subtle.exportKey('raw', originalVek);
    const rawDecrypted = await crypto.subtle.exportKey('raw', decryptedVek);
    assert.deepStrictEqual(new Uint8Array(rawOriginal), new Uint8Array(rawDecrypted), 'Decrypted VEK must match original');
  });

  // TEST 3: Zero-Knowledge AES-256-GCM Payload Encryption
  await test('Zero-Knowledge Item Payload Encryption & Decryption', async () => {
    const { key: vek } = await generateVek();
    const sensitivePayload = {
      title: 'Defense Satellite Uplink',
      username: 'general_admin',
      password: 'NuclearLaunchCode!#998',
      url: 'https://satcom.defense.mil',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      notes: 'Emergency frequency 142.5 MHz',
      tags: ['satellite', 'classified'],
    };

    const encryptedString = await encryptPayload(sensitivePayload, vek);
    assert.ok(!encryptedString.includes('NuclearLaunchCode'), 'Plaintext must NEVER appear in ciphertext');
    assert.ok(!encryptedString.includes('general_admin'), 'Username must NEVER appear in ciphertext');

    const decrypted = await decryptPayload(encryptedString, vek);
    assert.deepStrictEqual(decrypted, sensitivePayload, 'Decrypted payload must exactly match original');
  });

  // TEST 4: Tamper Detection (AEAD Tag Verification)
  await test('Tamper Detection & Cryptographic Integrity', async () => {
    const { key: vek } = await generateVek();
    const payload = { secret: 'ClassifiedDocument' };
    const encryptedString = await encryptPayload(payload, vek);

    const parsed = JSON.parse(encryptedString);
    // Corrupt one character in the ciphertext
    const corruptedCt = parsed.ct.substring(0, 5) + (parsed.ct.charAt(5) === 'A' ? 'B' : 'A') + parsed.ct.substring(6);
    const corruptedPayload = JSON.stringify({ ct: corruptedCt, iv: parsed.iv });

    let threw = false;
    try {
      await decryptPayload(corruptedPayload, vek);
    } catch {
      threw = true;
    }
    assert.ok(threw, 'Decryption of tampered ciphertext MUST throw an authentication failure');
  });

  // TEST 5: RFC 6238 TOTP Engine
  await test('RFC 6238 TOTP Engine 2FA Code Generation', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const result = await generateTotp(secret, 1700000000000);
    assert.ok(result, 'TOTP result must not be null');
    assert.strictEqual(typeof result.token, 'string');
    assert.strictEqual(result.token.length, 6, 'TOTP code must be 6 digits');
    assert.ok(/^\d{6}$/.test(result.token), 'TOTP code must contain only numbers');
    assert.ok(result.remainingSeconds >= 1 && result.remainingSeconds <= 30, 'Remaining seconds must be between 1 and 30');
  });

  // TEST 6: Password Generator & Entropy Meter
  await test('Military Password Generator & Entropy Meter', async () => {
    const pwd = generatePassword({ length: 32, useUpper: true, useLower: true, useNumbers: true, useSymbols: true });
    assert.strictEqual(pwd.length, 32, 'Password length must be 32 characters');

    const entropy = calculatePasswordEntropy(pwd);
    assert.ok(entropy.bits >= 90, `32-char password should have >=90 bits of entropy (got ${entropy.bits})`);
    assert.strictEqual(entropy.rating, 'Military-Grade', 'Should be rated Military-Grade');
  });

  // TEST 7: Duress Decoy Sector Isolation
  await test('Duress Coercion Mode Isolation (Option A)', async () => {
    const { key: duressVek } = await generateVek();
    const decoys = await createDefaultDecoyItems(duressVek);
    assert.ok(decoys.length >= 3, 'At least 3 decoy accounts generated');

    // Verify first decoy decrypts to realistic benign data
    const firstDecoy = await decryptPayload(decoys[0].encryptedPayload, duressVek);
    assert.ok(firstDecoy.title.includes('Library'), 'Decoy item should be benign library card');
  });

  // TEST 8: Full User Registration & Login Workflow
  await test('Zero-Knowledge User Registration & Authentication API', async () => {
    const testUser = `soldier_${Date.now()}`;
    const kdfSalt = getRandomHex(16);
    const authSalt = getRandomHex(16);
    const { mek, authHash } = await deriveMasterKeys('StrongMasterPass!2026', kdfSalt, 5000);
    const { key: vek } = await generateVek();
    const encryptedVek = await encryptVek(vek, mek);

    // Setup Duress PIN: "4321"
    const duressSalt = getRandomHex(16);
    const { mek: duressMek, authHash: duressAuthHash } = await deriveMasterKeys('4321', duressSalt, 5000);
    const { key: duressVek } = await generateVek();
    const duressEncryptedVek = await encryptVek(duressVek, duressMek);
    const decoyItems = await createDefaultDecoyItems(duressVek);

    // Mock HTTP Request/Response for API test
    function createMockRes() {
      return {
        status: 200,
        headers: {},
        data: '',
        writeHead(s, h) { this.status = s; Object.assign(this.headers, h); },
        end(d) { this.data = d; },
      };
    }

    function createMockReq(method, path, body = null, headers = {}) {
      const req = new EventEmitter();
      req.method = method;
      req.headers = { host: 'localhost:8443', ...headers };
      req.socket = { encrypted: true, remoteAddress: '127.0.0.1' };
      setImmediate(() => {
        if (body) req.emit('data', Buffer.from(JSON.stringify(body)));
        req.emit('end');
      });
      return req;
    }

    // 1. Register User
    const regReq = createMockReq('POST', '/api/auth/register', {
      username: testUser,
      authSalt,
      authHash,
      kdfSalt,
      kdfIterations: 5000,
      encryptedVek,
      duressSalt,
      duressHash: duressAuthHash,
      duressEncryptedVek,
      decoyItems,
    });
    const regRes = createMockRes();
    await handleApiRequest(regReq, regRes, '/api/auth/register', new URLSearchParams());
    assert.strictEqual(regRes.status, 200, 'Registration must succeed with status 200');
    const regBody = JSON.parse(regRes.data);
    assert.strictEqual(regBody.success, true);
    const sessionToken = regBody.sessionToken;

    // 2. Normal Login
    const loginReq = createMockReq('POST', '/api/auth/login', { username: testUser, authHash });
    const loginRes = createMockRes();
    await handleApiRequest(loginReq, loginRes, '/api/auth/login', new URLSearchParams());
    assert.strictEqual(loginRes.status, 200, 'Login must succeed with status 200');
    const loginBody = JSON.parse(loginRes.data);
    assert.strictEqual(loginBody.isDuress, false, 'Normal login must have isDuress = false');

    // 3. Duress Login (Entering "4321" PIN)
    const duressReq = createMockReq('POST', '/api/auth/login', { username: testUser, authHash: duressAuthHash });
    const duressRes = createMockRes();
    await handleApiRequest(duressReq, duressRes, '/api/auth/login', new URLSearchParams());
    assert.strictEqual(duressRes.status, 200, 'Duress login must succeed');
    const duressBody = JSON.parse(duressRes.data);
    assert.strictEqual(duressBody.isDuress, true, 'Duress PIN must activate isDuress = true decoy mode');

    // 4. Create Item in Real Vault
    const encTitle = await encryptPayload({ title: 'Top Secret Real Server' }, vek);
    const encPayload = await encryptPayload({ title: 'Top Secret Real Server', password: 'RealSecretPassword' }, vek);
    const addReq = createMockReq('POST', '/api/vault', {
      encryptedTitle: encTitle,
      category: 'Infrastructure',
      encryptedPayload: encPayload,
      isFavorite: true,
    }, { authorization: `Bearer ${sessionToken}` });
    const addRes = createMockRes();
    await handleApiRequest(addReq, addRes, '/api/vault', new URLSearchParams());
    assert.strictEqual(addRes.status, 201, 'Item creation must succeed');

    // 5. Read Real Vault Items
    const getReq = createMockReq('GET', '/api/vault', null, { authorization: `Bearer ${sessionToken}` });
    const getRes = createMockRes();
    await handleApiRequest(getReq, getRes, '/api/vault', new URLSearchParams());
    const realItems = JSON.parse(getRes.data);
    assert.ok(realItems.length >= 1, 'Real vault must contain the created item');

    // 6. Read Duress Vault Items (must see ONLY decoy items, NEVER real item!)
    const duressSessionToken = duressBody.sessionToken;
    const getDuressReq = createMockReq('GET', '/api/vault', null, { authorization: `Bearer ${duressSessionToken}` });
    const getDuressRes = createMockRes();
    await handleApiRequest(getDuressReq, getDuressRes, '/api/vault', new URLSearchParams());
    const duressItems = JSON.parse(getDuressRes.data);

    assert.ok(duressItems.length >= 3, 'Duress vault must contain the 3 decoy items');
    for (const dItem of duressItems) {
      assert.notStrictEqual(dItem.encrypted_payload, encPayload, 'Decoy vault must NEVER contain real vault items!');
    }
  });

  // TEST 9: Encrypted .vault Backup Export & Emergency Decryptor
  await test('Encrypted .vault Backup Export & Disaster Recovery Decryption', async () => {
    const masterPassword = 'MyUltraSecureVaultPass2026!';
    const kdfSalt = getRandomHex(16);
    const authSalt = getRandomHex(16);
    const iterations = 10000; // fast iterations for test

    const { mek, authHash } = await deriveMasterKeys(masterPassword, kdfSalt, iterations);
    const { key: vek } = await generateVek();
    const encryptedVek = await encryptVek(vek, mek);

    // Encrypt sensitive user credentials
    const credentials = [
      { id: '1', title: 'Google Mail', username: 'alex@gmail.com', password: 'SuperSecretGooglePassword!1', url: 'https://gmail.com', notes: 'Personal primary' },
      { id: '2', title: 'Bank Account', username: 'alex_bank', password: 'BankingPassword#7788', url: 'https://bank.com', notes: 'Checking acct' },
    ];

    const encryptedItems = [];
    for (const cred of credentials) {
      const encryptedPayload = await encryptPayload(cred, vek);
      encryptedItems.push({ id: cred.id, encrypted_payload: encryptedPayload });
    }

    // Package into .vault format
    const vaultBackup = {
      format: 'aegis-encrypted-vault',
      version: '1.0',
      username: 'alex',
      kdfSalt,
      kdfIterations: iterations,
      authSalt,
      authHash,
      encryptedVek,
      items: encryptedItems,
      exportedAt: new Date().toISOString(),
    };

    // Serialize to JSON file string (simulating .vault file on disk or email attachment)
    const vaultFileContent = JSON.stringify(vaultBackup);
    const parsedFile = JSON.parse(vaultFileContent);

    // 1. Attempt decryption with WRONG password -> must throw authentication error
    let wrongPassThrew = false;
    try {
      const wrongKeys = await deriveMasterKeys('WrongPassword!', parsedFile.kdfSalt, parsedFile.kdfIterations);
      await decryptVek(parsedFile.encryptedVek, wrongKeys.mek);
    } catch {
      wrongPassThrew = true;
    }
    assert.strictEqual(wrongPassThrew, true, 'Decryption with wrong password MUST fail AEAD tag check');

    // 2. Attempt decryption with CORRECT password -> must succeed and recover exact data
    const recoveredKeys = await deriveMasterKeys(masterPassword, parsedFile.kdfSalt, parsedFile.kdfIterations);
    assert.strictEqual(recoveredKeys.authHash, parsedFile.authHash, 'Derived authHash must match vault file');

    const recoveredVek = await decryptVek(parsedFile.encryptedVek, recoveredKeys.mek);
    const recoveredItems = [];
    for (const item of parsedFile.items) {
      const decrypted = await decryptPayload(item.encrypted_payload, recoveredVek);
      recoveredItems.push(decrypted);
    }

    assert.strictEqual(recoveredItems.length, 2, 'Must recover exactly 2 credentials');
    assert.strictEqual(recoveredItems[0].title, 'Google Mail');
    assert.strictEqual(recoveredItems[0].password, 'SuperSecretGooglePassword!1');
    assert.strictEqual(recoveredItems[1].title, 'Bank Account');
    assert.strictEqual(recoveredItems[1].password, 'BankingPassword#7788');
  });

  // TEST 10: ECDH Cross-Device Handshake & Zero-Knowledge Vault Transfer
  await test('ECDH Cross-Device Handshake & E2E Encrypted Vault Transfer', async () => {
    // 1. Target device (e.g. Laptop) generates ephemeral ECDH P-256 keypair
    const targetKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
    const targetPubKeyRaw = await crypto.subtle.exportKey('raw', targetKeyPair.publicKey);

    // 2. Primary device (e.g. iPhone) generates ephemeral ECDH P-256 keypair
    const phoneKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
    const phonePubKeyRaw = await crypto.subtle.exportKey('raw', phoneKeyPair.publicKey);

    // 3. Both devices import each other's public key
    const importedTargetPub = await crypto.subtle.importKey(
      'raw',
      targetPubKeyRaw,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );
    const importedPhonePub = await crypto.subtle.importKey(
      'raw',
      phonePubKeyRaw,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    // 4. Derive shared secrets (Diffie-Hellman)
    const phoneSharedKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: importedTargetPub },
      phoneKeyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const targetSharedKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: importedPhonePub },
      targetKeyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // 5. Phone prepares vault payload with VEK and encrypted credentials
    const { key: userVek } = await generateVek();
    const rawVek = await crypto.subtle.exportKey('raw', userVek);

    const secretCred = {
      title: 'Secret Service Portal',
      username: 'agent007',
      password: 'LicenseToEncrypt!2026',
    };
    const encryptedItemPayload = await encryptPayload(secretCred, userVek);

    const vaultPayload = {
      username: 'agent007',
      rawVek: Buffer.from(rawVek).toString('base64url'),
      items: [{ id: 'cred-007', encrypted_payload: encryptedItemPayload }],
    };

    // 6. Phone encrypts payload with shared key (AES-256-GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(vaultPayload));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      phoneSharedKey,
      plaintext
    );

    // 7. Target device decrypts ciphertext with its shared key
    const decryptedBytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      targetSharedKey,
      ciphertext
    );
    const decryptedPayload = JSON.parse(new TextDecoder().decode(decryptedBytes));

    assert.strictEqual(decryptedPayload.username, 'agent007');
    assert.strictEqual(decryptedPayload.items.length, 1);

    // 8. Target imports transmitted VEK and successfully decrypts the credential item
    const targetVek = await crypto.subtle.importKey(
      'raw',
      Buffer.from(decryptedPayload.rawVek, 'base64url'),
      { name: 'AES-GCM', length: 256 },
      true,
      ['decrypt']
    );

    const recoveredItem = await decryptPayload(decryptedPayload.items[0].encrypted_payload, targetVek);
    assert.strictEqual(recoveredItem.title, 'Secret Service Portal');
    assert.strictEqual(recoveredItem.password, 'LicenseToEncrypt!2026');

    // 9. Negative test: Third party / eavesdropper without target private key CANNOT decrypt
    const eavesdropperKey = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey']
    );
    const eavesdropperShared = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: importedPhonePub },
      eavesdropperKey.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    let eavesdropThrew = false;
    try {
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, eavesdropperShared, ciphertext);
    } catch {
      eavesdropThrew = true;
    }
    assert.strictEqual(eavesdropThrew, true, 'Eavesdropper MUST fail AES-GCM AEAD decryption tag verification');
  });

  console.log('\n================================================================');
  console.log(`TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
  console.log('================================================================\n');

  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
