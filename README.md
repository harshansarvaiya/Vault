# ⚡ KŪṬA-X (कूट·X) // Ancient Cipher • Quantum Matrix

**KŪṬA-X** (*Kūṭa* [कूट]: Sanskrit for sacred cipher & unbreakable code) is a zero-knowledge, end-to-end encrypted (E2EE) identity and password matrix fusing **ancient Vedic cryptographic philosophy** with **far-future sci-fi tech**. Featuring **1-Touch Drishti Glance (Face ID / WebAuthn Biometrics)**, **Quantum QR Device Handshake ("Scan to Unlock")**, **Duress Coercion Decoy**, and immediate **Disaster & Theft Recovery**.

---

## ⚡ Quick Start

### 1. Launch the Defense Core

You can launch AegisVault using any of the following:

- **Double click:** `start.bat`
- **Or via PowerShell:** `./start.ps1`
- **Or directly via CLI:**
  ```powershell
  agy-node server/server.mjs
  ```

### 2. Access the Application

Once launched, AegisVault runs dual listeners:

- **💻 Desktop Browser Access (Passkeys & Biometrics Ready):**  
  [https://localhost:8443](https://localhost:8443) *(or standard [http://localhost:3000](http://localhost:3000))*

- **📱 Mobile Smartphone Access (iOS Safari & Android Chrome):**  
  `https://<LAN-IP>:8443` (e.g. `https://192.168.1.11:8443`)  
  *Open this link on your smartphone connected to the same Wi-Fi. You can also click the **Mobile Pair (QR)** button on the desktop header to scan the QR code with your phone camera!*

- **📲 Install as Standalone Mobile App (PWA):**
  - **iPhone / iPad:** In Safari, tap **Share** > **Add to Home Screen**.
  - **Android:** In Chrome, tap the menu (⋮) > **Install app** or **Add to Home screen**.
  - The app will run in full-screen standalone mode without any browser URL bars.

---

## 🔒 Military-Grade Security Architecture

### 1. Zero-Knowledge E2EE Cryptography
- **Client-Side Key Derivation:** Uses **PBKDF2 with SHA-256 and 600,000 rounds** (exceeding OWASP guidance) to derive the **Master Encryption Key (MEK)** and **Master Authentication Hash (MAH)**.
- **Cryptographic Separation:** The authentication proof sent to the server is derived independently from the encryption key using cryptographically separated domains. Even if the server database is compromised, the attacker cannot decrypt vault data.
- **Authenticated Cipher:** Every entity is individually encrypted using **AES-256-GCM (AEAD)** with a fresh, cryptographically random 96-bit Initialization Vector (`crypto.getRandomValues`).
- **Two-Tier Key Hierarchy:** The 256-bit Vault Encryption Key (VEK) is wrapped by the Master Key, enabling rapid password changes and multi-passkey unlocking without re-encrypting the entire database.

### 2. Futuristic Authentication & Passkeys
- **FIDO2 / WebAuthn Biometrics:** 1-touch passwordless biometric unlocking via **Face ID**, **Touch ID**, **Windows Hello**, and **YubiKey** hardware tokens.
- **Self-Contained FIDO2 Server:** Native CBOR decoding, attestation validation, and ECDSA P-256 / RSA cryptographic signature verification using Node.js standard libraries.

### 3. Duress Coercion Defense (Option A Decoy Sector)
- **Stealth Protection:** If an operator is forced under coercion or threat to unlock the vault, entering the **Duress PIN** instead of the Master Password seamlessly unlocks an authentic-looking **Decoy Vault** populated with realistic accounts (library cards, gym membership, coffee loyalty).
- **Physical Partitioning:** The decoy vault operates on a distinct encryption key and database partition. The adversary believes they gained full access, while real classified credentials remain encrypted and invisible.

### 4. Integrated RFC 6238 TOTP Authenticator
- Built-in 2FA authenticator engine computing live 6-digit rolling codes from Base32 secrets.
- Animated circular progress indicator with 30-second live refresh.

### 5. Anti-Tamper & Ephemeral Hardening
- **Clipboard Sanitization:** Copying any password or identifier automatically schedules a 30-second wipe timer that cleanses the system clipboard.
- **Inactivity Auto-Lock:** Automatically zeroes cryptographic keys from memory and locks the vault after 5 minutes of inactivity.
- **Privacy Shield:** Automatically blurs and obscures sensitive vault contents when the browser window loses focus or the tab is switched.
- **Entropy Password Generator:** High-entropy random passwords (up to 128 characters) and Diceware passphrases with live bit-entropy calculations and crack-time estimations.
- **Security Audit Scanner:** Scans the decrypted vault for weak, reused, or missing-2FA credentials.

---

## 🛠️ Technology Stack (Zero-External-Dependencies)

- **Backend:** Node.js 24 (`agy-node`) using built-in standard modules:
  - `node:sqlite`: High-performance embedded SQLite database (`DatabaseSync`) with WAL mode.
  - `node:https` & `node:http`: Dual secure listener with dynamic self-signed X.509 v3 SAN TLS generation.
  - `node:crypto`: Native cryptographic operations, scrypt verifiers, and ECDSA signature checks.
- **Frontend:** Pure Modern Vanilla ES Modules, Web Crypto API (`window.crypto.subtle`), WebAuthn API, Responsive Cyber HUD CSS3, and PWA Service Worker.

---

## 🧪 Automated Verification Suite

Run the full automated cryptographic and API test suite:

```powershell
agy-node tests/crypto_and_api_test.mjs
```

**Test Coverage:**
- Master Key Derivation (MEK & MAH domain separation)
- VEK two-tier wrapping and unwrapping
- Zero-knowledge payload encryption & tamper detection (AEAD tag check)
- RFC 6238 TOTP code generation accuracy
- Military password generator & entropy scoring
- Duress decoy sector physical isolation
- Full registration, login, and CRUD API workflows
