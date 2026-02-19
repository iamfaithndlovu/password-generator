# 🔐 Enterprise Password Vault v1.0

A cross-platform, production-grade local password vault built in Python using modern cryptographic standards.

This application provides secure password generation, encrypted credential storage, and Time-based One-Time Password (TOTP) multi-factor authentication support — all stored locally using AES-256-GCM authenticated encryption.

---

## 🚀 Features

- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256 key derivation (600,000 iterations)
- Secure password generation
- TOTP 2FA setup with QR code provisioning
- Auto-lock timeout protection
- Secure in-memory credential wipe
- Atomic vault writes (Windows-safe)
- Cross-platform compatibility (Windows / macOS / Linux)

---

## 🔒 Security Architecture

| Component              | Implementation |
|------------------------|----------------|
| Encryption Algorithm   | AES-256-GCM    |
| Key Derivation         | PBKDF2-HMAC-SHA256 |
| KDF Iterations         | 600,000        |
| Nonce Length           | 96-bit         |
| Salt Length            | 128-bit        |
| Authentication         | AEAD Tag Verification |
| 2FA                    | RFC 6238 TOTP  |

All credentials are encrypted locally and never transmitted externally.

---

## 📦 Dependencies

Install required packages before running:

```bash
pip install cryptography pyotp qrcode-terminal
