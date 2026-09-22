# Offline Password Vault

A local-only password generator and encrypted password vault written in Python.

The app generates strong passwords with Python's `secrets` module and stores saved credentials in an AES-256-GCM encrypted vault on your machine. It does not use a server and does not transmit passwords anywhere.

## Features

- Strong random password generation
- Encrypted offline password storage
- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256 key derivation with 600,000 iterations
- Master password validation
- Save, list, reveal, update, and delete credentials
- Optional TOTP secret storage with QR code setup
- Atomic vault writes
- Legacy v2 vault read support
- Vault files ignored by Git

## Install

```bash
pip install -r requirements.txt
```

## Quick start

Create your encrypted local vault:

```bash
python main.py setup
```

Generate a strong password without saving it:

```bash
python main.py generate --length 24
```

Save a generated password for a service:

```bash
python main.py add github --username your_email@example.com
```

List saved services without revealing passwords:

```bash
python main.py list
```

Reveal a saved password:

```bash
python main.py get github --reveal
```

Delete a saved password:

```bash
python main.py delete github
```

Run the interactive menu:

```bash
python main.py
```

## Desktop app

Launch the desktop password assistant:

```bash
python desktop_app.py
```

The desktop app can stay always-on-top, suggest a fresh strong password while you type a service name, copy passwords to the clipboard, clear copied passwords after 30 seconds, and save selected passwords into the same encrypted offline vault.

It does not watch other apps or browser tabs automatically. That is intentional: automatic app/browser monitoring would need accessibility permissions or a browser extension, which is a larger privacy and security decision.
## TOTP

Add a TOTP secret and show a QR code for an existing saved service:

```bash
python main.py totp setup github
```

Print the current TOTP code:

```bash
python main.py totp code github
```

## Vault location

By default, the vault is stored outside the repo at:

```text
~/.password_vault/vault.enc
```

Use a custom vault path with `--vault`:

```bash
python main.py --vault ./my-vault.enc setup
python main.py --vault ./my-vault.enc add email --username me@example.com
```

Vault files (`*.enc`, temporary encrypted files, and `salt.bin`) are ignored by Git so saved passwords remain local.

## Run tests

```bash
python -m unittest
```

## Security notes

- Use a unique master password that you do not use anywhere else.
- Back up your vault file; if it is deleted, the saved passwords cannot be recovered.
- If you forget the master password, the encrypted vault cannot be unlocked.
- Revealing passwords prints them to your terminal, so avoid doing it while screen sharing.
