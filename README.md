# Manage that Password

ICS0027 Web Application Security: final project (TalTech).

A web-based password manager where **encryption happens in the browser**. The server stores only ciphertext, so a stolen database does not expose anyone's passwords. Built with Flask, SQLite and the browser's WebCrypto API.

## Features

- Register and log in with a master password (never sent to the server)
- Store, edit, delete and copy credentials; built-in random password generator
- Per-user encrypted vault (AES-256-GCM)
- Server-side sessions with 15-minute idle timeout, rotation on login and real logout
- Logging of security events
- Strict Content-Security-Policy and other security headers

## Architecture

```
Browser (static/app.js)  <--HTTPS/JSON-->  Flask (app.py)  <-->  SQLite (vault.db)
 key derivation, AES-GCM                   auth, sessions,        users, sessions,
 encrypt / decrypt, UI                     access control,        credentials
                                           validation, logging    (ciphertext only)
```

## Cryptographic design

1. The master password is run through **PBKDF2-SHA256** (600,000 iterations, random 16-byte salt) in the browser to produce a master key.
2. **HKDF** splits the master key into two independent keys:
   - **auth key**: sent to the server, which stores only `Argon2id(auth_key)`.
   - **AES key**: never leaves the browser; non-extractable and held only in memory.
3. Each credential is encrypted with **AES-256-GCM** using a fresh random 12-byte IV. The server stores `iv` + `ciphertext`.
4. GCM's authentication tag means a modified ciphertext fails to decrypt.

Why two keys: if one key served both purposes, the server would receive what it needs to decrypt the vault.
Why PBKDF2 in the browser: WebCrypto supports PBKDF2 and HKDF but not Argon2, so Argon2id is applied server-side to the auth key.

## Security controls (OWASP Top 10:2025)

| Risk | Control |
|---|---|
| A01 Broken Access Control | `user_id` in every credential query; other users' IDs return 404 |
| A02 Security Misconfiguration | Debug off, CSP and security headers, `Secure`/`HttpOnly`/`SameSite=Strict` cookie |
| A03 Supply Chain Failures | Three dependencies, versions pinned with `pip freeze` |
| A04 Cryptographic Failures | AES-256-GCM, PBKDF2 (600k), Argon2id; no plaintext in the database |
| A05 Injection | Parameterized SQL, `textContent` instead of `innerHTML`, CSP |
| A06 Insecure Design | Zero-knowledge design; encryption key never sent to the server |
| A07 Authentication Failures | Argon2id, lockout, session rotation, idle timeout, fake salt for unknown users |
| A08 Integrity Failures | GCM authentication, server-side validation, ownership checks, CSRF token |
| A09 Logging Failures | `security.log` records logins, failures and lockouts, never secrets |
| A10 Exceptional Conditions | Generic error responses; details only in the server log |

## Project structure

```
app.py                 Flask backend: routes, sessions, Argon2id, headers, logging
requirements.txt       Pinned dependencies
templates/index.html   Single page: login and vault
static/app.js          All cryptography and UI logic
static/style.css       Styling (no inline CSS or JS, so the CSP stays strict)
```

## Setup

Requires Python 3.11+ and Git.

```bash
git clone https://github.com/Xnogst/ics0027
cd ics0027
python -m venv venv
source venv/bin/activate          # Windows Git Bash: source venv/Scripts/activate
pip install -r requirements.txt
```

## Run

```bash
flask --app app run --cert adhoc
```

Open https://localhost:5000 and accept the self-signed certificate warning. HTTPS is required because the session cookie is `Secure` and WebCrypto needs a secure context. Do not run with `--debug`.

The first start creates `vault.db`, `security.log` and `.app_secret`. All three are git-ignored and must never be committed.

## Manual security tests

1. **No plaintext stored:** inspect `credentials` in `vault.db`; only base64 `iv` and `ciphertext` appear.
2. **Unauthenticated access:** `curl -k -i https://localhost:5000/api/credentials` returns 401.
3. **IDOR:** as user B, `DELETE /api/credentials/<user A's id>` returns 404.
4. **CSRF:** a POST without the `X-CSRF-Token` header returns 403.
5. **Lockout:** 5 wrong passwords lock the account; see `security.log`.
6. **XSS:** an entry named `<img src=x onerror=alert(1)>` is displayed as plain text.
7. **Headers:** `curl -kI https://localhost:5000/` shows CSP, HSTS and `nosniff`.
8. **Errors:** `curl -k -i https://localhost:5000/api/credentials/abc` returns a generic JSON error.

## Limitations

- There is no master-password recovery by design: a lost master password means a lost vault.
- As with any web-based vault, a compromised server could serve malicious JavaScript; the strict CSP and absence of `innerHTML` reduce, but do not remove, this risk.
- Lockout is per account (it can be abused to lock out a known username); there is no per-IP rate limiting.
- The development certificate is self-signed; a real deployment needs a trusted certificate and a production server (for example gunicorn or waitress).
- Not yet implemented: TOTP multi-factor authentication, export/import.
- The server still sees usernames, entry counts, ciphertext sizes and timestamps.

## Author

Kaan Metin, TalTech.
