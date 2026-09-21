# ics0027
# Web-Based Secure Password Manager

A secure web application for managing personal login credentials, created for the ICS0027 Web Application Security course[cite: 1].

---

## Scope and Features

### In-Scope Features
* **User Accounts:** Registration and authentication using an email and a master password[cite: 1].
* **Vault Operations:** Creating, viewing, editing, and deleting login items containing a title, login name, and password[cite: 1].
* **Session Management:** Server-side sessions where the derived vault key exists strictly in temporary server memory[cite: 1].
* **Optional Multi-Factor Authentication:** Two-factor authentication using TOTP authenticator codes[cite: 1].

### Out-of-Scope Features
* Folders and sub-categories[cite: 1].
* Multiple web addresses per item[cite: 1].
* Password history and credential sharing[cite: 1].
* Changing the master password[cite: 1].
* Browser extensions[cite: 1].
* Account recovery or password reset mechanisms, because the key protecting the vault is derived from the master password and no copy is retained[cite: 1].

---

## Planned Application Routes

* `POST /register`: Registers a new account with an email and master password[cite: 1].
* `POST /login`: Authenticates credentials, derives the vault key into memory, and creates a session[cite: 1].
* `POST /logout`: Terminates the server session and wipes the vault key from memory[cite: 1].
* `GET /items`: Fetches and displays the decrypted login items for the authenticated owner[cite: 1].
* `POST /items/new`: Encrypts credentials with AES-256-GCM and saves a new entry[cite: 1].
* `POST /items/<id>/edit`: Re-encrypts and updates an existing item owned by the user[cite: 1].
* `POST /items/<id>/delete`: Removes an owned vault item from the database[cite: 1].
* `POST /mfa/setup`: Sets up optional TOTP multi-factor authentication[cite: 1].

---

## How to Run Locally

### Prerequisites
* Python 3.12[cite: 1].
* `mkcert` for generating trusted local HTTPS certificates[cite: 1].

### Setup Steps

1. **Clone the repository and enter the project directory:**
   ```bash
   git clone [https://github.com/sebasp-9/ics0027.git](https://github.com/sebasp-9/ics0027.git)
   cd ics0027
