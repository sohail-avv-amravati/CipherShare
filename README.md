# CipherShare — Zero-Trust Encrypted Storage & Expiration File Sharing

CipherShare is a server-side rendered web application for authenticated AES-256-GCM file encryption, zero-email password recovery using a 500-question pool, and server-enforced file sharing expiration built completely from scratch using **PHP**, **SQLite**, **HTML**, and **CSS**.

---

## 🌟 Key Features & Strict Architecture

- **Zero JavaScript**: 100% pure server-side HTML/CSS rendering. Zero `.js` files, zero inline JavaScript, zero AJAX, and zero client scripting.
- **Zero Email / REST API / External AI**: Authentication relies solely on `USERNAME` + `PASSWORD` + 5 assigned Security Questions. No SMTP, Brevo, OTP, REST routes (`/api/...`), or AI dependencies.
- **500 Security Questions System**: Dedicated DB pool initialized with exactly 500 active practical security questions.
- **Permanent 5-Question Binding**: 5 questions are randomly selected during registration and permanently bound to the user. During password reset, only display order is randomized. All 5 answers must be verified.
- **AES-256-GCM Authenticated Encryption**: Modern symmetric file container protection using PBKDF2 key derivation.
- **Educational Classical Ciphers**: Includes 11 classical ciphers (Caesar, Playfair, Vigenère, Hill, Transposition, etc.) clearly labeled for academic learning.
- **Server-Enforced Share Expiration**: Expiration deadlines (30m to 1d) are verified strictly against server time. Unaccessed expired shares transition to `FAILED` with exact reason: *"Recipient did not access the file before the expiration time."* Original sender file remains intact.
- **Owner Portal & Privacy**: Owner can manage platform health and user account statuses (ACTIVE, SUSPENDED, DEACTIVATED). Owner CANNOT access user passwords, hashes, security answers, encryption keys, or file contents.
- **Responsive Cybersecurity UI**: Cybersecurity dark theme with sky-blue accents and pure CSS mobile navigation.

---

## 📂 Project Structure

```
CipherShare/
│
├── config/
│   └── config.php                # System configuration & helper functions
│
├── database/
│   ├── schema.sql                # SQLite database DDL schema
│   └── ciphershare.sqlite        # SQLite database file
│
├── public/                       # Web Root
│   ├── index.php                 # Landing page
│   ├── register.php              # Account registration (Username + 5 Questions)
│   ├── login.php                 # User login
│   ├── logout.php                # Session destruction
│   ├── forgot-password.php       # Step 1 Password Reset
│   ├── reset-password.php        # Step 2 Verification & New Password
│   ├── dashboard.php             # User Dashboard
│   ├── files.php                 # My Files view & management
│   ├── upload.php                # File upload form
│   ├── encrypt.php               # AES-256-GCM & Classical Cipher tool
│   ├── decrypt.php               # AES-256-GCM decryption engine
│   ├── shares.php                # Share file form
│   ├── sent-shares.php           # Sent shares tracker
│   ├── received-shares.php       # Received shares & download portal
│   ├── account.php               # Account settings & password change
│   ├── static/
│   │   └── css/style.css         # Responsive pure CSS stylesheet
│   └── owner/
│       ├── login.php             # Owner portal login
│       ├── dashboard.php         # Owner overview dashboard
│       ├── users.php             # User management (Suspend/Reactivate)
│       ├── files.php             # File storage statistics
│       ├── shares.php            # File share statistics
│       ├── security.php          # Security indicators & events
│       └── audit.php             # Immutable audit log view
│
├── src/                          # Core Classes
│   ├── Auth/AuthManager.php
│   ├── Crypto/AES256GCM.php
│   ├── Crypto/ClassicalCiphers.php
│   ├── Database/Database.php
│   ├── Files/FileManager.php
│   ├── Owner/OwnerManager.php
│   ├── Security/AuditLogger.php
│   ├── Security/CSRF.php
│   ├── Security/SecurityQuestions.php
│   └── Shares/ShareManager.php
│
├── storage/                      # File Storage Directories
│   ├── uploads/                  # Raw uploaded files
│   ├── encrypted/                # AES-256-GCM encrypted containers
│   └── temporary/                # Scratch upload directory
│
├── scripts/
│   ├── init_db.php               # Database schema & 500 questions seeder
│   └── init_owner.php            # Owner account CLI initialization tool
│
├── templates/                    # Component Templates (Header, Footer, Nav)
├── tests/                        # Automated PHP Test Suite
├── .gitignore
├── .env.example
└── README.md
```

---

## 🚀 Running CipherShare Locally

### 1. Requirements
- **PHP 8.0+** with `pdo_sqlite`, `openssl`, `mbstring` enabled.
- **SQLite3**.

### 2. Database & Owner Initialization
Run the initialization scripts using PHP CLI:
```cmd
php scripts/init_db.php
php scripts/init_owner.php --username=admin_owner --password=CipherOwner#2026
```

### 3. Launch PHP Development Server
Start PHP's built-in development server pointing to the `public/` directory:
```cmd
php -S 127.0.0.1:8000 -t public
```

Open your browser and navigate to:
[http://127.0.0.1:8000](http://127.0.0.1:8000)

---

## 🧪 Running Automated Tests

Run the full test suite verifying authentication, 500 questions, password reset, AES-256-GCM encryption, classical ciphers, sharing expiration, owner controls, and security audit:
```cmd
php tests/run_tests.php
```

---

## 🛡️ Security Model & Privacy

- **Zero-Trust Administrative Safeguards**: The owner cannot read user files, view decryption keys, view password hashes, or read security answer hashes.
- **Cryptographic Security**: Passwords are hashed using PHP's native `password_hash()` (bcrypt/argon2). Security answers are trimmed, lowercased, and hashed with `password_hash()`.
- **File Container Authenticated Encryption**: AES-256-GCM with PBKDF2 (10,000 iterations SHA-256) key derivation.
- **CSRF & Rate Limiting**: All POST forms include CSRF tokens. Login attempts and password reset attempts are rate-limited to block brute-force guessing.
