# Safespace

**SafeSpace** is a web application, similar to Twitter, built with a security-first mindset. While its feature set is minimal, the primary focus is on implementing robust security controls at every layer of the stack, from the web server configuration down to the cryptographic handling of data.

This project serves as a demonstration of how to build a web application that prioritizes user safety, data integrity, and resilience against common web vulnerabilities and attacks.

## Table of Contents

- [Safespace](#safespace)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
    - [Security Highlights](#security-highlights)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Building \& running](#building--running)
  - [Usage Examples](#usage-examples)
  - [Design \& Implementation Details](#design--implementation-details)
    - [Authentication \& Access Control](#authentication--access-control)
    - [Cryptography \& Data Integrity](#cryptography--data-integrity)
    - [Infrastructure \& Server Hardening](#infrastructure--server-hardening)
    - [Application Security](#application-security)
  - [Development Tasks \& Roadmap](#development-tasks--roadmap)

-----

## Features

SafeSpace implements the core features of a microblogging platform, with security integrated at every step.

- **User Accounts**: Secure registration, login, and password management.
- **Microblogging ("Tweets")**: Users can create short text posts (up to 140 characters) and optionally attach an image.
- **Profile Pages**: View a user's profile and all their posts.
- **Post Signatures**: Users can cryptographically sign their posts to prove authorship and integrity.
- **File Uploads**: Supports image uploads for posts and `.pem` files for public/private keys, with all uploads scanned for malware.

### Security Highlights

- **State-of-the-Art Password Hashing**: Passwords are hashed using **Argon2id** with strong, recommended parameters (https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice).
- **Mandatory Two-Factor Authentication (2FA)**: **TOTP** is required for all accounts, enforced at login and for sensitive actions like password changes.
- **Digitally Signed Posts**: Posts can be signed with RSA-PSS and SHA-512 to guarantee authenticity and integrity.
- **Comprehensive Security Headers**: Nginx is configured with HSTS, CSP, X-Frame-Options, and more to protect against a wide range of web attacks.
- **Infrastructure Hardening**: The application is served via Nginx and uWSGI with rate limiting, connection limiting, and automatic worker recycling for resilience.
- **Antivirus Scanning**: All user-uploaded files are scanned by `ClamAV` before being processed.
- **Input Sanitization**: User-generated content is sanitized with `Bleach` to prevent XSS attacks.
- **Privacy-Preserving Email Storage**: User emails are hashed in the database to protect user privacy.
- **Password Suggestion**: Informing user of password's strength via `zxcvbn`.

-----

## Getting Started

The entire application stack is containerized with Docker, simplifying setup and deployment.

### Prerequisites

- **Docker** and **Docker Compose**

### Building & running

In the root of the project, run the following command to build and run the Docker image:

```bash
docker-compose up --build
```

The application will be available at `https://localhost`. The `entrypoint.sh` script handles all necessary setup, including generating self-signed certificates, setting file permissions, running database migrations, and starting all services.

-----

## Usage Examples

The user workflow is designed to be secure from the very first step.

1. **Register**: A new user signs up with a username, email, and password. They must also provide a public RSA key (`.pem` format).
2. **Confirm Email**: The user must click a link sent to their email to verify their account. (this is simulated via CLI)
3. **Setup 2FA**: The user is presented with a TOTP secret/QR code to add to their authenticator app.
4. **Login**: A user logs in using their username/password, followed by a second step to enter their TOTP code.
5. **Post a Tweet**: On the main "wall", a user can write a message. To sign it, they can optionally upload their corresponding private RSA key. The server will use it to sign the post and then immediately discard the key.

-----

## Design & Implementation Details

### Authentication & Access Control

- **Passwords**: Handled by `passlib` using `argon2`, with parameters defined in `models.py`. The `validate_password` method handles verification.
- **2FA (TOTP)**: Integrated directly into the `User` model. The `is_otp_valid` method checks the user-provided code against the stored secret with a 30-second window.
- **Session Management**: Uses standard Flask login sessions, with critical actions requiring re-verification of identity (e.g., 2FA for password changes).
- **Brute-Force Mitigation**: Login and 2FA endpoints are rate-limited. The application maintains logs (`login_logs`, `totp_logs`) of attempts, which can be used to implement IP blocking.

### Cryptography & Data Integrity

- **Tweet Signing**: The logic resides in `content/views.py`. When a user provides a private key, the application uses the `pycryptodome` library to:
    1. Create a `SHA512` hash of the tweet's text.
    2. Sign the hash using the private key with the `pss` padding scheme.
    3. Verify the signature with the user's stored public key to ensure correctness before saving.
- **TLS/SSL**: The `entrypoint.sh` script generates a private Certificate Authority (CA) and uses it to sign the server's SSL certificate, ensuring all traffic is encrypted over HTTPS.

### Infrastructure & Server Hardening

- **Nginx**: Acts as a reverse proxy. The `safespace.conf` file enforces TLS, sets all security headers, and defines rate limits (`limit_req_zone`) and connection limits (`limit_conn_zone`) to prevent abuse and DoS attacks.
- **uWSGI**: The `uwsgi.ini` file configures a resilient application server. It uses the `cheaper` algorithm to scale workers based on traffic load and recycles workers periodically to prevent memory leaks or state corruption.
- **File Permissions**: The `entrypoint.sh` script uses `chmod` and `chown` to apply the principle of least privilege to all application files and directories, such as the database and uploads folder.

### Application Security

- **Malware Scanning**: All file uploads are passed to a `scan_file` utility function, which uses `pyclamd` to interface with the ClamAV daemon running in the background.
- **XSS Prevention**: User-provided strings (tweet text, usernames) are passed through `bleach.clean()` in the view functions before being rendered in templates, stripping out any potentially malicious HTML.
- **Form Validation**: All forms use `Flask-WTF` with strict validators for length, character types, password strength, and even email domain deliverability (`check_deliverability=True`).

-----

## Development Tasks & Roadmap

Potential enhancements for the project include:

- **Improve Key Management**: Add functionality for users to generate RSA key pairs within the application and manage their public keys.
- **Expand Social Features**: Implement a "follow" system, direct messaging, and a notification system.
- **Formalize Testing**: Add a comprehensive suite of unit and integration tests to verify security controls and application logic.
- **CI/CD Pipeline**: Implement a GitHub Actions workflow to automatically build, lint, and test the application on every commit.
- **Enhanced Monitoring**: Integrate structured logging and export metrics for monitoring with tools like Prometheus or an ELK stack.
- **Database Choice**: Switch from SQLite to a more production-ready database like PostgreSQL.
