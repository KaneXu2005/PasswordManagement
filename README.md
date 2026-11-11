# PasswordManagement
Software Security PasswordManagement Project

## Team Members

| Name | Student ID |
| --- | --- |
| Kane | 2023901702 |
| Jim | 2023901704 |
| Enzo | 2023905940 |

## Current status

A's encrypted-vault backend is implemented. The complete course application is
not finished: C owns the CLI, account operations and strong password generator;
B owns the optional encrypted sharing and breach check. A/B/C are role labels,
not an assumed mapping to the names above.

Read [the shared version 1 interface contract](docs/INTERFACES.md) before adding
features. It defines public functions, entries, exceptions and the on-disk format.
[A's explanation and manual verification guide](docs/A_GUIDE.md) covers the crypto.
[The verification record](docs/VERIFICATION.md) reports 36 passing backend tests.
[The requirement checklist](docs/REQUIREMENTS_CHECK.md) maps A's work to the course.

## Setup and backend verification

Python 3.9+:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

On Windows use `.venv\Scripts\python.exe` instead of `.venv/bin/python`.
Test data and temporary files stay in the ignored `work/` directory.
There is no `vault.py` CLI yet; do not treat the course's example commands as
implemented commands.

## Backend API

```python
from storage import initialize_vault, load_vault, save_vault

# `master_password` should come from getpass(), never a hard-coded real secret.
initialize_vault("vault.json", master_password)
entries = load_vault("vault.json", master_password)
# C modifies entries in memory, then saves the entire list:
save_vault("vault.json", master_password, entries)
```

Each entry contains exactly `site`, `username`, `password`, all non-empty strings.
Version 1 allows one entry per site, with case-sensitive matching. Read-modify-write
operations must run sequentially: there is no multi-process conflict detection.

## Why these cryptographic choices? (A's part)

- **Argon2id rather than SHA-256 or AES for the master password:** Argon2id makes
  guessing expensive in memory and computation; SHA-256 alone is deliberately
  fast, and AES is reversible encryption requiring a separate secret key. A fresh
  salt prevents equal passwords from producing equal verifiers across vaults.
- **Derive the encryption key rather than store it beside the vault:** a stolen
  vault plus a plaintext key file would expose every entry. The AES key here is
  recomputed using the supplied master password and an independent public salt.
  The stored password-verification hash is not used as the AES key.
- **AES-GCM rather than unauthenticated encryption:** GCM detects changes before
  any plaintext is returned. The public header is authenticated as AAD; a fresh
  random 12-byte nonce is generated on every encryption. The library appends a
  16-byte authentication tag to the ciphertext.
- **Libraries and parameters:** `argon2-cffi` handles Argon2id hashing and raw key
  derivation; `cryptography` supplies AESGCM. Explicit Argon2id parameters are
  65536 KiB memory, 3 iterations, parallelism 4, a 16-byte salt and 32-byte output,
  matching the documented RFC 9106 low-memory profile. The two Argon2 uses have
  independent salts. The v1 profile is fixed and checked before expensive work.
  These established libraries provide standard implementations instead of custom
  hashing or encryption; PasswordHasher handles encoded verifier generation and
  verification, and AESGCM checks its tag before returning plaintext.

The password-generator explanation (`secrets` versus `random`) belongs to C and
must be added with that implementation. B must document any implemented bonus.
These notes are a starting point: every group member must understand the code
and explain the final choices in their own words.

## Security model

A stolen vault file contains public metadata and authenticated encrypted entries,
not the plaintext master password, plaintext accounts or an AES key file. A strong
master password is still necessary: offline guessing remains possible.

This tool does not protect against keyloggers, a compromised computer, weak master
passwords, screen observation or plaintext in the unlocked process's memory.
Python cannot reliably erase secret objects from memory; swap and crash dumps are
outside this tool's control. There is no forgotten-password recovery, rollback
protection, concurrent-writer support or guaranteed power-loss recovery. The v1
file has a fixed JSON byte representation: changing whitespace, key order or the
final newline is rejected by format validation; altered authenticated values or
encrypted data are rejected by format/password checks or AES-GCM authentication.
Do not edit or reformat a vault by hand. POSIX files are created with mode 0600; other systems
need appropriate filesystem permissions. Initialization requires a filesystem
supporting hard links to publish a complete file without overwriting a target.

## Before submitting the complete project

- C: implement and test init/add/list/get/delete/gen and document their exact usage.
- C: explain why the generator uses `secrets` instead of `random`.
- B: integrate bonus features after all four required blocks pass; explain the design.
- Everyone: review the security model, run the complete CLI checks and be ready to
  explain any cryptographic line. Do not commit real vaults or private keys.

## References

- [Project requirements](https://kristenpire.github.io/epita-security-labs/project2/)
- [argon2-cffi API and profiles](https://argon2-cffi.readthedocs.io/en/stable/api.html)
- [cryptography AESGCM](https://cryptography.io/en/stable/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
