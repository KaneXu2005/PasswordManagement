# A: course-requirement checklist

Source: [Project 2 — Password manager](https://kristenpire.github.io/epita-security-labs/project2/),
read again on 2026-11-11. This checklist separates course requirements from team
implementation choices. It is not a claim that B/C's work has been completed.

| Course requirement relevant to A | Implementation / evidence | Status |
| --- | --- | --- |
| Store an Argon2id master-password verifier; reject wrong passwords | `crypto.hash_master_password`, `verify_master_password`; `$argon2id$` and wrong-password tests | Passed |
| Derive the vault encryption key from the master password using Argon2 | `crypto.derive_key`, using argon2-cffi's raw Argon2id function and a separate salt | Passed |
| No persisted vault encryption key | Only public parameters, verifier, nonce and ciphertext are written; a fresh process can unlock using the password | Passed |
| Encrypt all stored entries with AES-GCM | `encrypt_entries`, `decrypt_entries`, called only through authenticated storage operations | Passed |
| A one-byte vault-file change must produce an explicit failure | Fixed file encoding plus GCM; actual file-byte test flips one bit at each position and checks every mutation is rejected | Passed for tested fixture and cases |
| Use established cryptographic libraries | `argon2-cffi` for Argon2id hashing/KDF; `cryptography` for AESGCM; no custom primitive | Implemented |
| README names libraries and explains choices | Main README explains Argon2 vs SHA-256/AES, deriving vs storing a key, AES-GCM authentication and library choice | Written; each member must understand it |
| State protection against vault theft and limits | Main README covers stolen vaults, offline guessing, keyloggers, weak master passwords and screen observation | Written |
| Be able to explain the cryptographic code | `docs/A_GUIDE.md` provides a reading guide and manual checks | Human preparation still required |

## Integration still required

C must connect the backend to a working CLI with initialization/unlock and
add/list/get/delete, implement `secrets` password generation and document its
reasoning. B owns the optional sharing and breach check. The group must then run
complete CLI acceptance checks; backend tests do not substitute for this.

## Team design choices, not extra course requirements

The three storage functions, JSON format, one entry per case-sensitive site,
16 MiB size limit, sequential access and Argon2 parameters are our v1 decisions.
They are documented in the [shared contract](INTERFACES.md). The course does not
prescribe these exact names, limits or a JSON file format.

Fixed JSON encoding is the chosen way to meet the course's literal file-byte
criterion. Modifications to encrypted data/header values are checked by AES-GCM
or rejected by format/password checks; edits only to JSON presentation are rejected
by byte-format validation. These are different mechanisms and should be explained
accurately during demonstration.

## Useful next optimizations

1. Before final submission, C should provide exact CLI examples and include a
   reproducible command-line tampering demonstration using fake data. A supplies
   the backend and current tests, not a second competing CLI.
2. If teammates use Windows or another target environment, run this same test
   suite there. Initialization uses atomic hard-link publication; filesystem
   compatibility is documented but has only been tested on the current Mac.
3. Measure normal load/save latency on target machines before attempting speed
   changes. The safe load-modify-save flow currently repeats verification and
   derivation. Retaining this design is reasonable for a small local CLI; reducing
   Argon2 costs or introducing a cached key is not necessary to meet the assignment.
4. Keep final README focused on design reasons and a short acceptance summary;
   detailed troubleshooting and historical test records can stay in docs.

Latest result: 36 tests passed. See [verification record](VERIFICATION.md).
