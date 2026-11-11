# PasswordManagement
Software Security PasswordManagement Project

## Team Members

| Name | Student ID |
| --- | --- |
| Kane | 2023901702 |
| Jim | 2023901704 |
| Enzo | 2023905940 |

## Status and scope

The four required building blocks and the minimum CLI are implemented: A owns
Argon2id verification/key derivation, AES-GCM and encrypted storage; C owns account
operations, CLI interaction and the secure password generator. B's optional sharing
and breach check are not part of this handoff and remain to be integrated. A/B/C
are role labels, not an assumed mapping to the names above.

The demonstration target is macOS, tested with Python 3.9.6. Windows is not a
validated target. See the [interface contract](docs/INTERFACES.md),
[A's guide](docs/A_GUIDE.md), [C's guide](docs/C_GUIDE.md),
[A's verification record](docs/VERIFICATION.md) and
[C's verification record](docs/C_VERIFICATION.md).

## Install and run on the Mac

From the project directory:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
source .venv/bin/activate
python vault.py --help
```

The remaining examples assume this virtual environment is active. Each teammate
creates their own environment; do not copy `.venv` or commit it.

## Commands

```bash
python vault.py init
python vault.py add github --user alice
python vault.py list
python vault.py get github
python vault.py delete github
python vault.py gen --length 20
```

- `init`: enter a master password twice to create an encrypted empty vault. Use a
  long, unique passphrase. Existing files are never overwritten by initialization.
- `add`: unlock with the master password and add one site/username/password. It
  generates a 20-character account password unless another mode is requested.
- `list`: unlock and print JSON summaries with site/username only, never passwords.
- `get SITE`: unlock and print the selected complete entry as JSON. This explicitly
  reveals its password; JSON escapes describe characters, not extra password text.
- `delete SITE`: unlock and remove the entry. There is no extra confirmation after
  the master password; missing sites are errors.
- `gen`: print a fresh password without unlocking or creating a vault.

Two add modes:

```bash
python vault.py add mail --user alice@example.com --length 28
python vault.py add school --user student123 --prompt-password
```

`--prompt-password` reads the account password privately twice. It cannot be
combined with `--length`. Master passwords and manual account passwords are never
accepted as command-line values, and spaces in passwords are preserved. Input is
hidden, so nothing appearing while you type is normal. If hidden input is not
available, the operation fails instead of falling back to echoing the password.
Use a real terminal for vault operations; `gen` does not need one.

`--file` works before or after the subcommand:

```bash
mkdir -p work
python vault.py --file work/demo-vault.json init
python vault.py add github --user alice --file work/demo-vault.json
python vault.py get github --file work/demo-vault.json
```

The default is `vault.json` in the current working directory. Parent directories
must already exist. Do not edit/reformat a vault or commit real credential data.
Version 1 allows one entry per case-sensitive site and has a 16 MiB file limit.
Read-modify-write operations must be sequential; concurrent writers are unsupported.

Successful commands return 0. Vault/input failures print `Error:` to standard error
and return 1; invalid arguments return 2; Ctrl+C returns 130. Failures never trigger
a reset or silent replacement of an unreadable vault.

## Why these choices?

1. **Argon2id for the master password, not SHA-256 or AES.** Argon2id adds memory
   and computation costs to each guess; SHA-256 alone is deliberately fast. AES is
   reversible and would require a separate secret key. Random salts prevent equal
   passwords from producing equal verifiers across vaults. Weak passwords can
   still be guessed. The stored verifier starts with `$argon2id$`.
2. **Derive the AES key, do not save it beside the vault.** A stolen vault plus a
   plaintext key file would expose every account. We derive a 32-byte AES key from
   the entered master password and an independent public Argon2id salt. The stored
   verifier is not used as the AES key; no vault encryption key is written to disk.
3. **AES-GCM instead of unauthenticated encryption.** GCM provides authentication
   as well as confidentiality, so modified encrypted data is rejected before any
   plaintext is returned. AAD binds the public header to the tag. Each encryption
   generates a fresh random 12-byte nonce; the library appends a 16-byte tag. The
   file also has one fixed JSON encoding so formatting edits are rejected.
4. **`secrets`, not the default `random` generator.** Python's default `random`
   generator is for simulation and is predictable when its state is known.
   `secrets.choice` uses the operating system's cryptographically secure random
   source. Each character is sampled from 94 printable ASCII letters, digits and
   punctuation symbols. Candidates without a lowercase letter, uppercase letter,
   digit or symbol are rejected and regenerated. This yields uniform sampling
   within the accepted set, without a predictable template. Default length is 20;
   our CLI permits 12-1024 characters. These limits are project policy, not exact
   lengths prescribed by the course.
5. **Use established libraries, not custom cryptography.** `argon2-cffi` implements
   Argon2id hashing, verification and raw key derivation; `cryptography` supplies
   AESGCM and checks its tag before returning plaintext. Explicit Argon2id settings
   are 65536 KiB memory, 3 iterations, parallelism 4, 16-byte salts and 32-byte
   output, matching the documented RFC 9106 low-memory profile. Verification and
   key derivation have independent salts. Version 1 fixes and bounds parameters
   before expensive work, rather than trusting attacker-controlled costs.

Every group member must understand these choices and explain the final code in
their own words. Bonus-specific design explanations belong with B's implementation.

## Security model

A stolen vault file contains public metadata and authenticated encrypted entries,
not plaintext credentials or an AES key file. A strong master password is still
necessary because offline guessing remains possible.

This tool does not protect against keyloggers, a compromised computer, weak master
passwords, screen observation or plaintext in the unlocked process's memory.
Python cannot reliably erase secrets from memory; swap and crash dumps are outside
this tool's control. There is no forgotten-password recovery, rollback protection,
concurrent-writer support or guaranteed power-loss recovery. `get` and `gen`
intentionally reveal a password on screen. No network is needed for the required
features; B's future optional breach check is the networked extension.

POSIX vault files use mode 0600; other systems need appropriate filesystem
permissions. Initialization requires a filesystem supporting hard links. The v1
JSON byte representation is fixed: changing whitespace, key order or the final
newline is rejected by format validation. Encrypted data and header values are
protected by AES-GCM and format/password checks. A cleanup failure can leave an
encrypted temporary file; if publication already succeeded, the error says the
vault was saved. Neither formatting checks nor file permissions replace encryption.

## Verification

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Tests use fake credentials and keep temporary files under ignored `work/`.
Coverage includes A's crypto/storage checks, generator length/character policy,
account operations, CLI success and error behavior, real Mac terminal sessions,
hidden input and explicit password reveal. All 72 A+C tests passed on the Mac, including an isolated A-baseline + C-package
integration check. The actual results and handoff-package verification are recorded in [C's verification record](docs/C_VERIFICATION.md).

B should integrate its optional feature only after the four required blocks pass.
The group should run the complete demonstration on the actual presentation Mac.

## References

- [Course requirements](https://kristenpire.github.io/epita-security-labs/project2/)
- [argon2-cffi API and profiles](https://argon2-cffi.readthedocs.io/en/stable/api.html)
- [cryptography AESGCM](https://cryptography.io/en/stable/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
- [Python secrets](https://docs.python.org/3/library/secrets.html)
- [Python getpass](https://docs.python.org/3/library/getpass.html)
