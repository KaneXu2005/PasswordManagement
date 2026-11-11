# PasswordManagement

An offline Python command-line password manager using Argon2id and AES-256-GCM.
It stores site credentials in an encrypted local vault unlocked by one master
password. Encrypted sharing and breach checking are not implemented.

## Team members

| Name | Student ID |
| --- | --- |
| Kane | 2023901702 |
| Jim | 2023901704 |
| Enzo | 2023905940 |

## Installation

Requires Python 3.9+. Tested on macOS with Python 3.9.6.
From the project directory:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
source .venv/bin/activate
python vault.py --help
```

## Usage

```bash
python vault.py init
python vault.py add github --user alice
python vault.py list
python vault.py get github
python vault.py delete github
python vault.py gen --length 20
```

| Command | Behavior |
| --- | --- |
| `init` | Confirm a new master password and create an empty vault; refuse to overwrite an existing file. |
| `add SITE --user USER` | Unlock and add an entry with a generated 20-character password. |
| `list` | Unlock and list sites/usernames as JSON, without passwords. |
| `get SITE` | Unlock and reveal the selected complete entry as JSON. |
| `delete SITE` | Unlock and remove the selected entry; no additional deletion confirmation. |
| `gen --length N` | Print a password of the requested length without opening a vault. |

For a different generated length or a manually entered account password:

```bash
python vault.py add mail --user alice@example.com --length 28
python vault.py add school --user student123 --prompt-password
```

`--prompt-password` reads the account password privately twice and cannot be
combined with `--length`. Master passwords are also read privately; nothing
appearing while typing is normal. Passwords are not accepted as command-line
values, and their leading/trailing spaces are preserved. If hidden input is
unavailable, vault operations fail instead of using input that may echo secrets.

The default file is `vault.json` in the current working directory. `--file PATH`
works before or after the command; its parent directory must already exist:

```bash
mkdir -p work
python vault.py --file work/demo-vault.json init
python vault.py add github --user alice --file work/demo-vault.json
python vault.py get github --file work/demo-vault.json
```

Each site label is case-sensitive and has one entry. `get` returns JSON: escape
sequences represent characters, not additional password text. Do not edit or
reformat the vault. Success exits 0; operation/input errors exit 1, argument errors
exit 2, and Ctrl+C exits 130. An unreadable vault is never automatically reset.

## Cryptographic choices

1. **Argon2id for master-password verification.** Argon2id makes guesses expensive
   in memory and computation; SHA-256 alone is designed to be fast. AES is
   reversible encryption requiring another secret key, not a password verifier.
   Random salts prevent equal passwords from producing equal verifiers across
   vaults. The stored verifier starts with `$argon2id$`.
2. **Derive the vault key instead of storing a key file.** A vault stolen together
   with a plaintext key file would expose its contents. A 32-byte AES key is
   derived from the entered master password and an independent public Argon2id
   salt. The verifier is not the AES key; neither the master password nor the
   derived key is written to the vault.
3. **AES-GCM for encryption and authentication.** GCM detects changes before
   returning plaintext. AAD authenticates the public header, and the library
   appends a 16-byte authentication tag. Every encryption generates a fresh
   random 12-byte nonce; nonce reuse with a key must be avoided. Fixed JSON
   encoding additionally rejects presentation-only edits to the file.
4. **`secrets` for password generation.** The default `random` generator is for
   simulation and becomes predictable if its state is known. `secrets.choice`
   uses the operating system's cryptographically secure randomness. Candidates
   are drawn from 94 printable ASCII letters, digits and punctuation, then
   rejected if they lack lowercase, uppercase, digits or symbols. This samples
   uniformly from the accepted set. Default length is 20; the supported 12-1024
   range is project policy.

`argon2-cffi` provides standard Argon2id hashing, verification and raw key
derivation. `cryptography` provides AESGCM and authenticates before returning
plaintext. These established implementations avoid custom cryptographic
primitives. The fixed Argon2id profile uses 65536 KiB memory, 3 iterations,
parallelism 4, 16-byte salts and 32-byte output, matching the documented RFC 9106
low-memory profile. Verification and key derivation use independent salts;
unsupported file parameters are rejected before expensive computation.

## Security model

A stolen vault contains public metadata and authenticated ciphertext. A strong,
unique master passphrase is essential: offline password guessing remains possible.

The tool does not protect against keyloggers, a compromised machine, weak master
passwords, screen observation or access to the unlocked process's memory. `get`
and `gen` intentionally show passwords. Python cannot reliably erase secret
objects; swap and crash dumps are outside this program's control. There is no
forgotten-password recovery, rollback protection, concurrent-writer support or
guaranteed recovery from power loss.

Vault size is limited to 16 MiB. POSIX files use mode 0600; initialization requires
a filesystem supporting hard links. Writes use encrypted temporary files and
atomic publication. Failed cleanup may leave encrypted temporary files; an error
after successful publication explicitly says the vault was saved. Format checks
and filesystem permissions do not replace AES-GCM authentication.

## Verification and implementation details

```bash
.venv/bin/python -m unittest discover -s tests -v
```

All 72 tests and 16 additional terminal scenarios passed on macOS using fake
credentials. Tests keep temporary files under ignored `work/` and clean them up.
See the [verification record](docs/VERIFICATION.md) and
[API/file-format reference](docs/INTERFACES.md).

## References

- [Course requirements](https://kristenpire.github.io/epita-security-labs/project2/)
- [argon2-cffi API and profiles](https://argon2-cffi.readthedocs.io/en/stable/api.html)
- [cryptography AESGCM](https://cryptography.io/en/stable/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
- [Python secrets](https://docs.python.org/3/library/secrets.html)
