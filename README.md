# PasswordManagement

An offline-first Python command-line password manager using Argon2id and AES-256-GCM.
It stores site credentials in an encrypted local vault unlocked by one master
password. Both course bonuses are implemented: encrypted sharing of one entry
and an explicitly requested Have I Been Pwned (HIBP) password check.

## Team members

| Name | Student ID |
| --- | --- |
| Kane | 2023901702 |
| Jim | 2023901704 |
| Enzo | 2023905940 |

## Installation

Requires Python 3.9+. Tested on macOS with Python 3.9.6 and 3.13.7.
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
| `keygen --private-key PATH --public-key PATH` | Generate sharing keys; confirm a separate private-key passphrase. No vault needed. |
| `share SITE --recipient-key PATH --out PATH` | Unlock and encrypt exactly one entry for the recipient; leave the vault unchanged. |
| `receive PACKAGE --private-key PATH` | Unlock the destination vault and decrypt the package with the recipient's private key; add the entry without overwriting an existing site. |
| `check [SITE]` | Explicitly query HIBP for a stored entry, or privately enter a password when SITE is omitted. |

For a different generated length or a manually entered account password:

```bash
python vault.py add mail --user alice@example.com --length 28
python vault.py add school --user student123 --prompt-password
```

`--prompt-password` reads the account password privately twice and cannot be
combined with `--length`. Master passwords are also read privately; nothing
appearing while typing is normal. Passwords are not accepted as command-line
values, including sharing-key passphrases, and leading/trailing spaces are
preserved. If hidden input is
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

## Bonus: share one entry (Kane)

The recipient first creates a key pair and sends **only the public key** to the
sender. These examples use `work/`, which is ignored by Git:

```bash
mkdir -p work
# Recipient: enter and confirm a new private-key passphrase.
python vault.py keygen --private-key work/recipient-private.pem --public-key work/recipient-public.pem
# Sender: use the recipient's verified public key and unlock the sender's vault.
python vault.py share github --recipient-key work/recipient-public.pem --out work/github.share.json
# Recipient: transfer the encrypted package, initialize a destination vault once,
# then enter its master password and the separate private-key passphrase.
python vault.py --file work/recipient-vault.json init
python vault.py --file work/recipient-vault.json receive work/github.share.json --private-key work/recipient-private.pem
python vault.py --file work/recipient-vault.json get github
```

The sender encrypts one complete entry with a new random AES-256-GCM key and a
new 12-byte nonce. RSA-3072 with OAEP (SHA-256 and MGF1-SHA-256) encrypts that
32-byte key for the recipient. This hybrid construction avoids RSA's small
message-size limit and gives the entry authenticated encryption. Public envelope
metadata is bound to the GCM tag as AAD. The existing vault format is unchanged;
neither a vault master password nor its derived key is shared.

The private key is stored as encrypted PKCS#8 PEM using `cryptography`'s
`BestAvailableEncryption`, with a separately prompted passphrase. Key and package
files use owner-only POSIX permissions; existing output paths are never
overwritten. A wrong key, wrong passphrase or modified package fails without
printing account data or modifying the recipient's vault. Duplicate site labels
are rejected; delete an old entry explicitly before intentionally replacing it.

Verify the recipient's public-key SHA-256 fingerprint over a trusted independent
channel before sharing (for example, compare the following output together):

```bash
openssl pkey -pubin -in work/recipient-public.pem -outform DER | openssl dgst -sha256
```

Encryption does not prove who sent a package: anyone with the public key can
create one. Accept packages only from a trusted sender. There is no signature,
revocation, expiry or forward secrecy; a recipient can copy a decrypted password,
and later theft of their private key and passphrase can expose old packages.
Keep the private key private, use a strong unique passphrase, and never send it
alongside the package. Sharing does not protect against public-key substitution
unless the fingerprint is verified.

## Bonus: breach check with k-anonymity (Kane)

```bash
# Unlock and check the stored password without displaying it.
python vault.py check github
# Privately enter any complete password; no vault needed.
python vault.py check
```

Only `check` connects to the network. It computes SHA-1 of the complete UTF-8
password locally and sends **only its first five hexadecimal characters** to
`https://api.pwnedpasswords.com/range/{prefix}`. The returned 35-character suffixes
are compared locally. The password, username, site, full hash and remaining hash
suffix are never transmitted. SHA-1 is required here as a lookup identifier; it
does not replace Argon2id for password storage.

Five hex characters reveal 20 hash bits rather than a complete password hash:
the request refers to a bucket of possible passwords instead of identifying the
exact candidate. HTTPS verifies the server; `Add-Padding: true` reduces response
size leakage, and zero-count padding records are ignored. This reduces exposure,
but is not perfect anonymity: HIBP sees the IP address, time and hash prefix, and
weak passwords can still be guessed. A single explicit lookup happens after
complete input, never while typing; no automatic checks, retries or logging of
passwords or hashes are performed. No API key or subscription is needed.

The JSON result is `{"breached": true, "count": N}` for a known breached password,
or `{"breached": false, "count": 0}` if no match is found in the current dataset.
Both completed checks exit 0; a match means the password should be replaced.
No match does **not** establish that a password is strong or has never leaked.
Network/TLS/HTTP errors, redirects, malformed responses and responses above
1 MiB fail with exit 1 and no result; an unavailable check is never called safe.
Connections use a 10-second timeout. Offline vault operations continue to work
without HIBP.

## Verification and implementation details

```bash
.venv/bin/python -m unittest discover -s tests -v
```

All 131 tests passed on Python 3.9.6 and 3.13.7. The suite covers the original
vault operations and both bonuses,
including real cryptographic round trips, failure paths and hidden-input terminal
sessions. HIBP unit/integration tests mock HTTP and never submit real credentials.
Tests keep temporary files under ignored `work/` and clean them up.
See the [verification record](docs/VERIFICATION.md) and
[API/file-format reference](docs/INTERFACES.md).

## References

- [Course requirements](https://kristenpire.github.io/epita-security-labs/project2/)
- [argon2-cffi API and profiles](https://argon2-cffi.readthedocs.io/en/stable/api.html)
- [cryptography AESGCM](https://cryptography.io/en/stable/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
- [Python secrets](https://docs.python.org/3/library/secrets.html)
- [cryptography RSA/OAEP and encrypted private-key serialization](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/)
- [HIBP Pwned Passwords range API and padding](https://haveibeenpwned.com/API/v3#PwnedPasswords)
