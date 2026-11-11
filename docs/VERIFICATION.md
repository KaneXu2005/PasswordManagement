# Verification record

Verified on 11 November 2026 (Europe/Paris), on macOS with Python 3.9.6 and 3.13.7.
The current suite covers both bonuses and the original vault functionality.
Libraries in both environments: argon2-cffi 25.1.0, cryptography 46.0.7.

## Automated suite

From the project root:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

| Test module | Tests | Result |
| --- | ---: | --- |
| `test_backend.py` | 36 | Passed |
| `test_cli.py` | 24 | Passed |
| `test_entries.py` | 8 | Passed |
| `test_generator.py` | 4 | Passed |
| `test_sharing.py` | 26 | Passed |
| `test_breach.py` | 17 | Passed |
| `test_bonus_cli.py` | 16 | Passed |
| **Total** | **131** | **No failures, errors or skips** |

Observed summary:

```text
Python 3.13.7: Ran 131 tests in 18.849s — OK
Python 3.9.6:  Ran 131 tests in 17.763s — OK
```

Both dependency environments also passed `python -m pip check`.
The environments were tested concurrently; timings are not benchmarks.

To reproduce the Python 3.9 compatibility run separately:

```bash
mkdir -p work
/usr/bin/python3 -m venv work/venv39
work/venv39/bin/python -m pip install -r requirements.txt
work/venv39/bin/python -m unittest discover -s tests -v
```

Coverage includes Argon2id verification and derivation; encrypted persistence;
ciphertext/tag/header tampering; file-byte and formatting edits; atomic-write
failures; invalid input; generator character/length policy; account operations;
and actual hidden-input terminal sessions.

Sharing tests additionally cover real RSA-OAEP/AES-GCM round trips; encrypted
private-key unlocking; wrong keys/passphrases; ciphertext, tag, nonce and wrapped
key tampering; AAD binding even with a valid rewrapped key; invalid package
formats; output collisions and symlinks; file limits, owner-only permissions,
failed publication and key-pair rollback. CLI tests verify that only one selected
entry is shared, duplicate imports do not overwrite existing credentials, and
failed imports preserve the destination vault byte for byte.

HIBP tests replace HTTP transport and assert that only a five-character SHA-1
prefix leaves the process, with padding requested. They cover positive and
negative matches, Unicode/password spaces, zero-count padding, malformed or
oversized responses, duplicate records, redirects, HTTP errors, timeouts, TLS
failures and interrupted response reads. A CLI-to-HTTP-mock integration also
checks the real hashing/request path and preserves the source vault. No unit
test depends on live network access.

The bonus terminal test runs `keygen`, `share` and `receive` in three real PTY
processes, verifies that neither vault nor private-key passphrases are echoed,
and loads the received entry from the encrypted destination vault.

## Additional terminal checks

The original sixteen additional scenarios passed using the actual CLI in
separate terminal processes: initialization; generated and manual account addition; Unicode values
and password spaces; password-free listing; retrieval after process restart;
standalone generation; deletion to an empty vault; and explicit failure for wrong
master passwords, duplicate sites, reinitialization, missing entries and tampering.
Failed operations preserved the existing file and did not return account plaintext.

Only fake credentials were used. Temporary vaults were cleaned up; local raw logs
remain under ignored `work/`. Dependency consistency checks also passed.

Those original checks preceded the bonuses, at runtime revision
`9febc1c3e4cd8b82acfdf21d55525daf6e0052e4`; the original suite contained 72 tests.

## Live HIBP smoke check

A separate real HTTPS lookup with the public test password `password` succeeded:
`breached=True`, count `52372427` at verification time. The implementation sent
only the prefix `5BAA6`, requested padding and matched the remaining hash locally.
This count changes as the dataset grows. No real credential was used; this live
check is deliberately separate from the repeatable offline test suite.

## Scope

These results cover the four required cryptographic building blocks, encrypted
single-entry sharing and explicitly requested HIBP breach checks.
Windows, concurrent writers and power-loss recovery are not validated targets.
The documented security limitations in the main README still apply.
