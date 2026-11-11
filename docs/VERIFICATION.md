# A backend verification record

Date: 2026-11-11 (Europe/Paris).
Scope: A's backend only, not the complete course application.
All project code, environment files and test fixtures were created inside
`PasswordManagement`. Tests use fake credentials and clean up their temporary vaults.

## Environment

- Python: 3.9.6, macOS arm64.
- argon2-cffi: 25.1.0.
- argon2-cffi-bindings: 25.1.0.
- cryptography: 46.0.7.
- cffi: 2.0.0.

## Command and observed result

```bash
.venv/bin/python -m unittest discover -s tests -v
```

```text
Ran 36 tests in 14.116s

OK
```

All 36 tests passed; no tests were skipped in the course-requirement review.
The initial implementation had 25 tests, the first review expanded this to 35,
and the course-requirement review replaced the formatting-policy test and added
one file-wide single-bit tampering test, bringing the total to 36.
The original command above reproduces the same suite. Full review output is saved
locally in ignored `work/course-review-tests.log`; the previous review log is
`work/review-tests.log`.

`git diff --check`, syntax/whitespace checks of all four Python files and
`pip check` also passed (no broken dependency requirements).

## Review findings and fixes

The review reproduced failures before changing code, then reran the full suite.
These were error-handling and input-validation defects; the tested failure paths
did not reveal passwords or overwrite the original vault.

1. Non-ASCII characters in a corrupted password verifier passed parameter extraction
   but caused an unhandled Unicode encoding error during verification. The file
   reader now rejects such hashes as `VaultFormatError` before invoking Argon2.
2. Strings containing isolated Unicode surrogate code points could fail during
   encryption with an unhandled encoding error. Entries are now checked as valid
   UTF-8 text before saving and rejected as `EntryValidationError`; invalid master
   password text is rejected with a clear `ValueError`.
3. Failure to delete a temporary file could mask the primary save error or report
   a raw permission exception after initialization had already succeeded. Cleanup
   now preserves the original save error; a failure after publication explicitly
   reports `Vault was saved` through `VaultIOError`. A cleanup failure can leave
   an encrypted temporary file, as documented in the interface contract.

The first review kept the three public signatures and file format unchanged.
The later course-requirement review below tightens the draft v1 encoding policy.
The manual guide now explicitly creates `work/` for a fresh checkout.

## Course-requirement review

The course says a one-byte vault-file modification should fail loudly. The former
draft accepted equivalent JSON whitespace and key reordering. Although account
data and header values were authenticated, that did not meet the strict literal
file-tampering acceptance criterion.

The writer now uses one fixed UTF-8 JSON representation (sorted keys, two-space
indentation, one trailing newline), and the reader rejects any other representation.
GCM still authenticates encrypted entries and header values; byte-format checking
only adds rejection of otherwise equivalent formatting edits. It does not replace
cryptographic authentication.

The three public function signatures and document fields remain unchanged. This
is a tightening of the not-yet-committed v1 draft; older draft files are not promised
compatible. There were no user vaults in the project when this change was made.
The shared interface contract documents this change.

One test takes an actual generated vault file and, for each byte position, flips
its least significant bit and verifies that load raises a `VaultError`. This tests
all positions in that fixture, not all possible mutations of all possible vaults.
Separate cases reject reformatting, key reordering and newline changes, and confirm
that save refuses to overwrite a file whose formatting was modified.

## Coverage of A's responsibilities

| Behavior | Observed result |
| --- | --- |
| Initial encrypted empty vault and `$argon2id$` verifier | Passed |
| Correct password accepted, incorrect password rejected | Passed |
| Empty master password rejected without creating a vault | Passed |
| Initialization refuses to overwrite an existing vault | Passed |
| Save/load multiple entries, including Unicode | Passed |
| Account fields and master password not present as plaintext in saved test vault | Passed |
| C's intended read-modify-write sequence, including saving an empty list | Passed |
| Fresh nonce and ciphertext on successive saves | Passed |
| Independent verifier and KDF salts | Passed |
| Key derivation reproducible; changed password or salt changes key | Passed |
| One ciphertext byte or authentication-tag byte flipped | Authentication rejected |
| Nonce or KDF salt modified | Authentication rejected |
| Verifier replaced with another valid hash of the same password | AAD authentication rejected |
| Excessive KDF or verifier cost parameters | Rejected before expensive work |
| Invalid JSON, duplicate fields, invalid encodings or unsupported versions | Rejected |
| Invalid entry data | Rejected without changing file |
| Saving with wrong password or over a tampered vault | Rejected without changing file |
| Missing file | Rejected; not silently created |
| Simulated atomic-replace failure | Original file preserved; temporary file removed |
| POSIX creation and save permissions | 0600 |
| Fresh independent process reading a saved vault | Passed; no cached key required |
| Non-ASCII corrupted verifier | Format rejected before Argon2 verification |
| Invalid UTF-8 entry fields or master password | Rejected with documented error types |
| Save failure and simultaneous cleanup failure | Original save error preserved; original file unchanged |
| Cleanup failure after successful initialization | Reports saved state; published vault remains readable |
| Competing file created at initialization publication | Existing competing file preserved |
| Simulated fsync failure | Original file preserved; temporary file removed |
| Read/save size limits | Rejected; oversized save preserves original |
| JSON whitespace/key reordering or final-newline changes | Rejected by fixed-format validation |
| One bit flipped at each byte position of an actual on-disk fixture | Every position rejected |

## Not yet validated / remaining work

- C's CLI and end-to-end init/add/list/get/delete commands do not exist yet.
- The fourth required block, C's `secrets` password generator, is not implemented.
- B's encrypted sharing and HIBP check are not implemented.
- Windows behavior, concurrent writers and sudden power-loss recovery were not tested.
- This record is an automated backend acceptance result, not a claim of a complete security audit.

See [interface contract](INTERFACES.md), [A guide](A_GUIDE.md) and
[backend tests](../tests/test_backend.py).
