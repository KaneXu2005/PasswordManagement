# Verification record

Verified on 11 November 2026 (Europe/Paris), on macOS with Python 3.9.6.
Tested runtime revision: `9febc1c3e4cd8b82acfdf21d55525daf6e0052e4`.
Libraries: argon2-cffi 25.1.0, cryptography 46.0.7.

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
| **Total** | **72** | **No failures, errors or skips** |

Observed summary:

```text
Ran 72 tests in 9.659s

OK
```

Coverage includes Argon2id verification and derivation; encrypted persistence;
ciphertext/tag/header tampering; file-byte and formatting edits; atomic-write
failures; invalid input; generator character/length policy; account operations;
and actual hidden-input terminal sessions.

## Additional terminal checks

Sixteen additional scenarios passed using the actual CLI in separate terminal
processes: initialization; generated and manual account addition; Unicode values
and password spaces; password-free listing; retrieval after process restart;
standalone generation; deletion to an empty vault; and explicit failure for wrong
master passwords, duplicate sites, reinitialization, missing entries and tampering.
Failed operations preserved the existing file and did not return account plaintext.

Only fake credentials were used. Temporary vaults were cleaned up; local raw logs
remain under ignored `work/`. Dependency consistency checks also passed.

## Scope

These results cover the current offline CLI and its four required cryptographic
building blocks. Optional encrypted sharing and breach checks are not implemented.
Windows, concurrent writers and power-loss recovery are not validated targets.
The documented security limitations in the main README still apply.
