# C and combined verification record

Date: 2026-11-11 (Europe/Paris).
Target: macOS, Python 3.9.6. Fake credentials only; no real passwords used.
A baseline: `e7fd308733bf99a3c3a442df2fcc64fe03bc69a6`.

## Observed results

| Scope | Tests | Result |
| --- | ---: | --- |
| A's original crypto/storage acceptance suite | 36 | Passed |
| C's generator/account/CLI/real-terminal suite | 36 | Passed |
| Combined A baseline + C handoff payload | 72 | Passed, no skips |

C was first tested independently: 36 tests passed in 5.106 seconds.
The combined suite then passed in 20.240 seconds. To reproduce from the project root:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## Handoff verification procedure

1. Build a source-only preview of the handoff archive.
2. Create a separate temporary directory inside this project's ignored `work/`.
3. Restore the exact files of A's committed baseline, without using the current
   working tree's backend files as a substitute.
4. Overlay only the handoff's 15 listed source/document files.
5. Run the complete 72-test suite there, including real terminal child processes.
6. Record hashes of the tested C source and A core files. Final packaging checks
   that these code bytes have not changed, and verifies every payload checksum.

The final archive updates only documentation after the test run;
its tested Python source is unchanged. A's `crypto.py`, `storage.py`, `errors.py`,
`requirements.txt` and `tests/test_backend.py` remain byte-for-byte identical to A's
baseline. No C commit or remote push was created in this preparation step.

## C coverage

- Generator: default/chosen lengths, four character groups, allowed character set,
  invalid lengths and secure-choice rejection sampling.
- Entries: add/list/get/delete, missing sites, duplicate rejection, case-sensitive
  labels, input preservation, detached result copies and password-free summaries.
- CLI: password confirmation, auto/manual account passwords, custom lengths,
  list/get output, deletion, duplicate/missing records, wrong master password,
  file tampering, explicit nonzero errors, path option placement and default path.
- Input handling: hidden input, empty secrets, EOF, Ctrl+C and refusal to use an
  echoing fallback. Adding/listing never prints the account password.
- Real Mac terminal processes: init → manual add → list → get → delete → missing
  get; generated add followed by retrieval; standalone gen without a terminal.
- Persistence: the CLI subprocesses reopen the vault on successive commands;
  key material is not kept between those processes.

## Remaining scope

B's optional encrypted sharing and breach check are not implemented or tested by
this handoff. Windows behavior is not claimed; the final demo target is the Mac.
The group must still understand the code and rehearse the final presentation after
B's integration. This is functional/security acceptance evidence, not a claim of
a comprehensive independent security audit.

## Actual combined test output

```text
test_a_fresh_process_can_load_saved_entries_without_cached_key (test_backend.BackendTests) ... ok
test_bad_json_and_duplicate_fields_are_rejected (test_backend.BackendTests) ... ok
test_changed_json_formatting_is_rejected_without_modifying_file (test_backend.BackendTests) ... ok
test_cleanup_failure_after_publish_reports_that_vault_was_saved (test_backend.BackendTests) ... ok
test_cleanup_failure_does_not_hide_original_save_error (test_backend.BackendTests) ... ok
test_correct_password_verifies_and_wrong_password_is_rejected (test_backend.BackendTests) ... ok
test_corrupt_vault_cannot_be_silently_overwritten (test_backend.BackendTests) ... ok
test_empty_master_password_does_not_create_a_file (test_backend.BackendTests) ... ok
test_failed_atomic_replace_preserves_existing_file_and_cleans_temp (test_backend.BackendTests) ... ok
test_flipping_one_authentication_tag_byte_is_rejected (test_backend.BackendTests) ... ok
test_flipping_one_bit_at_every_file_byte_is_rejected (test_backend.BackendTests) ... ok
test_flipping_one_ciphertext_byte_is_rejected (test_backend.BackendTests) ... ok
test_fsync_failure_preserves_original_and_removes_temporary_file (test_backend.BackendTests) ... ok
test_header_verifier_is_authenticated_even_if_password_still_matches (test_backend.BackendTests) ... ok
test_independent_vaults_have_independent_salts_and_nonces (test_backend.BackendTests) ... ok
test_initialization_creates_argon2id_and_encrypted_empty_vault (test_backend.BackendTests) ... ok
test_initialization_publish_race_does_not_overwrite_competing_file (test_backend.BackendTests) ... ok
test_invalid_entries_do_not_modify_the_file (test_backend.BackendTests) ... ok
test_invalid_utf8_entry_is_rejected_without_modifying_file (test_backend.BackendTests) ... ok
test_invalid_utf8_master_password_has_a_clear_parameter_error (test_backend.BackendTests) ... ok
test_invalid_version_fields_and_encodings_are_rejected (test_backend.BackendTests) ... ok
test_key_derivation_is_reproducible_and_depends_on_password_and_salt (test_backend.BackendTests) ... ok
test_missing_vault_is_not_implicitly_created (test_backend.BackendTests) ... ok
test_modified_kdf_salt_is_rejected (test_backend.BackendTests) ... ok
test_modified_nonce_is_rejected (test_backend.BackendTests) ... ok
test_non_ascii_verifier_is_rejected_before_verification (test_backend.BackendTests) ... ok
test_read_size_limit_is_enforced (test_backend.BackendTests) ... ok
test_reinitialization_cannot_overwrite_a_vault (test_backend.BackendTests) ... ok
test_round_trip_preserves_multiple_entries_and_unicode (test_backend.BackendTests) ... ok
test_same_entries_get_a_fresh_nonce_on_each_save (test_backend.BackendTests) ... ok
test_save_size_limit_preserves_original_file (test_backend.BackendTests) ... ok
test_storage_supports_c_read_modify_write_flow (test_backend.BackendTests) ... ok
test_successful_creation_and_save_use_owner_only_permissions (test_backend.BackendTests) ... ok
test_unsupported_kdf_parameters_rejected_before_derivation (test_backend.BackendTests) ... ok
test_unsupported_verifier_cost_rejected_before_verification (test_backend.BackendTests) ... ok
test_wrong_password_cannot_overwrite_existing_data (test_backend.BackendTests) ... ok
test_add_generates_default_password_without_printing_it (test_cli.CliTests) ... ok
test_add_manual_password_is_confirmed_and_spaces_preserved (test_cli.CliTests) ... ok
test_add_supports_custom_generated_length (test_cli.CliTests) ... ok
test_bad_length_and_conflicting_options_fail_before_password_prompt (test_cli.CliTests) ... ok
test_default_file_is_resolved_from_current_working_directory (test_cli.CliTests) ... ok
test_delete_persists_removal (test_cli.CliTests) ... ok
test_duplicate_add_keeps_existing_file (test_cli.CliTests) ... ok
test_echoing_password_fallback_is_refused (test_cli.CliTests) ... ok
test_empty_password_is_rejected (test_cli.CliTests) ... ok
test_eof_and_interrupt_cancel_without_modifying_file (test_cli.CliTests) ... ok
test_file_option_works_before_or_after_subcommand (test_cli.CliTests) ... ok
test_gen_does_not_prompt_or_create_a_vault (test_cli.CliTests) ... ok
test_get_reveals_only_the_requested_entry (test_cli.CliTests) ... ok
test_initialization_mismatch_does_not_create_a_vault (test_cli.CliTests) ... ok
test_initialize_confirms_password_and_creates_readable_vault (test_cli.CliTests) ... ok
test_list_does_not_reveal_passwords (test_cli.CliTests) ... ok
test_manual_password_mismatch_keeps_existing_file (test_cli.CliTests) ... ok
test_missing_get_and_delete_fail_without_saving (test_cli.CliTests) ... ok
test_reinitialization_refuses_to_overwrite (test_cli.CliTests) ... ok
test_tampering_fails_loudly_in_cli_and_cannot_be_overwritten (test_cli.CliTests) ... ok
test_wrong_master_password_does_not_expose_or_modify_data (test_cli.CliTests) ... ok
test_actual_terminal_generated_password_and_later_retrieval (test_cli.TerminalTests) ... ok
test_actual_terminal_init_add_list_get_delete_and_missing_entry (test_cli.TerminalTests) ... ok
test_redirected_secret_input_is_rejected_but_gen_needs_no_terminal (test_cli.TerminalTests) ... ok
test_add_returns_detached_data_and_preserves_password_spaces (test_entries.EntryTests) ... ok
test_bad_entry_fields_are_rejected (test_entries.EntryTests) ... ok
test_case_sensitive_site_contract (test_entries.EntryTests) ... ok
test_delete_preserves_input_and_other_entries (test_entries.EntryTests) ... ok
test_duplicate_site_rejected_without_modifying_input (test_entries.EntryTests) ... ok
test_get_returns_a_copy (test_entries.EntryTests) ... ok
test_list_is_sorted_and_contains_no_password_fields (test_entries.EntryTests) ... ok
test_missing_get_or_delete_is_an_error (test_entries.EntryTests) ... ok
test_default_password (test_generator.GeneratorTests) ... ok
test_invalid_lengths_are_rejected (test_generator.GeneratorTests) ... ok
test_requested_lengths_and_all_four_character_groups (test_generator.GeneratorTests) ... ok
test_secure_choice_and_rejection_of_a_missing_character_group (test_generator.GeneratorTests) ... ok

----------------------------------------------------------------------
Ran 72 tests in 20.240s

OK
```
