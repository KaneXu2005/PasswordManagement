"""Backend acceptance tests; fixtures and temporary files stay inside work/."""

import base64
import copy
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from crypto import derive_key, hash_master_password, verify_master_password
from errors import (
    EntryValidationError,
    InvalidMasterPassword,
    VaultAlreadyExistsError,
    VaultFormatError,
    VaultIOError,
    VaultIntegrityError,
    VaultNotFoundError,
    VaultError,
)
from storage import initialize_vault, load_vault, save_vault

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "work"
MASTER = "test-only long master passphrase / 主密码"
ENTRIES = [
    {"site": "github", "username": "alice", "password": "test-only-GitHub-secret!"},
    {"site": "学校", "username": "学号123", "password": "test-only-学校-secret!"},
]


class BackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        WORK.mkdir(exist_ok=True)
        cls.fixture = tempfile.TemporaryDirectory(prefix="fixture-", dir=WORK)
        fixture_path = Path(cls.fixture.name) / "vault.json"
        initialize_vault(fixture_path, MASTER)
        cls.original = fixture_path.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="test-", dir=WORK)
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "vault.json"
        self.path.write_bytes(self.original)

    def document(self):
        return json.loads(self.path.read_text(encoding="utf-8"))

    def write_document(self, document):
        self.path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def flip_field(self, field):
        document = self.document()
        value = bytearray(base64.b64decode(document[field]))
        value[0] ^= 1
        document[field] = base64.b64encode(value).decode("ascii")
        self.write_document(document)

    def test_initialization_creates_argon2id_and_encrypted_empty_vault(self):
        document = self.document()
        self.assertTrue(document["master_hash"].startswith("$argon2id$"))
        self.assertNotIn(MASTER.encode("utf-8"), self.original)
        self.assertEqual(load_vault(self.path, MASTER), [])
        self.assertEqual(set(document), {"version", "master_hash", "kdf", "nonce", "ciphertext"})

    def test_correct_password_verifies_and_wrong_password_is_rejected(self):
        verifier = self.document()["master_hash"]
        self.assertIsNone(verify_master_password(MASTER, verifier))
        with self.assertRaises(InvalidMasterPassword):
            load_vault(self.path, "incorrect test password")

    def test_empty_master_password_does_not_create_a_file(self):
        target = self.path.parent / "empty.json"
        with self.assertRaises(ValueError):
            initialize_vault(target, "")
        self.assertFalse(target.exists())

    def test_reinitialization_cannot_overwrite_a_vault(self):
        with self.assertRaises(VaultAlreadyExistsError):
            initialize_vault(self.path, "a different master password")
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_round_trip_preserves_multiple_entries_and_unicode(self):
        save_vault(self.path, MASTER, ENTRIES)
        self.assertEqual(load_vault(self.path, MASTER), ENTRIES)
        raw = self.path.read_bytes()
        for entry in ENTRIES:
            for value in entry.values():
                self.assertNotIn(value.encode("utf-8"), raw)
        self.assertNotIn(MASTER.encode("utf-8"), raw)
        self.assertEqual(sorted(p.name for p in self.path.parent.iterdir()), ["vault.json"])

    def test_storage_supports_c_read_modify_write_flow(self):
        entries = load_vault(self.path, MASTER)
        entries.append(copy.deepcopy(ENTRIES[0]))
        save_vault(self.path, MASTER, entries)
        entries = load_vault(self.path, MASTER)
        entries[0]["password"] = "updated test password"
        save_vault(self.path, MASTER, entries)
        self.assertEqual(load_vault(self.path, MASTER)[0]["password"], "updated test password")
        entries.pop()
        save_vault(self.path, MASTER, entries)
        self.assertEqual(load_vault(self.path, MASTER), [])

    def test_same_entries_get_a_fresh_nonce_on_each_save(self):
        save_vault(self.path, MASTER, ENTRIES)
        first = self.document()
        save_vault(self.path, MASTER, ENTRIES)
        second = self.document()
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])
        self.assertEqual(first["master_hash"], second["master_hash"])
        self.assertEqual(first["kdf"], second["kdf"])

    def test_independent_vaults_have_independent_salts_and_nonces(self):
        target = self.path.parent / "second.json"
        initialize_vault(target, MASTER)
        first = self.document()
        second = json.loads(target.read_text(encoding="utf-8"))
        self.assertNotEqual(first["master_hash"], second["master_hash"])
        self.assertNotEqual(first["kdf"]["salt"], second["kdf"]["salt"])
        self.assertNotEqual(first["nonce"], second["nonce"])
        verifier_salt = base64.b64decode(first["master_hash"].split("$")[4] + "==")
        self.assertNotEqual(verifier_salt, base64.b64decode(first["kdf"]["salt"]))

    def test_key_derivation_is_reproducible_and_depends_on_password_and_salt(self):
        salt = b"1" * 16
        key = derive_key(MASTER, salt)
        self.assertEqual(len(key), 32)
        self.assertEqual(key, derive_key(MASTER, salt))
        self.assertNotEqual(key, derive_key("another password", salt))
        self.assertNotEqual(key, derive_key(MASTER, b"2" * 16))

    def test_flipping_one_ciphertext_byte_is_rejected(self):
        save_vault(self.path, MASTER, ENTRIES)
        self.flip_field("ciphertext")
        with self.assertRaises(VaultIntegrityError):
            load_vault(self.path, MASTER)

    def test_flipping_one_authentication_tag_byte_is_rejected(self):
        document = self.document()
        value = bytearray(base64.b64decode(document["ciphertext"]))
        value[-1] ^= 1
        document["ciphertext"] = base64.b64encode(value).decode("ascii")
        self.write_document(document)
        with self.assertRaises(VaultIntegrityError):
            load_vault(self.path, MASTER)

    def test_modified_nonce_is_rejected(self):
        self.flip_field("nonce")
        with self.assertRaises(VaultIntegrityError):
            load_vault(self.path, MASTER)

    def test_modified_kdf_salt_is_rejected(self):
        document = self.document()
        document["kdf"]["salt"] = base64.b64encode(b"3" * 16).decode("ascii")
        self.write_document(document)
        with self.assertRaises(VaultIntegrityError):
            load_vault(self.path, MASTER)

    def test_header_verifier_is_authenticated_even_if_password_still_matches(self):
        document = self.document()
        document["master_hash"] = hash_master_password(MASTER)
        self.write_document(document)
        with self.assertRaises(VaultIntegrityError):
            load_vault(self.path, MASTER)

    def test_unsupported_kdf_parameters_rejected_before_derivation(self):
        document = self.document()
        document["kdf"]["memory_cost"] = 2 ** 40
        self.write_document(document)
        with patch("storage.derive_key") as derive:
            with self.assertRaises(VaultFormatError):
                load_vault(self.path, MASTER)
            derive.assert_not_called()

    def test_unsupported_verifier_cost_rejected_before_verification(self):
        document = self.document()
        document["master_hash"] = document["master_hash"].replace("m=65536", "m=1099511627776")
        self.write_document(document)
        with patch("crypto._PH") as hasher:
            with self.assertRaises(VaultFormatError):
                load_vault(self.path, MASTER)
            hasher.verify.assert_not_called()

    def test_bad_json_and_duplicate_fields_are_rejected(self):
        for data in (b"not JSON", b"\xff", b'{"version":1,"version":1}', b'NaN'):
            with self.subTest(data=data):
                self.path.write_bytes(data)
                with self.assertRaises(VaultFormatError):
                    load_vault(self.path, MASTER)

    def test_invalid_version_fields_and_encodings_are_rejected(self):
        original = self.document()
        variants = []
        for version in (2, True):
            item = copy.deepcopy(original)
            item["version"] = version
            variants.append(item)
        for field, value in (("nonce", "!!!"), ("nonce", ""), ("ciphertext", ""), ("master_hash", "sha256:bad")):
            item = copy.deepcopy(original)
            item[field] = value
            variants.append(item)
        item = copy.deepcopy(original)
        item["unknown"] = "untrusted"
        variants.append(item)
        for document in variants:
            with self.subTest(document=document):
                self.write_document(document)
                with self.assertRaises(VaultFormatError):
                    load_vault(self.path, MASTER)

    def test_wrong_password_cannot_overwrite_existing_data(self):
        with self.assertRaises(InvalidMasterPassword):
            save_vault(self.path, "wrong test password", ENTRIES)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_corrupt_vault_cannot_be_silently_overwritten(self):
        self.flip_field("ciphertext")
        damaged = self.path.read_bytes()
        with self.assertRaises(VaultIntegrityError):
            save_vault(self.path, MASTER, ENTRIES)
        self.assertEqual(self.path.read_bytes(), damaged)

    def test_invalid_entries_do_not_modify_the_file(self):
        invalid = [
            {}, [{"site": "github"}],
            [{"site": "github", "username": "alice", "password": 123}],
            [{"site": "github", "username": "alice", "password": ""}],
            [{"site": " ", "username": "alice", "password": "secret"}],
            [ENTRIES[0], ENTRIES[0]],
            [dict(ENTRIES[0], notes="unsupported")],
        ]
        for entries in invalid:
            with self.subTest(entries=entries):
                with self.assertRaises(EntryValidationError):
                    save_vault(self.path, MASTER, entries)
                self.assertEqual(self.path.read_bytes(), self.original)

    def test_missing_vault_is_not_implicitly_created(self):
        missing = self.path.parent / "missing.json"
        with self.assertRaises(VaultNotFoundError):
            load_vault(missing, MASTER)
        with self.assertRaises(VaultNotFoundError):
            save_vault(missing, MASTER, ENTRIES)
        self.assertFalse(missing.exists())

    def test_failed_atomic_replace_preserves_existing_file_and_cleans_temp(self):
        with patch("storage.os.replace", side_effect=OSError("simulated write failure")):
            with self.assertRaises(VaultIOError):
                save_vault(self.path, MASTER, ENTRIES)
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual([p.name for p in self.path.parent.iterdir()], ["vault.json"])

    def test_successful_creation_and_save_use_owner_only_permissions(self):
        if os.name != "posix":
            self.skipTest("POSIX permission check")
        target = self.path.parent / "private.json"
        initialize_vault(target, MASTER)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        save_vault(target, MASTER, ENTRIES)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_changed_json_formatting_is_rejected_without_modifying_file(self):
        document = self.document()
        variants = [
            json.dumps(document, sort_keys=True).encode("utf-8"),
            (json.dumps(dict(reversed(list(document.items()))), indent=2) + "\n").encode("utf-8"),
            self.original.rstrip(b"\n"),
            self.original + b" ",
            self.original.replace(b"  ", b" ", 1),
        ]
        for changed in variants:
            with self.subTest(changed=changed):
                self.path.write_bytes(changed)
                with self.assertRaises(VaultFormatError):
                    load_vault(self.path, MASTER)
                with self.assertRaises(VaultFormatError):
                    save_vault(self.path, MASTER, ENTRIES)
                self.assertEqual(self.path.read_bytes(), changed)

    def test_flipping_one_bit_at_every_file_byte_is_rejected(self):
        # Exercise the actual on-disk bytes, including JSON formatting, metadata,
        # Base64 ciphertext and tag; not merely a decoded ciphertext buffer.
        for offset in range(len(self.original)):
            with self.subTest(offset=offset):
                changed = bytearray(self.original)
                changed[offset] ^= 1
                self.path.write_bytes(changed)
                with self.assertRaises(VaultError):
                    load_vault(self.path, MASTER)


    def test_non_ascii_verifier_is_rejected_before_verification(self):
        for field in (4, 5):
            with self.subTest(field=field):
                document = json.loads(self.original)
                parts = document["master_hash"].split("$")
                parts[field] = "é" * len(parts[field])
                document["master_hash"] = "$".join(parts)
                self.write_document(document)
                with patch("crypto._PH") as hasher:
                    with self.assertRaises(VaultFormatError):
                        load_vault(self.path, MASTER)
                    hasher.verify.assert_not_called()

    def test_invalid_utf8_entry_is_rejected_without_modifying_file(self):
        for field in ("site", "username", "password"):
            with self.subTest(field=field):
                entry = dict(ENTRIES[0])
                entry[field] = "invalid-" + chr(0xD800)
                with self.assertRaises(EntryValidationError):
                    save_vault(self.path, MASTER, [entry])
                self.assertEqual(self.path.read_bytes(), self.original)

    def test_invalid_utf8_master_password_has_a_clear_parameter_error(self):
        target = self.path.parent / "invalid-master.json"
        with self.assertRaisesRegex(ValueError, "valid UTF-8"):
            initialize_vault(target, "invalid-" + chr(0xD800))
        self.assertFalse(target.exists())

    def test_cleanup_failure_does_not_hide_original_save_error(self):
        with patch("storage.os.replace", side_effect=OSError("simulated write failure")):
            with patch("storage.Path.unlink", side_effect=PermissionError("simulated cleanup failure")):
                with self.assertRaisesRegex(VaultIOError, "Could not save"):
                    save_vault(self.path, MASTER, ENTRIES)
        self.assertEqual(self.path.read_bytes(), self.original)
        # Failed cleanup may leave encrypted temporary files, never plaintext.
        for temporary in self.path.parent.glob("*.tmp"):
            self.assertEqual(load_vault(temporary, MASTER), ENTRIES)

    def test_cleanup_failure_after_publish_reports_that_vault_was_saved(self):
        target = self.path.parent / "published.json"
        with patch("storage.Path.unlink", side_effect=PermissionError("simulated cleanup failure")):
            with self.assertRaisesRegex(VaultIOError, "was saved"):
                initialize_vault(target, MASTER)
        self.assertTrue(target.exists())
        self.assertEqual(load_vault(target, MASTER), [])

    def test_initialization_publish_race_does_not_overwrite_competing_file(self):
        target = self.path.parent / "racing.json"
        real_link = os.link

        def create_competing_file(source, destination):
            Path(destination).write_bytes(b"another process created this file")
            return real_link(source, destination)

        with patch("storage.os.link", side_effect=create_competing_file):
            with self.assertRaises(VaultAlreadyExistsError):
                initialize_vault(target, MASTER)
        self.assertEqual(target.read_bytes(), b"another process created this file")
        self.assertEqual(list(self.path.parent.glob("*.tmp")), [])

    def test_fsync_failure_preserves_original_and_removes_temporary_file(self):
        with patch("storage.os.fsync", side_effect=OSError("simulated sync failure")):
            with self.assertRaises(VaultIOError):
                save_vault(self.path, MASTER, ENTRIES)
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual([p.name for p in self.path.parent.iterdir()], ["vault.json"])

    def test_read_size_limit_is_enforced(self):
        with patch("storage.MAX_VAULT_BYTES", len(self.original) - 1):
            with self.assertRaises(VaultFormatError):
                load_vault(self.path, MASTER)

    def test_save_size_limit_preserves_original_file(self):
        with patch("storage.MAX_VAULT_BYTES", len(self.original)):
            with self.assertRaises(EntryValidationError):
                save_vault(self.path, MASTER, ENTRIES)
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual([p.name for p in self.path.parent.iterdir()], ["vault.json"])

    def test_a_fresh_process_can_load_saved_entries_without_cached_key(self):
        save_vault(self.path, MASTER, ENTRIES)
        program = (
            "import json, sys; from storage import load_vault; "
            "password = sys.stdin.read(); "
            "print(json.dumps(load_vault(sys.argv[1], password), ensure_ascii=True))"
        )
        result = subprocess.run(
            [sys.executable, "-B", "-c", program, str(self.path)],
            input=MASTER, text=True, capture_output=True, cwd=str(ROOT), check=True,
        )
        self.assertEqual(json.loads(result.stdout), ENTRIES)


if __name__ == "__main__":
    unittest.main()
