"""Real-cryptography sharing tests using only throwaway fake credentials."""

import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from errors import EntryValidationError
from sharing import (
    MAX_KEY_BYTES, MAX_SHARE_BYTES, SharingError,
    export_entry, generate_keypair, import_entry,
)

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "work"
PASSPHRASE = "test-only recipient private passphrase / 密钥"
ENTRY = {"site": "学校", "username": "student123", "password": " fake-only-secret / 密码 "}


class SharingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        WORK.mkdir(exist_ok=True)
        cls.fixture = tempfile.TemporaryDirectory(prefix="sharing-fixture-", dir=WORK)
        fixture = Path(cls.fixture.name)
        cls.private_path = fixture / "recipient-private.pem"
        cls.public_path = fixture / "recipient-public.pem"
        generate_keypair(cls.private_path, cls.public_path, PASSPHRASE)
        cls.other_private = fixture / "other-private.pem"
        generate_keypair(cls.other_private, fixture / "other-public.pem", PASSPHRASE)
        package = fixture / "example.share.json"
        export_entry(ENTRY, cls.public_path, package)
        cls.original = package.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sharing-test-", dir=WORK)
        self.addCleanup(self.directory.cleanup)
        self.directory_path = Path(self.directory.name)
        self.package = self.directory_path / "entry.share.json"
        self.package.write_bytes(self.original)

    def document(self):
        return json.loads(self.package.read_text(encoding="utf-8"))

    def write_document(self, document):
        self.package.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def test_round_trip_preserves_unicode_and_password_spaces(self):
        self.assertEqual(import_entry(self.package, self.private_path, PASSPHRASE), ENTRY)

    def test_export_contains_no_entry_plaintext_or_vault_material(self):
        for value in ENTRY.values():
            self.assertNotIn(value.encode("utf-8"), self.original)
        self.assertNotIn(PASSPHRASE.encode("utf-8"), self.original)
        self.assertEqual(set(self.document()), {"version", "algorithm", "wrapped_key", "nonce", "ciphertext"})

    def test_every_export_uses_fresh_key_nonce_and_ciphertext(self):
        second = self.directory_path / "second.share.json"
        export_entry(ENTRY, self.public_path, second)
        other = json.loads(second.read_text())
        for field in ("wrapped_key", "nonce", "ciphertext"):
            self.assertNotEqual(self.document()[field], other[field])
        self.assertEqual(import_entry(second, self.private_path, PASSPHRASE), ENTRY)

    def test_private_key_is_encrypted_pkcs8_and_matches_public_key(self):
        raw = self.private_path.read_bytes()
        self.assertTrue(raw.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        self.assertNotIn(PASSPHRASE.encode("utf-8"), raw)
        with self.assertRaises(TypeError):
            serialization.load_pem_private_key(raw, password=None)
        private = serialization.load_pem_private_key(raw, password=PASSPHRASE.encode("utf-8"))
        public = serialization.load_pem_public_key(self.public_path.read_bytes())
        self.assertEqual(private.key_size, 3072)
        self.assertEqual(public.public_numbers(), private.public_key().public_numbers())

    def test_wrong_private_key_does_not_return_plaintext(self):
        with self.assertRaisesRegex(SharingError, "authentication failed"):
            import_entry(self.package, self.other_private, PASSPHRASE)

    def test_wrong_private_passphrase_has_clear_error_without_secret(self):
        wrong = "wrong fake passphrase"
        with self.assertRaises(SharingError) as context:
            import_entry(self.package, self.private_path, wrong)
        self.assertNotIn(wrong, str(context.exception))
        self.assertIn("Could not unlock private key", str(context.exception))

    def test_tampering_wrapped_key_nonce_ciphertext_or_tag_fails(self):
        for field in ("wrapped_key", "nonce", "ciphertext"):
            for offset in (0, -1):
                with self.subTest(field=field, offset=offset):
                    document = json.loads(self.original)
                    value = bytearray(base64.b64decode(document[field]))
                    value[offset] ^= 1
                    document[field] = base64.b64encode(value).decode("ascii")
                    self.write_document(document)
                    with self.assertRaisesRegex(SharingError, "authentication failed"):
                        import_entry(self.package, self.private_path, PASSPHRASE)

    def test_rewrapped_key_is_bound_to_aad(self):
        document = self.document()
        private = serialization.load_pem_private_key(self.private_path.read_bytes(), password=PASSPHRASE.encode("utf-8"))
        # OAEP is randomized: the same key re-encrypted yields a different header.
        from sharing import _oaep
        key = private.decrypt(base64.b64decode(document["wrapped_key"]), _oaep())
        document["wrapped_key"] = base64.b64encode(private.public_key().encrypt(key, _oaep())).decode("ascii")
        self.write_document(document)
        with self.assertRaisesRegex(SharingError, "authentication failed"):
            import_entry(self.package, self.private_path, PASSPHRASE)

    def test_unknown_header_or_version_is_rejected(self):
        for field, value in (("version", 2), ("version", True), ("version", 1.0), ("algorithm", "RSA-PKCS1v15")):
            with self.subTest(field=field, value=value):
                document = json.loads(self.original)
                document[field] = value
                self.write_document(document)
                with self.assertRaises(SharingError):
                    import_entry(self.package, self.private_path, PASSPHRASE)
        document = json.loads(self.original)
        document["extra"] = "unsupported"
        self.write_document(document)
        with self.assertRaises(SharingError):
            import_entry(self.package, self.private_path, PASSPHRASE)

    def test_noncanonical_duplicate_or_invalid_json_is_rejected(self):
        invalid = [
            self.original + b" ", b"{", b"[]", b"\xff",
            b'{"version":1,"version":1}', b'{"version":NaN}',
            b"[" * 1100 + b"]" * 1100,
        ]
        for raw in invalid:
            with self.subTest(raw=raw[:30]):
                self.package.write_bytes(raw)
                with self.assertRaises(SharingError):
                    import_entry(self.package, self.private_path, PASSPHRASE)

    def test_invalid_base64_and_lengths_are_rejected(self):
        changes = [("nonce", "!invalid!"), ("nonce", ""), ("wrapped_key", "AA=="), ("ciphertext", "AA=="), ("ciphertext", None)]
        for field, value in changes:
            with self.subTest(field=field, value=value):
                document = json.loads(self.original)
                document[field] = value
                self.write_document(document)
                with self.assertRaises(SharingError):
                    import_entry(self.package, self.private_path, PASSPHRASE)

    def test_decrypted_share_must_contain_one_valid_entry(self):
        from sharing import _aad, _oaep
        for entry in ([], [ENTRY, ENTRY], {}, dict(ENTRY, extra="no"), dict(ENTRY, password="")):
            with self.subTest(entry=entry):
                document = self.document()
                public = serialization.load_pem_public_key(self.public_path.read_bytes())
                key = AESGCM.generate_key(bit_length=256)
                document["wrapped_key"] = base64.b64encode(public.encrypt(key, _oaep())).decode("ascii")
                nonce = os.urandom(12)
                plaintext = json.dumps(entry).encode("utf-8")
                document["nonce"] = base64.b64encode(nonce).decode("ascii")
                document["ciphertext"] = base64.b64encode(AESGCM(key).encrypt(nonce, plaintext, _aad(document))).decode("ascii")
                self.write_document(document)
                with self.assertRaisesRegex(SharingError, "one valid entry"):
                    import_entry(self.package, self.private_path, PASSPHRASE)

    def test_invalid_entry_never_creates_output(self):
        target = self.directory_path / "invalid.share.json"
        for entry in ({}, dict(ENTRY, username=" "), dict(ENTRY, password=""), dict(ENTRY, extra="no")):
            with self.subTest(entry=entry):
                with self.assertRaises(EntryValidationError):
                    export_entry(entry, self.public_path, target)
                self.assertFalse(target.exists())

    def test_export_never_overwrites_existing_output(self):
        before = self.package.read_bytes()
        with self.assertRaisesRegex(SharingError, "already exists"):
            export_entry(ENTRY, self.public_path, self.package)
        self.assertEqual(self.package.read_bytes(), before)

    def test_keygen_never_overwrites_either_existing_output(self):
        for existing_name in ("private.pem", "public.pem"):
            with self.subTest(existing_name=existing_name):
                directory = self.directory_path / existing_name.replace(".", "-")
                directory.mkdir()
                existing = directory / existing_name
                existing.write_bytes(b"existing fake file")
                with self.assertRaisesRegex(SharingError, "already exists"):
                    generate_keypair(directory / "private.pem", directory / "public.pem", PASSPHRASE)
                self.assertEqual(existing.read_bytes(), b"existing fake file")
                self.assertEqual(list(directory.iterdir()), [existing])

    def test_same_key_output_path_is_rejected(self):
        target = self.directory_path / "same.pem"
        with self.assertRaisesRegex(SharingError, "must differ"):
            generate_keypair(target, target.parent / "." / target.name, PASSPHRASE)
        self.assertFalse(target.exists())

    def test_empty_invalid_and_oversized_passphrases_are_rejected(self):
        for passphrase in ("", None, "\ud800", "x" * 1024):
            with self.subTest(passphrase=repr(passphrase)[:30]):
                with self.assertRaises(ValueError):
                    generate_keypair(self.directory_path / "p.pem", self.directory_path / "u.pem", passphrase)
        self.assertEqual(list(self.directory_path.iterdir()), [self.package])

    def test_rejects_unencrypted_private_keys(self):
        private = serialization.load_pem_private_key(self.private_path.read_bytes(), password=PASSPHRASE.encode("utf-8"))
        unencrypted = self.directory_path / "unencrypted.pem"
        unencrypted.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        with self.assertRaisesRegex(SharingError, "passphrase-encrypted"):
            import_entry(self.package, unencrypted, PASSPHRASE)

    def test_rejects_non_rsa_or_weak_public_keys(self):
        public_path = self.directory_path / "bad-public.pem"
        keys = [ec.generate_private_key(ec.SECP256R1()).public_key(), rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()]
        for key in keys:
            with self.subTest(key=type(key).__name__):
                public_path.write_bytes(key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
                with self.assertRaisesRegex(SharingError, "RSA-3072"):
                    export_entry(ENTRY, public_path, self.directory_path / "bad.share.json")

    def test_missing_or_invalid_key_files_have_clear_errors(self):
        missing = self.directory_path / "missing.pem"
        invalid = self.directory_path / "invalid.pem"
        invalid.write_bytes(b"not a key")
        for key_path in (missing, invalid):
            with self.subTest(key_path=key_path.name):
                with self.assertRaises(SharingError):
                    export_entry(ENTRY, key_path, self.directory_path / "bad.share.json")
                with self.assertRaises(SharingError):
                    import_entry(self.package, key_path, PASSPHRASE)
        with self.assertRaisesRegex(SharingError, "Could not read"):
            import_entry(self.directory_path / "missing.share.json", self.private_path, PASSPHRASE)

    def test_key_and_share_size_limits_are_enforced(self):
        huge_key = self.directory_path / "huge.pem"
        huge_key.write_bytes(b"x" * (MAX_KEY_BYTES + 1))
        with self.assertRaisesRegex(SharingError, "size limit"):
            export_entry(ENTRY, huge_key, self.directory_path / "bad.share.json")
        self.package.write_bytes(b"x" * (MAX_SHARE_BYTES + 1))
        with self.assertRaisesRegex(SharingError, "size limit"):
            import_entry(self.package, self.private_path, PASSPHRASE)
        oversized = dict(ENTRY, password="x" * (MAX_SHARE_BYTES + 1))
        with self.assertRaisesRegex(EntryValidationError, "too large"):
            export_entry(oversized, self.public_path, self.directory_path / "large.share.json")

    def test_io_failure_does_not_leave_partial_output_or_temporary_file(self):
        target = self.directory_path / "failed.share.json"
        with patch("sharing.os.fsync", side_effect=OSError("fake disk failure")):
            with self.assertRaises(SharingError):
                export_entry(ENTRY, self.public_path, target)
        self.assertEqual(list(self.directory_path.iterdir()), [self.package])

    def test_key_pair_publication_failure_rolls_back_new_private_file(self):
        original_link = os.link
        calls = []

        def fail_second_link(source, destination):
            calls.append(destination)
            if len(calls) == 2:
                raise OSError("fake publication failure")
            return original_link(source, destination)

        with patch("sharing.os.link", side_effect=fail_second_link):
            with self.assertRaises(SharingError):
                generate_keypair(self.directory_path / "private.pem", self.directory_path / "public.pem", PASSPHRASE)
        self.assertEqual(list(self.directory_path.iterdir()), [self.package])

    def test_missing_output_directory_does_not_create_output(self):
        target = self.directory_path / "missing" / "entry.share.json"
        with self.assertRaisesRegex(SharingError, "Could not save"):
            export_entry(ENTRY, self.public_path, target)
        self.assertFalse(target.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_key_and_share_files_are_owner_only(self):
        target = self.directory_path / "fresh.share.json"
        export_entry(ENTRY, self.public_path, target)
        for path in (self.private_path, self.public_path, target):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(os.name == "posix", "requires symlinks")
    def test_existing_or_broken_output_symlinks_are_not_followed(self):
        target = self.directory_path / "symlink.share.json"
        for destination in (self.package, self.directory_path / "missing-target"):
            with self.subTest(destination=destination.name):
                target.symlink_to(destination)
                with self.assertRaisesRegex(SharingError, "already exists"):
                    export_entry(ENTRY, self.public_path, target)
                self.assertTrue(target.is_symlink())
                target.unlink()
        self.assertEqual(self.package.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main()
