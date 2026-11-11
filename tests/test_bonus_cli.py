"""Bonus CLI integration, privacy failures and real hidden-input sessions."""

import base64
from contextlib import redirect_stderr, redirect_stdout
import errno
import getpass
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import warnings

if os.name == "posix":
    import pty
    import select

from breach import BreachCheckError
from sharing import generate_keypair, import_entry
from storage import initialize_vault, load_vault, save_vault
from vault import main


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "work"
MASTER = "fake bonus master passphrase / 主密码"
PASSPHRASE = "fake recipient private-key passphrase"
PASSWORD = "  fake shared password / 密码 !  "
ENTRY = {"site": "school", "username": "student@example.test", "password": PASSWORD}
OTHER = {"site": "unshared", "username": "private-user", "password": "fake unshared secret!"}


class BonusCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        WORK.mkdir(exist_ok=True)
        cls.fixture = tempfile.TemporaryDirectory(prefix="bonus-cli-fixture-", dir=WORK)
        fixture = Path(cls.fixture.name)
        cls.private = fixture / "recipient-private.pem"
        cls.public = fixture / "recipient-public.pem"
        cls.wrong_private = fixture / "other-private.pem"
        generate_keypair(cls.private, cls.public, PASSPHRASE)
        generate_keypair(cls.wrong_private, fixture / "other-public.pem", PASSPHRASE)
        source, target = fixture / "source.json", fixture / "target.json"
        initialize_vault(source, MASTER)
        save_vault(source, MASTER, [ENTRY, OTHER])
        initialize_vault(target, MASTER)
        cls.source_bytes = source.read_bytes()
        cls.target_bytes = target.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="bonus-cli-", dir=WORK)
        self.addCleanup(self.directory.cleanup)
        self.directory_path = Path(self.directory.name)
        self.source = self.directory_path / "source.json"
        self.target = self.directory_path / "target.json"
        self.package = self.directory_path / "school.share.json"
        self.source.write_bytes(self.source_bytes)
        self.target.write_bytes(self.target_bytes)

    def invoke(self, arguments, secrets=()):
        output, error = io.StringIO(), io.StringIO()
        with patch("vault.getpass.getpass", side_effect=list(secrets)) as prompt:
            with redirect_stdout(output), redirect_stderr(error):
                code = main(arguments)
        return code, output.getvalue(), error.getvalue(), prompt.call_count

    def assert_no_secrets(self, text):
        for value in (MASTER, PASSPHRASE, PASSWORD, OTHER["password"]):
            self.assertNotIn(value, text)

    def share(self):
        return self.invoke(
            ["--file", str(self.source), "share", ENTRY["site"],
             "--recipient-key", str(self.public), "--out", str(self.package)],
            [MASTER],
        )

    def receive(self, target=None, private=None, passphrase=PASSPHRASE):
        return self.invoke(
            ["receive", str(self.package), "--private-key", str(private or self.private),
             "--file", str(target or self.target)],
            [MASTER, passphrase],
        )

    def test_keygen_works_without_a_vault_and_hides_confirmed_passphrase(self):
        private = self.directory_path / "new-private.pem"
        public = self.directory_path / "new-public.pem"
        absent_vault = self.directory_path / "absent.json"
        code, output, error, calls = self.invoke(
            ["--file", str(absent_vault), "keygen", "--private-key", str(private),
             "--public-key", str(public)], [PASSPHRASE, PASSPHRASE],
        )
        self.assertEqual((code, error, calls), (0, "", 2))
        self.assertIn(b"ENCRYPTED PRIVATE KEY", private.read_bytes())
        self.assertIn(b"PUBLIC KEY", public.read_bytes())
        self.assertFalse(absent_vault.exists())
        self.assert_no_secrets(output + error)

    def test_keygen_mismatched_passphrases_do_not_create_files(self):
        private, public = self.directory_path / "new-private.pem", self.directory_path / "new-public.pem"
        code, output, error, _ = self.invoke(
            ["keygen", "--private-key", str(private), "--public-key", str(public)],
            [PASSPHRASE, "different fake passphrase"],
        )
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("do not match", error)
        self.assertFalse(private.exists())
        self.assertFalse(public.exists())
        self.assert_no_secrets(error)

    def test_share_and_receive_round_trip_only_selected_entry_without_network(self):
        with patch("vault.check_password") as network:
            code, output, error, calls = self.share()
            self.assertEqual((code, error, calls), (0, "", 1))
            self.assert_no_secrets(output)
            self.assertEqual(self.source.read_bytes(), self.source_bytes)
            package_bytes = self.package.read_bytes()
            for value in (ENTRY["site"], ENTRY["username"], PASSWORD, OTHER["password"]):
                self.assertNotIn(value.encode("utf-8"), package_bytes)
            self.assertEqual(import_entry(self.package, self.private, PASSPHRASE), ENTRY)
            code, output, error, calls = self.receive()
            self.assertEqual((code, error, calls), (0, "", 2))
            self.assert_no_secrets(output)
            self.assertEqual(load_vault(self.target, MASTER), [ENTRY])
            self.assertNotIn(PASSWORD.encode("utf-8"), self.target.read_bytes())
            self.assertEqual(self.source.read_bytes(), self.source_bytes)
            network.assert_not_called()

    def test_share_missing_site_or_wrong_master_creates_no_package(self):
        for site, master in (("missing", MASTER), (ENTRY["site"], "wrong fake master")):
            with self.subTest(site=site):
                code, output, error, _ = self.invoke(
                    ["share", site, "--file", str(self.source), "--recipient-key",
                     str(self.public), "--out", str(self.package)], [master],
                )
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("Error:", error)
                self.assertFalse(self.package.exists())
                self.assertEqual(self.source.read_bytes(), self.source_bytes)
                self.assert_no_secrets(error)

    def test_share_refuses_to_overwrite_a_package(self):
        self.assertEqual(self.share()[0], 0)
        original = self.package.read_bytes()
        code, output, error, _ = self.share()
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("Error:", error)
        self.assertEqual(self.package.read_bytes(), original)
        self.assertEqual(self.source.read_bytes(), self.source_bytes)

    def test_receive_duplicate_site_preserves_the_vault(self):
        self.assertEqual(self.share()[0], 0)
        code, output, error, _ = self.receive(target=self.source)
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("Duplicate site", error)
        self.assertEqual(self.source.read_bytes(), self.source_bytes)
        self.assert_no_secrets(error)

    def test_receive_wrong_key_or_passphrase_preserves_destination(self):
        self.assertEqual(self.share()[0], 0)
        for private, passphrase in ((self.wrong_private, PASSPHRASE), (self.private, "wrong fake passphrase")):
            with self.subTest(private=private.name, correct_passphrase=passphrase == PASSPHRASE):
                code, output, error, _ = self.receive(private=private, passphrase=passphrase)
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("Error:", error)
                self.assert_no_secrets(error)
                self.assertEqual(self.target.read_bytes(), self.target_bytes)

    def test_receive_tampered_ciphertext_preserves_destination(self):
        self.assertEqual(self.share()[0], 0)
        document = json.loads(self.package.read_text(encoding="utf-8"))
        ciphertext = bytearray(base64.b64decode(document["ciphertext"]))
        ciphertext[0] ^= 1
        document["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
        self.package.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        code, output, error, _ = self.receive()
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("authentication failed", error)
        self.assert_no_secrets(error)
        self.assertEqual(self.target.read_bytes(), self.target_bytes)

    def test_check_stored_entry_through_real_breach_logic_sends_only_prefix(self):
        # Fixed SHA-1 test vector for PASSWORD, including its Unicode and spaces.
        digest = "ED674F84B1470C4D96BEABC46F346502F159F81C"
        url = "https://api.pwnedpasswords.com/range/ED674"
        with patch("breach.build_opener") as build_opener:
            response = build_opener.return_value.open.return_value.__enter__.return_value
            response.getcode.return_value = 200
            response.geturl.return_value = url
            response.read.return_value = (digest[5:] + ":17\r\n" + "A" * 35 + ":0\r\n").encode("ascii")
            code, output, error, calls = self.invoke(
                ["check", ENTRY["site"], "--file", str(self.source)], [MASTER],
            )
        self.assertEqual((code, calls), (0, 1))
        self.assertEqual(json.loads(output), {"breached": True, "count": 17})
        opener = build_opener.return_value
        opener.open.assert_called_once()
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, url)
        self.assertEqual(request.method, "GET")
        self.assertIsNone(request.data)
        self.assertEqual(request.get_header("Add-padding"), "true")
        sent = request.full_url + repr(request.header_items())
        for secret in (PASSWORD, MASTER, digest, digest[5:]):
            self.assertNotIn(secret, sent)
            self.assertNotIn(secret, output + error)
        self.assert_no_secrets(output + error)
        self.assertEqual(self.source.read_bytes(), self.source_bytes)

    def test_check_standalone_needs_no_vault_and_preserves_password_spaces(self):
        absent = self.directory_path / "absent.json"
        with patch("vault.check_password", return_value=42) as check:
            code, output, error, calls = self.invoke(["check", "--file", str(absent)], [PASSWORD])
        self.assertEqual((code, calls), (0, 1))
        self.assertEqual(json.loads(output), {"breached": True, "count": 42})
        check.assert_called_once_with(PASSWORD)
        self.assertIn("5", error)
        self.assertFalse(absent.exists())
        self.assert_no_secrets(output + error)

    def test_check_stored_entry_uses_its_password_without_modifying_vault(self):
        with patch("vault.check_password", return_value=0) as check:
            code, output, error, calls = self.invoke(
                ["--file", str(self.source), "check", ENTRY["site"]], [MASTER],
            )
        self.assertEqual((code, calls), (0, 1))
        self.assertEqual(json.loads(output), {"breached": False, "count": 0})
        check.assert_called_once_with(PASSWORD)
        self.assertEqual(self.source.read_bytes(), self.source_bytes)
        self.assert_no_secrets(output + error)

    def test_check_failed_unlock_or_missing_site_never_requests_network(self):
        for site, master in (("missing", MASTER), (ENTRY["site"], "wrong fake master")):
            with self.subTest(site=site):
                with patch("vault.check_password") as check:
                    code, output, error, _ = self.invoke(
                        ["check", site, "--file", str(self.source)], [master],
                    )
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("Error:", error)
                self.assert_no_secrets(error)
                check.assert_not_called()
                self.assertEqual(self.source.read_bytes(), self.source_bytes)

    def test_check_network_failure_is_an_error_without_a_safe_result(self):
        with patch("vault.check_password", side_effect=BreachCheckError("Breach service unavailable.")):
            code, output, error, _ = self.invoke(["check"], [PASSWORD])
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("Error:", error)
        self.assertNotIn('"breached": false', error.lower())
        self.assert_no_secrets(error)

    def test_empty_check_password_never_requests_network(self):
        with patch("vault.check_password") as check:
            code, output, error, _ = self.invoke(["check"], [""])
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("cannot be empty", error)
        check.assert_not_called()

    def test_bonus_secret_prompts_refuse_echoing_fallback(self):
        def unavailable(prompt):
            warnings.warn("simulated terminal unavailable", getpass.GetPassWarning)
            return PASSPHRASE

        for arguments in (
            ["check"],
            ["keygen", "--private-key", str(self.directory_path / "new-private.pem"),
             "--public-key", str(self.directory_path / "new-public.pem")],
        ):
            with self.subTest(command=arguments[0]):
                output, error = io.StringIO(), io.StringIO()
                with patch("vault.getpass.getpass", side_effect=unavailable), patch("vault.check_password") as check:
                    with redirect_stdout(output), redirect_stderr(error):
                        code = main(arguments)
                self.assertEqual(code, 1)
                self.assertEqual(output.getvalue(), "")
                self.assertIn("Hidden password input is unavailable", error.getvalue())
                self.assert_no_secrets(error.getvalue())
                check.assert_not_called()

    def terminal(self, arguments, answers):
        master_fd, slave_fd = pty.openpty()
        process = subprocess.Popen(
            [sys.executable, "-B", str(ROOT / "vault.py"), *arguments],
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            cwd=str(ROOT), start_new_session=True,
        )
        os.close(slave_fd)
        output, cursor, answer_index = bytearray(), 0, 0
        deadline = time.monotonic() + 20
        try:
            while True:
                if time.monotonic() > deadline:
                    self.fail("Terminal command timed out: " + repr(arguments))
                ready, _, _ = select.select([master_fd], [], [], 0.1)
                if ready:
                    try:
                        chunk = os.read(master_fd, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        break
                    if not chunk:
                        break
                    output.extend(chunk)
                while answer_index < len(answers):
                    prompt, value = answers[answer_index]
                    position = output.find(prompt.encode("utf-8"), cursor)
                    if position < 0:
                        break
                    cursor = position + len(prompt.encode("utf-8"))
                    os.write(master_fd, (value + "\n").encode("utf-8"))
                    answer_index += 1
                if not ready and process.poll() is not None:
                    break
            code = process.wait(timeout=5)
        finally:
            os.close(master_fd)
            if process.poll() is None:
                process.kill()
                process.wait()
        self.assertEqual(answer_index, len(answers), "Not all hidden-input prompts were reached")
        return code, output.decode("utf-8", errors="replace").replace("\r\n", "\n")

    @unittest.skipUnless(os.name == "posix", "Real hidden-input sessions use a POSIX PTY")
    def test_real_terminal_keygen_share_receive_keeps_secrets_hidden(self):
        private = self.directory_path / "terminal-private.pem"
        public = self.directory_path / "terminal-public.pem"
        sessions = (
            (["keygen", "--private-key", str(private), "--public-key", str(public)],
             [("Private-key passphrase: ", PASSPHRASE), ("Confirm private-key passphrase: ", PASSPHRASE)]),
            (["share", ENTRY["site"], "--file", str(self.source), "--recipient-key", str(public),
              "--out", str(self.package)], [("Master password: ", MASTER)]),
            (["receive", str(self.package), "--file", str(self.target), "--private-key", str(private)],
             [("Master password: ", MASTER), ("Private-key passphrase: ", PASSPHRASE)]),
        )
        for arguments, answers in sessions:
            code, output = self.terminal(arguments, answers)
            self.assertEqual(code, 0, output)
            self.assert_no_secrets(output)
        self.assertEqual(load_vault(self.target, MASTER), [ENTRY])
        self.assertEqual(self.source.read_bytes(), self.source_bytes)


if __name__ == "__main__":
    unittest.main()
