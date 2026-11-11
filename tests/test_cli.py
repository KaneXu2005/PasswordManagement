"""C's CLI checks, including actual hidden-input terminal sessions on macOS."""

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

from generator import ALPHABET, CHARACTER_GROUPS
from storage import initialize_vault, load_vault, save_vault
from vault import main

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "work"
MASTER = "fake terminal master passphrase / 主密码"
ACCOUNT_PASSWORD = "fake-account-password!"
ENTRY = {"site": "github", "username": "alice", "password": ACCOUNT_PASSWORD}


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        WORK.mkdir(exist_ok=True)
        cls.fixture = tempfile.TemporaryDirectory(prefix="cli-fixture-", dir=WORK)
        path = Path(cls.fixture.name) / "vault.json"
        initialize_vault(path, MASTER)
        save_vault(path, MASTER, [ENTRY])
        cls.original = path.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="cli-test-", dir=WORK)
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "vault.json"
        self.path.write_bytes(self.original)

    def invoke(self, arguments, secrets=()):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("vault.getpass.getpass", side_effect=list(secrets)) as read_secret:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue(), read_secret.call_count

    def args(self, *arguments):
        return ["--file", str(self.path), *arguments]

    def test_initialize_confirms_password_and_creates_readable_vault(self):
        target = self.path.parent / "new.json"
        code, output, error, calls = self.invoke(["init", "--file", str(target)], [MASTER, MASTER])
        self.assertEqual((code, error, calls), (0, "", 2))
        self.assertIn("initialized", output)
        self.assertEqual(load_vault(target, MASTER), [])
        self.assertNotIn(MASTER, output)

    def test_initialization_mismatch_does_not_create_a_vault(self):
        target = self.path.parent / "new.json"
        code, output, error, _ = self.invoke(["--file", str(target), "init"], [MASTER, "different"])
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("do not match", error)
        self.assertFalse(target.exists())

    def test_reinitialization_refuses_to_overwrite(self):
        code, _, error, _ = self.invoke(self.args("init"), [MASTER, MASTER])
        self.assertEqual(code, 1)
        self.assertIn("already exists", error)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_list_does_not_reveal_passwords(self):
        code, output, error, calls = self.invoke(self.args("list"), [MASTER])
        self.assertEqual((code, error, calls), (0, "", 1))
        self.assertEqual(json.loads(output), [{"site": "github", "username": "alice"}])
        self.assertNotIn(ACCOUNT_PASSWORD, output + error)
        self.assertNotIn(MASTER, output + error)

    def test_get_reveals_only_the_requested_entry(self):
        code, output, error, _ = self.invoke(self.args("get", "github"), [MASTER])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(output), ENTRY)
        self.assertNotIn(MASTER, output)

    def test_add_generates_default_password_without_printing_it(self):
        code, output, error, calls = self.invoke(self.args("add", "mail", "--user", "alice@example.com"), [MASTER])
        self.assertEqual((code, error, calls), (0, "", 1))
        entry = load_vault(self.path, MASTER)[-1]
        self.assertEqual(entry["site"], "mail")
        self.assertEqual(len(entry["password"]), 20)
        self.assertTrue(all(any(c in group for c in entry["password"]) for group in CHARACTER_GROUPS))
        self.assertNotIn(entry["password"], output)

    def test_add_supports_custom_generated_length(self):
        code, _, error, _ = self.invoke(self.args("add", "mail", "--user", "alice", "--length", "32"), [MASTER])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(len(load_vault(self.path, MASTER)[-1]["password"]), 32)

    def test_add_manual_password_is_confirmed_and_spaces_preserved(self):
        password = "  fake password with spaces  "
        code, output, error, calls = self.invoke(self.args("add", "mail", "--user", "alice", "--prompt-password"), [MASTER, password, password])
        self.assertEqual((code, error, calls), (0, "", 3))
        self.assertEqual(load_vault(self.path, MASTER)[-1]["password"], password)
        self.assertNotIn(password, output)

    def test_manual_password_mismatch_keeps_existing_file(self):
        code, _, error, _ = self.invoke(self.args("add", "mail", "--user", "alice", "--prompt-password"), [MASTER, "first", "second"])
        self.assertEqual(code, 1)
        self.assertIn("do not match", error)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_duplicate_add_keeps_existing_file(self):
        code, output, error, _ = self.invoke(self.args("add", "github", "--user", "bob"), [MASTER])
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("Duplicate site", error)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_delete_persists_removal(self):
        code, _, error, _ = self.invoke(self.args("delete", "github"), [MASTER])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(load_vault(self.path, MASTER), [])

    def test_missing_get_and_delete_fail_without_saving(self):
        for command in ("get", "delete"):
            with self.subTest(command=command):
                code, output, error, _ = self.invoke(self.args(command, "missing"), [MASTER])
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("Entry not found", error)
                self.assertEqual(self.path.read_bytes(), self.original)

    def test_wrong_master_password_does_not_expose_or_modify_data(self):
        code, output, error, _ = self.invoke(self.args("get", "github"), ["wrong fake master"])
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("Incorrect master password", error)
        self.assertNotIn(ACCOUNT_PASSWORD, error)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_tampering_fails_loudly_in_cli_and_cannot_be_overwritten(self):
        document = json.loads(self.original)
        text = document["ciphertext"]
        document["ciphertext"] = ("A" if text[0] != "A" else "B") + text[1:]
        raw = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")
        self.path.write_bytes(raw)
        for arguments in (("get", "github"), ("add", "mail", "--user", "alice")):
            with self.subTest(arguments=arguments):
                code, output, error, _ = self.invoke(self.args(*arguments), [MASTER])
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("Error:", error)
                self.assertNotIn(ACCOUNT_PASSWORD, error)
                self.assertEqual(self.path.read_bytes(), raw)

    def test_file_option_works_before_or_after_subcommand(self):
        for arguments in (self.args("list"), ["list", "--file", str(self.path)]):
            with self.subTest(arguments=arguments):
                code, output, error, _ = self.invoke(arguments, [MASTER])
                self.assertEqual((code, error), (0, ""))
                self.assertEqual(json.loads(output)[0]["site"], "github")

    def test_default_file_is_resolved_from_current_working_directory(self):
        previous = Path.cwd()
        try:
            os.chdir(self.path.parent)
            code, output, error, _ = self.invoke(["list"], [MASTER])
        finally:
            os.chdir(previous)
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(output)[0]["site"], "github")

    def test_gen_does_not_prompt_or_create_a_vault(self):
        target = self.path.parent / "absent.json"
        code, output, error, calls = self.invoke(["gen", "--file", str(target), "--length", "24"])
        self.assertEqual((code, error, calls), (0, "", 0))
        self.assertEqual(len(output.rstrip("\n")), 24)
        self.assertFalse(target.exists())

    def test_bad_length_and_conflicting_options_fail_before_password_prompt(self):
        cases = (["gen", "--length", "8"], ["gen", "--length", "text"], ["add", "mail", "--user", "alice", "--prompt-password", "--length", "20"])
        for arguments in cases:
            with self.subTest(arguments=arguments):
                with patch("vault.getpass.getpass") as read_secret:
                    with redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit) as error:
                            main(arguments)
                    self.assertEqual(error.exception.code, 2)
                    read_secret.assert_not_called()

    def test_empty_password_is_rejected(self):
        code, output, error, _ = self.invoke(self.args("list"), [""])
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("cannot be empty", error)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_eof_and_interrupt_cancel_without_modifying_file(self):
        for exception, expected in ((EOFError(), 1), (KeyboardInterrupt(), 130)):
            with self.subTest(exception=type(exception).__name__):
                with patch("vault.getpass.getpass", side_effect=exception):
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        self.assertEqual(main(self.args("delete", "github")), expected)
                self.assertEqual(self.path.read_bytes(), self.original)

    def test_echoing_password_fallback_is_refused(self):
        def unavailable(prompt):
            warnings.warn("simulated echoing input", getpass.GetPassWarning)
            return MASTER
        output, error = io.StringIO(), io.StringIO()
        with patch("vault.getpass.getpass", side_effect=unavailable):
            with redirect_stdout(output), redirect_stderr(error):
                self.assertEqual(main(self.args("list")), 1)
        self.assertIn("Hidden password input is unavailable", error.getvalue())
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(self.path.read_bytes(), self.original)


@unittest.skipUnless(os.name == "posix", "Real PTY sessions are tested on the Mac demo target")
class TerminalTests(unittest.TestCase):
    def setUp(self):
        WORK.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="terminal-test-", dir=WORK)
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "vault.json"

    def terminal(self, arguments, answers):
        master_fd, slave_fd = pty.openpty()
        process = subprocess.Popen(
            [sys.executable, "-B", str(ROOT / "vault.py"), "--file", str(self.path), *arguments],
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, cwd=str(ROOT), start_new_session=True,
        )
        os.close(slave_fd)
        output = bytearray()
        cursor, answer_index = 0, 0
        deadline = time.monotonic() + 15
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
        self.assertEqual(answer_index, len(answers), "Not all secret prompts were reached")
        return code, output.decode("utf-8", errors="replace").replace("\r\n", "\n")

    def unlock(self):
        return [("Master password: ", MASTER)]

    def test_actual_terminal_init_add_list_get_delete_and_missing_entry(self):
        code, output = self.terminal(["init"], self.unlock() + [("Confirm master password: ", MASTER)])
        self.assertEqual(code, 0, output)
        self.assertNotIn(MASTER, output)
        code, output = self.terminal(["add", "github", "--user", "alice", "--prompt-password"], self.unlock() + [("Account password: ", ACCOUNT_PASSWORD), ("Confirm account password: ", ACCOUNT_PASSWORD)])
        self.assertEqual(code, 0, output)
        self.assertNotIn(MASTER, output)
        self.assertNotIn(ACCOUNT_PASSWORD, output)
        code, output = self.terminal(["list"], self.unlock())
        self.assertEqual(code, 0, output)
        self.assertIn('"site": "github"', output)
        self.assertNotIn(ACCOUNT_PASSWORD, output)
        code, output = self.terminal(["get", "github"], self.unlock())
        self.assertEqual(code, 0, output)
        self.assertIn(ACCOUNT_PASSWORD, output)
        self.assertNotIn(MASTER, output)
        code, output = self.terminal(["delete", "github"], self.unlock())
        self.assertEqual(code, 0, output)
        code, output = self.terminal(["get", "github"], self.unlock())
        self.assertEqual(code, 1, output)
        self.assertIn("Entry not found", output)
        self.assertEqual(load_vault(self.path, MASTER), [])

    def test_actual_terminal_generated_password_and_later_retrieval(self):
        code, output = self.terminal(["init"], self.unlock() + [("Confirm master password: ", MASTER)])
        self.assertEqual(code, 0, output)
        code, output = self.terminal(["add", "mail", "--user", "alice", "--length", "28"], self.unlock())
        self.assertEqual(code, 0, output)
        code, output = self.terminal(["get", "mail"], self.unlock())
        self.assertEqual(code, 0, output)
        entry = json.loads(output[output.index("{"):output.rindex("}") + 1])
        password = entry["password"]
        self.assertEqual(len(password), 28)
        self.assertTrue(all(c in ALPHABET for c in password))
        self.assertTrue(all(any(c in group for c in password) for group in CHARACTER_GROUPS))

    def test_redirected_secret_input_is_rejected_but_gen_needs_no_terminal(self):
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "vault.py"), "--file", str(self.path), "init"],
            input=MASTER + "\n" + MASTER + "\n", text=True, capture_output=True,
            cwd=str(ROOT), start_new_session=True, timeout=10,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Hidden password input is unavailable", result.stderr)
        self.assertNotIn(MASTER, result.stdout + result.stderr)
        self.assertFalse(self.path.exists())
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "vault.py"), "--file", str(self.path), "gen", "--length", "24"],
            text=True, capture_output=True, cwd=str(ROOT), timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.rstrip("\n")), 24)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
