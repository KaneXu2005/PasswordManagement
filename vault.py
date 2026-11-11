"""Command-line password manager. C's UI calls A's public storage API."""

import argparse
import getpass
import json
from pathlib import Path
import sys
from typing import List, Optional
import warnings

from entries import add_entry, delete_entry, get_entry, list_entries
from errors import VaultError
from generator import DEFAULT_LENGTH, MAX_LENGTH, MIN_LENGTH, generate_password
from storage import initialize_vault, load_vault, save_vault


def _password_length(value: str) -> int:
    try:
        length = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Length must be an integer.") from exc
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise argparse.ArgumentTypeError("Length must be from 12 to 1024.")
    return length


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="A local encrypted password vault.")
    parser.add_argument("--file", type=Path, default=Path("vault.json"), help="vault path (default: ./vault.json)")
    commands = parser.add_subparsers(dest="command", required=True)
    subparsers = {}
    for name, help_text in (
        ("init", "set a master password and create an empty vault"),
        ("add", "add an account; generate its password unless --prompt-password is used"),
        ("list", "list sites and usernames without passwords"),
        ("get", "reveal one account, including its password"),
        ("delete", "delete one account"),
        ("gen", "generate a strong password without opening a vault"),
    ):
        subparser = commands.add_parser(name, help=help_text)
        # Accept --file before OR after the subcommand without overwriting a
        # path already parsed by the parent when the option is absent here.
        subparser.add_argument("--file", type=Path, default=argparse.SUPPRESS, help="vault path")
        subparsers[name] = subparser
    add = subparsers["add"]
    add.add_argument("site", help="case-sensitive site label")
    add.add_argument("--user", required=True, help="account username")
    password_options = add.add_mutually_exclusive_group()
    password_options.add_argument("--prompt-password", action="store_true", help="enter the account password privately, twice")
    password_options.add_argument("--length", type=_password_length, help="generated account password length (default: 20)")
    for name in ("get", "delete"):
        subparsers[name].add_argument("site", help="case-sensitive site label")
    subparsers["gen"].add_argument("--length", type=_password_length, default=DEFAULT_LENGTH, help="password length, 12-1024 (default: 20)")
    return parser


def _read_secret(prompt: str) -> str:
    try:
        with warnings.catch_warnings():
            # getpass otherwise falls back to input that may echo the secret.
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass(prompt)
    except getpass.GetPassWarning as exc:
        raise ValueError("Hidden password input is unavailable. Run this command in a terminal.") from exc
    if not value:
        raise ValueError("Password cannot be empty.")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Password must be valid UTF-8 text.") from exc
    return value


def _confirmed_secret(prompt: str, confirmation_prompt: str) -> str:
    value = _read_secret(prompt)
    confirmation = _read_secret(confirmation_prompt)
    if value != confirmation:
        raise ValueError("Passwords do not match.")
    return value


def _run(args: argparse.Namespace) -> None:
    if args.command == "gen":
        print(generate_password(args.length))
        return
    if args.command == "init":
        master = _confirmed_secret("Master password: ", "Confirm master password: ")
        initialize_vault(args.file, master)
        print("Vault initialized.")
        return
    master = _read_secret("Master password: ")
    entries = load_vault(args.file, master)
    if args.command == "list":
        print(json.dumps(list_entries(entries), ensure_ascii=True, indent=2))
    elif args.command == "get":
        print(json.dumps(get_entry(entries, args.site), ensure_ascii=True, indent=2))
    elif args.command == "add":
        if args.prompt_password:
            password = _confirmed_secret("Account password: ", "Confirm account password: ")
        else:
            password = generate_password(args.length if args.length is not None else DEFAULT_LENGTH)
        updated = add_entry(entries, args.site, args.user, password)
        save_vault(args.file, master, updated)
        print("Entry added. Use get to reveal its password.")
    elif args.command == "delete":
        updated = delete_entry(entries, args.site)
        save_vault(args.file, master, updated)
        print("Entry deleted.")


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        _run(args)
    except (VaultError, ValueError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 1
    except EOFError:
        print("Error: Password input ended; operation cancelled.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Operation cancelled.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
