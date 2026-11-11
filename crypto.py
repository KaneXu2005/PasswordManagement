"""A's cryptographic building blocks. No file I/O or CLI interaction."""

import json
import secrets
from typing import Dict, List, Tuple

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import ARGON2_VERSION, Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from errors import (
    EntryValidationError,
    InvalidMasterPassword,
    VaultFormatError,
    VaultIntegrityError,
)

# Explicit parameters keep the v1 format independent of library default changes.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # KiB = 64 MiB, per Argon2 invocation.
ARGON2_PARALLELISM = 4
SALT_LENGTH = 16
KEY_LENGTH = 32  # AES-256.
NONCE_LENGTH = 12

_PH = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=KEY_LENGTH,
    salt_len=SALT_LENGTH,
    type=Type.ID,
)


def _check_password(master_password: str) -> None:
    if not isinstance(master_password, str) or not master_password:
        raise ValueError("Master password must be a non-empty string.")
    try:
        master_password.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Master password must be valid UTF-8 text.") from exc


def hash_master_password(master_password: str) -> str:
    """Create an Argon2id verifier with a fresh library-generated salt."""
    _check_password(master_password)
    return _PH.hash(master_password)


def validate_master_hash(master_hash: str) -> None:
    """Reject unsupported parameters before running expensive verification."""
    if (
        not isinstance(master_hash, str)
        or len(master_hash) > 256
        or not master_hash.isascii()
    ):
        raise VaultFormatError("Invalid master-password hash.")
    try:
        parameters = extract_parameters(master_hash)
    except (InvalidHashError, ValueError, TypeError) as exc:
        raise VaultFormatError("Invalid master-password hash.") from exc
    if (
        parameters.type != Type.ID
        or parameters.version != ARGON2_VERSION
        or parameters.time_cost != ARGON2_TIME_COST
        or parameters.memory_cost != ARGON2_MEMORY_COST
        or parameters.parallelism != ARGON2_PARALLELISM
        or parameters.hash_len != KEY_LENGTH
        or parameters.salt_len != SALT_LENGTH
    ):
        raise VaultFormatError("Unsupported Argon2id parameters for vault version 1.")


def verify_master_password(master_password: str, master_hash: str) -> None:
    """Return normally on success; raise a shared exception on failure."""
    _check_password(master_password)
    validate_master_hash(master_hash)
    try:
        _PH.verify(master_hash, master_password)
    except VerifyMismatchError as exc:
        raise InvalidMasterPassword("Incorrect master password or modified verifier.") from exc
    except (InvalidHashError, VerificationError) as exc:
        raise VaultFormatError("Invalid master-password hash.") from exc


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a raw AES key with a separate salt, never from the verifier."""
    _check_password(master_password)
    if not isinstance(salt, bytes) or len(salt) != SALT_LENGTH:
        raise VaultFormatError("Key-derivation salt must contain 16 bytes.")
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LENGTH,
        type=Type.ID,
        version=ARGON2_VERSION,
    )


def validate_entries(entries: List[Dict[str, str]]) -> None:
    """Require unique, case-sensitive sites and exactly three string fields."""
    if not isinstance(entries, list):
        raise EntryValidationError("Entries must be a list.")
    sites = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"site", "username", "password"}:
            raise EntryValidationError("Each entry needs exactly site, username and password.")
        if any(not isinstance(value, str) or not value for value in entry.values()):
            raise EntryValidationError("Entry fields must be non-empty strings.")
        try:
            for value in entry.values():
                value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise EntryValidationError("Entry fields must be valid UTF-8 text.") from exc
        if not entry["site"].strip() or not entry["username"].strip():
            raise EntryValidationError("Site and username cannot contain only whitespace.")
        if entry["site"] in sites:
            raise EntryValidationError("Duplicate site; version 1 allows one entry per site.")
        sites.add(entry["site"])


def encrypt_entries(
    key: bytes, entries: List[Dict[str, str]], associated_data: bytes
) -> Tuple[bytes, bytes]:
    """Return (fresh nonce, ciphertext including the 16-byte GCM tag)."""
    validate_entries(entries)
    if not isinstance(key, bytes) or len(key) != KEY_LENGTH:
        raise ValueError("AES-256 key must contain 32 bytes.")
    plaintext = json.dumps(entries, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    nonce = secrets.token_bytes(NONCE_LENGTH)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_entries(
    key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes
) -> List[Dict[str, str]]:
    """Authenticate before decoding or returning any account information."""
    if not isinstance(key, bytes) or len(key) != KEY_LENGTH:
        raise ValueError("AES-256 key must contain 32 bytes.")
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_LENGTH:
        raise VaultFormatError("AES-GCM nonce must contain 12 bytes.")
    if not isinstance(ciphertext, bytes) or len(ciphertext) < 16:
        raise VaultFormatError("Ciphertext is missing its authentication tag.")
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise VaultIntegrityError("Vault authentication failed; the file may have been modified.") from exc
    try:
        entries = json.loads(plaintext.decode("utf-8"))
        validate_entries(entries)
    except (ValueError, EntryValidationError) as exc:
        raise VaultFormatError("Decrypted data does not follow the entry format.") from exc
    return entries
