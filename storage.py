"""Public integration API: initialize_vault, load_vault, save_vault.

The caller owns prompts and account operations. This module owns the encrypted
file format. Version 1 supports sequential use, not concurrent writers.
"""

import base64
import binascii
import json
import os
from pathlib import Path
import secrets
import tempfile
from typing import Dict, List, Union

from crypto import (
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    ARGON2_VERSION,
    KEY_LENGTH,
    NONCE_LENGTH,
    SALT_LENGTH,
    decrypt_entries,
    derive_key,
    encrypt_entries,
    hash_master_password,
    validate_entries,
    validate_master_hash,
    verify_master_password,
)
from errors import (
    EntryValidationError,
    VaultAlreadyExistsError,
    VaultFormatError,
    VaultIOError,
    VaultNotFoundError,
)

VaultPath = Union[str, os.PathLike]
MAX_VAULT_BYTES = 16 * 1024 * 1024
_KDF_PROFILE = {
    "name": "argon2id",
    "version": ARGON2_VERSION,
    "time_cost": ARGON2_TIME_COST,
    "memory_cost": ARGON2_MEMORY_COST,
    "parallelism": ARGON2_PARALLELISM,
    "length": KEY_LENGTH,
}


def _serialize_document(document: dict) -> bytes:
    """Version 1 has one byte representation, including its final newline."""
    return (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode(value: str, field: str, length: int = None) -> bytes:
    if not isinstance(value, str):
        raise VaultFormatError(field + " must be a Base64 string.")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise VaultFormatError("Invalid Base64 in " + field + ".") from exc
    if _encode(result) != value or (length is not None and len(result) != length):
        raise VaultFormatError("Invalid encoding or length for " + field + ".")
    return result


def _associated_data(document: dict) -> bytes:
    # Bind public header values to the same GCM tag as the encrypted entries.
    header = {key: document[key] for key in ("version", "master_hash", "kdf")}
    return json.dumps(header, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise VaultFormatError("Duplicate JSON field.")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise VaultFormatError("Non-standard JSON number: " + value)


def _read_document(path: Path) -> dict:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_VAULT_BYTES + 1)
    except FileNotFoundError as exc:
        raise VaultNotFoundError("Vault not found; initialize it first.") from exc
    except OSError as exc:
        raise VaultIOError("Could not read the vault file.") from exc
    if len(raw) > MAX_VAULT_BYTES:
        raise VaultFormatError("Vault exceeds the 16 MiB version 1 size limit.")
    try:
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError) as exc:
        raise VaultFormatError("Vault is not valid UTF-8 JSON.") from exc
    if not isinstance(document, dict) or set(document) != {
        "version", "master_hash", "kdf", "nonce", "ciphertext"
    }:
        raise VaultFormatError("Unexpected vault fields.")
    if type(document["version"]) is not int or document["version"] != 1:
        raise VaultFormatError("Unsupported vault version.")
    validate_master_hash(document["master_hash"])
    kdf = document["kdf"]
    if not isinstance(kdf, dict) or set(kdf) != set(_KDF_PROFILE) | {"salt"}:
        raise VaultFormatError("Unexpected key-derivation fields.")
    for name, expected in _KDF_PROFILE.items():
        if type(kdf[name]) is not type(expected) or kdf[name] != expected:
            raise VaultFormatError("Unsupported version 1 key-derivation parameters.")
    _decode(kdf["salt"], "kdf.salt", SALT_LENGTH)
    _decode(document["nonce"], "nonce", NONCE_LENGTH)
    if len(_decode(document["ciphertext"], "ciphertext")) < 16:
        raise VaultFormatError("Ciphertext is missing its authentication tag.")
    # GCM authenticates the values. Enforcing the writer's exact encoding also
    # rejects edits to whitespace, key order, escapes and the trailing newline.
    if raw != _serialize_document(document):
        raise VaultFormatError("Vault file formatting was modified or is unsupported.")
    return document


def _unlock(document: dict, master_password: str):
    verify_master_password(master_password, document["master_hash"])
    key = derive_key(master_password, _decode(document["kdf"]["salt"], "kdf.salt", SALT_LENGTH))
    entries = decrypt_entries(
        key,
        _decode(document["nonce"], "nonce", NONCE_LENGTH),
        _decode(document["ciphertext"], "ciphertext"),
        _associated_data(document),
    )
    return key, entries


def _write_document(path: Path, document: dict, *, create: bool) -> None:
    raw = _serialize_document(document)
    if len(raw) > MAX_VAULT_BYTES:
        raise EntryValidationError("Encrypted vault exceeds the 16 MiB version 1 size limit.")
    temporary = None
    published = False
    try:
        descriptor, name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=str(path.parent))
        temporary = Path(name)
        # mkstemp creates an owner-only file (0600 on POSIX).
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        if create:
            # Publish a complete file atomically without overwriting an existing one.
            os.link(str(temporary), str(path))
        else:
            os.replace(str(temporary), str(path))
        published = True
    except FileExistsError as exc:
        raise VaultAlreadyExistsError("Vault already exists; initialization will not overwrite it.") from exc
    except OSError as exc:
        raise VaultIOError("Could not save the vault file.") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as exc:
                if published:
                    raise VaultIOError(
                        "Vault was saved, but its encrypted temporary file could not be removed."
                    ) from exc
                # Preserve the primary save error. A leftover temp contains only
                # encrypted data, and must not hide why publication failed.


def initialize_vault(path: VaultPath, master_password: str) -> None:
    """Create an encrypted empty vault; never overwrite an existing path."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise VaultAlreadyExistsError("Vault already exists; initialization will not overwrite it.")
    salt = secrets.token_bytes(SALT_LENGTH)
    document = {
        "version": 1,
        "master_hash": hash_master_password(master_password),
        "kdf": dict(_KDF_PROFILE, salt=_encode(salt)),
    }
    key = derive_key(master_password, salt)
    nonce, ciphertext = encrypt_entries(key, [], _associated_data(document))
    document.update(nonce=_encode(nonce), ciphertext=_encode(ciphertext))
    _write_document(path, document, create=True)


def load_vault(path: VaultPath, master_password: str) -> List[Dict[str, str]]:
    """Verify, authenticate and return entries; never return a partial result."""
    _, entries = _unlock(_read_document(Path(path)), master_password)
    return entries


def save_vault(path: VaultPath, master_password: str, entries: List[Dict[str, str]]) -> None:
    """Replace all entries after authenticating the existing vault.

    This does not create a missing vault, merge entries or change the password.
    Each save uses a fresh nonce. Callers must serialize read-modify-write use.
    """
    validate_entries(entries)
    path = Path(path)
    document = _read_document(path)
    key, _ = _unlock(document, master_password)
    nonce, ciphertext = encrypt_entries(key, entries, _associated_data(document))
    document.update(nonce=_encode(nonce), ciphertext=_encode(ciphertext))
    _write_document(path, document, create=False)
