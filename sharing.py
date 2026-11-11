"""Encrypt exactly one entry for a recipient; never export vault secrets.

RSA-OAEP wraps a fresh AES key, while AES-GCM authenticates both the entry and
the public envelope. This provides recipient confidentiality, not sender identity.
Callers must authenticate the recipient's public key through a trusted channel.
"""

import base64
import binascii
import json
import os
from pathlib import Path
import secrets
import tempfile
from typing import Dict, Union

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto import validate_entries
from errors import EntryValidationError, VaultError

SharePath = Union[str, os.PathLike]
MAX_SHARE_BYTES = 16 * 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
RSA_BITS = 3072
_ALGORITHM = "RSA-OAEP-SHA256+AES-256-GCM"
_HEADER_FIELDS = ("version", "algorithm", "wrapped_key")


class SharingError(VaultError):
    """A share/key file is invalid, inaccessible or cannot be authenticated."""


def _passphrase_bytes(passphrase: str) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("Private-key passphrase must be non-empty text.")
    try:
        encoded = passphrase.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Private-key passphrase must be valid UTF-8 text.") from exc
    # Bound input consistently before passing it to the PEM encryption backend.
    if len(encoded) > 1023:
        raise ValueError("Private-key passphrase must not exceed 1023 UTF-8 bytes.")
    return encoded


def _read_bounded(path: Path, maximum: int, description: str) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(maximum + 1)
    except OSError as exc:
        raise SharingError("Could not read " + description + ".") from exc
    if len(raw) > maximum:
        raise SharingError(description.capitalize() + " exceeds its size limit.")
    return raw


def _ensure_new(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise SharingError("Output already exists; sharing never overwrites files.")


def _write_new_files(outputs: list) -> None:
    """Stage owner-only files, then publish without replacing any existing path."""
    staged = []
    published = []
    completed = False
    try:
        for path, raw in outputs:
            _ensure_new(path)
            descriptor, name = tempfile.mkstemp(
                prefix="." + path.name + ".", suffix=".tmp", dir=str(path.parent)
            )
            temporary = Path(name)
            staged.append((path, temporary))
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        for path, temporary in staged:
            os.link(str(temporary), str(path))
            published.append((path, temporary))
        completed = True
    except FileExistsError as exc:
        raise SharingError("Output already exists; sharing never overwrites files.") from exc
    except OSError as exc:
        raise SharingError("Could not save sharing files.") from exc
    finally:
        if not completed:
            # Only remove links to files this operation published, never a
            # pre-existing target. Like vault writes, this is sequential use.
            for path, temporary in published:
                try:
                    if path.samefile(temporary):
                        path.unlink()
                except OSError:
                    pass
        cleanup_failed = False
        for _, temporary in staged:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                cleanup_failed = True
        if completed and cleanup_failed:
            raise SharingError("Sharing files were saved, but encrypted temporary files could not be removed.")


def generate_keypair(private_path: SharePath, public_path: SharePath, passphrase: str) -> None:
    """Create RSA-3072 keys; the private PEM is passphrase-encrypted PKCS8."""
    password = _passphrase_bytes(passphrase)
    private_path, public_path = Path(private_path), Path(public_path)
    if private_path.resolve() == public_path.resolve():
        raise SharingError("Private and public key output paths must differ.")
    _ensure_new(private_path)
    _ensure_new(public_path)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    _write_new_files([(private_path, private_bytes), (public_path, public_bytes)])


def _load_public(path: Path) -> rsa.RSAPublicKey:
    raw = _read_bounded(path, MAX_KEY_BYTES, "recipient public key")
    try:
        key = serialization.load_pem_public_key(raw)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise SharingError("Recipient public key is not a supported PEM key.") from exc
    if (
        not isinstance(key, rsa.RSAPublicKey)
        or key.key_size != RSA_BITS
        or key.public_numbers().e != 65537
    ):
        raise SharingError("Sharing requires an RSA-3072 public key with exponent 65537.")
    return key


def _load_private(path: Path, passphrase: str) -> rsa.RSAPrivateKey:
    password = _passphrase_bytes(passphrase)
    raw = _read_bounded(path, MAX_KEY_BYTES, "recipient private key")
    # Deliberately reject unencrypted private-key inputs rather than encouraging
    # storage of another plaintext secret next to the encrypted vault.
    if not raw.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"):
        raise SharingError("Private key must be a passphrase-encrypted PKCS8 PEM key.")
    try:
        key = serialization.load_pem_private_key(raw, password=password)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise SharingError("Could not unlock private key; passphrase or key file is invalid.") from exc
    if (
        not isinstance(key, rsa.RSAPrivateKey)
        or key.key_size != RSA_BITS
        or key.public_key().public_numbers().e != 65537
    ):
        raise SharingError("Sharing requires an RSA-3072 private key with exponent 65537.")
    return key


def _oaep() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: str, length: int = None) -> bytes:
    if not isinstance(value, str):
        raise SharingError("Share fields must be Base64 text.")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SharingError("Share contains invalid Base64.") from exc
    if _encode(raw) != value or (length is not None and len(raw) != length):
        raise SharingError("Share contains an invalid field length or encoding.")
    return raw


def _serialize(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _aad(document: dict) -> bytes:
    header = {field: document[field] for field in _HEADER_FIELDS}
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def export_entry(entry: Dict[str, str], recipient_public_path: SharePath, output_path: SharePath) -> None:
    """Encrypt one entry; no master password or other vault entry is exported."""
    validate_entries([entry])
    output_path = Path(output_path)
    _ensure_new(output_path)
    plaintext = json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(plaintext) > MAX_SHARE_BYTES:
        raise EntryValidationError("Entry is too large to share.")
    recipient = _load_public(Path(recipient_public_path))
    key = AESGCM.generate_key(bit_length=256)
    document = {
        "version": 1,
        "algorithm": _ALGORITHM,
        "wrapped_key": _encode(recipient.encrypt(key, _oaep())),
    }
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _aad(document))
    document.update(nonce=_encode(nonce), ciphertext=_encode(ciphertext))
    raw = _serialize(document)
    if len(raw) > MAX_SHARE_BYTES:
        raise EntryValidationError("Encrypted share exceeds the 16 MiB size limit.")
    _write_new_files([(output_path, raw)])


def _unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise SharingError("Share contains duplicate JSON fields.")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise SharingError("Share contains a non-standard JSON value.")


def import_entry(package_path: SharePath, private_path: SharePath, passphrase: str) -> Dict[str, str]:
    """Authenticate and decrypt one share; caller decides how to save it locally."""
    raw = _read_bounded(Path(package_path), MAX_SHARE_BYTES, "encrypted share")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise SharingError("Share is not valid UTF-8 JSON.") from exc
    if not isinstance(document, dict) or set(document) != {
        "version", "algorithm", "wrapped_key", "nonce", "ciphertext"
    }:
        raise SharingError("Share has unexpected fields.")
    if type(document["version"]) is not int or document["version"] != 1 or document["algorithm"] != _ALGORITHM:
        raise SharingError("Share version or algorithm is unsupported.")
    wrapped_key = _decode(document["wrapped_key"], RSA_BITS // 8)
    nonce = _decode(document["nonce"], 12)
    ciphertext = _decode(document["ciphertext"])
    if len(ciphertext) < 16:
        raise SharingError("Share is missing its authentication tag.")
    if raw != _serialize(document):
        raise SharingError("Share formatting was modified or is unsupported.")
    private_key = _load_private(Path(private_path), passphrase)
    try:
        key = private_key.decrypt(wrapped_key, _oaep())
        if len(key) != 32:
            raise ValueError("Unexpected wrapped key length.")
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, _aad(document))
    except (ValueError, InvalidTag) as exc:
        raise SharingError("Share authentication failed; recipient key is wrong or the share was modified.") from exc
    try:
        entry = json.loads(plaintext.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        validate_entries([entry])
    except (ValueError, RecursionError, EntryValidationError) as exc:
        raise SharingError("Decrypted share does not contain exactly one valid entry.") from exc
    return entry
