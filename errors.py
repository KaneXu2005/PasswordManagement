"""Exceptions shared by the storage backend and its CLI callers."""


class VaultError(Exception):
    """Base class: the CLI may display this error without a traceback."""


class InvalidMasterPassword(VaultError):
    """The password does not match the stored verifier."""


class VaultFormatError(VaultError):
    """The file is malformed or its format/parameters are unsupported."""


class VaultIntegrityError(VaultError):
    """Authenticated decryption failed; no plaintext was returned."""


class VaultAlreadyExistsError(VaultError):
    """Initialization refused to overwrite an existing file."""


class VaultNotFoundError(VaultError):
    """The requested vault does not exist."""


class VaultIOError(VaultError):
    """The operating system could not read or save the vault."""


class EntryValidationError(VaultError):
    """Entries do not follow the shared site/username/password contract."""
