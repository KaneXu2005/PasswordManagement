"""C's password generator: secure randomness, no vault or terminal access."""

import secrets
import string

DEFAULT_LENGTH = 20
MIN_LENGTH = 12
MAX_LENGTH = 1024
CHARACTER_GROUPS = (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation)
ALPHABET = "".join(CHARACTER_GROUPS)


def generate_password(length: int = DEFAULT_LENGTH) -> str:
    """Generate a password with every character group and the requested length.

    Rejection sampling preserves a uniform distribution over the strings that
    satisfy the group rule. All choices come from the OS-backed secrets module.
    """
    if type(length) is not int or not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError("Password length must be an integer from 12 to 1024.")
    while True:
        password = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if all(any(character in group for character in password) for group in CHARACTER_GROUPS):
            return password
