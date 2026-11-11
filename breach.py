"""Explicit, privacy-preserving Pwned Passwords checks; no vault or CLI I/O."""

import hashlib
from http.client import HTTPException
import re
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from errors import VaultError

RANGE_URL = "https://api.pwnedpasswords.com/range/"
TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 1024 * 1024
_RECORD = re.compile(r"([0-9A-Fa-f]{35}):([0-9]{1,20})", re.ASCII)


class BreachCheckError(VaultError):
    """A lookup failed; this must never be reported as a clean password."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        # A hash prefix must only be sent to the fixed HTTPS API endpoint.
        return None


def _count_matches(raw: bytes, expected_suffix: str) -> int:
    if len(raw) > MAX_RESPONSE_BYTES:
        raise BreachCheckError("Breach check failed: response exceeds the 1 MiB limit.")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise BreachCheckError("Breach check failed: invalid API response.") from None
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if not lines:
        raise BreachCheckError("Breach check failed: empty API response.")
    count = 0
    seen = set()
    for line in lines:
        if line.endswith("\r"):
            line = line[:-1]
        record = _RECORD.fullmatch(line)
        if record is None:
            raise BreachCheckError("Breach check failed: invalid API response.")
        suffix, occurrences = record.groups()
        suffix = suffix.upper()
        # Padding records have count 0; they are not evidence of a breach.
        occurrences = int(occurrences)
        if occurrences == 0:
            continue
        if suffix in seen:
            raise BreachCheckError("Breach check failed: duplicate API record.")
        seen.add(suffix)
        if suffix == expected_suffix:
            count = occurrences
    return count


def check_password(password: str) -> int:
    """Return HIBP's occurrence count using only a five-character SHA-1 prefix.

    SHA-1 is only the API's lookup identifier, never a password-storage KDF.
    Network/protocol failures raise BreachCheckError instead of returning zero.
    No password, full hash, hash suffix or API response is logged or persisted.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    try:
        encoded = password.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Password must be valid UTF-8 text.") from None
    # usedforsecurity=False states SHA-1's non-cryptographic lookup purpose.
    digest = hashlib.sha1(encoded, usedforsecurity=False).hexdigest().upper()
    url = RANGE_URL + digest[:5]
    request = Request(
        url,
        headers={
            "Add-Padding": "true",
            "User-Agent": "PasswordManagement/1.0",
            "Accept": "text/plain",
        },
        method="GET",
    )
    # The default HTTPSHandler retains certificate/hostname verification.
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            if response.getcode() != 200:
                raise BreachCheckError("Breach check failed: API did not return HTTP 200.")
            if response.geturl() != url:
                raise BreachCheckError("Breach check failed: API redirect refused.")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        code = exc.code
        exc.close()
        raise BreachCheckError("Breach check failed: API returned HTTP " + str(code) + ".") from None
    except (URLError, OSError, HTTPException):
        raise BreachCheckError("Breach check unavailable: network or TLS error; try again later.") from None
    return _count_matches(raw, digest[5:])
