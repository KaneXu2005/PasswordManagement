"""C's account operations. They return copies and never access files."""

from typing import Dict, List

from crypto import validate_entries
from errors import VaultError

Entry = Dict[str, str]


class EntryNotFoundError(VaultError):
    """No entry has the requested case-sensitive site name."""


def _check_site(site: str) -> None:
    if not isinstance(site, str) or not site.strip():
        raise ValueError("Site must be a non-empty string.")
    try:
        site.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Site must be valid UTF-8 text.") from exc


def add_entry(entries: List[Entry], site: str, username: str, password: str) -> List[Entry]:
    """Return a new list; the shared validator rejects malformed/duplicate entries."""
    validate_entries(entries)
    result = [entry.copy() for entry in entries]
    result.append({"site": site, "username": username, "password": password})
    validate_entries(result)
    return result


def list_entries(entries: List[Entry]) -> List[Entry]:
    """Return sorted site/username summaries; omit every password."""
    validate_entries(entries)
    return [
        {"site": entry["site"], "username": entry["username"]}
        for entry in sorted(entries, key=lambda entry: entry["site"])
    ]


def get_entry(entries: List[Entry], site: str) -> Entry:
    """Return a detached copy of one complete entry."""
    validate_entries(entries)
    _check_site(site)
    for entry in entries:
        if entry["site"] == site:
            return entry.copy()
    raise EntryNotFoundError("Entry not found.")


def delete_entry(entries: List[Entry], site: str) -> List[Entry]:
    """Return all other entries; missing sites are errors, not silent successes."""
    get_entry(entries, site)
    return [entry.copy() for entry in entries if entry["site"] != site]
