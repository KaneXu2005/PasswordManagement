"""Account operations must preserve input data and avoid password listing."""

import copy
import unittest

from entries import EntryNotFoundError, add_entry, delete_entry, get_entry, list_entries
from errors import EntryValidationError


class EntryTests(unittest.TestCase):
    def setUp(self):
        self.entries = [
            {"site": "z-school", "username": "学号", "password": "fake-school-password"},
            {"site": "github", "username": "alice", "password": "fake-github-password"},
        ]
        self.original = copy.deepcopy(self.entries)

    def test_add_returns_detached_data_and_preserves_password_spaces(self):
        result = add_entry(self.entries, "mail", "alice@example.com", "  fake password  ")
        self.assertEqual(self.entries, self.original)
        self.assertEqual(result[-1]["password"], "  fake password  ")
        result[0]["password"] = "changed"
        self.assertEqual(self.entries, self.original)

    def test_duplicate_site_rejected_without_modifying_input(self):
        with self.assertRaises(EntryValidationError):
            add_entry(self.entries, "github", "bob", "another fake password")
        self.assertEqual(self.entries, self.original)

    def test_case_sensitive_site_contract(self):
        result = add_entry(self.entries, "GitHub", "bob", "another fake password")
        self.assertEqual(get_entry(result, "GitHub")["username"], "bob")
        self.assertEqual(get_entry(result, "github")["username"], "alice")

    def test_list_is_sorted_and_contains_no_password_fields(self):
        result = list_entries(self.entries)
        self.assertEqual(result, [
            {"site": "github", "username": "alice"},
            {"site": "z-school", "username": "学号"},
        ])
        self.assertEqual(self.entries, self.original)
        result[0]["username"] = "changed"
        self.assertEqual(self.entries, self.original)

    def test_get_returns_a_copy(self):
        result = get_entry(self.entries, "github")
        self.assertEqual(result, self.entries[1])
        result["password"] = "changed"
        self.assertEqual(self.entries, self.original)

    def test_delete_preserves_input_and_other_entries(self):
        result = delete_entry(self.entries, "github")
        self.assertEqual(result, [self.entries[0]])
        self.assertEqual(self.entries, self.original)
        result[0]["password"] = "changed"
        self.assertEqual(self.entries, self.original)

    def test_missing_get_or_delete_is_an_error(self):
        for operation in (get_entry, delete_entry):
            with self.subTest(operation=operation.__name__):
                with self.assertRaises(EntryNotFoundError):
                    operation(self.entries, "missing")
        self.assertEqual(self.entries, self.original)

    def test_bad_entry_fields_are_rejected(self):
        for site, user, password in (("", "alice", "fake"), ("site", "", "fake"), ("site", "alice", ""), ("site", "alice", 123)):
            with self.subTest(site=site, user=user, password=password):
                with self.assertRaises(EntryValidationError):
                    add_entry(self.entries, site, user, password)
        self.assertEqual(self.entries, self.original)


if __name__ == "__main__":
    unittest.main()
