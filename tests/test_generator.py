"""Acceptance tests for C's secure password generator."""

import unittest
from unittest.mock import patch

from generator import ALPHABET, CHARACTER_GROUPS, DEFAULT_LENGTH, generate_password


class GeneratorTests(unittest.TestCase):
    def assert_password(self, password, length):
        self.assertEqual(len(password), length)
        self.assertTrue(all(character in ALPHABET for character in password))
        self.assertTrue(all(any(character in group for character in password) for group in CHARACTER_GROUPS))

    def test_default_password(self):
        self.assert_password(generate_password(), DEFAULT_LENGTH)

    def test_requested_lengths_and_all_four_character_groups(self):
        for length in (12, 20, 48, 1024):
            with self.subTest(length=length):
                self.assert_password(generate_password(length), length)

    def test_invalid_lengths_are_rejected(self):
        for length in (0, -1, 11, 1025, 12.0, "20", True, None):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    generate_password(length)

    def test_secure_choice_and_rejection_of_a_missing_character_group(self):
        valid = "aA1!aA1!aA1!"
        with patch("generator.secrets.choice", side_effect=list("a" * 12 + valid)) as choice:
            self.assertEqual(generate_password(12), valid)
            self.assertEqual(choice.call_count, 24)
            self.assertTrue(all(call.args == (ALPHABET,) for call in choice.call_args_list))


if __name__ == "__main__":
    unittest.main()
