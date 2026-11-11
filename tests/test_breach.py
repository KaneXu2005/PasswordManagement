"""Offline HIBP protocol tests: every HTTP request is mocked."""

import hashlib
from http.client import IncompleteRead
import io
import ssl
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from breach import (
    BreachCheckError,
    MAX_RESPONSE_BYTES,
    RANGE_URL,
    TIMEOUT_SECONDS,
    _NoRedirect,
    check_password,
)

PASSWORD = "password"  # Public test vector only; never a real credential.
DIGEST = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
SUFFIX = DIGEST[5:]


class BreachTests(unittest.TestCase):
    def setUp(self):
        self.factory = patch("breach.build_opener")
        self.build_opener = self.factory.start()
        self.addCleanup(self.factory.stop)
        self.opener = self.build_opener.return_value
        self.response = MagicMock()
        self.opener.open.return_value.__enter__.return_value = self.response
        self.response.getcode.return_value = 200
        self.response.geturl.return_value = RANGE_URL + DIGEST[:5]
        self.response.read.return_value = (SUFFIX + ":12345\r\n").encode("ascii")

    def assert_private_error(self, error):
        message = str(error)
        self.assertNotIn(PASSWORD, message)
        self.assertNotIn(DIGEST, message)
        self.assertNotIn(SUFFIX, message)

    def test_known_sha1_vector_sends_only_prefix_and_matches_locally(self):
        self.assertEqual(check_password(PASSWORD), 12345)
        self.opener.open.assert_called_once()
        request = self.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, RANGE_URL + "5BAA6")
        self.assertEqual(request.get_method(), "GET")
        self.assertIsNone(request.data)
        self.assertEqual(request.get_header("Add-padding"), "true")
        self.assertEqual(request.get_header("Accept"), "text/plain")
        self.assertEqual(request.get_header("User-agent"), "PasswordManagement/1.0")
        self.assertNotIn(PASSWORD, repr(request.header_items()))
        self.assertNotIn(DIGEST, request.full_url + repr(request.header_items()))
        self.assertNotIn(SUFFIX, request.full_url + repr(request.header_items()))
        self.assertEqual(self.opener.open.call_args.kwargs, {"timeout": TIMEOUT_SECONDS})
        self.response.read.assert_called_once_with(MAX_RESPONSE_BYTES + 1)

    def test_no_matching_suffix_returns_zero(self):
        self.response.read.return_value = b"00000000000000000000000000000000000:500\r\n"
        self.assertEqual(check_password(PASSWORD), 0)

    def test_padding_zero_is_not_a_breach(self):
        self.response.read.return_value = (SUFFIX + ":0\r\n" + "A" * 35 + ":8\r\n").encode("ascii")
        self.assertEqual(check_password(PASSWORD), 0)

    def test_padding_and_order_do_not_hide_a_positive_match(self):
        self.response.read.return_value = ("0" * 35 + ":0\n" + SUFFIX + ":7\n" + "F" * 35 + ":0\n").encode("ascii")
        self.assertEqual(check_password(PASSWORD), 7)

    def test_lowercase_suffix_is_normalized(self):
        self.response.read.return_value = (SUFFIX.lower() + ":42").encode("ascii")
        self.assertEqual(check_password(PASSWORD), 42)

    def test_unicode_and_password_spaces_are_preserved(self):
        for value in (" 密码! ", " ", " password "):
            with self.subTest(value=value):
                digest = hashlib.sha1(value.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
                self.response.geturl.return_value = RANGE_URL + digest[:5]
                self.response.read.return_value = (digest[5:] + ":4\n").encode("ascii")
                self.assertEqual(check_password(value), 4)
                self.assertEqual(self.opener.open.call_args.args[0].full_url, RANGE_URL + digest[:5])

    def test_invalid_passwords_fail_without_network(self):
        for value in ("", None, b"password", 1, True, "\ud800"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    check_password(value)
        self.build_opener.assert_not_called()

    def test_network_timeout_tls_and_interrupted_reads_are_errors(self):
        failures = (URLError("fake failure " + DIGEST), TimeoutError(PASSWORD), ssl.SSLError(PASSWORD), IncompleteRead(b"partial"))
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                self.opener.open.side_effect = failure
                with self.assertRaises(BreachCheckError) as error:
                    check_password(PASSWORD)
                self.assert_private_error(error.exception)

    def test_http_error_codes_never_mean_clean_password(self):
        for code in (301, 302, 307, 308, 404, 429, 503):
            with self.subTest(code=code):
                body = io.BytesIO(PASSWORD.encode("ascii"))
                self.opener.open.side_effect = HTTPError(RANGE_URL + "5BAA6", code, DIGEST, {}, body)
                with self.assertRaises(BreachCheckError) as error:
                    check_password(PASSWORD)
                self.assertIn(str(code), str(error.exception))
                self.assert_private_error(error.exception)
                self.assertTrue(body.closed)

    def test_interrupted_body_read_is_an_error_and_closes_response(self):
        self.response.read.side_effect = IncompleteRead((SUFFIX + ":12").encode("ascii"))
        with self.assertRaises(BreachCheckError) as error:
            check_password(PASSWORD)
        self.assert_private_error(error.exception)
        self.opener.open.return_value.__exit__.assert_called_once()

    def test_non_200_response_is_an_error_even_without_http_exception(self):
        self.response.getcode.return_value = 404
        with self.assertRaises(BreachCheckError):
            check_password(PASSWORD)
        self.response.read.assert_not_called()

    def test_redirect_handler_refuses_all_redirects(self):
        check_password(PASSWORD)
        self.assertIsInstance(self.build_opener.call_args.args[0], _NoRedirect)
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://evil.invalid/"))

    def test_unexpected_final_url_is_rejected_before_reading(self):
        self.response.geturl.return_value = "https://other.invalid/range/5BAA6"
        with self.assertRaises(BreachCheckError):
            check_password(PASSWORD)
        self.response.read.assert_not_called()

    def test_oversized_response_is_an_error(self):
        self.response.read.return_value = b"A" * (MAX_RESPONSE_BYTES + 1)
        with self.assertRaises(BreachCheckError) as error:
            check_password(PASSWORD)
        self.assertIn("limit", str(error.exception))

    def test_empty_non_ascii_and_malformed_responses_are_errors(self):
        malformed = (
            b"", b"\n", b"\xff", b"<html>unavailable</html>",
            (SUFFIX + ":-1").encode("ascii"), (SUFFIX + ":1.5").encode("ascii"),
            (SUFFIX + ":").encode("ascii"), (SUFFIX[:-1] + ":12").encode("ascii"),
            ("G" * 35 + ":12").encode("ascii"), (SUFFIX + ":12:34").encode("ascii"),
            (SUFFIX + ":12\n\n").encode("ascii"),
            (SUFFIX + ":12\v" + "A" * 35 + ":0").encode("ascii"),
            (SUFFIX + ":" + "9" * 21).encode("ascii"),
        )
        for raw in malformed:
            with self.subTest(raw=raw[:60]):
                self.response.read.return_value = raw
                with self.assertRaises(BreachCheckError) as error:
                    check_password(PASSWORD)
                self.assert_private_error(error.exception)

    def test_valid_match_before_malformed_record_is_still_an_error(self):
        self.response.read.return_value = (SUFFIX + ":100\nmalformed\n").encode("ascii")
        with self.assertRaises(BreachCheckError):
            check_password(PASSWORD)

    def test_duplicate_positive_records_are_rejected(self):
        self.response.read.return_value = (SUFFIX + ":5\n" + SUFFIX + ":6\n").encode("ascii")
        with self.assertRaises(BreachCheckError):
            check_password(PASSWORD)


if __name__ == "__main__":
    unittest.main()
