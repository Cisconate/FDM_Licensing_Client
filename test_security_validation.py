"""Boundary-focused tests for hostile and malformed external input."""

import math
import unittest

from cisco_support_api_client import CiscoPlrError, CiscoPlrReservationClient
from fdm_certificate_store import certificate_bundle_path
from fdm_client import FDMClient
from security_validation import (
    encode_json_payload,
    safe_error_text,
    validate_host,
    validate_https_base_url,
    validate_timeout,
)


class SecurityValidationTests(unittest.TestCase):
    def test_host_normalizes_dns_ipv4_and_ipv6(self) -> None:
        self.assertEqual(validate_host("FDM.EXAMPLE.COM."), "fdm.example.com")
        self.assertEqual(validate_host("192.0.2.1"), "192.0.2.1")
        self.assertEqual(validate_host("2001:db8::1"), "[2001:db8::1]")

    def test_host_rejects_url_syntax_and_control_characters(self) -> None:
        for value in ("https://fdm.example.com", "user@host", "host/path", "host\r\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_host(value)

    def test_https_url_rejects_credentials_query_and_fragment(self) -> None:
        for value in (
            "https://user:secret@example.com/api/",
            "https://example.com/api/?x=1",
            "https://example.com/api/#fragment",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_https_base_url(value)

    def test_timeout_rejects_boolean_nonfinite_and_excessive_values(self) -> None:
        for value in ((True, 1), (math.inf, 1), (1, 301), (0, 1)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_timeout(value)

    def test_json_payload_is_strict_bounded_and_snapshotted(self) -> None:
        payload = {"enabled": True, "items": [1, 2]}
        encoded = encode_json_payload(payload)
        payload["items"].append(3)
        self.assertEqual(encoded, '{"enabled":true,"items":[1,2]}')
        with self.assertRaises(ValueError):
            encode_json_payload({"value": math.nan})
        with self.assertRaises(ValueError):
            encode_json_payload({"value": object()})

    def test_error_text_is_single_line_and_bounded(self) -> None:
        self.assertEqual(safe_error_text("first\r\nsecond", limit=12), "first??secon")

    def test_certificate_bundle_name_cannot_escape_store(self) -> None:
        for value in ("../bundle.pem", "subdir/bundle.pem", "..", "bundle\n.pem"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                certificate_bundle_path("certificates", bundle_name=value)

    def test_fdm_constructor_rejects_invalid_configuration(self) -> None:
        with self.assertRaises(ValueError):
            FDMClient(host="host/path", username="user", password="secret", verify_certificate=False)
        with self.assertRaises(ValueError):
            FDMClient(host="host", username="user", password="secret", api_version="version6", verify_certificate=False)
        with self.assertRaises(ValueError):
            FDMClient(host="host", username="user\n", password="secret", verify_certificate=False)

    def test_fdm_request_rejects_traversal_and_header_injection_before_network(self) -> None:
        client = FDMClient(host="host", username="user", password="secret", verify_certificate=False)
        try:
            for path in ("../admin", "%2e%2e/admin", "%252e%252e/admin"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    client.request("GET", path)
            with self.assertRaises(ValueError):
                client.request("GET", "object/networks", headers={"X-Test": "ok\r\nInjected: yes"})
            with self.assertRaises(ValueError):
                client.request("GET", "object/networks", headers={"Authorization": "Bearer attacker"})
        finally:
            client.close()

    def test_cisco_request_stays_under_configured_api_root(self) -> None:
        client = CiscoPlrReservationClient(bearer_token="token")
        try:
            with self.assertRaises(ValueError):
                client.request("GET", "../outside")
            with self.assertRaises(ValueError):
                client.request("GET", "resource?unexpected=query")
        finally:
            client.close()

    def test_token_provider_result_rejects_control_characters(self) -> None:
        client = CiscoPlrReservationClient(token_provider=lambda: "token\r\nInjected: yes")
        try:
            with self.assertRaises(CiscoPlrError):
                client._resolve_bearer_token()
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
