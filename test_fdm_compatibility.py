"""Tests for authenticated FTD version detection and route selection."""

import unittest
from unittest.mock import Mock

from fdm_client import FDMClient, FDMError
from fdm_compatibility import (
    FTD_7_6_PROFILE,
    FdmCompatibilityError,
    detect_fdm_compatibility,
    parse_software_version,
)
from fdm_plr_client import FdmPlrClient


class FdmCompatibilityTests(unittest.TestCase):
    def test_parses_ftd_release_and_build(self) -> None:
        version = parse_software_version("7.6.2-329")
        self.assertEqual((version.major, version.minor, version.patch), (7, 6, 2))
        self.assertEqual(version.build, 329)

    def test_detects_supported_7_6_profile(self) -> None:
        client = Mock()
        client.get_json.return_value = {"softwareVersion": "7.6.2-329"}
        compatibility = detect_fdm_compatibility(client)
        self.assertEqual(compatibility.profile, FTD_7_6_PROFILE)
        client.get_json.assert_called_once_with("operational/systeminfo/default")

    def test_rejects_unknown_release_with_actionable_message(self) -> None:
        client = Mock()
        client.get_json.return_value = {"softwareVersion": "8.0.0-1"}
        with self.assertRaisesRegex(FdmCompatibilityError, "supported releases: 7.6.x"):
            detect_fdm_compatibility(client)

    def test_rejects_malformed_or_missing_version(self) -> None:
        for value in (None, "7.6", "7.6.2\nspoof"):
            with self.subTest(value=value):
                client = Mock()
                client.get_json.return_value = {"softwareVersion": value}
                with self.assertRaises(FdmCompatibilityError):
                    detect_fdm_compatibility(client)

    def test_context_authenticates_before_version_detection(self) -> None:
        client = FDMClient(
            host="fdm.example.com",
            username="admin",
            password="secret",
            verify_certificate=False,
        )
        events = []
        client.authenticate = Mock(side_effect=lambda: events.append("authenticate"))
        client.get_json = Mock(
            side_effect=lambda _path: (
                events.append("system-information")
                or {"softwareVersion": "7.6.2-329"}
            )
        )
        client.close = Mock()

        entered = client.__enter__()

        self.assertIs(entered, client)
        self.assertEqual(client.software_version, "7.6.2-329")
        self.assertEqual(events, ["authenticate", "system-information"])
        client.authenticate.assert_called_once_with()
        client.get_json.assert_called_once_with("operational/systeminfo/default")

    def test_unsupported_context_closes_client(self) -> None:
        client = FDMClient(
            host="fdm.example.com",
            username="admin",
            password="secret",
            verify_certificate=False,
        )
        client.authenticate = Mock()
        client.get_json = Mock(return_value={"softwareVersion": "8.0.0-1"})
        client.close = Mock()
        with self.assertRaises(FdmCompatibilityError):
            client.__enter__()
        client.close.assert_called_once_with()

    def test_plr_operations_require_completed_handshake(self) -> None:
        client = FDMClient(
            host="fdm.example.com",
            username="admin",
            password="secret",
            verify_certificate=False,
        )
        try:
            with self.assertRaisesRegex(FDMError, "compatibility is not validated"):
                FdmPlrClient(client)
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
