"""Optional live integration test for Cisco OAuth token acquisition."""

import os
import unittest
from unittest.mock import Mock, patch

from cisco_support_token_client import CiscoSupportTokenClient, CiscoSupportTokenError
from key_manager import CredentialsNotFoundError, KeyManager


LIVE_TEST_ENVIRONMENT_VARIABLE = "RUN_CISCO_LIVE_TESTS"


def _live_test_enabled() -> bool:
    """Return whether live OAuth testing was explicitly enabled."""
    value = os.environ.get(LIVE_TEST_ENVIRONMENT_VARIABLE)
    if value is None:
        return False
    if value != "1":
        raise RuntimeError(
            f"{LIVE_TEST_ENVIRONMENT_VARIABLE} must be '1' when set"
        )
    return True


def _load_integration_credentials() -> tuple[str, str] | None:
    """Load CI secrets first, then try the native operating-system keyring."""
    environment_configured = (
        "CISCO_CLIENT_ID" in os.environ or "CISCO_CLIENT_SECRET" in os.environ
    )
    client_id = os.environ.get("CISCO_CLIENT_ID")
    client_secret = os.environ.get("CISCO_CLIENT_SECRET")
    if environment_configured:
        if not client_id or not client_secret:
            missing = "CISCO_CLIENT_ID" if not client_id else "CISCO_CLIENT_SECRET"
            raise RuntimeError(
                f"{missing} is empty or absent while Cisco integration environment credentials are configured"
            )
        return client_id, client_secret

    try:
        credentials = KeyManager().get_cisco_credentials()
    except CredentialsNotFoundError:
        return None
    return credentials.client_id, credentials.client_secret


class CiscoTokenIntegrationTests(unittest.TestCase):
    def test_live_client_credentials_authentication_when_configured(self) -> None:
        if not _live_test_enabled():
            self.skipTest(
                f"Cisco live authentication is disabled; set "
                f"{LIVE_TEST_ENVIRONMENT_VARIABLE}=1 to enable it"
            )

        credentials = _load_integration_credentials()
        if credentials is None:
            self.skipTest("Cisco integration credentials are not configured")

        client = CiscoSupportTokenClient(
            client_id=credentials[0],
            client_secret=credentials[1],
        )
        try:
            token = client.authenticate()
            self.assertTrue(token.access_token)
            self.assertGreater(token.expires_at, 0)
            self.assertTrue(token.token_type)
        except CiscoSupportTokenError as exc:
            self.fail(str(exc))
        finally:
            client.close()


class LiveTestGateTests(unittest.TestCase):
    def test_live_authentication_skips_before_loading_credentials_by_default(self) -> None:
        test_case = CiscoTokenIntegrationTests(
            "test_live_client_credentials_authentication_when_configured"
        )
        with patch.dict(os.environ, {}, clear=True), patch(
            "tests.test_live_cisco_token._load_integration_credentials"
        ) as load_credentials:
            with self.assertRaises(unittest.SkipTest):
                test_case.test_live_client_credentials_authentication_when_configured()
        load_credentials.assert_not_called()

    def test_live_authentication_loads_credentials_when_explicitly_enabled(self) -> None:
        test_case = CiscoTokenIntegrationTests(
            "test_live_client_credentials_authentication_when_configured"
        )
        with patch.dict(
            os.environ, {LIVE_TEST_ENVIRONMENT_VARIABLE: "1"}, clear=True
        ), patch(
            "tests.test_live_cisco_token._load_integration_credentials",
            return_value=None,
        ) as load_credentials:
            with self.assertRaisesRegex(
                unittest.SkipTest, "credentials are not configured"
            ):
                test_case.test_live_client_credentials_authentication_when_configured()
        load_credentials.assert_called_once_with()

    def test_invalid_live_authentication_flag_is_rejected(self) -> None:
        with patch.dict(
            os.environ, {LIVE_TEST_ENVIRONMENT_VARIABLE: "true"}, clear=True
        ):
            with self.assertRaisesRegex(RuntimeError, "must be '1'"):
                _live_test_enabled()


class IntegrationCredentialLoadingTests(unittest.TestCase):
    def test_empty_environment_credential_is_a_failure_not_keyring_fallback(self) -> None:
        with patch.dict(
            os.environ,
            {"CISCO_CLIENT_ID": "", "CISCO_CLIENT_SECRET": "secret"},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "CISCO_CLIENT_ID is empty"):
                _load_integration_credentials()

    def test_missing_keyring_credentials_are_the_only_keyring_skip_case(self) -> None:
        manager = Mock()
        manager.get_cisco_credentials.side_effect = CredentialsNotFoundError("missing")
        with patch.dict(os.environ, {}, clear=True), patch(
            "tests.test_live_cisco_token.KeyManager", return_value=manager
        ):
            self.assertIsNone(_load_integration_credentials())

    def test_keyring_access_error_propagates(self) -> None:
        from key_manager import CredentialAccessError

        manager = Mock()
        manager.get_cisco_credentials.side_effect = CredentialAccessError("no access")
        with patch.dict(os.environ, {}, clear=True), patch(
            "tests.test_live_cisco_token.KeyManager", return_value=manager
        ):
            with self.assertRaises(CredentialAccessError):
                _load_integration_credentials()


if __name__ == "__main__":
    unittest.main()
