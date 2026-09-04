"""Unit tests for key_manager.py; no real credential store is accessed."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from cisco_support_api_client import CiscoPlrReservationClient
from cisco_support_token_client import (
    BearerToken,
    CiscoSupportTokenClient,
    main as token_client_main,
)
from key_manager import (
    CLIENT_ID_KEY,
    CLIENT_SECRET_KEY,
    CredentialStorageError,
    CredentialsNotFoundError,
    KeyManager,
    SecureBackendUnavailableError,
    UnsupportedPlatformError,
    main,
)


class MemoryBackend:
    priority = 5

    def __init__(self) -> None:
        self.values = {}

    def get_password(self, service, username):
        return self.values.get((service, username))

    def set_password(self, service, username, password):
        self.values[(service, username)] = password

    def delete_password(self, service, username):
        self.values.pop((service, username), None)


class PlaintextBackend(MemoryBackend):
    pass


class KeyManagerTests(unittest.TestCase):
    def setUp(self):
        self.backend = MemoryBackend()
        self.manager = KeyManager(backend=self.backend, system_name="Darwin")

    def test_round_trip_and_status(self):
        self.manager.store_cisco_credentials("client-id-value", "secret-value")
        credentials = self.manager.get_cisco_credentials()
        self.assertEqual(credentials.client_id, "client-id-value")
        self.assertEqual(credentials.client_secret, "secret-value")
        self.assertTrue(self.manager.credential_status().complete)

    def test_incomplete_credentials_fail(self):
        self.backend.set_password(self.manager.service_name, CLIENT_ID_KEY, "id")
        with self.assertRaises(CredentialsNotFoundError):
            self.manager.get_cisco_credentials()

    def test_delete_removes_both_values(self):
        self.manager.store_cisco_credentials("id", "secret")
        self.manager.delete_cisco_credentials()
        self.assertFalse(self.manager.credential_status().complete)

    def test_rejects_unknown_platform(self):
        with self.assertRaises(UnsupportedPlatformError):
            KeyManager(backend=self.backend, system_name="Plan9")

    def test_rejects_plaintext_backend(self):
        with self.assertRaises(SecureBackendUnavailableError):
            KeyManager(backend=PlaintextBackend(), system_name="Linux")

    def test_partial_store_failure_restores_old_pair(self):
        self.manager.store_cisco_credentials("old-id", "old-secret")
        original_set = self.backend.set_password

        def fail_on_secret(service, username, password):
            if username == CLIENT_SECRET_KEY and password == "new-secret":
                raise RuntimeError("simulated failure")
            original_set(service, username, password)

        self.backend.set_password = fail_on_secret
        with self.assertRaises(CredentialStorageError):
            self.manager.store_cisco_credentials("new-id", "new-secret")
        credentials = self.manager.get_cisco_credentials()
        self.assertEqual(credentials.client_id, "old-id")
        self.assertEqual(credentials.client_secret, "old-secret")

    def test_status_cli_does_not_print_values(self):
        self.manager.store_cisco_credentials("sensitive-id", "sensitive-secret")
        output = io.StringIO()
        with patch("key_manager.KeyManager", return_value=self.manager):
            with redirect_stdout(output):
                result = main(["status"])
        self.assertEqual(result, 0)
        self.assertNotIn("sensitive-id", output.getvalue())
        self.assertNotIn("sensitive-secret", output.getvalue())

    def test_credentials_feed_token_provider_without_entering_licensing_client(self):
        self.manager.store_cisco_credentials("client-id", "client-secret")
        credentials = self.manager.get_cisco_credentials()
        self.assertEqual(credentials.client_id, "client-id")
        self.assertEqual(credentials.client_secret, "client-secret")

        response = Mock(is_redirect=False, ok=True)
        session = Mock()
        session.request.return_value = response
        licensing = CiscoPlrReservationClient(
            token_provider=lambda: "short-lived-token"
        )
        licensing.session = session
        licensing.request("GET", "read-only-health")

        request_headers = session.request.call_args.kwargs["headers"]
        self.assertEqual(request_headers["Authorization"], "Bearer short-lived-token")

    def test_token_client_clears_long_lived_credentials_on_close(self):
        client = CiscoSupportTokenClient(
            client_id="client-id", client_secret="client-secret"
        )
        client.close()
        self.assertEqual(client._client_id, "")
        self.assertEqual(client._client_secret, "")

    def test_token_check_cli_does_not_print_token_or_credentials(self):
        self.manager.store_cisco_credentials("sensitive-id", "sensitive-secret")
        mock_client = Mock()
        mock_client.authenticate.return_value = BearerToken(
            access_token="sensitive-token",
            expires_at=999999999.0,
            token_type="Bearer",
        )
        output = io.StringIO()
        with patch("key_manager.KeyManager", return_value=self.manager):
            with patch(
                "cisco_support_token_client.CiscoSupportTokenClient",
                return_value=mock_client,
            ):
                with redirect_stdout(output):
                    result = token_client_main(["--check"])

        self.assertEqual(result, 0)
        self.assertIn("authentication succeeded", output.getvalue())
        self.assertNotIn("sensitive-id", output.getvalue())
        self.assertNotIn("sensitive-secret", output.getvalue())
        self.assertNotIn("sensitive-token", output.getvalue())
        mock_client.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
