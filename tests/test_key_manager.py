"""Unit tests for key_manager.py; no real credential store is accessed."""

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

import requests

from cisco_support_api_client import CiscoPlrReservationClient
from cisco_support_token_client import (
    BearerToken,
    CiscoSupportCredentialRejectedError,
    CiscoSupportTokenClient,
    CiscoSupportTokenServiceError,
    CiscoSupportTokenTransportError,
    main as token_client_main,
)
from key_manager import (
    CLIENT_ID_KEY,
    CLIENT_SECRET_KEY,
    CISCO_CLIENT,
    CredentialAccessError,
    CredentialStorageError,
    CredentialsNotFoundError,
    InvalidStoredCredentialsError,
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

    def test_fdm_credentials_are_scoped_to_stored_device_identity(self):
        self.manager.store_fdm_credentials(
            host="FTD.EXAMPLE.COM", port=8443, username="admin", password="secret"
        )
        credentials = self.manager.get_fdm_credentials()
        self.assertEqual(credentials.host, "ftd.example.com")
        self.assertEqual(credentials.port, 8443)
        self.assertEqual(credentials.username, "admin")
        self.assertEqual(credentials.password, "secret")
        self.assertTrue(self.manager.fdm_credential_status().complete)

    def test_multiple_fdm_hosts_are_looked_up_directly_without_enumeration(self):
        self.manager.store_fdm_credentials(
            host="192.0.2.10", port=443, username="first", password="first-secret"
        )
        self.manager.store_fdm_credentials(
            host="192.0.2.20", port=8443, username="second", password="second-secret"
        )
        summary = self.manager.fdm_credential_summary()
        self.assertEqual(summary.count, 2)
        self.assertIsNone(summary.only_host)
        self.assertEqual(
            self.manager.get_fdm_credentials(host="192.0.2.20").username,
            "second",
        )
        with self.assertRaisesRegex(CredentialsNotFoundError, "Multiple FDM"):
            self.manager.get_fdm_credentials()

    def test_single_fdm_host_summary_supports_safe_prefill(self):
        self.manager.store_fdm_credentials(
            host="192.0.2.10", port=443, username="operator", password="secret"
        )
        summary = self.manager.fdm_credential_summary()
        self.assertEqual(summary.count, 1)
        self.assertEqual(summary.only_host, "192.0.2.10")

    def test_store_cli_prompts_only_for_missing_fdm_group(self):
        self.manager.store_cisco_credentials("existing-id", "existing-secret")
        with patch("key_manager.KeyManager", return_value=self.manager), patch(
            "key_manager.input",
            side_effect=["192.0.2.10", "", ""],
        ), patch("key_manager.getpass.getpass", return_value="fdm-secret"), redirect_stdout(
            io.StringIO()
        ):
            result = main(["store"])
        self.assertEqual(result, 0)
        self.assertEqual(self.manager.get_cisco_credentials().client_id, "existing-id")
        self.assertEqual(self.manager.get_fdm_credentials().host, "192.0.2.10")

    def test_update_cli_replaces_only_requested_cisco_group(self):
        self.manager.store_cisco_credentials("old-id", "old-secret")
        self.manager.store_fdm_credentials(
            host="192.0.2.10", port=443, username="admin", password="fdm-secret"
        )
        with patch("key_manager.KeyManager", return_value=self.manager), patch(
            "key_manager.input", return_value="new-id"
        ), patch("key_manager.getpass.getpass", return_value="new-secret"), redirect_stdout(
            io.StringIO()
        ):
            result = main(["update", CISCO_CLIENT])
        self.assertEqual(result, 0)
        self.assertEqual(self.manager.get_cisco_credentials().client_id, "new-id")
        self.assertEqual(self.manager.get_fdm_credentials().password, "fdm-secret")

    def test_incomplete_credentials_fail(self):
        self.backend.set_password(self.manager.service_name, CLIENT_ID_KEY, "id")
        with self.assertRaises(CredentialsNotFoundError):
            self.manager.get_cisco_credentials()

    def test_retrieved_credentials_are_validated_at_keyring_boundary(self):
        self.backend.set_password(self.manager.service_name, CLIENT_ID_KEY, "id\n")
        self.backend.set_password(self.manager.service_name, CLIENT_SECRET_KEY, "secret")
        with self.assertRaises(InvalidStoredCredentialsError):
            self.manager.get_cisco_credentials()

    def test_missing_credentials_identify_empty_fields(self):
        with self.assertRaisesRegex(
            CredentialsNotFoundError, "Client ID and Client Secret.*empty or not stored"
        ):
            self.manager.get_cisco_credentials()
        self.backend.set_password(self.manager.service_name, CLIENT_ID_KEY, "id")
        with self.assertRaisesRegex(CredentialsNotFoundError, "Client Secret is"):
            self.manager.get_cisco_credentials()

    def test_backend_read_failure_identifies_native_store_and_access_problem(self):
        self.backend.get_password = Mock(side_effect=RuntimeError("sensitive detail"))
        with self.assertRaises(CredentialAccessError) as raised:
            self.manager.get_cisco_credentials()
        message = str(raised.exception)
        self.assertIn("macOS Keychain could not be accessed", message)
        self.assertNotIn("sensitive detail", message)

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
        self.manager.store_fdm_credentials(
            host="fdm.example.com", port=443,
            username="sensitive-user", password="sensitive-password",
        )
        output = io.StringIO()
        with patch("key_manager.KeyManager", return_value=self.manager):
            with redirect_stdout(output):
                result = main(["status"])
        self.assertEqual(result, 0)
        self.assertNotIn("sensitive-id", output.getvalue())
        self.assertNotIn("sensitive-secret", output.getvalue())
        self.assertNotIn("sensitive-user", output.getvalue())
        self.assertNotIn("sensitive-password", output.getvalue())

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

    def test_token_invalidation_discards_cached_token(self):
        client = CiscoSupportTokenClient(
            client_id="client-id", client_secret="client-secret"
        )
        client._token = BearerToken("token", 999999999.0)
        client.invalidate()
        self.assertIsNone(client._token)
        client.close()

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

    def test_oauth_invalid_client_is_reported_as_rejected_credentials(self):
        client = CiscoSupportTokenClient(
            client_id="client-id", client_secret="client-secret"
        )
        response = Mock(is_redirect=False, status_code=401)
        response.json.return_value = {"error": "invalid_client", "error_description": "secret detail"}
        client.session.post = Mock(return_value=response)
        try:
            with self.assertRaises(CiscoSupportCredentialRejectedError) as raised:
                client.authenticate()
        finally:
            client.close()
        self.assertIn("Client ID or Client Secret", str(raised.exception))
        self.assertNotIn("secret detail", str(raised.exception))

    def test_oauth_ambiguous_rejection_does_not_claim_credentials_are_wrong(self):
        client = CiscoSupportTokenClient(
            client_id="client-id", client_secret="client-secret"
        )
        response = Mock(is_redirect=False, status_code=403)
        response.json.return_value = {"error": "insufficient_scope"}
        client.session.post = Mock(return_value=response)
        try:
            with self.assertRaisesRegex(
                Exception, "does not conclusively identify a bad credential pair"
            ):
                client.authenticate()
        finally:
            client.close()

    def test_oauth_timeouts_and_provider_outage_are_distinct(self):
        client = CiscoSupportTokenClient(
            client_id="client-id", client_secret="client-secret"
        )
        client.session.post = Mock(side_effect=requests.exceptions.ConnectTimeout())
        with self.assertRaisesRegex(CiscoSupportTokenTransportError, "connecting"):
            client.authenticate()
        response = Mock(is_redirect=False, status_code=503)
        response.json.return_value = {}
        client.session.post = Mock(return_value=response)
        with self.assertRaisesRegex(CiscoSupportTokenServiceError, "unavailable"):
            client.authenticate()
        client.close()

    def test_token_cli_reports_keychain_access_failure_not_missing_credentials(self):
        error = CredentialAccessError("macOS Keychain could not be accessed")
        stderr = io.StringIO()
        with patch("key_manager.KeyManager", side_effect=error):
            with redirect_stderr(stderr):
                result = token_client_main(["--check"])
        self.assertEqual(result, 1)
        self.assertIn("Keychain could not be accessed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
