"""Optional live integration test for Cisco OAuth token acquisition."""

import os
import unittest

from cisco_support_token_client import CiscoSupportTokenClient, CiscoSupportTokenError
from key_manager import KeyManager, KeyManagerError


def _load_integration_credentials() -> tuple[str, str] | None:
    """Load CI secrets first, then try the native operating-system keyring."""
    client_id = os.environ.get("CISCO_CLIENT_ID")
    client_secret = os.environ.get("CISCO_CLIENT_SECRET")
    if client_id or client_secret:
        if not client_id or not client_secret:
            raise RuntimeError("Cisco integration credentials are incomplete")
        return client_id, client_secret

    try:
        credentials = KeyManager().get_cisco_credentials()
    except KeyManagerError:
        return None
    return credentials.client_id, credentials.client_secret


class CiscoTokenIntegrationTests(unittest.TestCase):
    def test_live_client_credentials_authentication_when_configured(self) -> None:
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
        except CiscoSupportTokenError:
            # Avoid emitting a provider response that could contain sensitive data.
            self.fail("Cisco OAuth authentication failed; inspect Cisco credentials")
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
