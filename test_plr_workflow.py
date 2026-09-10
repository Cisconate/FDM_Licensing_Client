"""Mocked tests for atomic FDM and Cisco PLR operations."""

import unittest
from unittest.mock import Mock

from cisco_support_api_client import (
    APX_SOFTWARE_API_PROFILE,
    AccountSelection,
    CiscoPlrRequestError,
    CiscoPlrReservationClient,
    ExistingProductInstanceError,
    ReservationPreflight,
    SmartAccount,
    VirtualAccount,
)
from fdm_client import FDMClient
from fdm_compatibility import FTD_7_6_PROFILE
from fdm_plr_client import FdmPlrClient, FdmPlrError


class FdmPlrClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fdm = Mock(spec=FDMClient)
        self.fdm.require_api_profile.return_value = FTD_7_6_PROFILE
        self.client = FdmPlrClient(self.fdm)

    def test_create_universal_plr_connection_is_one_atomic_post(self) -> None:
        response = Mock()
        response.json.return_value = {"id": "connection-id", "version": "1"}
        self.fdm.request.return_value = response

        result = self.client.create_universal_plr_connection()

        self.assertEqual(result["id"], "connection-id")
        self.fdm.request.assert_called_once_with(
            "POST",
            "license/smartagentconnections",
            json={"type": "smartagentconnection", "connectionType": "UNIVERSAL_PLR"},
        )

    def test_update_universal_plr_connection_preserves_version_boundary(self) -> None:
        response = Mock()
        response.json.return_value = {"id": "connection-id", "version": "2"}
        self.fdm.request.return_value = response

        self.client.update_connection_to_universal_plr(
            connection_id="connection-id", version="1"
        )

        self.fdm.request.assert_called_once_with(
            "PUT",
            "license/smartagentconnections/connection-id",
            json={
                "id": "connection-id",
                "version": "1",
                "type": "smartagentconnection",
                "connectionType": "UNIVERSAL_PLR",
            },
        )

    def test_request_code_is_validated_at_response_boundary(self) -> None:
        self.fdm.get_json.return_value = {
            "items": [{"id": "request-id", "code": "DE-ZNGFWv:request"}]
        }
        codes = self.client.list_plr_request_codes()
        self.assertEqual(codes[0].code, "DE-ZNGFWv:request")
        self.fdm.get_json.assert_called_once_with("license/plrrequestcodes")

        self.fdm.get_json.return_value = {"items": [{"code": "bad\ncode"}]}
        with self.assertRaises(FdmPlrError):
            self.client.list_plr_request_codes()

    def test_install_authorization_code_is_one_atomic_post(self) -> None:
        response = Mock()
        response.json.return_value = {"type": "PLRAuthorizationCode"}
        self.fdm.request.return_value = response
        code = "ABC123-ABC123-ABC123-ABC123-ABC123-ABC123"

        self.client.install_authorization_code(code)

        self.fdm.request.assert_called_once_with(
            "POST",
            "license/action/installplrcode",
            json={"type": "PLRAuthorizationCode", "code": code},
        )

    def test_invalid_authorization_code_fails_before_network(self) -> None:
        with self.assertRaises(ValueError):
            self.client.install_authorization_code("not-a-uplr-code")
        self.fdm.request.assert_not_called()


class CiscoPlrExchangeTests(unittest.TestCase):
    @staticmethod
    def _response(status_code, payload):
        response = Mock()
        response.status_code = status_code
        response.ok = 200 <= status_code < 300
        response.is_redirect = False
        response.url = "https://apx.cisco.com/v1/software/apis/test"
        response.json.return_value = payload
        return response

    def test_401_refreshes_token_and_retries_exactly_once(self) -> None:
        tokens = iter(("old-token", "new-token"))
        refresher = Mock()
        client = CiscoPlrReservationClient(
            profile=APX_SOFTWARE_API_PROFILE,
            token_provider=lambda: next(tokens),
            token_refresher=refresher,
        )
        client.session = Mock()
        client.session.request.side_effect = [
            self._response(401, {}),
            self._response(200, {"data": []}),
        ]
        try:
            client.get_json("pnp/v2/accounts")
        finally:
            client.close()
        self.assertEqual(client.session.request.call_count, 2)
        refresher.assert_called_once_with()

    def test_repeated_401_is_not_retried_again(self) -> None:
        client = CiscoPlrReservationClient(
            profile=APX_SOFTWARE_API_PROFILE,
            token_provider=lambda: "token",
            token_refresher=Mock(),
        )
        client.session = Mock()
        client.session.request.side_effect = [
            self._response(401, {}), self._response(401, {})
        ]
        try:
            with self.assertRaises(CiscoPlrRequestError):
                client.get_json("pnp/v2/accounts")
        finally:
            client.close()
        self.assertEqual(client.session.request.call_count, 2)

    def test_smart_account_discovery_follows_pagination_and_deduplicates(self) -> None:
        client = CiscoPlrReservationClient(bearer_token="token")
        client.get_json = Mock(side_effect=[
            {"totalRows": 2, "data": [{
                "companyName": "Example", "domainIdentifier": "example.com",
                "accountIdentifier": "10",
            }]},
            {"totalRows": 2, "data": [{
                "companyName": "Second", "domainIdentifier": "second.example",
                "accountIdentifier": "20",
            }]},
        ])
        try:
            accounts = client.list_smart_accounts()
        finally:
            client.close()
        self.assertEqual([item.account_id for item in accounts], ["10", "20"])
        self.assertEqual(client.get_json.call_count, 2)

    def test_slr_search_returns_universal_entitlement_mapping(self) -> None:
        client = CiscoPlrReservationClient(bearer_token="token")
        client.post_json = Mock(return_value={
            "status": "SUCCESS",
            "data": [{"softwareTag": "software-tag", "entitlements": [{
                "type": "UNIVERSAL", "entitlementTag": "plr-tag"
            }]}],
        })
        try:
            result = client.search_slr_entitlements(("software-tag",))
        finally:
            client.close()
        self.assertEqual(result[0].reservation_type, "UNIVERSAL")
        self.assertEqual(result[0].entitlement_tag, "plr-tag")

    def test_universal_reservation_uses_contract_path_body_and_nested_code(self) -> None:
        client = CiscoPlrReservationClient(
            bearer_token="token", profile=APX_SOFTWARE_API_PROFILE
        )
        client.post_json = Mock(return_value={
            "status": "SUCCESS",
            "authorizationCodes": [{
                "status": "SUCCESS",
                "reservationCode": "DC-ZCSF-220:FVH3011AHB3-AkARi7gUQ-02",
                "authorizationCode": "ABC123-ABC123-ABC123-ABC123-ABC123-ABC123",
            }],
        })
        selection = AccountSelection(
            SmartAccount("Example", "example.com", "10"),
            VirtualAccount("Default VA", "20", True),
        )
        client.preflight_universal_plr = Mock(return_value=ReservationPreflight(
            client.reservation_request_identity(
                "DC-ZCSF-220:FVH3011AHB3-AkARi7gUQ-02"
            ),
            None,
        ))
        try:
            result = client.reserve_universal_plr(
                selection, "DC-ZCSF-220:FVH3011AHB3-AkARi7gUQ-02"
            )
        finally:
            client.close()
        self.assertEqual(
            result.authorization_code,
            "ABC123-ABC123-ABC123-ABC123-ABC123-ABC123",
        )
        client.post_json.assert_called_once_with(
            "licensing/v2/account/example.com/virtual-account/Default%20VA/licenses/reserve",
            json={"reservationRequests": [{
                "reservationCode": "DC-ZCSF-220:FVH3011AHB3-AkARi7gUQ-02",
                "reservationType": "UNIVERSAL"
            }]},
        )

    def test_preflight_finds_existing_product_instance_without_mutation(self) -> None:
        client = CiscoPlrReservationClient(
            bearer_token="token", profile=APX_SOFTWARE_API_PROFILE
        )
        client.get_json = Mock(return_value={
            "status": "SUCCESS",
            "totalRecords": 1,
            "devices": [{
                "instanceName": "UDI_PID:CSF-220; UDI_SN:FVH3011AHB3; ",
                "productTagName": "regid.example.CSF200_FTD",
                "sudi": {"udiPid": "CSF-220", "udiSerialNumber": "FVH3011AHB3"},
            }],
        })
        selection = AccountSelection(
            SmartAccount("Example", "federal.cisco.com", "102727"),
            VirtualAccount("nstapp", "190132", False),
        )
        try:
            result = client.preflight_universal_plr(
                selection, "DC-ZCSF-220:FVH3011AHB3-AkARi7gUQ-02"
            )
        finally:
            client.close()
        self.assertFalse(result.may_reserve)
        self.assertEqual(result.existing_instance.product_id, "CSF-220")
        client.get_json.assert_called_once_with(
            "licensing/v2/accounts/federal.cisco.com/devices",
            params={
                "virtualAccountName": "nstapp",
                "instanceName": "FVH3011AHB3",
                "limit": 50,
                "offset": 0,
            },
        )

    def test_reservation_is_blocked_when_preflight_finds_existing_instance(self) -> None:
        client = CiscoPlrReservationClient(bearer_token="token")
        selection = AccountSelection(
            SmartAccount("Example", "example.com", "10"),
            VirtualAccount("Default", "20", True),
        )
        existing = client._product_instances({
            "status": "SUCCESS",
            "devices": [{
                "instanceName": "UDI_PID:CSF-220; UDI_SN:FVH3011AHB3; ",
                "productTagName": "tag",
                "sudi": {"udiPid": "CSF-220", "udiSerialNumber": "FVH3011AHB3"},
            }],
        })[0]
        client.preflight_universal_plr = Mock(return_value=ReservationPreflight(
            client.reservation_request_identity(
                "DC-ZCSF-220:FVH3011AHB3-AkARi7gUQ-02"
            ),
            existing,
        ))
        client.post_json = Mock()
        try:
            with self.assertRaisesRegex(ExistingProductInstanceError, "poisoned"):
                client.reserve_universal_plr(
                    selection, "DC-ZCSF-220:FVH3011AHB3-AkARi7gUQ-02"
                )
        finally:
            client.close()
        client.post_json.assert_not_called()

    def test_reservation_rejects_mismatched_request_code(self) -> None:
        client = CiscoPlrReservationClient(bearer_token="token")
        result = {"status": "SUCCESS", "authorizationCodes": [{
            "status": "SUCCESS", "reservationCode": "different",
            "authorizationCode": "auth-code",
        }]}
        with self.assertRaises(CiscoPlrRequestError):
            client._parse_universal_authorization(result, "submitted")
        client.close()

    def test_exchange_returns_code_from_one_reservation_post(self) -> None:
        client = CiscoPlrReservationClient(bearer_token="token")
        client.reserve_licenses = Mock(return_value={"authorizationCode": "auth-code"})
        try:
            result = client.exchange_plr_request_code(
                "approved/reservation/path", payload={"requestCode": "request-code"}
            )
        finally:
            client.close()
        self.assertEqual(result, "auth-code")
        client.reserve_licenses.assert_called_once_with(
            "approved/reservation/path",
            payload={"requestCode": "request-code"},
            headers=None,
        )

    def test_exchange_rejects_missing_code(self) -> None:
        client = CiscoPlrReservationClient(bearer_token="token")
        client.reserve_licenses = Mock(return_value={"status": "accepted"})
        try:
            with self.assertRaises(CiscoPlrRequestError):
                client.exchange_plr_request_code("approved/path", payload={"x": "y"})
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
