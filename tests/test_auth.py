# Copyright (c) 2025-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Auth-mode resolution, OAuth token lifecycle, and attribution headers."""

import time
import tomllib
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import src.app as app_module
from src.app import Asset, _make_request, test_connectivity

from .conftest import FakeAuthState


class TestApiKeyMode:
    def test_v1_url_and_api_key_headers(self, api_key_asset, doppel_api):
        ok, _status, _data, error = _make_request(api_key_asset, "GET", "/alerts")

        assert ok, error
        call = doppel_api.calls[0]
        assert call["url"] == "https://api.doppel.com/v1/alerts"
        assert call["headers"]["x-api-key"] == "test-api-key"
        assert "Authorization" not in call["headers"]

    def test_optional_v1_headers(self, doppel_api):
        asset = Asset(doppel_api_key="k", user_api_key="user-key", org_code="org-1")
        _make_request(asset, "GET", "/alerts")

        headers = doppel_api.calls[0]["headers"]
        assert headers["x-user-api-key"] == "user-key"
        assert headers["x-organization-code"] == "org-1"

    def test_attribution_headers_present(self, api_key_asset, doppel_api):
        _make_request(api_key_asset, "GET", "/alerts")

        headers = doppel_api.calls[0]["headers"]
        assert headers["x-doppel-client"] == f"splunk-soar/{app_module.APP_VERSION}"
        assert headers["User-Agent"] == f"doppel-splunk-soar/{app_module.APP_VERSION}"


class TestOAuthMode:
    def test_v2_url_and_bearer_token(self, oauth_asset, token_endpoint, doppel_api):
        ok, _status, _data, error = _make_request(oauth_asset, "GET", "/alerts")

        assert ok, error
        call = doppel_api.calls[0]
        assert call["url"] == "https://api.doppel.com/v2/alerts"
        assert call["headers"]["Authorization"] == "Bearer token-1"
        assert "x-api-key" not in call["headers"]

    def test_attribution_headers_present(self, oauth_asset, token_endpoint, doppel_api):
        _make_request(oauth_asset, "GET", "/alerts")

        headers = doppel_api.calls[0]["headers"]
        assert headers["x-doppel-client"] == f"splunk-soar/{app_module.APP_VERSION}"

    def test_mint_request_shape(self, oauth_asset, token_endpoint, doppel_api):
        _make_request(oauth_asset, "GET", "/alerts")

        assert token_endpoint.mint_count == 1
        mint = token_endpoint.requests[0]
        assert str(mint.url) == "https://api.doppel.com/oauth/token"
        body = dict(pair.split("=", 1) for pair in mint.content.decode().split("&"))
        assert body["grant_type"] == "client_credentials"
        assert body["client_id"] == "test-client-id"
        assert body["audience"] == "doppel-external"
        # Attribution rides on the mint too.
        assert (
            mint.headers["x-doppel-client"] == f"splunk-soar/{app_module.APP_VERSION}"
        )

    def test_token_cached_across_requests(
        self, oauth_asset, token_endpoint, doppel_api
    ):
        _make_request(oauth_asset, "GET", "/alerts")
        _make_request(oauth_asset, "GET", "/alerts")
        _make_request(oauth_asset, "GET", "/alert", params={"id": "TST-1"})

        assert token_endpoint.mint_count == 1

    def test_expired_token_is_reminted(self, oauth_asset, token_endpoint, doppel_api):
        _make_request(oauth_asset, "GET", "/alerts")
        # Force the stored token past expiry (leeway is 30s).
        state = oauth_asset.auth_state.get_all()
        state["oauth"]["token"]["expires_at"] = time.time() - 1
        oauth_asset.auth_state.put_all(state)

        _make_request(oauth_asset, "GET", "/alerts")

        assert token_endpoint.mint_count == 2
        assert doppel_api.calls[1]["headers"]["Authorization"] == "Bearer token-2"

    def test_401_reminted_once_then_succeeds(
        self, oauth_asset, token_endpoint, doppel_api
    ):
        doppel_api.queue(401, {"message": "unauthorized"})
        doppel_api.queue(200, {"alerts": []})

        ok, _status, _data, error = _make_request(oauth_asset, "GET", "/alerts")

        assert ok, error
        assert token_endpoint.mint_count == 2
        assert doppel_api.calls[1]["headers"]["Authorization"] == "Bearer token-2"

    def test_persistent_401_fails(self, oauth_asset, token_endpoint, doppel_api):
        doppel_api.queue(401, {"message": "unauthorized"})
        doppel_api.queue(401, {"message": "unauthorized"})

        ok, status, _data, _error = _make_request(oauth_asset, "GET", "/alerts")

        assert not ok
        assert status == 401
        assert token_endpoint.mint_count == 2  # exactly one re-mint retry

    def test_oauth_preferred_when_both_modes_configured(
        self, token_endpoint, doppel_api
    ):
        asset = Asset(
            doppel_api_key="legacy-key",  # pragma: allowlist secret
            client_id="test-client-id",
            client_secret="test-client-secret",  # pragma: allowlist secret
        )
        asset._auth_state = FakeAuthState()

        _make_request(asset, "GET", "/alerts")

        call = doppel_api.calls[0]
        assert call["url"].startswith("https://api.doppel.com/v2")
        assert "x-api-key" not in call["headers"]


class TestMisconfiguration:
    def test_half_oauth_pair_fails(self, doppel_api):
        asset = Asset(client_id="only-id")

        ok, _status, _data, error = _make_request(asset, "GET", "/alerts")

        assert not ok
        assert "Incomplete OAuth credentials" in error
        assert not doppel_api.calls

    def test_no_credentials_fails(self, doppel_api):
        asset = Asset()

        ok, _status, _data, error = _make_request(asset, "GET", "/alerts")

        assert not ok
        assert "Missing Doppel credentials" in error
        assert not doppel_api.calls


class TestAttributionConstants:
    def test_version_matches_pyproject(self):
        pyproject = Path(app_module.__file__).resolve().parent.parent / "pyproject.toml"
        expected = tomllib.loads(pyproject.read_text())["project"]["version"]
        assert expected == app_module.APP_VERSION

    def test_header_format(self):
        assert app_module.ATTRIBUTION_HEADERS["x-doppel-client"].startswith(
            "splunk-soar/"
        )
        assert app_module.ATTRIBUTION_HEADERS["User-Agent"].startswith(
            "doppel-splunk-soar/"
        )


class _FakeSoarClient:
    def __init__(self) -> None:
        self.message: str | None = None

    def set_message(self, message: str) -> None:
        self.message = message


class TestConnectivityProbe:
    def test_probe_is_bounded_by_activity_window(self, api_key_asset, doppel_api):
        """The probe must stay cheap and tenant-size independent.

        An unfiltered page-0 query is rejected by the API's result-window
        guard for orgs with very large alert volumes, so the probe pins
        page_size=1 and a ~24h last_activity_timestamp window.
        """
        # The SDK decorator wraps the handler and injects the asset itself;
        # __wrapped__ is the original (soar, asset) function.
        test_connectivity.__wrapped__(soar=_FakeSoarClient(), asset=api_key_asset)

        params = doppel_api.calls[0]["params"]
        assert params["page_size"] == 1

        since = datetime.strptime(
            params["last_activity_timestamp"], "%Y-%m-%dT%H:%M:%S"
        ).replace(tzinfo=ZoneInfo("UTC"))
        now = datetime.now(ZoneInfo("UTC"))
        assert timedelta(hours=23) < now - since < timedelta(hours=25)

    def test_probe_passes_on_success(self, api_key_asset, doppel_api):
        soar = _FakeSoarClient()
        test_connectivity.__wrapped__(soar=soar, asset=api_key_asset)
        assert soar.message == "Test connectivity passed"
