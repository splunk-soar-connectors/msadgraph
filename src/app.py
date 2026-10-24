# Copyright (c) 2026 Splunk Inc.
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
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App

from .actions import register_actions
from .asset import Asset
from .consts import OAUTH_CALLBACK_ROUTE, OAUTH_START_ROUTE
from .test_connectivity import run_test_connectivity
from .webhooks import register_webhooks


def create_msadgraph_app() -> App:
    app = App(
        name="MS Graph for Active Directory",
        app_type="identity management",
        logo="logo_msadgraph.svg",
        logo_dark="logo_msadgraph_dark.svg",
        product_vendor="Microsoft",
        product_name="MS Graph for Active Directory",
        publisher="Splunk",
        appid="f2a239df-acb2-47d6-861c-726a435cfe76",
        min_phantom_version="8.6.0",
        fips_compliant=True,
        encrypt_cache_state=True,
        encrypt_ingest_state=True,
        asset_cls=Asset,
    )

    register_webhooks(app)

    @app.test_connectivity()
    def test_connectivity(soar: SOARClient, asset: Asset) -> None:
        if asset.admin_access_required and asset.admin_access_granted:
            run_test_connectivity(
                soar,
                asset,
                oauth_callback_url="",
                oauth_start_url="",
            )
            return

        run_test_connectivity(
            soar,
            asset,
            oauth_callback_url=app.get_webhook_url(OAUTH_CALLBACK_ROUTE),
            oauth_start_url=app.get_webhook_url(OAUTH_START_ROUTE),
        )

    return register_actions(app)


app: App = create_msadgraph_app()


if __name__ == "__main__":
    app.cli()
