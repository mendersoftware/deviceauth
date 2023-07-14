# Copyright 2023 Northern.tech AS
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
import bravado
import pytest
import requests
import time
import json
import base64

from contextlib import contextmanager

from common import (
    Device,
    DevAuthorizer,
    device_auth_req,
    explode_jwt,
    clean_migrated_db,
    clean_db,
    mongo,
    cli,
    management_api,
    internal_api,
    device_api,
    get_fake_tenantadm_addr,
    make_fake_tenant_token,
)

from cryptutil import compare_keys

import orchestrator
import mockserver


@contextmanager
def mock_tenantadm_auth(tenant_addons):
    def tenantadm_handler(req):
        auth = req.headers["Authorization"]
        # jwt = <header (base64)>.<claims (base64)>.<signature (base64)>
        jwt_b64 = auth.split(".")
        if len(jwt_b64) > 1:
            print(jwt_b64)
            # Convert base64 from url- to std-encoding and append padding
            claims_b64 = jwt_b64[1].replace("+", "-").replace("?", "_")
            # Add padding
            claims_b64 += "=" * (-len(claims_b64) % 4)
            # Decode claims
            claims = base64.b64decode(claims_b64)
            d = json.loads(claims)
            tenant_id = d["mender.tenant"]
            return (
                200,
                {},
                {
                    "id": tenant_id,
                    "name": "Acme",
                    "addons": [
                        {"name": addon, "enabled": True} for addon in tenant_addons
                    ],
                },
            )
        else:
            return (500, {}, {})

    with mockserver.run_fake(
        get_fake_tenantadm_addr(),
        handlers=[
            ("POST", "/api/internal/v1/tenantadm/tenants/verify", tenantadm_handler)
        ],
    ) as srv:
        yield srv


def request_token(device, dev_auth, url, tenant_addons=[]):
    with mock_tenantadm_auth(tenant_addons):
        rsp = device_auth_req(url, dev_auth, device)
        assert rsp.status_code == 200

    dev_auth.parse_rsp_payload(device, rsp.text)
    return device.token


def verify_token(token, status_code, url):
    auth_hdr = "Bearer {}".format(token)
    rsp = requests.post(url, data="", headers={"Authorization": auth_hdr})
    assert rsp.status_code == status_code


@pytest.fixture(scope="function")
def accepted_tenants_devices(
    device_api, management_api, clean_migrated_db, cli, request
):
    """Fixture that sets up an accepted devices for tenants. The fixture can
    be parametrized with a tenants, number of devices and number of authentication sets.
    Yields a dict:
    [tenant ID: [device object, ...], ]"""

    requested = request.param

    tenants_devices = dict()
    url = device_api.auth_requests_url

    for tenant, dev_count, auth_count in requested:
        tenant_devices = []
        cli.migrate(tenant=tenant)
        tenant_token = make_fake_tenant_token(tenant)
        for _ in range(int(dev_count)):
            d = Device()
            for i in range(int(auth_count)):
                d.rotate_key()
                da = DevAuthorizer(tenant_token=tenant_token)

                # poke devauth so that device appears
                handlers = [
                    (
                        "POST",
                        "/api/internal/v1/tenantadm/tenants/verify",
                        lambda _: (
                            200,
                            {},
                            {
                                "id": tenant,
                                "name": "Acme",
                            },
                        ),
                    ),
                ]

                try:
                    with orchestrator.run_fake_for_device_id(1) as server:
                        with mockserver.run_fake(
                            get_fake_tenantadm_addr(), handlers=handlers
                        ) as fake:
                            rsp = device_auth_req(url, da, d)
                            assert rsp.status_code == 401
                except bravado.exception.HTTPError as e:
                    assert e.response.status_code == 204

                # try to find our devices in all devices listing
                dev = management_api.find_device_by_identity(
                    d.identity,
                    Authorization="Bearer " + tenant_token,
                )
                devid = dev.id
                for a in dev.auth_sets:
                    if compare_keys(a.pubkey, d.public_key):
                        aid = a.id
                        break

                try:
                    with orchestrator.run_fake_for_device_id(devid) as server:
                        management_api.accept_device(
                            devid, aid, Authorization="Bearer " + tenant_token
                        )
                        token = request_token(d, da, device_api.auth_requests_url)
                        assert len(token) > 0
                except bravado.exception.HTTPError as e:
                    assert e.response.status_code == 204

            assert dev
            tenant_devices.append(d)

        tenants_devices[tenant] = tenant_devices
    yield tenants_devices


class TestEnterpriseDeleteTokens:
    @pytest.mark.parametrize(
        "accepted_tenants_devices", [[("foo", 2, 2), ("bar", 1, 3)]], indirect=True
    )
    def test_delete_tokens_by_device_ok(
        self, accepted_tenants_devices, internal_api, management_api, device_api
    ):
        td = accepted_tenants_devices
        try:
            tenant_foo_token = make_fake_tenant_token("foo")
            da_foo = DevAuthorizer(tenant_token=tenant_foo_token)
            d1_foo = td["foo"][0]
            with orchestrator.run_fake_for_device_id(1) as server:
                token1 = request_token(d1_foo, da_foo, device_api.auth_requests_url)
                assert len(token1) > 0
            d2_foo = td["foo"][1]
            with orchestrator.run_fake_for_device_id(2) as server:
                token2 = request_token(d2_foo, da_foo, device_api.auth_requests_url)
                assert len(token2) > 0

            tenant_bar_token = make_fake_tenant_token("bar")
            da_bar = DevAuthorizer(tenant_token=tenant_bar_token)
            d1_bar = td["bar"][0]
            with orchestrator.run_fake_for_device_id(1) as server:
                token3 = request_token(d1_bar, da_bar, device_api.auth_requests_url)
                assert len(token2) > 0

            verify_url = internal_api.make_api_url("/tokens/verify")
            verify_token(token1, 200, verify_url)
            verify_token(token2, 200, verify_url)
            verify_token(token3, 200, verify_url)

            dev1 = management_api.find_device_by_identity(
                d1_foo.identity, Authorization="Bearer " + tenant_foo_token
            )
            payload = {"device_id": dev1.id, "tenant_id": "foo"}
            rsp = requests.delete(internal_api.make_api_url("/tokens"), params=payload)
            assert rsp.status_code == 204

            verify_token(token1, 401, verify_url)
            verify_token(token2, 200, verify_url)
            verify_token(token3, 200, verify_url)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 204

    @pytest.mark.parametrize(
        "accepted_tenants_devices", [[("foo", 2, 2), ("bar", 1, 3)]], indirect=True
    )
    def test_delete_tokens_by_non_existent_device_ok(
        self, accepted_tenants_devices, internal_api, management_api, device_api
    ):
        try:
            td = accepted_tenants_devices

            tenant_foo_token = make_fake_tenant_token("foo")
            da_foo = DevAuthorizer(tenant_token=tenant_foo_token)
            d1_foo = td["foo"][0]
            with orchestrator.run_fake_for_device_id(1) as server:
                token1 = request_token(d1_foo, da_foo, device_api.auth_requests_url)
                assert len(token1) > 0
            d2_foo = td["foo"][1]
            with orchestrator.run_fake_for_device_id(2) as server:
                token2 = request_token(d2_foo, da_foo, device_api.auth_requests_url)
                assert len(token2) > 0

            tenant_bar_token = make_fake_tenant_token("bar")
            da_bar = DevAuthorizer(tenant_token=tenant_bar_token)
            d1_bar = td["bar"][0]
            with orchestrator.run_fake_for_device_id(1) as server:
                token3 = request_token(d1_bar, da_bar, device_api.auth_requests_url)
                assert len(token2) > 0

            verify_url = internal_api.make_api_url("/tokens/verify")
            verify_token(token1, 200, verify_url)
            verify_token(token2, 200, verify_url)
            verify_token(token3, 200, verify_url)

            payload = {"device_id": "foo", "tenant_id": "foo"}
            rsp = requests.delete(internal_api.make_api_url("/tokens"), params=payload)
            assert rsp.status_code == 204

            verify_token(token1, 200, verify_url)
            verify_token(token2, 200, verify_url)
            verify_token(token3, 200, verify_url)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 204

    @pytest.mark.parametrize(
        "accepted_tenants_devices", [[("foo", 2, 2), ("bar", 1, 3)]], indirect=True
    )
    def test_delete_tokens_by_tenant_ok(
        self, accepted_tenants_devices, internal_api, management_api, device_api
    ):
        try:
            td = accepted_tenants_devices

            tenant_foo_token = make_fake_tenant_token("foo")
            da_foo = DevAuthorizer(tenant_token=tenant_foo_token)
            d1_foo = td["foo"][0]
            with orchestrator.run_fake_for_device_id(1) as server:
                token1 = request_token(d1_foo, da_foo, device_api.auth_requests_url)
                assert len(token1) > 0
            d2_foo = td["foo"][1]
            with orchestrator.run_fake_for_device_id(2) as server:
                token2 = request_token(d2_foo, da_foo, device_api.auth_requests_url)
                assert len(token2) > 0

            tenant_bar_token = make_fake_tenant_token("bar")
            da_bar = DevAuthorizer(tenant_token=tenant_bar_token)
            d1_bar = td["bar"][0]
            with orchestrator.run_fake_for_device_id(1) as server:
                token3 = request_token(d1_bar, da_bar, device_api.auth_requests_url)
                assert len(token2) > 0

            verify_url = internal_api.make_api_url("/tokens/verify")
            verify_token(token1, 200, verify_url)
            verify_token(token2, 200, verify_url)
            verify_token(token3, 200, verify_url)

            dev1 = management_api.find_device_by_identity(
                d1_foo.identity, Authorization="Bearer " + tenant_foo_token
            )
            payload = {"tenant_id": "foo"}
            rsp = requests.delete(internal_api.make_api_url("/tokens"), params=payload)
            assert rsp.status_code == 204

            verify_token(token1, 401, verify_url)
            verify_token(token2, 401, verify_url)
            verify_token(token3, 200, verify_url)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 204

    @pytest.mark.parametrize(
        "accepted_tenants_devices", [[("foo", 2, 2), ("bar", 1, 3)]], indirect=True
    )
    def test_delete_tokens_by_non_existent_tenant_ok(
        self, accepted_tenants_devices, internal_api, management_api, device_api
    ):
        try:
            td = accepted_tenants_devices

            tenant_foo_token = make_fake_tenant_token("foo")
            da_foo = DevAuthorizer(tenant_token=tenant_foo_token)
            d1_foo = td["foo"][0]
            with orchestrator.run_fake_for_device_id(1) as server:
                token1 = request_token(d1_foo, da_foo, device_api.auth_requests_url)
                assert len(token1) > 0
            d2_foo = td["foo"][1]
            with orchestrator.run_fake_for_device_id(2) as server:
                token2 = request_token(d2_foo, da_foo, device_api.auth_requests_url)
                assert len(token2) > 0

            tenant_bar_token = make_fake_tenant_token("bar")
            da_bar = DevAuthorizer(tenant_token=tenant_bar_token)
            d1_bar = td["bar"][0]
            with orchestrator.run_fake_for_device_id(1) as server:
                token3 = request_token(d1_bar, da_bar, device_api.auth_requests_url)
                assert len(token2) > 0

            verify_url = internal_api.make_api_url("/tokens/verify")
            verify_token(token1, 200, verify_url)
            verify_token(token2, 200, verify_url)
            verify_token(token3, 200, verify_url)

            dev1 = management_api.find_device_by_identity(
                d1_foo.identity, Authorization="Bearer " + tenant_foo_token
            )
            payload = {"tenant_id": "baz"}
            rsp = requests.delete(internal_api.make_api_url("/tokens"), params=payload)
            assert rsp.status_code == 204

            verify_token(token1, 200, verify_url)
            verify_token(token2, 200, verify_url)
            verify_token(token3, 200, verify_url)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 204

    def test_delete_tokens_no_tenant_id_bad_request(self, internal_api):
        rsp = requests.delete(internal_api.make_api_url("/tokens"))
        assert rsp.status_code == 400

    def test_delete_tokens_by_device_no_tenant_id_bad_request(self, internal_api):
        payload = {"device_id": "foo"}
        rsp = requests.delete(internal_api.make_api_url("/tokens"), params=payload)
        assert rsp.status_code == 400
