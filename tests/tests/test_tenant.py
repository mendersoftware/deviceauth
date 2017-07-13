# Copyright 2017 Northern.tech AS
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        https://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
import os
import json

from base64 import urlsafe_b64encode

from client import BaseDevicesApiClient, ManagementClient, \
    SimpleManagementClient
from common import Device, DevAuthorizer, device_auth_req

import mockserver
import deviceadm


def get_fake_tenantadm_addr():
    return os.environ.get('FAKE_TENANTADM_ADDR', '0.0.0.0:9999')


class TestMultiTenant(ManagementClient):

    devapi = BaseDevicesApiClient()

    def test_auth_req_no_tenantadm(self):
        d = Device()
        da = DevAuthorizer(tenant_token=make_fake_tenant_token(tenant='foobar'))
        url = self.devapi.make_api_url("/auth_requests")

        # poke devauth so that device appears, but since tenantadm service is
        # unavailable we'll get 500 in return
        rsp = device_auth_req(url, da, d)
        assert rsp.status_code == 500

        # request failed, so device should not even be listed as known
        self.verify_tenant_dev_present(d.identity, False, tenant='foobar')

    def test_auth_req_fake_tenantadm_invalid_tenant_token(self):
        d = Device()
        da = DevAuthorizer(tenant_token="bad-token")
        url = self.devapi.make_api_url("/auth_requests")


        handlers = [
            ('POST', '/api/internal/v1/tenantadm/tenants/verify',
             lambda _: (401, {}, '')),
        ]
        with mockserver.run_fake(get_fake_tenantadm_addr(),
                                handlers=handlers) as fake:
            rsp = device_auth_req(url, da, d)
            assert rsp.status_code == 401

        # request failed, so device should not even be listed as known
        self.verify_tenant_dev_present(d.identity, False, tenant='')

    def test_auth_req_fake_tenantadm_valid_tenant_token(self):
        d = Device()
        da = DevAuthorizer(tenant_token=make_fake_tenant_token(tenant='foobar'))
        url = self.devapi.make_api_url("/auth_requests")


        handlers = [
            ('POST', '/api/internal/v1/tenantadm/tenants/verify',
             lambda _: (200, {}, {
                 'id': '507f191e810c19729de860ea',
                 'name': 'Acme',
             })),
        ]
        with mockserver.run_fake(get_fake_tenantadm_addr(),
                                handlers=handlers) as fake:
            with deviceadm.run_fake_for_device(d) as fakedevadm:
                rsp = device_auth_req(url, da, d)
                assert rsp.status_code == 401

        # device should be appear in devices listing
        self.verify_tenant_dev_present(d.identity, tenant='foobar')

    def test_auth_req_fake_tenantadm_no_tenant_token(self):
        d = Device()
        # use empty tenant token
        da = DevAuthorizer(tenant_token="")
        url = self.devapi.make_api_url("/auth_requests")

        rsp = device_auth_req(url, da, d)
        assert rsp.status_code == 401

        self.verify_tenant_dev_present(d.identity, False, tenant='')

    def verify_tenant_dev_present(self, identity, present=True, tenant='foobar'):
        """Assert that device with `identity` is present (or not)"""

        # request was rejected, device should not be listed
        mc = SimpleManagementClient()

        if tenant:
            token = make_fake_tenant_token(tenant=tenant)
            dev = mc.find_device_by_identity(identity,
                                             Authorization='Bearer '+token)
        else:
            # use default auth
            dev = mc.find_device_by_identity(identity)

        if present:
            assert dev
        else:
            assert not dev


def make_fake_tenant_token(tenant='foobar', subject='someid', override={}):
    """make_fake_tenant_token will generate a JWT-like tenant token which looks
    like this: 'fake.<base64 JSON encoded claims>.fake-sig'. The claims are:
    issuer (Mender), subject (someid), mender.tenant (foobar). Pass `override`
    to override or add more claims or set tenant/subject to override only
    tenant and subject claims.

    """
    claims = {
        'iss': 'Mender',
        'sub': subject,
        'mender.tenant': tenant,
    }
    claims.update(override)

    # serialize claims to JSON, encode as base64 and strip padding to be
    # compatible with JWT
    enc = urlsafe_b64encode(json.dumps(claims).encode()). \
          decode().strip('==')

    return 'fake.' + enc + '.fake-sig'
