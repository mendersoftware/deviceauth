# Copyright 2018 Northern.tech AS
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
from common import clean_db, mongo, \
                   management_api, device_api, internal_api, \
                   make_fake_tenant_token, \
                   Device, DevAuthorizer, \
                   make_devices, get_keypair, \
                   device_auth_req, \
                   cli, \
                   get_fake_tenantadm_addr

from contextlib import contextmanager

import deviceadm
import mockserver
import pytest
import json
import orchestrator
import bravado

PRIVKEY, PUBKEY = get_keypair()
DEVID = 'devid-preauth'
AID = 'aid-preauth'
MAC = 'mac-preauth'
IDDATA = json.dumps({'mac': MAC}).replace(" ","")

@pytest.yield_fixture(scope='function')
def clean_migrated_db(clean_db, cli, request):
    """Clean database with migrations applied to multiple tenant DBs at once.
    TODO should replace the common.clean_migrated_db, which supports just 1 tenant at a time."""
    tenants = []
    if hasattr(request, 'param'):
        tenant_ids = request.param

    if len(tenants) > 0:
        for t in tenants:
            cli.migrate(tenant=t)
    else:
            cli.migrate()

    yield clean_db

@pytest.fixture(scope='function')
def devices(management_api, device_api, clean_migrated_db):
    do_make_devices(management_api, device_api)

TENANTS = ['tenant1', 'tenant2']
@pytest.fixture(scope="function")
@pytest.mark.parametrize('clean_migrated_db', [TENANTS], indirect=True)
def devices_mt(management_api, device_api, clean_migrated_db):
    with tenantadm_fake_tenant_verify():
        for t in TENANTS:
            token = make_fake_tenant_token(t)
            do_make_devices(management_api, device_api, token)

def do_make_devices(management_api, device_api, tenant_token=""):
    """
       Prepare a set of devices, including a 'preauthorized' one.
    """
    auth = {}
    if tenant_token != '':
        auth = management_api.make_auth(tenant_token=tenant_token)

    cnt = 5
    devs = make_devices(device_api, cnt, tenant_token)

    aid = AID
    device_id = DEVID
    iddata = IDDATA
    key = PUBKEY

    req = management_api.make_preauth_req(aid, device_id, iddata, key)
    _, rsp = management_api.preauthorize(req, **auth)

    assert rsp.status_code == 201

    devs = management_api.list_devices(**auth)
    assert len(devs) == cnt + 1

@contextmanager
def devadm_fake_status_update(authset_id):
    def fake_status_update(request, aid):
        assert aid == authset_id
        return (200, {}, '')

    handlers= [
        ('PUT', '/api/internal/v1/admission/devices/(.*)/status', fake_status_update),
    ]

    with mockserver.run_fake(deviceadm.get_fake_deviceadm_addr(),
                             handlers=handlers) as server:
        yield server

@contextmanager
def tenantadm_fake_tenant_verify():
    handlers = [
        ('POST', '/api/internal/v1/tenantadm/tenants/verify',
         lambda _: (200, {}, '')),
    ]
    with mockserver.run_fake(get_fake_tenantadm_addr(),
                            handlers=handlers) as fake:
        yield fake

class TestDevicesSubmitAuthRequestBase:
    def _do_test_ok_preauth(self, management_api, device_api, tenant_token=""):
        d = Device(IDDATA)
        d.public_key = PUBKEY
        d.private_key = PRIVKEY

        da = DevAuthorizer(tenant_token=tenant_token)

        # get the authset id - need it for the url
        auth = management_api.make_auth(tenant_token)

        dbg = management_api.list_devices()
        print(dbg)

        dev = management_api.find_device_by_identity(d.identity, **auth)
        assert dev

        with devadm_fake_status_update(AID), \
             orchestrator.run_fake_for_device_id(DEVID):
            rsp = device_auth_req(device_api.auth_requests_url, da, d)
            assert rsp.status_code == 200

        dev = management_api.get_device(id=dev.id, **auth)
        assert dev.auth_sets[0].status == 'accepted'


    def _do_test_error_preauth_limit(self, management_api, device_api, tenant_token=""):
        auth = management_api.make_auth(tenant_token)
        devs = management_api.list_devices(**auth)
        assert len(devs) == 6

        limit = 3

        for i in range(limit):
            dev = devs[i]
            aid = dev.auth_sets[0].id
            with orchestrator.run_fake_for_device_id(dev.id):
                management_api.accept_device(dev.id, aid, **auth)

        try:
            d = Device(IDDATA)
            d.public_key = PUBKEY
            d.private_key = PRIVKEY

            da = DevAuthorizer(tenant_token)

            rsp = device_auth_req(device_api.auth_requests_url, da, d)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 401

        dev = management_api.find_device_by_identity(d.identity, **auth)
        assert dev.auth_sets[0].status == 'preauthorized'

class TestDevicesSubmitAuthRequest(TestDevicesSubmitAuthRequestBase):
    def test_ok_preauth(self, management_api, device_api, devices):
        self._do_test_ok_preauth(management_api, device_api)

    def test_error_preauth_limit(self, management_api, device_api, devices):
        self._do_test_error_preauth_limit(management_api, device_api)


# TODO rename to SubmitAuthRequestMultiTenant when naming conventions are fixed
class TestMultiTenantDevicesSubmitAuthRequest(TestDevicesSubmitAuthRequestBase):
    @pytest.mark.parametrize("tenant_id", TENANTS)
    def test_ok_preauth(self, management_api, device_api, devices_mt, tenant_id):
        with tenantadm_fake_tenant_verify():
            token = make_fake_tenant_token(tenant_id)
            self._do_test_ok_preauth(management_api, device_api, token)

    @pytest.mark.parametrize("tenant_id", TENANTS)
    def test_error_preauth_limit(self, management_api, device_api, devices_mt, tenant_id):
        token = make_fake_tenant_token(tenant_id)
        self._do_test_error_preauth_limit(management_api, device_api, token)
