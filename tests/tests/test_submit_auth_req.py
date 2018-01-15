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
from common import clean_db, mongo, \
                   management_api, device_api, internal_api, \
                   Device, DevAuthorizer, \
                   make_devices, get_keypair, \
                   device_auth_req, \
                   cli

from contextlib import contextmanager

import deviceadm
import mockserver
import pytest
import json
import inventory
import bravado

PRIVKEY, PUBKEY = get_keypair()
DEVID = 'devid-preauth'
AID = 'aid-preauth'
MAC = 'mac-preauth'
IDDATA = json.dumps({'mac': MAC})

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
    """
       Prepare a set of devices, including a 'preauthorized' one.
    """
    cnt = 5
    devs = make_devices(device_api, cnt)

    aid = AID
    device_id = DEVID
    iddata = IDDATA
    key = PUBKEY

    req = management_api.make_preauth_req(aid, device_id, iddata, key)
    _, rsp = management_api.preauthorize(req)

    assert rsp.status_code == 201

    devs = management_api.list_devices()
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


class TestDevicesSubmitAuthRequest:
    def test_ok_preauth(self, management_api, device_api, devices):
        d = Device()
        d.public_key = PUBKEY
        d.private_key = PRIVKEY
        d.mac = MAC

        da = DevAuthorizer()

        # get the authset id - need it for the url
        dev = management_api.find_device_by_identity(d.identity)
        assert dev

        with devadm_fake_status_update(AID), \
             inventory.run_fake_for_device_id(DEVID):
            rsp = device_auth_req(device_api.auth_requests_url, da, d)
            assert rsp.status_code == 200

    def test_error_preauth_limit(self, management_api, device_api, devices):
        devs = management_api.list_devices()
        assert len(devs) == 6

        limit = 3

        for i in range(limit):
            dev = devs[i]
            aid = dev.auth_sets[0].id
            with inventory.run_fake_for_device_id(dev.id):
                management_api.accept_device(dev.id, aid)

        try:
            d = Device()
            d.public_key = PUBKEY
            d.private_key = PRIVKEY
            d.mac = MAC

            da = DevAuthorizer()

            rsp = device_auth_req(device_api.auth_requests_url, da, d)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 401

