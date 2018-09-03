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
import pytest

from common import clean_db, mongo, management_api, clean_migrated_db, devices, device_api, cli, \
tenant_foobar, tenant_foobar_devices, tenant_foobar_clean_migrated_db

import json
import bravado


class TestManagementPreauthorizeBase:
    def _test_ok(self, management_api, devices, **kwargs):
        aid = '1'
        device_id = '2'
        key = 'key'
        iddata = '{"foo":"bar"}'

        req = management_api.make_preauth_req(aid, device_id, iddata, key)
        _, rsp = management_api.preauthorize(req, **kwargs)
        assert rsp.status_code == 201

        devs = management_api.list_devices(**kwargs)
        assert len(devs) == 6

        found = [d for d in devs if d.id == device_id]
        assert len(found) == 1

        found = found[0]
        assert found.id == device_id
        assert found.id_data == iddata
        assert len(found.auth_sets) == 1

        auth_set = found.auth_sets[0]
        assert auth_set.id == aid
        assert auth_set.id_data == iddata
        assert auth_set.pubkey == key
        assert auth_set.status == 'preauthorized'

    def _test_conflict(self, management_api, devices, **kwargs):
        existing = devices[0][0]
        req = management_api.make_preauth_req('1', '2', existing.identity, 'key')
        try:
            _, rsp = management_api.preauthorize(req, **kwargs)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 409
        else:
            assert False, "unexpected code " + str(rsp.status_code)

        devs = management_api.list_devices(**kwargs)
        assert len(devs) == 5

class TestManagementPreauthorize(TestManagementPreauthorizeBase):
    @pytest.mark.parametrize('devices', ['5'], indirect=True)
    def test_ok(self, management_api, devices):
        self._test_ok(management_api, devices)

    @pytest.mark.parametrize('devices', ['5'], indirect=True)
    def test_conflict(self, management_api, devices):
        self._test_conflict(management_api, devices)

class TestManagementPreauthorizeMultiTenant(TestManagementPreauthorizeBase):
    @pytest.mark.parametrize('tenant_foobar_devices', ['5'], indirect=True)
    def test_ok(self, management_api, tenant_foobar_devices, tenant_foobar):
        auth = 'Bearer ' + tenant_foobar
        self._test_ok(management_api, tenant_foobar_devices, Authorization=auth)

    @pytest.mark.parametrize('tenant_foobar_devices', ['5'], indirect=True)
    def test_conflict(self, management_api, tenant_foobar_devices, tenant_foobar):
        auth = 'Bearer ' + tenant_foobar
        self._test_conflict(management_api, tenant_foobar_devices, Authorization=auth)
