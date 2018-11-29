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
import pytest

from common import clean_db, mongo, internal_api

import bravado

class TestInternalApi:

    def test_create_tenant_ok(self, internal_api, clean_db):
        _, r = internal_api.create_tenant('foobar')
        assert r.status_code == 201

        assert 'deviceauth-foobar' in clean_db.database_names()
        assert 'migration_info' in clean_db['deviceauth-foobar'].collection_names()

    def test_create_tenant_twice(self, internal_api, clean_db):
        _, r = internal_api.create_tenant('foobar')
        assert r.status_code == 201

        # creating once more should not fail
        _, r = internal_api.create_tenant('foobar')
        assert r.status_code == 201

    def test_create_tenant_empty(self, internal_api):
        try:
            _, r = internal_api.create_tenant('')
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400
