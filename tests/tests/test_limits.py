import bravado
import pytest
import bravado_core

from common import internal_api, clean_db, mongo


@pytest.mark.usefixtures("clean_db")
class TestLimits:

    def test_get_limit_default_limit(self, internal_api):
        limit = internal_api.get_max_devices_limit('foo')
        assert limit.limit == 0

    def test_put_limit(self, internal_api):
        max_devs = 100
        internal_api.put_max_devices_limit('foo', max_devs)

    def test_limit(self, internal_api):
        max_devs = 10
        internal_api.put_max_devices_limit('foo', max_devs)

        limit = internal_api.get_max_devices_limit('foo')
        assert limit.limit == max_devs

    def test_limit_differnt_tenants(self, internal_api):
        max_devs = 10
        internal_api.put_max_devices_limit('foo', max_devs)

        limit = internal_api.get_max_devices_limit('bar')
        assert limit.limit == 0

    def test_put_limit_malformed_limit(self, internal_api):
        try:
            internal_api.put_max_devices_limit('foo', '1')
        except bravado.exception.HTTPError as herr:
            assert herr.response.status_code == 400
        else:
            pytest.fail("Expected Bad Request (400)")
