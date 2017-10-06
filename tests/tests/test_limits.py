import json
import os

import bravado
import pytest
import bravado_core

from common import internal, clean_db, mongo

from client import InternalClient, SimpleInternalClient
import mockserver

@pytest.mark.usefixtures("clean_db")
class TestLimits:

    def test_get_limit_default_limit(self, internal):
        limit = internal.get_max_devices_limit('foo')
        assert limit.limit == 0

    def test_put_limit(self, internal):
        max_devs = 100
        _, http_rsp = internal.put_max_devices_limit('foo', max_devs).result()
        assert isinstance(http_rsp, bravado_core.response.IncomingResponse)
        assert http_rsp.status_code == 204

    def test_limit(self, internal):
        max_devs = 10
        _, http_rsp = internal.put_max_devices_limit('foo', max_devs).result()
        assert isinstance(http_rsp, bravado_core.response.IncomingResponse)
        assert http_rsp.status_code == 204

        limit = internal.get_max_devices_limit('foo')
        assert limit.limit == max_devs

    def test_limit_differnt_tenants(self, internal):
        max_devs = 10
        _, http_rsp = internal.put_max_devices_limit('foo', max_devs).result()
        assert isinstance(http_rsp, bravado_core.response.IncomingResponse)
        assert http_rsp.status_code == 204

        limit = internal.get_max_devices_limit('bar')
        assert limit.limit == 0

    def test_put_limit_malformed_limit(self, internal):
        try:
            _, http_rsp = internal.put_max_devices_limit('foo', '1').result()
        except bravado.exception.HTTPError as herr:
            assert herr.response.status_code == 400
        else:
            assert isinstance(http_rsp, bravado_core.response.IncomingResponse)
            pytest.fail("Expected Bad Request (400), got: %d" %(http_rsp.status_code,))
