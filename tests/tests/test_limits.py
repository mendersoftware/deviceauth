import json
import os

import bravado
import pytest
import bravado_core

from client import InternalClient, SimpleInternalClient
import mockserver

class TestLimits(InternalClient):

    def test_get_limit_default_limit(self):
        limit = self.get_max_devices_limit('foo')
        assert limit.limit == 0

    def test_put_limit(self):
        max_devs = 100
        _, http_rsp = self.put_max_devices_limit('foo', max_devs).result()
        assert isinstance(http_rsp, bravado_core.response.IncomingResponse)
        assert http_rsp.status_code == 204

    def test_limit(self):
        max_devs = 10
        _, http_rsp = self.put_max_devices_limit('foo', max_devs).result()
        assert isinstance(http_rsp, bravado_core.response.IncomingResponse)
        assert http_rsp.status_code == 204

        limit = self.get_max_devices_limit('foo')
        assert limit.limit == max_devs

    def test_limit_differnt_tenants(self):
        max_devs = 10
        _, http_rsp = self.put_max_devices_limit('foo', max_devs).result()
        assert isinstance(http_rsp, bravado_core.response.IncomingResponse)
        assert http_rsp.status_code == 204

        limit = self.get_max_devices_limit('bar')
        assert limit.limit == 0

    def test_put_limit_malformed_limit(self):
        try:
            _, http_rsp = self.put_max_devices_limit('foo', '1').result()
        except bravado.exception.HTTPError as herr:
            assert herr.response.status_code == 400
        else:
            assert isinstance(http_rsp, bravado_core.response.IncomingResponse)
            pytest.fail("Expected Bad Request (400), got: %d" %(http_rsp.status_code,))
