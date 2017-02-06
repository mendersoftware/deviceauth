import bravado
import pytest

from client import Client
from common import Device, DevAuthorizer, device_auth_req, make_devid


class TestDevice(Client):

    def test_device_new(self):
        d = Device()
        da = DevAuthorizer()
        url = self.make_api_url("auth_requests")
        self.log.error("device URL: %s", url)
        rsp = device_auth_req(self.make_api_url("auth_requests"),
                              da, d)
        assert rsp.status_code == 401

    def test_device_accept_nonexistent(self):
        try:
            self.accept_device('funnyid')
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 404

    def test_device_reject_nonexistent(self):
        try:
            self.accept_device('funnyid')
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 404

    def test_device_accept_reject(self):
        d = Device()
        da = DevAuthorizer()
        url = self.make_api_url("auth_requests")

        # generate device ID from its identity
        devid = make_devid(d.identity)

        try:
            self.accept_device(devid)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 404

        # poke devauth so that device appears
        rsp = device_auth_req(url, da, d)
        assert rsp.status_code == 401

        try:
            self.accept_device(devid)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 204

        # device is accepted, we should get a token now
        rsp = device_auth_req(url, da, d)
        assert rsp.status_code == 200

        da.parse_rsp_payload(d, rsp.text)

        assert len(d.token) > 0
        self.log.info("device token: %s", d.token)

        # reject it now
        try:
            self.reject_device(devid)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 204

        # device is rejected, should get unauthorized
        rsp = device_auth_req(url, da, d)
        assert rsp.status_code == 401
