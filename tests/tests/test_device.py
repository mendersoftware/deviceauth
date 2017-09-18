import json
import os

import bravado
import pytest

from client import ManagementClient, SimpleManagementClient, BaseDevicesApiClient, ConductorClient
from common import Device, DevAuthorizer, device_auth_req, make_devid
import mockserver
import deviceadm
import inventory


class TestDevice(ManagementClient):

    devapi = BaseDevicesApiClient()

    def test_device_new(self):
        d = Device()
        da = DevAuthorizer()
        url = self.devapi.make_api_url("auth_requests")
        self.log.error("device URL: %s", url)

        with deviceadm.run_fake_for_device(d) as server:
            rsp = device_auth_req(self.devapi.make_api_url("auth_requests"),
                              da, d)
            assert rsp.status_code == 401

    def test_device_accept_nonexistent(self):
        try:
            self.accept_device('funnyid', 'funnyid')
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 404

    def test_device_reject_nonexistent(self):
        try:
            self.accept_device('funnyid', 'funnyid')
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 404

    def test_device_accept_reject(self):
        d = Device()
        da = DevAuthorizer()
        url = self.devapi.make_api_url("auth_requests")

        # poke devauth so that device appears
        with deviceadm.run_fake_for_device(d) as server:
            rsp = device_auth_req(url, da, d)
            assert rsp.status_code == 401

        # determine device ID by listing all devices and finding one with
        # matching public key
        mc = SimpleManagementClient()
        dev = mc.find_device_by_identity(d.identity)

        assert dev
        devid = dev.id

        self.log.debug('found matching device with ID: %s', dev.id)
        aid = dev.auth_sets[0].id

        try:
            with inventory.run_fake_for_device_id(devid) as server:
                self.accept_device(devid, aid)
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
            self.reject_device(devid, aid)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 204

        # device is rejected, should get unauthorized
        with deviceadm.run_fake_for_device(d) as server:
            rsp = device_auth_req(url, da, d)
            assert rsp.status_code == 401

    def test_get_devices(self):
        url = self.devapi.make_api_url("auth_requests")

        mc = SimpleManagementClient()

        devs = mc.list_devices()
        self.log.debug('devices; %s', devs)

        with deviceadm.run_fake_for_device(deviceadm.ANY_DEVICE) as server:
            devcount = 50
            for _ in range(devcount):
                dev = Device()
                da = DevAuthorizer()
                # poke devauth so that device appears
                rsp = device_auth_req(url, da, dev)
                assert rsp.status_code == 401

        # try to get a maximum number of devices
        devs = mc.list_devices(page=1, per_page=500)
        self.log.debug('got %d devices', len(devs))
        assert 500 >= len(devs) >= devcount

        # we have added at least `devcount` devices, so listing some lower
        # number of device should return exactly that number of entries
        plimit = devcount // 2
        devs = mc.list_devices(page=1, per_page=plimit)
        self.log.debug('got %d devices', len(devs))
        assert len(devs) == plimit

    def test_get_single_device(self):
        mc = SimpleManagementClient()

        try:
            mc.get_device(id='some-devid-foo')
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 404

        # setup single device and poke devauth
        dev = Device()
        da = DevAuthorizer()
        # poke devauth so that device appears
        with deviceadm.run_fake_for_device(dev) as server:
            rsp = device_auth_req(self.devapi.make_api_url("auth_requests"),
                                  da, dev)
            assert rsp.status_code == 401

        # try to find our devices in all devices listing
        mc = SimpleManagementClient()
        ourdev = mc.find_device_by_identity(dev.identity)

        authdev = mc.get_device(id=ourdev.id)
        assert authdev == ourdev

    def test_delete_device(self):
        # try delete a nonexistent device
        try:
            self.delete_device('some-devid-foo')
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 404

        # try delete an existing device, verify decommissioning workflow was started
        # setup single device and poke devauth
        dev = Device()
        da = DevAuthorizer()
        # poke devauth so that device appears
        with deviceadm.run_fake_for_device(dev) as server:
            rsp = device_auth_req(self.devapi.make_api_url("auth_requests"),
                                  da, dev)
            assert rsp.status_code == 401

        mc = SimpleManagementClient()
        ourdev = mc.find_device_by_identity(dev.identity)
        assert ourdev

        # handler for orchestrator's job endpoint
        def decommission_device_handler(request):
            dreq = json.loads(request.body.decode())
            self.log.info('decommision request %s', dreq)
            # verify that devauth tries to decommision correct device
            assert dreq.get('device_id', None) == ourdev.id
            # test is enforcing particular request ID
            assert dreq.get('request_id', None) == 'delete_device'
            # test is enforcing particular request ID
            assert dreq.get('authorization', None) == 'Bearer foobar'
            return (200, {}, '')

        handlers = [
            ('POST', '/api/workflow/decommission_device', decommission_device_handler),
        ]
        with mockserver.run_fake(get_fake_orchestrator_addr(),
                                 handlers=handlers) as server:

            rsp = self.delete_device(ourdev.id, {
                'X-MEN-RequestID':'delete_device',
                'Authorization': 'Bearer foobar',
            })
            self.log.info('decommission request finished with status: %s',
                          rsp.status_code)
            assert rsp.status_code == 204

        found = mc.find_device_by_identity(dev.identity)
        assert not found


def get_fake_orchestrator_addr():
    return os.environ.get('FAKE_ORCHESTRATOR_ADDR', '0.0.0.0:9998')

def get_fake_deviceadm_addr():
    return os.environ.get('FAKE_ADMISSION_ADDR', '0.0.0.0:9997')
