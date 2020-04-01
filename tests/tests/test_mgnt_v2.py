from client import ManagementClient
import bravado
import json
import pytest
import uuid

from common import (
    Device,
    DevAuthorizer,
    device_auth_req,
    make_devices,
    devices,
    clean_migrated_db,
    clean_db,
    mongo,
    cli,
    management_api,
    internal_api,
    device_api,
    tenant_foobar,
    tenant_foobar_devices,
    tenant_foobar_clean_migrated_db,
    get_keypair,
)

from tenantadm import fake_tenantadm
import orchestrator


class TestDeleteDevice(ManagementClient):
    def test_delete_device(self, management_api, devices):
        # try delete an existing device, verify decommissioning workflow was started
        # setup single device and poke devauth
        dev, _ = devices[0]
        ourdev = management_api.get_single_device()
        assert ourdev

        with orchestrator.run_fake_for_device_id(ourdev.id) as server:
            rsp = management_api.delete_device(
                ourdev.id,
                {"X-MEN-RequestID": "delete_device", "Authorization": "Bearer foobar",},
            )
        print("decommission request finished with status:", rsp.status_code)
        assert rsp.status_code == 204

        found = None
        status_code = None
        try:
            found = management_api.get_device(id=ourdev.id)
        except bravado.exception.HTTPError as e:
            status_code = e.response.status_code

        assert status_code == 404
        assert not found

    def test_delete_device_ochestrator_failure(self, management_api, devices):
        # try delete an existing device, verify it is failing when orchestrator
        # is failing
        dev, _ = devices[0]
        ourdev = management_api.get_single_device()
        assert ourdev

        with orchestrator.run_fake_for_device_id(ourdev.id, 500) as server:
            rsp = management_api.delete_device(
                ourdev.id,
                {"X-MEN-RequestID": "delete_device", "Authorization": "Bearer foobar",},
            )
        print("decommission request finished with status:", rsp.status_code)
        assert rsp.status_code == 500

    def test_delete_device_nonexistent(self, management_api):
        # try delete a nonexistent device
        rsp = management_api.delete_device(str(uuid.uuid4()))
        assert rsp.status_code == 404

    def test_device_accept_reject_cycle(self, devices, device_api, management_api):
        d, da = devices[0]
        url = device_api.auth_requests_url

        dev = management_api.get_single_device()

        assert dev
        devid = dev.id

        print("found device with ID:", dev.id)
        aid = dev.auth_sets[0].id

        with orchestrator.run_fake_for_device_id(devid) as server:
            _, rsp = management_api.accept_device(devid, aid)
        assert rsp.status_code == 204

        # device is accepted, we should get a token now
        rsp = device_auth_req(url, da, d)
        assert rsp.status_code == 200

        da.parse_rsp_payload(d, rsp.text)

        assert len(d.token) > 0

        # reject it now
        _, rsp = management_api.reject_device(devid, aid)
        print("RSP:", rsp)
        assert rsp.status_code == 204

        # device is rejected, should get unauthorized
        rsp = device_auth_req(url, da, d)
        assert rsp.status_code == 401

    def test_device_accept_orchestrator_failure(
        self, devices, device_api, management_api
    ):
        d, da = devices[0]
        url = device_api.auth_requests_url

        dev = management_api.get_single_device()

        assert dev
        devid = dev.id

        print("found device with ID:", dev.id)
        aid = dev.auth_sets[0].id

        status = None
        try:
            with orchestrator.run_fake_for_device_id(devid, 500) as server:
                management_api.accept_device(devid, aid)
        except bravado.exception.HTTPError as e:
            status = e.response.status_code
        assert status == 500
