from client import AdmissionClient
import bravado
import json
import pytest
from common import Device, DevAuthorizer, \
    device_auth_req, make_devices, devices, \
    clean_migrated_db, clean_db, mongo, cli, \
    management_api, admission_api, internal_api, device_api, \
    tenant_foobar, tenant_foobar_devices, tenant_foobar_clean_migrated_db,\
    get_keypair

from tenantadm import fake_tenantadm
import orchestrator

class TestAdmission(AdmissionClient):
    def test_get_non_existant_device(self, devices):
        """
            Test getting a specific device results in 404
        """
        try:
            self.client.devices.get_devices_id(id="0c396e0032f2b4367d6abe709c889ced728df1f97eb0c368a41465aa24a89454", _request_options={"headers": self.uauth}).result()
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 404
        else:
            pytest.fail("Error code 404 not returned")

    @pytest.mark.parametrize('devices', ['5'], indirect=True)
    def test_get_device(self, management_api, devices):
        dev, _ = devices[0]
        ourdev = management_api.find_device_by_identity(dev.identity)
        authset, _ = self.client.devices.get_devices_id(id=ourdev.auth_sets[0].id, _request_options={"headers": self.uauth}).result()
        assert authset.id == ourdev.auth_sets[0].id

    @pytest.mark.parametrize('devices', ['5'], indirect=True)
    def test_delete_device(self, management_api, devices):
        dev, _ = devices[0]
        ourdev = management_api.find_device_by_identity(dev.identity)
        rsp = self.delete_device_mgmt(ourdev.auth_sets[0].id)
        assert rsp.status_code == 204

        #try to get deleted auth set
        try:
            self.client.devices.get_devices_id(id=ourdev.auth_sets[0].id, _request_options={"headers": self.uauth}).result()
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 404
        else:
            pytest.fail("Error code 404 not returned")

    @pytest.mark.parametrize('devices', ['5'], indirect=True)
    def test_delete_non_existent_device(self, management_api, devices):
        rsp = self.delete_device_mgmt("nonexistent")
        assert rsp.status_code == 204

    @pytest.mark.parametrize('devices', ['5'], indirect=True)
    def test_get_devices(self, admission_api, devices):
        expected = 5
        devs = admission_api.get_devices()

        assert len(devs) == expected

    @pytest.mark.parametrize('devices', ['5'], indirect=True)
    def get_status_of_non_existent_device(self, devices):
        try:
            self.client.devices.get_devices_id_status(id="nonexistent", _request_options={"headers": self.uauth})
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 404
        else:
            pytest.fail("Error code 404 not returned")

class TestAdmissionPostDevicesBase:
    def _test_ok(self, admission_api, clean_migrated_db, auth=None):
        identity = json.dumps({"mac": "new-preauth-mac"})

        _, pub =  get_keypair()
        admission_api.preauthorize(identity, pub, auth)

        asets = admission_api.get_devices(auth=auth)
        assert len(asets) == 1
        assert asets[0].status == 'preauthorized'

    def _test_bad_req_iddata(self, admission_api, clean_migrated_db, auth=None):
        _, pub =  get_keypair()
        try:
            admission_api.preauthorize('not-valid-json', pub, auth)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400

        asets = admission_api.get_devices(auth=auth)
        assert len(asets) == 0

    def _test_conflict(self, admission_api, devices, auth=None):
        _, pub =  get_keypair()
        for dev, _ in devices:
            try:
                identity = dev.identity
                admission_api.preauthorize(identity, pub, auth)
            except bravado.exception.HTTPError as e:
                assert e.response.status_code == 409

        asets = admission_api.get_devices(auth=auth)
        assert len(asets) == len(devices)

    def _test_bad_key(self, admission_api, clean_migrated_db, auth=None):
        identity = json.dumps({"mac": "new-preauth-mac"})

        try:
            admission_api.preauthorize(identity, 'invalid', auth)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400
            assert e.response.swagger_result.error == 'cannot decode public key'

        asets = admission_api.get_devices(auth=auth)
        assert len(asets) == 0

class TestAdmissionPostDevices(TestAdmissionPostDevicesBase):
    def test_ok(self, admission_api, clean_migrated_db):
        self._test_ok(admission_api, clean_migrated_db)

    def test_bad_req_iddata(self, admission_api, clean_migrated_db):
        self._test_bad_req_iddata(admission_api, clean_migrated_db)

    @pytest.mark.parametrize('devices', ['5'], indirect=True)
    def test_conflict(self, admission_api, devices):
        self._test_conflict(admission_api, devices)

    def test_bad_key(self, admission_api, clean_migrated_db):
        self._test_bad_key(admission_api, clean_migrated_db)

class TestAdmissionChangeStatus(AdmissionClient):

    def change_status(self, id, device_id, expected_initial, expected_final, expected_error_code=None, auth=None):
        if auth is None:
            auth = self.uauth
        Status = self.client.get_model('Status')
        s = Status(status=expected_final)
        try:
            actual_initial = self.client.devices.get_devices_id(id=id, _request_options={"headers": auth}).result()[0].status
            assert actual_initial == expected_initial
            with orchestrator.run_fake_for_device_id(device_id) as server:
                self.client.devices.put_devices_id_status(id=id, status=s, _request_options={"headers": auth}).result()
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == expected_error_code
            return
        else:
            if expected_error_code is not None:
                pytest.fail("Expected an exception, but didnt get any!")
                return

        assert self.client.devices.get_devices_id_status(id=id, _request_options={"headers": auth}).result()[0].status == expected_final
        #assert self.client.devices.get_devices_id(id=id, _request_options={"headers": auth}).result()[0].status == expected_final

    def do_test_change_status(self, auth):
        r, h = self.client.devices.get_devices(_request_options={"headers": auth}).result()

        firstDevice = r[0]
        secondDevice = r[1]
        thirdDevice = r[2]

        # go from pending => accepted
        self.change_status(firstDevice.id, firstDevice.device_id, expected_initial="pending", expected_final="accepted", auth=auth)

        # go from pending => rejected
        self.change_status(secondDevice.id, secondDevice.device_id, expected_initial="pending", expected_final="rejected", auth=auth)

        # go from rejected => accepted
        self.change_status(secondDevice.id, secondDevice.device_id, expected_initial="rejected", expected_final="accepted", auth=auth)

        # go from accepted => rejected
        self.change_status(firstDevice.id, firstDevice.device_id, expected_initial="accepted", expected_final="rejected", auth=auth)

        # go from pending => rejected => accepted
        self.change_status(thirdDevice.id, thirdDevice.device_id, expected_initial="pending", expected_final="rejected", auth=auth)
        self.change_status(thirdDevice.id, thirdDevice.device_id, expected_initial="rejected", expected_final="accepted", auth=auth)

        # go from rejected => pending
        self.change_status(firstDevice.id, firstDevice.device_id, expected_initial="rejected", expected_final="pending", expected_error_code=400, auth=auth)

        # go from accepted => pending
        self.change_status(secondDevice.id, secondDevice.device_id, expected_initial="accepted", expected_final="pending", expected_error_code=400, auth=auth)

        # go from accepted => blah
        self.change_status(secondDevice.id, secondDevice.device_id, expected_initial="accepted", expected_final="blah", expected_error_code=400, auth=auth)

        # device not found
        self.change_status(secondDevice.id+'1', secondDevice.device_id, expected_initial="accepted", expected_final="pending", expected_error_code=404, auth=auth)

    @pytest.mark.parametrize('devices', ['5'], indirect=True)
    def test_change_status(self, devices):
        """
            Test every possible status transition works, invalid and non-specified transitions fail
        """
        self.do_test_change_status(auth=self.uauth)


# Mulit tenant tests

class TestAdmissionMultiTenant(AdmissionClient):
    @pytest.mark.parametrize('tenant_foobar_devices', ['5'], indirect=True)
    def test_get_devices(self, admission_api, tenant_foobar_devices, tenant_foobar):
        expected = 5
        auth = {"Authorization": "Bearer " + tenant_foobar}
        devs = admission_api.get_devices(auth=auth)

        assert len(devs) == expected

    @pytest.mark.parametrize('tenant_foobar_devices', ['5'], indirect=True)
    def test_delete_device(self, management_api, tenant_foobar_devices, tenant_foobar):
        auth = {"Authorization": "Bearer " + tenant_foobar}
        dev, _ = tenant_foobar_devices[0]
        ourdev = management_api.find_device_by_identity(dev.identity, Authorization="Bearer " + tenant_foobar)
        rsp = self.delete_device_mgmt(ourdev.auth_sets[0].id, auth=auth)
        assert rsp.status_code == 204

        #try to get deleted auth set
        try:
            self.client.devices.get_devices_id(id=ourdev.auth_sets[0].id, _request_options={"headers": auth}).result()
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 404
        else:
            pytest.fail("Error code 404 not returned")

class TestAdmissionMultiTenantChangeStatus(TestAdmissionChangeStatus):
    @pytest.mark.parametrize('tenant_foobar_devices', ['5'], indirect=True)
    def test_change_status(self, tenant_foobar_devices, tenant_foobar):
        """
            Test every possible status transition works, invalid and non-specified transitions fail
        """
        #auth = self.make_user_auth("user", tenant_id)
        auth = {"Authorization": "Bearer " + tenant_foobar}
        with fake_tenantadm():
            self.do_test_change_status(auth)

class TestAdmissionPostDevicesMultitenant(TestAdmissionPostDevicesBase):
    def test_ok(self, admission_api, tenant_foobar_clean_migrated_db, tenant_foobar):
        auth = {"Authorization": "Bearer " + tenant_foobar}
        self._test_ok(admission_api, tenant_foobar_clean_migrated_db, auth)

    def test_bad_req_iddata(self, admission_api, tenant_foobar_clean_migrated_db, tenant_foobar):
        auth = {"Authorization": "Bearer " + tenant_foobar}
        self._test_bad_req_iddata(admission_api, tenant_foobar_clean_migrated_db, auth)

    def test_bad_key(self, admission_api, tenant_foobar_clean_migrated_db, tenant_foobar):
        auth = {"Authorization": "Bearer " + tenant_foobar}
        self._test_bad_key(admission_api, tenant_foobar_clean_migrated_db, auth)

    @pytest.mark.parametrize('tenant_foobar_devices', ['5'], indirect=True)
    def test_conflict(self, admission_api, tenant_foobar_devices, tenant_foobar):
        auth = {"Authorization": "Bearer " + tenant_foobar}
        self._test_conflict(admission_api, tenant_foobar_devices, auth)
