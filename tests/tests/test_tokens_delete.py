import bravado
import pytest
import requests
import json

from common import Device, DevAuthorizer, device_auth_req, \
    explode_jwt, \
    clean_migrated_db, clean_db, mongo, cli, \
    management_api, internal_api, device_api, \
    get_fake_tenantadm_addr, make_fake_tenant_token

import deviceadm
import orchestrator
import mockserver


def request_token(device, dev_auth, url):
    handlers = [
        ('POST', '/api/internal/v1/tenantadm/tenants/verify',
         lambda _: (200, {}, {
             'id': '507f191e810c19729de860ea',
             'name': 'Acme',
         })),
    ]
    with mockserver.run_fake(get_fake_tenantadm_addr(),
                            handlers=handlers) as fake:
        with deviceadm.run_fake_for_device(device) as server:
            rsp = device_auth_req(url, dev_auth, device)
            assert rsp.status_code == 200
    dev_auth.parse_rsp_payload(device, rsp.text)
    return device.token

def verify_token(token, status_code, url):
    auth_hdr = 'Bearer {}'.format(token)
    rsp = requests.post(url, data='',
            headers={'Authorization': auth_hdr})
    assert rsp.status_code == status_code

@pytest.yield_fixture(scope='function')
def accepted_tenants_devices(device_api, management_api, clean_migrated_db, cli, request):
    """Fixture that sets up an accepted devices for tenants. The fixture can
       be parametrized with a tenants, number of devices and number of authentication sets.
       Yields a dict:
       [tenant ID: [device object, ...], ]"""

    requested = request.param

    tenants_devices = dict()
    url = device_api.auth_requests_url

    for (tenant, dev_count, auth_count) in requested:

        tenant_devices = []
        cli.migrate(tenant=tenant)
        tenant_token = make_fake_tenant_token(tenant)
        for _ in range(int(dev_count)):
            d = Device()
            for i in range(int(auth_count)):
                d.rotate_key()
                da = DevAuthorizer(tenant_token=tenant_token)

                # poke devauth so that device appears
                handlers = [
                    ('POST', '/api/internal/v1/tenantadm/tenants/verify',
                     lambda _: (200, {}, {
                         'id': '507f191e810c19729de860ea',
                         'name': 'Acme',
                     })),
                ]
                with mockserver.run_fake(get_fake_tenantadm_addr(),
                                        handlers=handlers) as fake:
                    with deviceadm.run_fake_for_device(d) as fakedevadm:
                        rsp = device_auth_req(url, da, d)
                        assert rsp.status_code == 401

                # try to find our devices in all devices listing
                dev = management_api.find_device_by_identity(d.identity,
                        Authorization='Bearer '+tenant_token)

                devid = dev.id
                for a in dev.auth_sets:
                    if a.pubkey == d.public_key:
                        aid = a.id
                        break

                try:
                    with orchestrator.run_fake_for_device_id(devid) as server:
                        management_api.accept_device(devid, aid, Authorization='Bearer '+ tenant_token)
                except bravado.exception.HTTPError as e:
                    assert e.response.status_code == 204

                token = request_token(d, da, device_api.auth_requests_url)
                assert len(token) > 0

            assert dev
            tenant_devices.append(d)

        tenants_devices[tenant] = tenant_devices
    yield tenants_devices


class TestMultiTenantDeleteTokens:
    @pytest.mark.parametrize('accepted_tenants_devices', [[('foo', 2, 2), ('bar', 1, 3)]], indirect=True)
    def test_delete_tokens_by_device_ok(self, accepted_tenants_devices, internal_api, management_api, device_api):
        td = accepted_tenants_devices

        tenant_foo_token = make_fake_tenant_token('foo')
        da_foo = DevAuthorizer(tenant_token=tenant_foo_token)
        d1_foo = td['foo'][0]
        token1 = request_token(d1_foo, da_foo, device_api.auth_requests_url)
        assert len(token1) > 0
        d2_foo = td['foo'][1]
        token2 = request_token(d2_foo, da_foo, device_api.auth_requests_url)
        assert len(token2) > 0

        tenant_bar_token = make_fake_tenant_token('bar')
        da_bar = DevAuthorizer(tenant_token=tenant_bar_token)
        d1_bar = td['bar'][0]
        token3 = request_token(d1_bar, da_bar, device_api.auth_requests_url)
        assert len(token2) > 0

        verify_url = internal_api.make_api_url("/tokens/verify")
        verify_token(token1, 200, verify_url)
        verify_token(token2, 200, verify_url)
        verify_token(token3, 200, verify_url)

        dev1 = management_api.find_device_by_identity(d1_foo.identity,
                Authorization='Bearer '+ tenant_foo_token)
        payload = {'device_id': dev1.id, 'tenant_id': 'foo'}
        rsp = requests.delete(internal_api.make_api_url("/tokens"), params=payload)
        assert rsp.status_code == 204

        verify_token(token1, 401, verify_url)
        verify_token(token2, 200, verify_url)
        verify_token(token3, 200, verify_url)

    @pytest.mark.parametrize('accepted_tenants_devices', [[('foo', 2, 2), ('bar', 1, 3)]], indirect=True)
    def test_delete_tokens_by_non_existent_device_ok(self, accepted_tenants_devices, internal_api, management_api, device_api):
        td = accepted_tenants_devices

        tenant_foo_token = make_fake_tenant_token('foo')
        da_foo = DevAuthorizer(tenant_token=tenant_foo_token)
        d1_foo = td['foo'][0]
        token1 = request_token(d1_foo, da_foo, device_api.auth_requests_url)
        assert len(token1) > 0
        d2_foo = td['foo'][1]
        token2 = request_token(d2_foo, da_foo, device_api.auth_requests_url)
        assert len(token2) > 0

        tenant_bar_token = make_fake_tenant_token('bar')
        da_bar = DevAuthorizer(tenant_token=tenant_bar_token)
        d1_bar = td['bar'][0]
        token3 = request_token(d1_bar, da_bar, device_api.auth_requests_url)
        assert len(token2) > 0

        verify_url = internal_api.make_api_url("/tokens/verify")
        verify_token(token1, 200, verify_url)
        verify_token(token2, 200, verify_url)
        verify_token(token3, 200, verify_url)

        payload = {'device_id': 'foo', 'tenant_id': 'foo'}
        rsp = requests.delete(internal_api.make_api_url("/tokens"), params=payload)
        assert rsp.status_code == 204

        verify_token(token1, 200, verify_url)
        verify_token(token2, 200, verify_url)
        verify_token(token3, 200, verify_url)

    @pytest.mark.parametrize('accepted_tenants_devices', [[('foo', 2, 2), ('bar', 1, 3)]], indirect=True)
    def test_delete_tokens_by_tenant_ok(self, accepted_tenants_devices, internal_api, management_api, device_api):
        td = accepted_tenants_devices

        tenant_foo_token = make_fake_tenant_token('foo')
        da_foo = DevAuthorizer(tenant_token=tenant_foo_token)
        d1_foo = td['foo'][0]
        token1 = request_token(d1_foo, da_foo, device_api.auth_requests_url)
        assert len(token1) > 0
        d2_foo = td['foo'][1]
        token2 = request_token(d2_foo, da_foo, device_api.auth_requests_url)
        assert len(token2) > 0

        tenant_bar_token = make_fake_tenant_token('bar')
        da_bar = DevAuthorizer(tenant_token=tenant_bar_token)
        d1_bar = td['bar'][0]
        token3 = request_token(d1_bar, da_bar, device_api.auth_requests_url)
        assert len(token2) > 0

        verify_url = internal_api.make_api_url("/tokens/verify")
        verify_token(token1, 200, verify_url)
        verify_token(token2, 200, verify_url)
        verify_token(token3, 200, verify_url)

        dev1 = management_api.find_device_by_identity(d1_foo.identity,
                Authorization='Bearer '+ tenant_foo_token)
        payload = {'tenant_id': 'foo'}
        rsp = requests.delete(internal_api.make_api_url("/tokens"), params=payload)
        assert rsp.status_code == 204

        verify_token(token1, 401, verify_url)
        verify_token(token2, 401, verify_url)
        verify_token(token3, 200, verify_url)

    @pytest.mark.parametrize('accepted_tenants_devices', [[('foo', 2, 2), ('bar', 1, 3)]], indirect=True)
    def test_delete_tokens_by_non_existent_tenant_ok(self, accepted_tenants_devices, internal_api, management_api, device_api):
        td = accepted_tenants_devices

        tenant_foo_token = make_fake_tenant_token('foo')
        da_foo = DevAuthorizer(tenant_token=tenant_foo_token)
        d1_foo = td['foo'][0]
        token1 = request_token(d1_foo, da_foo, device_api.auth_requests_url)
        assert len(token1) > 0
        d2_foo = td['foo'][1]
        token2 = request_token(d2_foo, da_foo, device_api.auth_requests_url)
        assert len(token2) > 0

        tenant_bar_token = make_fake_tenant_token('bar')
        da_bar = DevAuthorizer(tenant_token=tenant_bar_token)
        d1_bar = td['bar'][0]
        token3 = request_token(d1_bar, da_bar, device_api.auth_requests_url)
        assert len(token2) > 0

        verify_url = internal_api.make_api_url("/tokens/verify")
        verify_token(token1, 200, verify_url)
        verify_token(token2, 200, verify_url)
        verify_token(token3, 200, verify_url)

        dev1 = management_api.find_device_by_identity(d1_foo.identity,
                Authorization='Bearer '+ tenant_foo_token)
        payload = {'tenant_id': 'baz'}
        rsp = requests.delete(internal_api.make_api_url("/tokens"), params=payload)
        assert rsp.status_code == 204

        verify_token(token1, 200, verify_url)
        verify_token(token2, 200, verify_url)
        verify_token(token3, 200, verify_url)

    def test_delete_tokens_no_tenant_id_bad_request(self, internal_api):
        rsp = requests.delete(internal_api.make_api_url("/tokens"))
        assert rsp.status_code == 400

    def test_delete_tokens_by_device_no_tenant_id_bad_request(self, internal_api):
        payload = {'device_id': 'foo'}
        rsp = requests.delete(internal_api.make_api_url("/tokens"), params=payload)
        assert rsp.status_code == 400
