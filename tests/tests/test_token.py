import bravado
import pytest
import requests

from client import BaseDevicesApiClient, ManagementClient, \
    SimpleInternalClient, SimpleManagementClient
from common import Device, DevAuthorizer, device_auth_req, \
    make_devid, explode_jwt


class TestToken(ManagementClient):

    intclient = SimpleInternalClient()

    devapi = BaseDevicesApiClient()

    def test_token(self):
        d = Device()
        da = DevAuthorizer()
        url = self.devapi.make_api_url("/auth_requests")

        # poke devauth so that device appears
        rsp = device_auth_req(url, da, d)
        assert rsp.status_code == 401

        # try to find our devices in all devices listing
        mc = SimpleManagementClient()
        dev = mc.find_device_by_identity(d.identity)

        self.log.debug('found matching device with ID: %s', dev.id)
        devid = dev.id
        # extract authentication data set ID
        aid = dev.auth_sets[0].id

        try:
            self.accept_device(aid)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 204

        # device is accepted, we should get a token now
        rsp = device_auth_req(url, da, d)
        assert rsp.status_code == 200

        da.parse_rsp_payload(d, rsp.text)

        assert len(d.token) > 0
        self.log.info("device token: %s", d.token)

        thdr, tclaims, tsign = explode_jwt(d.token)
        assert 'typ' in thdr and thdr['typ'] == 'JWT'

        assert 'jti' in tclaims
        assert 'exp' in tclaims
        assert 'sub' in tclaims and tclaims['sub'] == devid
        assert 'iss' in tclaims and tclaims['iss'] == 'Mender'
        # TODO: signature verification?

        # verify token; the token is to be placed in the Authorization header
        # and it looks like bravado cannot handle a POST request with no data
        # in body, hence we fall back to sending request directly
        verify_url = self.intclient.make_api_url("/tokens/verify")
        self.log.info("verify URL: %s", verify_url)
        auth_hdr = 'Bearer {}'.format(d.token)

        # no auth header should raise an error
        rsp = requests.post(verify_url, data='')
        assert rsp.status_code == 401

        # successful verification
        rsp = requests.post(verify_url, data='',
                            headers={'Authorization': auth_hdr})
        assert rsp.status_code == 200

        # use a bogus token that is not a valid JWT
        rsp = requests.post(verify_url, data='',
                            headers={'Authorization': 'bogus'})
        assert rsp.status_code == 401

        # or a correct token with data appended at the end
        rsp = requests.post(verify_url, data='',
                            headers={'Authorization': auth_hdr + "==foo"})
        assert rsp.status_code == 401

        # bravado cannot handle DELETE requests either
        #   self.client.tokens.delete_tokens_id(id=tclaims['jti'])
        # use requests instead
        rsp = requests.delete(self.make_api_url('/tokens/{}'.format(tclaims['jti'])))
        assert rsp.status_code == 204

        # unsuccessful verification
        rsp = requests.post(verify_url, data='',
                            headers={'Authorization': auth_hdr})
        assert rsp.status_code == 401
