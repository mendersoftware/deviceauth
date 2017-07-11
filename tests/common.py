#!/usr/bin/python
# Copyright 2017 Northern.tech AS
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
import json
import requests
import random
import binascii
from base64 import b64encode, urlsafe_b64decode
from itertools import count

import pytest

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


def get_keypair():
    private = RSA.generate(1024)
    public = private.publickey()
    return private.exportKey().decode(), public.exportKey().decode()


def sign_data(data, privateKey):
    rsakey = RSA.importKey(privateKey)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    if type(data) is str:
        data = data.encode()
    digest.update(data)
    sign = signer.sign(digest)
    return b64encode(sign)


class Device(object):
    def __init__(self, mac=None):
        self.mac = mac or \
                   ":".join(["{:02x}".format(random.randint(0x00, 0xFF), 'x') for i in range(6)])
        self.private_key, self.public_key = get_keypair()
        self.token = ""

    @property
    def identity(self):
        """Provides device identity as a string"""
        return json.dumps({"mac": self.mac})


class DevAuthorizer(object):
    def __init__(self):
        self.tenant_token = "dummy"

    def make_req_payload(self, dev):
        """Make auth request for given device. Returns a tuple (payload, signature)"""
        payload = json.dumps({
            "id_data": dev.identity,
            "tenant_token": self.tenant_token,
            "pubkey": dev.public_key,
        })
        signature = sign_data(payload, dev.private_key)
        return payload, signature

    def parse_rsp_payload(self, dev, data):
        """Parse authorization payload and apply whatever settings to the device"""
        # data is supposed to be plain text token
        dev.token = data


def device_auth_req(url, dauth, dev):
    """Run authorization request to the backend and return requests.Response"""
    data, sign = dauth.make_req_payload(dev)
    headers = {
        "Content-type": "application/json",
        "X-MEN-Signature": sign,
    }
    rsp = requests.post(url, headers=headers, data=data, verify=False)
    return rsp


def make_devid(identity):
    """
    Generate device ID from device identity data trying to follow the same
    logic as devauth does. Returns a string containing device ID.
    """
    d = SHA256.new()
    # convert to binary as needed
    bid = identity if type(identity) is bytes else identity.encode()
    d.update(bid)
    return binascii.b2a_hex(d.digest()).decode()

def b64pad(b64data):
    """Pad base64 string with '=' to achieve a length that is a multiple of 4
    """
    return b64data + '=' * (4 - (len(b64data) % 4))


def explode_jwt(token):
    parts = token.split('.')
    assert len(parts) == 3

    # JWT fields are passed in a header and use URL safe encoding, which
    # substitutes - instead of + and _ instead of /
    hdr_raw = urlsafe_b64decode(b64pad(parts[0]))
    claims_raw = urlsafe_b64decode(b64pad(parts[1]))
    sign = urlsafe_b64decode(b64pad(parts[2]))

    # unpack json data
    hdr = json.loads(hdr_raw.decode())
    claims = json.loads(claims_raw.decode())

    return hdr, claims, sign
