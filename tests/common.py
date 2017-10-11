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
from base64 import b64encode, urlsafe_b64decode, urlsafe_b64encode

from itertools import count
from client import CliClient
from pymongo import MongoClient

import pytest

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

from client import SimpleInternalClient, SimpleManagementClient, ConductorClient, \
    BaseDevicesApiClient


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
    def __init__(self, tenant_token=""):
        self.tenant_token = tenant_token

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

@pytest.fixture(scope="session")
def cli():
    return CliClient()

@pytest.fixture(scope="session")
def mongo():
    return MongoClient('mender-mongo-device-auth:27017')


def mongo_cleanup(mongo):
    dbs = mongo.database_names()
    dbs = [d for d in dbs if d not in ['local', 'admin']]
    for d in dbs:
        mongo.drop_database(d)


@pytest.yield_fixture(scope='function')
def clean_db(mongo):
    """Fixture setting up a clean (i.e. empty database). Yields
    pymongo.MongoClient connected to the DB."""
    mongo_cleanup(mongo)
    yield mongo
    mongo_cleanup(mongo)

@pytest.yield_fixture(scope='function')
def clean_migrated_db(clean_db, cli, request):
    """Clean database with migrations applied. Yields pymongo.MongoClient connected
    to the DB. The fixture can be parametrized with tenant ID"""
    if hasattr(request, 'param'):
        tenant_id = request.param
    else:
        tenant_id = ""
    print("migrating DB")
    cli.migrate(tenant=tenant_id)
    yield clean_db

@pytest.yield_fixture(scope='session')
def conductor_api():
    yield ConductorClient()


@pytest.yield_fixture(scope='session')
def management_api():
    yield SimpleManagementClient()


@pytest.yield_fixture(scope='session')
def internal_api():
    yield SimpleInternalClient()


@pytest.yield_fixture(scope='session')
def device_api():
    yield BaseDevicesApiClient()


def make_fake_tenant_token(tenant):
    """make_fake_tenant_token will generate a JWT-like tenant token which looks
    like this: 'fake.<base64 JSON encoded claims>.fake-sig'. The claims are:
    issuer (Mender), subject (fake-tenant), mender.tenant (foobar)
    """
    claims = {
        'iss': 'Mender',
        'sub': 'fake-tenant',
        'mender.tenant': tenant,
    }

    # serialize claims to JSON, encode as base64 and strip padding to be
    # compatible with JWT
    enc = urlsafe_b64encode(json.dumps(claims).encode()). \
          decode().strip('==')

    return 'fake.' + enc + '.fake-sig'


@pytest.fixture
@pytest.mark.parametrize('clean_migrated_db', ['foobar'], indirect=True)
def tenant_foobar(request, clean_migrated_db):
    """Fixture that sets up a tenant with ID 'foobar', on top of a clean migrated
    (with tenant support) DB.
    """
    return make_fake_tenant_token('foobar')
