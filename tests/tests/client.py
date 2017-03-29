#!/usr/bin/python
# Copyright 2016 Mender Software AS
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
import os.path
import logging
import json
import urllib.parse as up
import requests

import pytest
from bravado.swagger_model import load_file
from bravado.client import SwaggerClient, RequestsClient
from requests.utils import parse_header_links


class BaseApiClient:

    api_url = "http://%s/api/management/v1/devauth/" % \
              pytest.config.getoption("host")

    def make_api_url(self, path):
        return os.path.join(self.api_url,
                            path if not path.startswith("/") else path[1:])


class BaseDevicesApiClient(BaseApiClient):
    api_url = "http://%s/api/devices/v1/authentication/" % \
              pytest.config.getoption("host")


class SwaggerApiClient(BaseApiClient):
    config = {
        'also_return_response': True,
        'validate_responses': True,
        'validate_requests': False,
        'validate_swagger_spec': False,
        'use_models': True,
    }

    log = logging.getLogger('client.SwaggerApiClient')
    spec_option = 'spec'

    def setup_swagger(self):
        self.http_client = RequestsClient()
        self.http_client.session.verify = False

        spec = pytest.config.getoption(self.spec_option)
        self.client = SwaggerClient.from_spec(load_file(spec),
                                              config=self.config,
                                              http_client=self.http_client)
        self.client.swagger_spec.api_url = self.api_url


class InternalClient(SwaggerApiClient):
    api_url = "http://%s/api/internal/v1/devauth/" % \
              pytest.config.getoption("host")

    log = logging.getLogger('client.InternalClient')


class SimpleInternalClient(InternalClient):
    """Internal API client. Cannot be used as pytest base class"""
    log = logging.getLogger('client.SimpleInternalClient')

    def __init__(self):
        self.setup_swagger()


class ManagementClient(SwaggerApiClient):
    log = logging.getLogger('client.ManagementClient')

    spec_option = 'management_spec'

    def setup(self):
        self.setup_swagger()

    def accept_device(self, devid, aid):
        return self.put_device_status(devid, aid, 'accepted')

    def reject_device(self, devid, aid):
        return self.put_device_status(devid, aid, 'rejected')

    def put_device_status(self, devid, aid, status):
        self.log.info("definitions: %s", self.client.swagger_spec.definitions)
        Status = self.client.get_model('Status')
        st = Status(status=status)
        return self.client.devices.put_devices_id_auth_aid_status(id=devid,
                                                                  aid=aid,
                                                                  status=st).result()

    def delete_device(self, devid, headers={}):
        if 'Authorization' not in headers:
            self.log.debug('appending default authorization header')
            headers['Authorization'] = 'Bearer foo'
        # bravado for some reason doesn't issue DELETEs properly (silent failure)
        # fall back to 'requests'
        #   return self.client.devices.delete_devices_id(id=devid, **kwargs)
        rsp = requests.delete(self.make_api_url('/devices/{}'.format(devid)), headers = headers)

class SimpleManagementClient(ManagementClient):
    """Management API client. Cannot be used as pytest base class"""
    log = logging.getLogger('client.SimpleManagementClient')

    def __init__(self):
        self.setup_swagger()

    def list_devices(self, **kwargs):
        if 'Authorization' not in kwargs:
            self.log.debug('appending default authorization header')
            kwargs['Authorization'] = 'Bearer foo'
        return self.client.devices.get_devices(**kwargs).result()[0]

    def get_device(self, **kwargs):
        if 'Authorization' not in kwargs:
            self.log.debug('appending default authorization header')
            kwargs['Authorization'] = 'Bearer foo'
        return self.client.devices.get_devices_id(**kwargs).result()[0]

    def find_device_by_identity(self, identity):
        page = 1
        per_page = 100
        self.log.debug('find device with identity: %s', identity)

        while True:
            self.log.debug('trying page %d', page)
            devs = self.list_devices(page=page, per_page=per_page)
            for dev in devs:
                if dev.id_data == identity:
                    # found
                    return dev
            # try another page
            if len(devs) < per_page:
                break
            page += 1

        return None

class ConductorClient():
    """Trivial Conductor API client.
    The official one doesn't wrap what we need (get *executed*
    workflows by name - only via the search endpoint)"""

    log = logging.getLogger('client.ConductorClient')

    def __init__(self, base_url="http://mender-conductor:8080/api/"):
        self.base_url = base_url

    def get_workflows(self, workflow_name):
        """Wraps the search endpoint.
        Gets workflows of a given name, starting with the most recently scheduled one."""

        sort = '{}:{}'.format('startTime', 'DESC')
        freetext = '{}:{}'.format('workflowType', workflow_name)

        params = {'sort': sort, 'freeText': freetext}
        endpoint = up.urljoin(self.base_url, 'workflow/search')

        return requests.get(endpoint, params=params)
