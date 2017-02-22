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

import pytest
from bravado.swagger_model import load_file
from bravado.client import SwaggerClient, RequestsClient
from requests.utils import parse_header_links


API_URL = "http://%s/api/%s/" % \
          (pytest.config.getoption("host"), \
           pytest.config.getoption("api"))


class BaseApiClient:
    api_url = API_URL

    def make_api_url(self, path):
        return os.path.join(self.api_url,
                            path if not path.startswith("/") else path[1:])



class SwaggerApiClient(BaseApiClient):

    config = {
        'also_return_response': True,
        'validate_responses': True,
        'validate_requests': False,
        'validate_swagger_spec': False,
        'use_models': True,
    }

    log = logging.getLogger('client.Client')
    spec_option = 'spec'

    def setup_swagger(self):
        self.http_client = RequestsClient()
        self.http_client.session.verify = False

        spec = pytest.config.getoption(self.spec_option)
        self.client = SwaggerClient.from_spec(load_file(spec),
                                              config=self.config,
                                              http_client=self.http_client)
        self.client.swagger_spec.api_url = self.api_url


class Client(SwaggerApiClient):

    def setup(self):
        self.setup_swagger()

    def accept_device(self, devid):
        return self.put_device_status(devid, 'accepted')

    def reject_device(self, devid):
        return self.put_device_status(devid, 'rejected')

    def put_device_status(self, devid, status):
        Status = self.client.get_model('Status')
        st = Status(status=status)
        return self.client.devices.put_devices_id_status(id=devid, status=st).result()

    def verify_token(self, token):
        return self.client.devices.put_devices_id_status(id=devid, status=st).result()
