#!/usr/bin/python
# Copyright 2018 Northern.tech AS
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
import subprocess

import pytest
from bravado.swagger_model import load_file
from bravado.client import SwaggerClient, RequestsClient
from requests.utils import parse_header_links


class BaseApiClient:

    api_url = "http://%s/api/management/v1/devauth/" % pytest.config.getoption("host")

    def make_api_url(self, path):
        return os.path.join(
            self.api_url, path if not path.startswith("/") else path[1:]
        )


class BaseDevicesApiClient(BaseApiClient):
    api_url = "http://%s/api/devices/v1/authentication/" % pytest.config.getoption(
        "host"
    )

    @property
    def auth_requests_url(self):
        """Provides device identity as a string"""
        return self.make_api_url("/auth_requests")


class SwaggerApiClient(BaseApiClient):
    config = {
        "also_return_response": True,
        "validate_responses": True,
        "validate_requests": False,
        "validate_swagger_spec": True,
        "use_models": True,
    }

    log = logging.getLogger("client.SwaggerApiClient")
    spec_option = "spec"

    def setup_swagger(self):
        self.http_client = RequestsClient()
        self.http_client.session.verify = False

        spec = pytest.config.getoption(self.spec_option)
        self.client = SwaggerClient.from_spec(
            load_file(spec), config=self.config, http_client=self.http_client
        )
        self.client.swagger_spec.api_url = self.api_url


class InternalClient(SwaggerApiClient):
    api_url = "http://%s/api/internal/v1/devauth/" % pytest.config.getoption("host")

    log = logging.getLogger("client.InternalClient")

    spec_option = "spec"

    def setup(self):
        self.setup_swagger()

    def get_max_devices_limit(self, tenant_id):
        return self.client.Internal_API.Get_Device_Limit(tenant_id=tenant_id).result()[
            0
        ]

    def put_max_devices_limit(self, tenant_id, limit):
        Limit = self.client.get_model("Limit")
        l = Limit(limit=limit)
        return self.client.Internal_API.Update_Device_Limit(
            tenant_id=tenant_id, limit=l
        ).result()[0]

    def create_tenant(self, tenant_id):
        return self.client.Internal_API.Create_Tenant(
            tenant={"tenant_id": tenant_id}
        ).result()


class SimpleInternalClient(InternalClient):
    """Internal API client. Cannot be used as pytest base class"""

    log = logging.getLogger("client.SimpleInternalClient")

    def __init__(self):
        self.setup_swagger()


class ManagementClient(SwaggerApiClient):
    api_url = "http://%s/api/management/v2/devauth/" % pytest.config.getoption("host")

    log = logging.getLogger("client.ManagementClient")

    spec_option = "management_spec"

    def setup(self):
        self.setup_swagger()

    def accept_device(self, devid, aid, **kwargs):
        return self.put_device_status(devid, aid, "accepted", **kwargs)

    def reject_device(self, devid, aid, **kwargs):
        return self.put_device_status(devid, aid, "rejected", **kwargs)

    def put_device_status(self, devid, aid, status, **kwargs):
        if "Authorization" not in kwargs:
            self.log.debug("appending default authorization header")
            kwargs["Authorization"] = "Bearer foo"

        self.log.info("definitions: %s", self.client.swagger_spec.definitions)
        Status = self.client.get_model("Status")
        st = Status(status=status)
        return self.client.Management_API.Set_Authentication_Status(
            id=devid, aid=aid, status=st, **kwargs
        ).result()

    def delete_device(self, devid, headers={}):
        if "Authorization" not in headers:
            self.log.debug("appending default authorization header")
            headers["Authorization"] = "Bearer foo"
        # bravado for some reason doesn't issue DELETEs properly (silent failure)
        # fall back to 'requests'
        #   return self.client.devices.delete_devices_id(id=devid, **kwargs)
        rsp = requests.delete(
            self.make_api_url("/devices/{}".format(devid)), headers=headers
        )
        return rsp

    def delete_authset(self, devid, aid, **kwargs):
        if "Authorization" not in kwargs:
            self.log.debug("appending default authorization header")
            kwargs["Authorization"] = "Bearer foo"

        headers = {"Authorization": kwargs["Authorization"]}
        rsp = requests.delete(
            self.make_api_url("/devices/{}/auth/{}".format(devid, aid)), headers=headers
        )
        return rsp

    def count_devices(self, status=None, **kwargs):
        if "Authorization" not in kwargs:
            self.log.debug("appending default authorization header")
            kwargs["Authorization"] = "Bearer foo"
        count = self.client.Management_API.Count_Devices(
            status=status, **kwargs
        ).result()[0]
        return count.count

    def make_auth(self, tenant_token):
        return {"Authorization": "Bearer " + tenant_token}


class SimpleManagementClient(ManagementClient):
    """Management API client. Cannot be used as pytest base class"""

    log = logging.getLogger("client.SimpleManagementClient")

    def __init__(self):
        self.setup_swagger()

    def list_devices(self, **kwargs):
        if "Authorization" not in kwargs:
            self.log.debug("appending default authorization header")
            kwargs["Authorization"] = "Bearer foo"
        return self.client.Management_API.List_Devices(**kwargs).result()[0]

    def get_device_limit(self, **kwargs):
        if "Authorization" not in kwargs:
            self.log.debug("appending default authorization header")
            kwargs["Authorization"] = "Bearer foo"
        return self.client.Management_API.Get_Device_Limit(**kwargs).result()[0]

    def get_device(self, **kwargs):
        if "Authorization" not in kwargs:
            self.log.debug("appending default authorization header")
            kwargs["Authorization"] = "Bearer foo"
        return self.client.Management_API.Get_Device(**kwargs).result()[0]

    def get_single_device(self, **kwargs):
        page = 1
        per_page = 100

        devs = self.list_devices(page=page, per_page=per_page, **kwargs)
        return devs[0]

    def find_device_by_identity(self, identity, **kwargs):
        page = 1
        per_page = 100
        self.log.debug("find device with identity: %s", identity)

        while True:
            self.log.debug("trying page %d", page)
            devs = self.list_devices(page=page, per_page=per_page, **kwargs)
            for dev in devs:
                if (
                    json.dumps({"mac": dev.identity_data.mac}, separators=(",", ":"))
                    == identity
                ):
                    # found
                    return dev
            # try another page
            if len(devs) < per_page:
                break
            page += 1

        return None


class CliClient:
    cmd = "/testing/deviceauth"

    def migrate(self, tenant=None):
        args = [self.cmd, "migrate"]

        if tenant is not None:
            args.extend(["--tenant", tenant])

        subprocess.run(args, check=True)

    def list_tenants(self, tenant=None):
        args = [self.cmd, "migrate", "--list-tenants"]

        return subprocess.run(args, check=True, stdout=subprocess.PIPE).stdout.decode(
            "utf-8"
        )
