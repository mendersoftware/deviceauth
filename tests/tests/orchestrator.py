#!/usr/bin/python3
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
import json
import os
import logging

from contextlib import contextmanager

import mockserver


def provision_device_handler(device_id=None, status=200):
    log = logging.getLogger('orchestartor.provision_device')

    def _provision_device(request):
        device = json.loads(request.body.decode())['device']
        log.info('provision device %s', device)
        if device_id is not None:
            assert device.get('id', None) == device_id
        else:
            assert device.get('id', None)

        return (status, {}, '')

    return _provision_device

def decommission_device_handler(device_id=None, status=200):
    log = logging.getLogger('orchestartor.decommision_device')

    def _decommission_device(request):
        dreq = json.loads(request.body.decode())
        print('decommision request', dreq)
        # verify that devauth tries to decommision correct device
        assert dreq.get('device_id', None) == device_id
        # test is enforcing particular request ID
        assert dreq.get('request_id', None) == 'delete_device'
        # test is enforcing particular request ID
        assert dreq.get('authorization', None) == 'Bearer foobar'
        return (status, {}, '')

    return _decommission_device

def update_device_status_handler(device_id=None, status=200):
    log = logging.getLogger('orchestartor.update_device_status')

    def _update_device_status(request):
        dreq = json.loads(request.body.decode())
        print('update_device_status request', dreq)
        return (status, {}, '')

    return _update_device_status

def get_fake_orchestrator_addr():
    return os.environ.get('FAKE_ORCHESTRATOR_ADDR', '0.0.0.0:9998')

ANY_DEVICE = None

@contextmanager
def run_fake_for_device_id(devid, status=None):
    if status is None:
        handlers = [
                ('POST', '/api/v1/workflow/provision_device', provision_device_handler(devid)),
                ('POST', '/api/v1/workflow/decommission_device', decommission_device_handler(devid)),
                ('POST', '/api/v1/workflow/update_device_status', update_device_status_handler(devid)),
                ]
    else:
        handlers = [
                ('POST', '/api/v1/workflow/provision_device', provision_device_handler(devid, status)),
                ('POST', '/api/v1/workflow/decommission_device', decommission_device_handler(devid, status)),
                ('POST', '/api/v1/workflow/update_device_status', update_device_status_handler(devid, status)),
                ]

    with mockserver.run_fake(get_fake_orchestrator_addr(),
                             handlers=handlers) as server:
        yield server
