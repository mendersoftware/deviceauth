#!/usr/bin/python3
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
import os
import logging

from contextlib import contextmanager

import mockserver


def device_add(device_id=None, status=201):
    log = logging.getLogger('inventory.device_add')

    def _device_add(request):
        inv_device = json.loads(request.body.decode())
        log.info('new inventory device %s', inv_device)
        if device_id is not None:
            assert inv_device.get('id', None) == device_id
        else:
            assert inv_device.get('id', None)

        return (status, {}, '')

    return _device_add


def get_fake_inventory_addr():
    return os.environ.get('FAKE_INVENTORY_ADDR', '0.0.0.0:9996')

ANY_DEVICE = None

@contextmanager
def run_fake_for_device_id(devid):
    handlers = [
        ('POST', '/api/0.1.0/devices', device_add(devid)),
    ]
    with mockserver.run_fake(get_fake_inventory_addr(),
                             handlers=handlers) as server:
        yield server
