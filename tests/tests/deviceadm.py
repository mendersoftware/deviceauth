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


def auth_set_put_for_device(device=None, status=204):
    log = logging.getLogger('deviceadm.auth_set_put_for_device')

    def auth_set_put(request, authid):
        authset = json.loads(request.body.decode())
        log.info('new auth put %s', authset)
        if device:
            assert authset.get('device_identity', None) == device.identity
            assert authset.get('key', None) == device.public_key
        else:
            assert authset.get('device_identity', None)
            assert authset.get('key', None)

        assert authset.get('device_id', None)

        return (status, {}, '')

    return auth_set_put


def get_fake_deviceadm_addr():
    return os.environ.get('FAKE_ADMISSION_ADDR', '0.0.0.0:9997')


ANY_DEVICE = None

@contextmanager
def run_fake_for_device(device):
    handlers = [
        ('PUT', '/api/management/v1/admission/devices/(.*)', auth_set_put_for_device(device)),
    ]
    with mockserver.run_fake(get_fake_deviceadm_addr(),
                             handlers=handlers) as server:
        yield server
