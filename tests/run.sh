#!/bin/bash
# Copyright 2022 Northern.tech AS
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

# tests are supposed to be located in the same directory as this file

DIR=$(readlink -f $(dirname $0))

export PYTHONDONTWRITEBYTECODE=1

HOST=${HOST="mender-device-auth:8080"}

# if we're running in a container, wait a little before starting tests
[ $$ -eq 1 ] && {
    echo "-- running in container, wait for other services"
    # wait 10s for containters to start and
    sleep 10
}

py.test -s --tb=short --host $HOST \
          --spec $DIR/internal_api.yml \
          --management-spec $DIR/management_api.yml \
          --verbose --junitxml=$DIR/results.xml \
          $DIR/tests/test_*.py "$@"
