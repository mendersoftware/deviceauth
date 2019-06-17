#!/bin/bash

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
