#!/bin/bash

# tests are supposed to be located in the same directory as this file

DIR=$(readlink -f $(dirname $0))

export PYTHONDONTWRITEBYTECODE=1

HOST="mender-device-auth:8080"
if [ -n "$1" ]; then
    HOST=$1
fi

# if we're running in a container, wait a little before starting tests
[ $$ -eq 1 ] && sleep 5

py.test-3 -s --tb=short --api=0.1.0  --host $HOST \
        --spec $DIR/internal_api.yml \
        --verbose --junitxml=$DIR/results.xml \
        $DIR/tests/test_*.py
