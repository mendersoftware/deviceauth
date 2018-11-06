# Acceptance tests!

Acceptance tests are run in a separate container within the same network as all
other Mender services. For this to work, acceptance tests container needs to be
described in its own `docker-compose` file. The whole setup is started as a
separate compose project named `acceptance-tests`.

The tests container service is expected to be named `acceptance`. Dependencies
on other services, networks, aliases need to be defined in the compose file.
Example definition of acceptance tests container for Device Auth service:

```
version: '2'
services:
    acceptance:
        image: testing
        networks:
            - mender
        volumes:
            - "${TESTS_DIR}:/testing"
        depends_on:
            - mender-device-adm
            - mender-device-auth
            - mender-inventory

```

## Building

Build docker image for your service, use the same tag as is used
in [integration](https://github.com/mendersoftware/integration) repository
setup.
   
Build acceptance tests container using `build-acceptance` script. The script
takes 2 parameters: a path to the location where acceptance tests `Dockerfile`
is placed and a list of extra files to copy to tests directory.

`Dockerfile` defines `/testing/run.sh` as container entry point. Make sure that
the path is a valid.

`build-acceptance` script tags the built image using name `testing`. The same
name needs to be used for container `image` in tests compose file.
   
## Running

Use `run-acceptance` script. The script takes 2 parameters: the path to
integration repository (we need to access docker-compose of the whole stack)
and a path to compose file that describes acceptance tests container.

It is possible to use environment variable expansion in tests compose file. Make
sure to set appropriate variables when running `run-acceptance`.

## Example

Assume that the user is at the top of device auth source code, integration was
cloned to `../integration`. The following commands will build and run acceptance
tests:

- `./tests/build-acceptance ./tests ./docs/internal_api.yml`

- `TESTS_DIR=$PWD/tests ./tests/run-acceptance ../integration ./tests/docker-compose.yml`
