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
import asyncio
import json
import tornado.web
from contextlib import contextmanager

import pytest

import mockserver
from common import (
    DevAuthorizer,
    Device,
    clean_db,
    cli,
    device_api,
    device_auth_req,
    get_fake_tenantadm_addr,
    get_fake_workflows_addr,
    internal_api,
    make_devices,
    make_fake_tenant_token,
    management_api,
    mongo,
)

DB_NAME = "deviceauth"
DB_MIGRATION_COLLECTION = "migration_info"
DB_VERSION = "1.9.0"


MIGRATED_TENANT_DBS = {
    "tenant-stale-1": "0.0.1",
    "tenant-stale-2": "0.2.0",
    "tenant-stale-3": "1.0.0",
    "tenant-current": "1.9.0",
    "tenant-future": "2.0.0",
}


@pytest.fixture(scope="function")
def migrated_tenant_dbs(clean_db, mongo):
    """ Init a set of tenant dbs to predefined versions. """
    for tid, ver in MIGRATED_TENANT_DBS.items():
        mongo_set_version(mongo, make_tenant_db(tid), ver)


@pytest.fixture(scope="function")
def fake_migrated_db(clean_db, mongo, request):
    """Init a default db to version passed in 'request'. Does not run the actual
    migrations, just records DB version in proper collection."""
    version = request.param
    mongo_set_version(mongo, DB_NAME, version)


def mongo_set_version(mongo, dbname, version):
    major, minor, patch = [int(x) for x in version.split(".")]

    version = {
        "major": major,
        "minor": minor,
        "patch": patch,
    }

    mongo[dbname][DB_MIGRATION_COLLECTION].insert_one({"version": version})


def make_tenant_db(tenant_id):
    return "{}-{}".format(DB_NAME, tenant_id)


class TestMigration:
    @staticmethod
    def verify_db_and_collections(client, dbname):
        dbs = client.database_names()
        assert dbname in dbs

        colls = client[dbname].collection_names()
        assert DB_MIGRATION_COLLECTION in colls

    @staticmethod
    def verify_migration(db, expected_version):
        major, minor, patch = [int(x) for x in expected_version.split(".")]
        version = {
            "version.major": major,
            "version.minor": minor,
            "version.patch": patch,
        }

        mi = db[DB_MIGRATION_COLLECTION].find_one(version)
        print("found migration:", mi)

        assert mi

    @staticmethod
    def verify(cli, mongo, dbname, version):
        TestMigration.verify_db_and_collections(mongo, dbname)
        TestMigration.verify_migration(mongo[dbname], version)


class TestListTenants:
    def test_ok(self, cli, migrated_tenant_dbs):
        dbs = list(MIGRATED_TENANT_DBS.keys())
        dbs.sort()
        listedTenants = cli.list_tenants()
        listedTenantsList = listedTenants.split("\n")
        listedTenantsList.remove("")
        listedTenantsList.sort()
        assert dbs == listedTenantsList

    def test_no_tenants(self, cli):
        assert cli.list_tenants() == ""


# runs 'last' since it drops/reinits the default db, which breaks deviceauth under test:
# - the indexes are destroyed by 'clean_db/fake_migrated_db'
# - even though we ensure them on every write - mgo caches their names
#   and thinks they're still there
# - writes by deviceauth are then essentially incorrect (duplicate data) and other tests fail
@pytest.mark.last
class TestCliMigrate:
    def test_ok_no_db(self, cli, clean_db, mongo):
        cli.migrate()
        TestMigration.verify(cli, mongo, DB_NAME, DB_VERSION)

    @pytest.mark.parametrize("fake_migrated_db", ["0.0.1"], indirect=True)
    def test_ok_stale_db(self, cli, fake_migrated_db, mongo):
        cli.migrate()
        TestMigration.verify(cli, mongo, DB_NAME, DB_VERSION)

    @pytest.mark.parametrize("fake_migrated_db", ["1.9.0"], indirect=True)
    def test_ok_current_db(self, cli, fake_migrated_db, mongo):
        cli.migrate()
        TestMigration.verify(cli, mongo, DB_NAME, DB_VERSION)

    @pytest.mark.parametrize("fake_migrated_db", ["2.0.0"], indirect=True)
    def test_ok_future_db(self, cli, fake_migrated_db, mongo):
        cli.migrate()
        TestMigration.verify(cli, mongo, DB_NAME, "2.0.0")


@pytest.mark.last
class TestCliMigrateEnterprise:
    @pytest.mark.parametrize(
        "tenant_id", list(MIGRATED_TENANT_DBS) + ["tenant-new-1", "tenant-new-2"]
    )
    def test_ok(self, cli, mongo, migrated_tenant_dbs, tenant_id):
        cli.migrate(tenant_id)

        dbname = make_tenant_db(tenant_id)
        # a 'future' version won't be migrated, make an exception
        init_ver = MIGRATED_TENANT_DBS.get(tenant_id, "0.0.0")
        if init_ver < DB_VERSION:
            TestMigration.verify(cli, mongo, dbname, DB_VERSION)
        else:
            TestMigration.verify(cli, mongo, dbname, MIGRATED_TENANT_DBS[tenant_id])

        # verify other tenant dbs not touched
        others = [t for t in MIGRATED_TENANT_DBS if t != tenant_id]
        for t in others:
            dbname = make_tenant_db(t)
            TestMigration.verify(cli, mongo, dbname, MIGRATED_TENANT_DBS[t])


class TestCheckDeviceLimitsEnterprise:
    @contextmanager
    def init_service_mocks(
        self,
        wflows_rsp_q: asyncio.Queue = None,
        tadm_rsp_q: asyncio.Queue = None,
    ) -> mockserver.MockServer:

        # Very simple tornado request handler for tenantadm and workflows that
        # generates responses from items pushed onto an asyncio.Queue object,
        # the object can either be a callable or a 3-tuple with (code, header,
        # body). Callables are passed 'self' (RequestHandler) as argument.
        class RequestHandler(tornado.web.RequestHandler):
            def initialize(self, rsp_q):
                self.rsp_q = rsp_q

            def prepare(self):
                rsp = self.rsp_q.get_nowait()
                if callable(rsp):
                    rsp(self)
                else:
                    (status, hdr, body) = rsp
                    self.set_status(status)

                    for key, val in hdr.items():
                        self.add_header(key, val)

                    if body:
                        self.write(body)

                self.finish()

        with mockserver.run_fake(get_fake_tenantadm_addr()) as tadm:
            tadm.app.add_handlers(
                r".*",
                [
                    (
                        r".*",
                        RequestHandler,
                        {"rsp_q": tadm_rsp_q},
                    )
                ],
            )
            with mockserver.run_fake(get_fake_workflows_addr()) as wflows:
                wflows.app.add_handlers(
                    r".*",
                    [
                        (
                            r".*",
                            RequestHandler,
                            {"rsp_q": wflows_rsp_q},
                        )
                    ],
                )
                yield tadm, wflows

    @pytest.mark.parametrize(
        "test_case",
        [
            {
                # Test case where tenant is above threshold
                "tenant": {
                    "id": "123456789012345678901234",
                    "device_limit": 10,
                    "users": [
                        {
                            "name": "user1@acme.io",
                            "id": "f8b343d2-f0f6-4cf0-8d6b-50d4dbdd10ca",
                        },
                        {
                            "name": "user2@acme.io",
                            "id": "f8b343d2-f0f6-4cf0-8d6b-50d4dbdd10cb",
                        },
                    ],
                },
                "device_count": 10,
                "threshold": 90.0,
            },
            {
                # Test case where tenant is below threshold
                "tenant": {
                    "id": "123456789012345678901234",
                    "device_limit": 10,
                    "users": [
                        {
                            "name": "user1@acme.io",
                            "id": "f8b343d2-f0f6-4cf0-8d6b-50d4dbdd10ca",
                        },
                        {
                            "name": "user2@acme.io",
                            "id": "f8b343d2-f0f6-4cf0-8d6b-50d4dbdd10cb",
                        },
                    ],
                },
                "device_count": 8,
                "threshold": 90.0,
            },
        ],
    )
    def test_check_device_limits(
        self, clean_db, cli, device_api, management_api, internal_api, test_case
    ):

        rsp_q_tadm = asyncio.Queue(
            maxsize=len(test_case["tenant"]["users"]) + test_case["device_count"]
        )
        rsp_q_wflows = asyncio.Queue(
            maxsize=len(test_case["tenant"]["users"]) + test_case["device_count"]
        )
        with self.init_service_mocks(wflows_rsp_q=rsp_q_wflows, tadm_rsp_q=rsp_q_tadm):
            tenant_token = make_fake_tenant_token(test_case["tenant"]["id"])

            internal_api.put_max_devices_limit(
                test_case["tenant"]["id"], test_case["tenant"]["device_limit"]
            )

            for _ in range(test_case["device_count"]):
                # POST /api/internal/v1/tenantadm/verify
                rsp_q_tadm.put_nowait(
                    (200, {}, '{"id": "%s", "sub": "user"}' % test_case["tenant"])
                )
                # POST /api/v1/workflows/provision_device
                rsp_q_wflows.put_nowait((201, {}, ""))
                dev = Device()
                da = DevAuthorizer(tenant_token=tenant_token)
                rsp = device_auth_req(device_api.auth_requests_url, da, dev)
                assert rsp.status_code == 401

            devs = management_api.list_devices(
                status="pending", Authorization="Bearer " + tenant_token
            )
            for dev in devs:
                # POST /api/v1/workflows/update_device_status
                rsp_q_wflows.put_nowait((201, {}, ""))
                # POST /api/v1/workflows/provision_device
                rsp_q_wflows.put_nowait((201, {}, ""))
                management_api.put_device_status(
                    dev["id"],
                    dev["auth_sets"][0]["id"],
                    "accepted",
                    Authorization="Bearer " + tenant_token,
                )

            if test_case["device_count"] >= (
                (test_case["tenant"]["device_limit"] * test_case["threshold"] / 100.0)
            ):
                # GET /api/management/v1/tenantadm/users
                usersJSON = json.dumps(test_case["tenant"]["users"])
                rsp_q_tadm.put_nowait((200, {}, usersJSON))

                usernames = [user["name"] for user in test_case["tenant"]["users"]]
                # Verify that workflow is started for each user
                for i in range(len(test_case["tenant"]["users"])):

                    def verify_workflow(handler):
                        assert handler.request.path.endswith("device_limit_email")
                        body_json = json.loads(handler.request.body.decode("utf-8"))
                        assert body_json["to"] in usernames
                        usernames.remove(body_json["to"])
                        handler.set_status(201)

                    # POST /api/v1/workflows/device_limit_email
                    rsp_q_wflows.put_nowait(verify_workflow)

            cli.check_device_limits()

            # All pushed mock responses should be consumed at this point.
            assert (
                rsp_q_tadm.empty()
            ), "TenantAdm mock responses not consumed as expected"
            assert (
                rsp_q_wflows.empty()
            ), "Workflows mock responses not consumed as expected"
