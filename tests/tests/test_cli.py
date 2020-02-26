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
from common import clean_db, mongo, cli
import pytest


DB_NAME = "deviceauth"
DB_MIGRATION_COLLECTION = "migration_info"
DB_VERSION = "1.1.0"


MIGRATED_TENANT_DBS={
    "tenant-stale-1": "0.0.1",
    "tenant-stale-2": "0.2.0",
    "tenant-stale-3": "1.0.0",
    "tenant-current": "1.1.0",
    "tenant-future": "2.0.0",
}

@pytest.fixture(scope='function')
def migrated_tenant_dbs(clean_db, mongo):
    ''' Init a set of tenant dbs to predefined versions. '''
    for tid, ver in MIGRATED_TENANT_DBS.items():
        mongo_set_version(mongo, make_tenant_db(tid), ver)


@pytest.fixture(scope='function')
def fake_migrated_db(clean_db, mongo, request):
    '''Init a default db to version passed in 'request'. Does not run the actual
    migrations, just records DB version in proper collection.'''
    version = request.param
    mongo_set_version(mongo, DB_NAME, version)


def mongo_set_version(mongo, dbname, version):
    major, minor, patch = [int(x) for x in version.split('.')]

    version = {
        "major": major,
        "minor": minor,
        "patch": patch,
    }

    mongo[dbname][DB_MIGRATION_COLLECTION].insert_one({"version": version})


def make_tenant_db(tenant_id):
    return '{}-{}'.format(DB_NAME, tenant_id)


class TestMigration:
    @staticmethod
    def verify_db_and_collections(client, dbname):
        dbs = client.database_names()
        assert dbname in dbs

        colls = client[dbname].collection_names()
        assert DB_MIGRATION_COLLECTION in colls

    @staticmethod
    def verify_migration(db, expected_version):
        major, minor, patch = [int(x) for x in expected_version.split('.')]
        version = {
            "version.major": major,
            "version.minor": minor,
            "version.patch": patch,
        }

        mi = db[DB_MIGRATION_COLLECTION].find_one(version)
        print('found migration:', mi)
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
        listedTenantsList.remove('')
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

    @pytest.mark.parametrize('fake_migrated_db', ["0.0.1"], indirect=True)
    def test_ok_stale_db(self, cli, fake_migrated_db, mongo):
        cli.migrate()
        TestMigration.verify(cli, mongo, DB_NAME, DB_VERSION)

    @pytest.mark.parametrize('fake_migrated_db', ["1.1.0"], indirect=True)
    def test_ok_current_db(self, cli, fake_migrated_db, mongo):
        cli.migrate()
        TestMigration.verify(cli, mongo, DB_NAME, DB_VERSION)

    @pytest.mark.parametrize('fake_migrated_db', ["2.0.0"], indirect=True)
    def test_ok_future_db(self, cli, fake_migrated_db, mongo):
        cli.migrate()
        TestMigration.verify(cli, mongo, DB_NAME, "2.0.0")


@pytest.mark.last
class TestCliMigrateEnterprise:
    @pytest.mark.parametrize('tenant_id',
            list(MIGRATED_TENANT_DBS) + ['tenant-new-1','tenant-new-2']
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
