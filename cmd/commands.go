// Copyright 2017 Northern.tech AS
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
package cmd

import (
	"context"
	"fmt"

	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/identity"
	mstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"

	dconfig "github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/deviceauth/store/mongo"
)

func makeDataStoreConfig() mongo.DataStoreMongoConfig {
	return mongo.DataStoreMongoConfig{
		ConnectionString: config.Config.GetString(dconfig.SettingDb),

		SSL:           config.Config.GetBool(dconfig.SettingDbSSL),
		SSLSkipVerify: config.Config.GetBool(dconfig.SettingDbSSLSkipVerify),

		Username: config.Config.GetString(dconfig.SettingDbUsername),
		Password: config.Config.GetString(dconfig.SettingDbPassword),
	}

}

func Migrate(c config.Reader, tenant string, listTenantsFlag bool) error {
	db, err := mongo.NewDataStoreMongo(makeDataStoreConfig())

	if err != nil {
		return errors.Wrap(err, "failed to connect to db")
	}

	// list tenants only
	if listTenantsFlag {
		return listTenants(db)
	}

	db = db.WithAutomigrate().(*mongo.DataStoreMongo)

	tenantCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})

	dbname := mstore.DbFromContext(tenantCtx, mongo.DbName)
	if err != nil {
		return errors.Wrap(err, "failed to decode dbname")
	}

	err = db.MigrateTenant(tenantCtx, dbname, mongo.DbVersion)
	if err != nil {
		return errors.Wrap(err, "failed to run migrations")
	}

	return nil
}

func listTenants(db *mongo.DataStoreMongo) error {
	tdbs, err := db.GetTenantDbs()
	if err != nil {
		return errors.Wrap(err, "failed to retrieve tenant DBs")
	}

	for _, tenant := range tdbs {
		fmt.Println(mstore.TenantFromDbName(tenant, mongo.DbName))
	}

	return nil
}

func Maintenance(decommissioningCleanupFlag bool, tenant string, dryRunFlag bool) error {
	db, err := mongo.NewDataStoreMongo(makeDataStoreConfig())
	if err != nil {
		return errors.Wrap(err, "failed to connect to db")
	}

	return maintenanceWithDataStore(decommissioningCleanupFlag, tenant, dryRunFlag, db)
}

func maintenanceWithDataStore(decommissioningCleanupFlag bool, tenant string, dryRunFlag bool, db *mongo.DataStoreMongo) error {
	// cleanup devauth database from leftovers after failed decommissioning
	if decommissioningCleanupFlag {
		return decommissioningCleanup(db, tenant, dryRunFlag)
	}

	return nil
}

func decommissioningCleanup(db *mongo.DataStoreMongo, tenant string, dryRunFlag bool) error {
	if tenant == "" {
		tdbs, err := db.GetTenantDbs()
		if err != nil {
			return errors.Wrap(err, "failed to retrieve tenant DBs")
		}
		decommissioningCleanupWithDbs(db, append(tdbs, mongo.DbName), dryRunFlag)
	} else {
		decommissioningCleanupWithDbs(db, []string{mstore.DbNameForTenant(tenant, mongo.DbName)}, dryRunFlag)
	}

	return nil
}

func decommissioningCleanupWithDbs(db *mongo.DataStoreMongo, tenantDbs []string, dryRunFlag bool) error {
	for _, dbName := range tenantDbs {
		println("database: ", dbName)
		if err := decommissioningCleanupWithDb(db, dbName, dryRunFlag); err != nil {
			return err
		}
	}
	return nil
}

func decommissioningCleanupWithDb(db *mongo.DataStoreMongo, dbName string, dryRunFlag bool) error {
	if dryRunFlag {
		return decommissioningCleanupDryRun(db, dbName)
	} else {
		return decommissioningCleanupExecute(db, dbName)
	}
}

func decommissioningCleanupDryRun(db *mongo.DataStoreMongo, dbName string) error {
	//devices
	devices, err := db.GetDevicesBeingDecommissioned(dbName)
	if err != nil {
		return err
	}
	fmt.Println("devices with decommissioning flag set:")
	for _, dev := range devices {
		fmt.Println(dev.Id)
	}

	//auth sets
	authSetIds, err := db.GetBrokenAuthSets(dbName)
	if err != nil {
		return err
	}
	fmt.Println("authentication sets to be removed:")
	for _, authSetId := range authSetIds {
		fmt.Println(authSetId)
	}

	//tokens
	tokenIds, err := db.GetBrokenTokens(dbName)
	if err != nil {
		return err
	}

	fmt.Println("tokens to be removed:")
	for _, tokenId := range tokenIds {
		fmt.Println(tokenId)
	}

	return nil
}

func decommissioningCleanupExecute(db *mongo.DataStoreMongo, dbName string) error {
	if err := decommissioningCleanupDryRun(db, dbName); err != nil {
		return err
	}

	if err := db.DeleteDevicesBeingDecommissioned(dbName); err != nil {
		return err
	}

	if err := db.DeleteBrokenAuthSets(dbName); err != nil {
		return err
	}

	if err := db.DeleteBrokenTokens(dbName); err != nil {
		return err
	}

	return nil
}
