// Copyright 2019 Northern.tech AS
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
	"encoding/json"
	"fmt"
	"sort"

	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/log"
	mstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"

	cinv "github.com/mendersoftware/deviceauth/client/inventory"
	dconfig "github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	"github.com/mendersoftware/deviceauth/store/mongo"
	"github.com/mendersoftware/deviceauth/utils"
)

var NowUnixMilis = utils.UnixMilis

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
	if len(devices) > 0 {
		fmt.Println("devices with decommissioning flag set:")
		for _, dev := range devices {
			fmt.Println(dev.Id)
		}
	}

	//auth sets
	authSetIds, err := db.GetBrokenAuthSets(dbName)
	if err != nil {
		return err
	}
	if len(authSetIds) > 0 {
		fmt.Println("authentication sets to be removed:")
		for _, authSetId := range authSetIds {
			fmt.Println(authSetId)
		}
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

	// Deletes broken auth sets and associated JWT tokens.
	if err := db.DeleteBrokenAuthSets(dbName); err != nil {
		return err
	}

	return nil
}

func PropagateInventory(db store.DataStore, c cinv.Client, tenant string, dryrun bool) error {
	l := log.NewEmpty()

	dbs, err := selectDbs(db, tenant)
	if err != nil {
		return errors.Wrap(err, "aborting")
	}

	for _, d := range dbs {
		err := tryPropagateInventoryForDb(db, c, d, dryrun)
		if err != nil {
			l.Errorf("giving up on DB %s due to fatal error: %s", d, err.Error())
			continue
		}
	}

	l.Info("all DBs processed, exiting.")
	return nil
}

func selectDbs(db store.DataStore, tenant string) ([]string, error) {
	l := log.NewEmpty()

	var dbs []string

	if tenant != "" {
		l.Infof("propagating inventory for user-specified tenant %s", tenant)
		n := mstore.DbNameForTenant(tenant, mongo.DbName)
		dbs = []string{n}
	} else {
		l.Infof("propagating inventory for all tenants")

		// infer if we're in ST or MT
		tdbs, err := db.GetTenantDbs()
		if err != nil {
			return nil, errors.Wrap(err, "failed to retrieve tenant DBs")
		}

		if len(tdbs) == 0 {
			l.Infof("no tenant DBs found - will try the default database %s", mongo.DbName)
			dbs = []string{mongo.DbName}
		} else {
			dbs = tdbs
		}
	}

	return dbs, nil
}

func tryPropagateInventoryForDb(db store.DataStore, c cinv.Client, dbname string, dryrun bool) error {
	l := log.NewEmpty()

	l.Infof("propagating inventory from DB: %s", dbname)

	tenant := mstore.TenantFromDbName(dbname, mongo.DbName)

	ctx := context.Background()
	if tenant != "" {
		ctx = identity.WithContext(ctx, &identity.Identity{
			Tenant: tenant,
		})
	}

	skip := 0
	limit := 100
	errs := false
	for {
		devs, err := db.GetDevices(ctx, uint(skip), uint(limit), store.DeviceFilter{})
		if err != nil {
			return errors.Wrap(err, "failed to get devices")
		}

		for _, d := range devs {
			l.Infof("propagating device %s", d.Id)
			err := propagateSingleDevice(d, c, tenant, dryrun)
			if err != nil {
				errs = true
				l.Errorf("FAILED: %s", err.Error())
				continue
			}
		}

		if len(devs) < limit {
			break
		} else {
			skip += limit
		}
	}

	if errs {
		l.Infof("Done with DB %s, but there were errors", dbname)
	} else {
		l.Infof("Done with DB %s", dbname)
	}

	return nil
}

func propagateSingleDevice(d model.Device, c cinv.Client, tenant string, dryrun bool) error {
	attrs, err := idDataToInventoryAttrs(d.IdDataStruct)
	if err != nil {
		return err
	}

	if !dryrun {
		err = c.PatchDeviceV2(context.Background(), d.Id, tenant, "deviceauth", NowUnixMilis(), attrs)
		if err != nil {
			return err
		}
	}

	return nil
}

func idDataToInventoryAttrs(id map[string]interface{}) ([]cinv.Attribute, error) {
	var out []cinv.Attribute

	for k, v := range id {
		a := cinv.Attribute{
			Name:  k,
			Scope: "identity",
		}
		venc, err := json.Marshal(v)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to encode attribute %s, value: %v", k, v)
		}

		a.Value = string(venc)
		out = append(out, a)
	}

	// mostly for testability tbh - iteration over map = random order
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})

	return out, nil
}
