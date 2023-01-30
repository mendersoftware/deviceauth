// Copyright 2023 Northern.tech AS
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	    http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.
package cmd

import (
	"context"
	"fmt"

	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	mstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"

	cinv "github.com/mendersoftware/deviceauth/client/inventory"
	"github.com/mendersoftware/deviceauth/client/orchestrator"
	"github.com/mendersoftware/deviceauth/client/tenant"
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

	if config.Config.Get(dconfig.SettingTenantAdmAddr) != "" {
		db = db.WithMultitenant()
	}

	ctx := context.Background()
	if tenant == "" {
		err = db.Migrate(ctx, mongo.DbVersion)
	} else {
		tenantCtx := identity.WithContext(ctx, &identity.Identity{
			Tenant: tenant,
		})
		dbname := mstore.DbFromContext(tenantCtx, mongo.DbName)
		err = db.MigrateTenant(tenantCtx, dbname, mongo.DbVersion)
	}
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

func maintenanceWithDataStore(
	decommissioningCleanupFlag bool,
	tenant string,
	dryRunFlag bool,
	db *mongo.DataStoreMongo,
) error {
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
		_ = decommissioningCleanupWithDbs(db, append(tdbs, mongo.DbName), dryRunFlag)
	} else {
		_ = decommissioningCleanupWithDbs(
			db,
			[]string{mstore.DbNameForTenant(tenant, mongo.DbName)},
			dryRunFlag,
		)
	}

	return nil
}

func decommissioningCleanupWithDbs(
	db *mongo.DataStoreMongo,
	tenantDbs []string,
	dryRunFlag bool,
) error {
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

	if err := db.DeleteBrokenAuthSets(dbName); err != nil {
		return err
	}

	return nil
}

func PropagateStatusesInventory(
	db store.DataStore,
	c cinv.Client,
	tenant string,
	migrationVersion string,
	dryRun bool,
) error {
	l := log.NewEmpty()

	dbs, err := selectDbs(db, tenant)
	if err != nil {
		return errors.Wrap(err, "aborting")
	}

	var errReturned error
	for _, d := range dbs {
		err := tryPropagateStatusesInventoryForDb(db, c, d, migrationVersion, dryRun)
		if err != nil {
			errReturned = err
			l.Errorf("giving up on DB %s due to fatal error: %s", d, err.Error())
			continue
		}
	}

	l.Info("all DBs processed, exiting.")
	return errReturned
}

func PropagateIdDataInventory(db store.DataStore, c cinv.Client, tenant string, dryRun bool) error {
	l := log.NewEmpty()

	dbs, err := selectDbs(db, tenant)
	if err != nil {
		return errors.Wrap(err, "aborting")
	}

	var errReturned error
	for _, d := range dbs {
		err := tryPropagateIdDataInventoryForDb(db, c, d, dryRun)
		if err != nil {
			errReturned = err
			l.Errorf("giving up on DB %s due to fatal error: %s", d, err.Error())
			continue
		}
	}

	l.Info("all DBs processed, exiting.")
	return errReturned
}

func PropagateReporting(db store.DataStore, wflows orchestrator.ClientRunner, tenant string,
	dryRun bool) error {
	l := log.NewEmpty()

	dbs, err := selectDbs(db, tenant)
	if err != nil {
		return errors.Wrap(err, "aborting")
	}

	var errReturned error
	for _, d := range dbs {
		err := tryPropagateReportingForDb(db, wflows, d, dryRun)
		if err != nil {
			errReturned = err
			l.Errorf("giving up on DB %s due to fatal error: %s", d, err.Error())
			continue
		}
	}

	l.Info("all DBs processed, exiting.")
	return errReturned
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

const (
	devicesBatchSize = 512
)

func updateDevicesStatus(
	ctx context.Context,
	db store.DataStore,
	c cinv.Client,
	tenant string,
	status string,
	dryRun bool,
) error {
	var skip uint

	skip = 0
	for {
		devices, err := db.GetDevices(ctx,
			skip,
			devicesBatchSize,
			model.DeviceFilter{Status: []string{status}},
		)
		if err != nil {
			return errors.Wrap(err, "failed to get devices")
		}

		if len(devices) < 1 {
			break
		}

		deviceUpdates := make([]model.DeviceInventoryUpdate, len(devices))

		for i, d := range devices {
			deviceUpdates[i].Id = d.Id
			deviceUpdates[i].Revision = d.Revision
		}

		if !dryRun {
			err = c.SetDeviceStatus(ctx, tenant, deviceUpdates, status)
			if err != nil {
				return err
			}
		}

		if len(devices) < devicesBatchSize {
			break
		} else {
			skip += devicesBatchSize
		}
	}
	return nil
}

func updateDevicesIdData(
	ctx context.Context,
	db store.DataStore,
	c cinv.Client,
	tenant string,
	dryRun bool,
) error {
	var skip uint

	skip = 0
	for {
		devices, err := db.GetDevices(ctx, skip, devicesBatchSize, model.DeviceFilter{})
		if err != nil {
			return errors.Wrap(err, "failed to get devices")
		}

		if len(devices) < 1 {
			break
		}

		if !dryRun {
			for _, d := range devices {
				err := c.SetDeviceIdentity(ctx, tenant, d.Id, d.IdDataStruct)
				if err != nil {
					return err
				}
			}
		}

		skip += devicesBatchSize
		if len(devices) < devicesBatchSize {
			break
		}
	}
	return nil
}

func tryPropagateStatusesInventoryForDb(
	db store.DataStore,
	c cinv.Client,
	dbname string,
	migrationVersion string,
	dryRun bool,
) error {
	l := log.NewEmpty()

	l.Infof("propagating device statuses to inventory from DB: %s", dbname)

	tenant := mstore.TenantFromDbName(dbname, mongo.DbName)

	ctx := context.Background()
	if tenant != "" {
		ctx = identity.WithContext(ctx, &identity.Identity{
			Tenant: tenant,
		})
	}

	var err error
	var errReturned error
	for _, status := range model.DevStatuses {
		err = updateDevicesStatus(ctx, db, c, tenant, status, dryRun)
		if err != nil {
			l.Infof(
				"Done with DB %s status=%s, but there were errors: %s.",
				dbname,
				status,
				err.Error(),
			)
			errReturned = err
		} else {
			l.Infof("Done with DB %s status=%s", dbname, status)
		}
	}
	if migrationVersion != "" && !dryRun {
		if errReturned != nil {
			l.Warnf(
				"Will not store %s migration version in %s.migration_info due to errors.",
				migrationVersion,
				dbname,
			)
		} else {
			version, err := migrate.NewVersion(migrationVersion)
			if version == nil || err != nil {
				l.Warnf(
					"Will not store %s migration version in %s.migration_info due to bad version"+
						" provided.",
					migrationVersion,
					dbname,
				)
				errReturned = err
			} else {
				_ = db.StoreMigrationVersion(ctx, version)
			}
		}
	}

	return errReturned
}

func tryPropagateIdDataInventoryForDb(
	db store.DataStore,
	c cinv.Client,
	dbname string,
	dryRun bool,
) error {
	l := log.NewEmpty()

	l.Infof("propagating device id_data to inventory from DB: %s", dbname)

	tenant := mstore.TenantFromDbName(dbname, mongo.DbName)

	ctx := context.Background()
	if tenant != "" {
		ctx = identity.WithContext(ctx, &identity.Identity{
			Tenant: tenant,
		})
	}

	err := updateDevicesIdData(ctx, db, c, tenant, dryRun)
	if err != nil {
		l.Infof("Done with DB %s, but there were errors: %s.", dbname, err.Error())
	} else {
		l.Infof("Done with DB %s", dbname)
	}

	return err
}

func tryPropagateReportingForDb(
	db store.DataStore,
	wflows orchestrator.ClientRunner,
	dbname string,
	dryRun bool,
) error {
	l := log.NewEmpty()

	l.Infof("propagating device data to reporting from DB: %s", dbname)

	tenant := mstore.TenantFromDbName(dbname, mongo.DbName)

	ctx := context.Background()
	if tenant != "" {
		ctx = identity.WithContext(ctx, &identity.Identity{
			Tenant: tenant,
		})
	}

	err := reindexDevicesReporting(ctx, db, wflows, tenant, dryRun)
	if err != nil {
		l.Infof("Done with DB %s, but there were errors: %s.", dbname, err.Error())
	} else {
		l.Infof("Done with DB %s", dbname)
	}

	return err
}

func reindexDevicesReporting(
	ctx context.Context,
	db store.DataStore,
	wflows orchestrator.ClientRunner,
	tenant string,
	dryRun bool,
) error {
	var skip uint

	skip = 0
	for {
		devices, err := db.GetDevices(ctx, skip, devicesBatchSize, model.DeviceFilter{})
		if err != nil {
			return errors.Wrap(err, "failed to get devices")
		}

		if len(devices) < 1 {
			break
		}

		if !dryRun {
			deviceIDs := make([]string, len(devices))
			for i, d := range devices {
				deviceIDs[i] = d.Id
			}
			err := wflows.SubmitReindexReportingBatch(ctx, deviceIDs)
			if err != nil {
				return err
			}
		}

		skip += devicesBatchSize
		if len(devices) < devicesBatchSize {
			break
		}
	}
	return nil
}

const (
	WorkflowsDeviceLimitText    = "@/etc/workflows-enterprise/data/device_limit_email.txt"
	WorkflowsDeviceLimitHTML    = "@/etc/workflows-enterprise/data/device_limit_email.html"
	WorkflowsDeviceLimitSubject = "Device limit almost reached"
)

func warnTenantUsers(
	ctx context.Context,
	tenantID string,
	tadm tenant.ClientRunner,
	wflows orchestrator.ClientRunner,
	remainingDevices uint,
) error {
	users, err := tadm.GetTenantUsers(ctx, tenantID)
	if err != nil {
		// Log the event and continue with the other tenants
		return err
	}
	for i := range users {
		warnWFlow := orchestrator.DeviceLimitWarning{
			RequestID:      "deviceAuthAdmin",
			RecipientEmail: users[i].Email,

			Subject:          WorkflowsDeviceLimitSubject,
			Body:             WorkflowsDeviceLimitText,
			BodyHTML:         WorkflowsDeviceLimitHTML,
			RemainingDevices: &remainingDevices,
		}
		err = wflows.SubmitDeviceLimitWarning(ctx, warnWFlow)
		if err != nil {
			return err
		}
	}
	return nil
}

// CheckDeviceLimits goes through all tenant databases and checks if the number
// of accepted devices is above a given threshold (in %) and sends an email
// to all registered users registered under the given tenant.
func CheckDeviceLimits(
	threshold float64,
	ds store.DataStore,
	tadm tenant.ClientRunner,
	wflows orchestrator.ClientRunner,
) error {
	// Sanitize threshold
	if threshold > 100.0 {
		threshold = 100.0
	} else if threshold < 0.0 {
		threshold = 0.0
	}
	threshProportion := threshold / 100.0

	// mapFunc is applied to all existing databases in datastore.
	mapFunc := func(ctx context.Context) error {
		id := identity.FromContext(ctx)
		if id == nil || id.Tenant == "" {
			// Not a tenant db - skip!
			return nil
		}
		tenantID := id.Tenant
		l := log.FromContext(ctx)

		lim, err := ds.GetLimit(ctx, model.LimitMaxDeviceCount)
		if err != nil {
			return err
		}
		n, err := ds.GetDevCountByStatus(ctx, model.DevStatusAccepted)
		if err != nil {
			return err
		}
		if float64(n) >= (float64(lim.Value) * threshProportion) {
			// User is above limit

			remainingUsers := uint(n) - uint(lim.Value)
			err := warnTenantUsers(ctx, tenantID, tadm, wflows, remainingUsers)
			if err != nil {
				l.Warnf(`Failed to warn tenant "%s" `+
					`users nearing device limit: %s`,
					tenantID, err.Error(),
				)
			}
		}
		return nil
	}
	// Start looping through the databases.
	return ds.ForEachDatabase(
		context.Background(),
		mapFunc,
	)
}
