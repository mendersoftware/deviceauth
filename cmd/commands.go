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
	"encoding/json"
	"fmt"
	"github.com/mendersoftware/go-lib-micro/mongo/oid"
	"github.com/mendersoftware/go-lib-micro/ratelimits"
	"time"

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
		err = db.MigrateTenant(ctx, mongo.DbName, mongo.DbVersion)
		if err != nil {
			return errors.Wrap(err, "failed to migrate main db")
		}

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
	tdbs, err := db.ListTenantsIds(context.Background())
	if err != nil {
		return errors.Wrap(err, "failed to retrieve tenant ids")
	}

	for _, tenant := range tdbs {
		fmt.Println(tenant)
	}

	return nil
}

func Diag(
	tenant string,
	listAll bool,
	deviceId string,
	insert bool,
	delete string,
	dryRunFlag bool,
) error {
	fmt.Println("deviceauth diagnostics.")
	fmt.Println("connecting to db")
	db, err := mongo.NewDataStoreMongo(makeDataStoreConfig())
	if err != nil {
		fmt.Printf("failed to connect to mongourl: %s\n", config.Config.GetString(dconfig.SettingDb))
		return errors.Wrap(err, "failed to connect to db")
	}
	fmt.Printf("connected to mongourl: %s\n", config.Config.GetString(dconfig.SettingDb))
	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Second)
	defer cancel()
	if listAll {
		var tenants []string
		if len(tenant)>0 {
			tenants=[]string{tenant}
		} else {
		tenants, err = db.ListTenantsIds(context.Background())
		if err != nil {
			fmt.Printf("error looking for all tenants: %s\n", err.Error())
		}
		}
		fmt.Printf("looking for all devices for all %d tenants\n", len(tenants))

		for _, t := range tenants {
			ctx = context.Background()
			ctx = identity.WithContext(ctx, &identity.Identity{
				Tenant: t,
			})
			devices, err := db.GetDevices(ctx, 0, 8388480, model.DeviceFilter{})
			if err != nil {
				fmt.Printf("error looking for devices: %s\n", err.Error())
			}
			fmt.Printf("listing all %d devices for tenant %s\n", len(devices), t)
			for _, d := range devices {
				fmt.Printf("%s\n", d.Id)
			}
		}
		return nil
	}
	if len(deviceId) < 1 {

	} else {
		fmt.Printf("checking device of id: %s\n", deviceId)
		ctx = identity.WithContext(ctx, &identity.Identity{
			Tenant: tenant,
		})
		device, err := db.GetDeviceById(ctx, deviceId)
		if err != nil {
			fmt.Printf("error looking for device of id: %s; %s\n", deviceId, err.Error())
		}
		if device == nil {
			fmt.Printf("cant find device of id: %s\n", deviceId)
			tenants, err := db.ListTenantsIds(context.Background())
			if err != nil {
				fmt.Printf("error looking for all tenants: %s\n", err.Error())
			}
			fmt.Printf("looking for all devices for all %d tenants\n", len(tenants))

			for _, t := range tenants {
				ctx = context.Background()
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: t,
				})
				devices, err := db.GetDevices(ctx, 0, 8388480, model.DeviceFilter{})
				if err != nil {
					fmt.Printf("error looking for devices: %s\n", err.Error())
				}
				fmt.Printf("listing all %d devices for tenant %s\n", len(devices), t)
				for _, d := range devices {
					fmt.Printf("%s\n", d.Id)
				}
			}
			// now delete a device, insert a dummy device
		}
		if device != nil {
			jsonDevice, _ := json.MarshalIndent(*device, "", " ")
			fmt.Printf("found device: +%v\n%s\n", *device, string(jsonDevice))
		}
	}
	if insert {
		ctx = identity.WithContext(ctx, &identity.Identity{
			Tenant: tenant,
		})
		newId := oid.NewUUIDv4().String()
		fmt.Printf("adding a device: %s\n", newId)
		err = db.AddDevice(ctx, model.Device{
			Id:              newId,
			IdData:          "some-id" + newId,
			IdDataStruct:    map[string]interface{}{"some-id-k0": "some-id-v0"},
			IdDataSha256:    []byte("some-hash" + newId),
			Status:          "preauthorized",
			Decommissioning: false,
			CreatedTs:       time.Now(),
			UpdatedTs:       time.Now(),
			AuthSets:        nil,
			CheckInTime:     nil,
			ApiLimits:       ratelimits.ApiLimits{},
			Revision:        0,
			TenantID:        tenant,
		})
		if err != nil {
			fmt.Printf("failed to add a device: %s\n", err.Error())
		} else {
			device, err := db.GetDeviceById(ctx, newId)
			if err != nil {
				fmt.Printf("failed to get the just added device: %s\n", err.Error())
			} else {
				if device == nil {
					fmt.Printf("cant find the just added device\n")
				} else {
					jsonDevice, _ := json.MarshalIndent(*device, "", " ")
					fmt.Printf("found just added device: +%v\n%s\n", *device, jsonDevice)
					if len(delete) > 0 {
						if delete != "%inserted" {
							newId = delete
						}
						fmt.Printf("removing inserted device %s\n", newId)
						err = db.DeleteDevice(ctx, newId)
						fmt.Printf("removing inserted device rc:%+v\n", err)
						device, err = db.GetDeviceById(ctx, newId)
						fmt.Printf("getting inserted-removed device rc:%+v\n", err)
						if device != nil {
							jsonDevice, _ = json.MarshalIndent(*device, "", " ")
							fmt.Printf("(!) found just removed device: +%v\n%s\n", *device, jsonDevice)
						}
					}
				}
			}
		}
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
	if dryRunFlag {
		return decommissioningCleanupDryRun(db, tenant)
	} else {
		return decommissioningCleanupExecute(db, tenant)
	}
}

func decommissioningCleanupDryRun(db *mongo.DataStoreMongo, tenantId string) error {
	//devices
	devices, err := db.GetDevicesBeingDecommissioned(tenantId)
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
	authSetIds, err := db.GetBrokenAuthSets(tenantId)
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

func decommissioningCleanupExecute(db *mongo.DataStoreMongo, tenantId string) error {
	if err := decommissioningCleanupDryRun(db, tenantId); err != nil {
		return err
	}

	if err := db.DeleteDevicesBeingDecommissioned(tenantId); err != nil {
		return err
	}

	if err := db.DeleteBrokenAuthSets(tenantId); err != nil {
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
	var err error

	l := log.NewEmpty()
	tenants := []string{tenant}
	if tenant == "" {
		tenants, err = db.ListTenantsIds(context.Background())
		if err != nil {
			return errors.Wrap(err, "cant list tenants")
		}
	}

	var errReturned error
	for _, t := range tenants {
		err = tryPropagateStatusesInventoryForTenant(db, c, t, migrationVersion, dryRun)
		if err != nil {
			errReturned = err
			l.Errorf("giving up on tenant %s due to fatal error: %s", t, err.Error())
			continue
		}
	}

	l.Info("all tenants processed, exiting.")
	return errReturned
}

func PropagateIdDataInventory(db store.DataStore, c cinv.Client, tenant string, dryRun bool) error {
	var err error

	l := log.NewEmpty()
	tenants := []string{tenant}
	if tenant == "" {
		tenants, err = db.ListTenantsIds(context.Background())
		if err != nil {
			return errors.Wrap(err, "cant list tenants")
		}
	}

	var errReturned error
	for _, d := range tenants {
		err := tryPropagateIdDataInventoryForTenant(db, c, d, dryRun)
		if err != nil {
			errReturned = err
			l.Errorf("giving up on tenant %s due to fatal error: %s", d, err.Error())
			continue
		}
	}

	l.Info("all tenants processed, exiting.")
	return errReturned
}

func PropagateReporting(
	db store.DataStore,
	wflows orchestrator.ClientRunner,
	tenant string,
	requestPeriod time.Duration,
	dryRun bool) error {
	l := log.NewEmpty()

	mapFunc := func(ctx context.Context) error {
		id := identity.FromContext(ctx)
		if id == nil || id.Tenant == "" {
			// Not a tenant db - skip!
			return nil
		}
		tenantId := id.Tenant
		return tryPropagateReportingForTenant(db, wflows, tenantId, requestPeriod, dryRun)
	}
	if tenant != "" {
		ctx := identity.WithContext(context.Background(),
			&identity.Identity{
				Tenant: tenant,
			},
		)
		err := mapFunc(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to propagate for given tenant")
		}
		l.Infof("tenant processed, exiting.")
	} else {
		err := db.ForEachTenant(context.Background(), mapFunc)
		if err != nil {
			return errors.Wrap(err, "failed to propagate for all tenant")
		}
		l.Info("all tenants processed, exiting.")
	}
	return nil
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

func tryPropagateStatusesInventoryForTenant(
	db store.DataStore,
	c cinv.Client,
	tenant string,
	migrationVersion string,
	dryRun bool,
) error {
	l := log.NewEmpty()

	l.Infof("propagating device statuses to inventory from tenant: %s", tenant)

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
				"Done with tenant %s status=%s, but there were errors: %s.",
				tenant,
				status,
				err.Error(),
			)
			errReturned = err
		} else {
			l.Infof("Done with tenant %s status=%s", tenant, status)
		}
	}
	if migrationVersion != "" && !dryRun {
		if errReturned != nil {
			l.Warnf(
				"Will not store %s migration version for tenant %s due to errors.",
				migrationVersion,
				tenant,
			)
		} else {
			version, err := migrate.NewVersion(migrationVersion)
			if version == nil || err != nil {
				l.Warnf(
					"Will not store %s migration version in %s.migration_info due to bad version"+
						" provided.",
					migrationVersion,
					tenant,
				)
				errReturned = err
			} else {
				_ = db.StoreMigrationVersion(ctx, version)
			}
		}
	}

	return errReturned
}

func tryPropagateIdDataInventoryForTenant(
	db store.DataStore,
	c cinv.Client,
	tenant string,
	dryRun bool,
) error {
	l := log.NewEmpty()

	l.Infof("propagating device id_data to inventory from tenant: %s", tenant)

	ctx := context.Background()
	if tenant != "" {
		ctx = identity.WithContext(ctx, &identity.Identity{
			Tenant: tenant,
		})
	}

	err := updateDevicesIdData(ctx, db, c, tenant, dryRun)
	if err != nil {
		l.Infof("Done with tenant %s, but there were errors: %s.", tenant, err.Error())
	} else {
		l.Infof("Done with tenant %s", tenant)
	}

	return err
}

func tryPropagateReportingForTenant(
	db store.DataStore,
	wflows orchestrator.ClientRunner,
	tenant string,
	requestPeriod time.Duration,
	dryRun bool,
) error {
	l := log.NewEmpty()

	l.Infof("propagating device data to reporting for tenant %s", tenant)

	ctx := context.Background()
	if tenant != "" {
		ctx = identity.WithContext(ctx, &identity.Identity{
			Tenant: tenant,
		})
	} else {
		return errors.New("you must provide a tenant id")
	}

	err := reindexDevicesReporting(ctx, requestPeriod, db, wflows, dryRun)
	if err != nil {
		l.Infof("Done with tenant %s, but there were errors: %s.", tenant, err.Error())
	} else {
		l.Infof("Done with tenant %s", tenant)
	}

	return err
}

func reindexDevicesReporting(
	ctx context.Context,
	requestPeriod time.Duration,
	db store.DataStore,
	wflows orchestrator.ClientRunner,
	dryRun bool,
) error {
	var skip uint

	skip = 0
	done := ctx.Done()
	rateLimit := time.NewTicker(requestPeriod)
	defer rateLimit.Stop()
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
		select {
		case <-rateLimit.C:

		case <-done:
			return ctx.Err()
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
	return ds.ForEachTenant(
		context.Background(),
		mapFunc,
	)
}
