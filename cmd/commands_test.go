// Copyright 2022 Northern.tech AS
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
	"testing"
	"time"

	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	"github.com/mendersoftware/go-lib-micro/mongo/oid"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	minv "github.com/mendersoftware/deviceauth/client/inventory/mocks"

	dconfig "github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/deviceauth/jwt"
	"github.com/mendersoftware/deviceauth/model"
	mstore "github.com/mendersoftware/deviceauth/store/mocks"
	"github.com/mendersoftware/deviceauth/store/mongo"
)

func TestMaintenance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestMaintenance in short mode.")
	}

	config.SetDefaults(config.Config, dconfig.Defaults)
	// Enable setting config values by environment variables
	config.Config.SetEnvPrefix("DEVICEAUTH")
	config.Config.AutomaticEnv()

	err := Maintenance(true, "", false)
	assert.NoError(t, err)
}

func TestMaintenanceWithDataStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestMaintenanceWithDataStore in short mode.")
	}
	datasetDevices := []interface{}{
		model.Device{
			Id:              oid.NewUUIDv5("001").String(),
			IdData:          "001",
			Status:          model.DevStatusPending,
			Decommissioning: false,
		},
		model.Device{
			Id:              oid.NewUUIDv5("002").String(),
			IdData:          "002",
			Status:          model.DevStatusPending,
			Decommissioning: true,
		},
	}

	datasetAuthSets := []interface{}{
		model.AuthSet{
			Id:       oid.NewUUIDv5("001").String(),
			DeviceId: oid.NewUUIDv5("001").String(),
			IdData:   "001",
			PubKey:   "001",
		},
		model.AuthSet{
			Id:       oid.NewUUIDv5("002").String(),
			DeviceId: oid.NewUUIDv5("003").String(),
			IdData:   "001",
			PubKey:   "002",
		},
	}

	datasetTokens := []interface{}{
		jwt.Token{Claims: jwt.Claims{
			ID:        oid.NewUUIDv5("001"),
			Subject:   oid.NewUUIDv5("001"),
			Issuer:    "Tester",
			ExpiresAt: jwt.Time{Time: time.Now().Add(time.Hour)},
		}},
		jwt.Token{Claims: jwt.Claims{
			ID:        oid.NewUUIDv5("002"),
			Subject:   oid.NewUUIDv5("003"),
			Issuer:    "Tester",
			ExpiresAt: jwt.Time{Time: time.Now().Add(time.Hour)},
		}},
	}

	testCases := map[string]struct {
		decommissioningCleanupFlag bool
		tenant                     string
		dryRunFlag                 bool
		withDataSets               bool
	}{
		"do nothing": {
			decommissioningCleanupFlag: false,
		},
		"do nothing with tenant": {
			decommissioningCleanupFlag: false,
			tenant:                     "foo",
		},
		"dry run without data": {
			decommissioningCleanupFlag: true,
			dryRunFlag:                 true,
		},
		"dry run": {
			decommissioningCleanupFlag: true,
			dryRunFlag:                 true,
			withDataSets:               true,
		},
		"dry run with tenant": {
			decommissioningCleanupFlag: true,
			tenant:                     "foo",
			dryRunFlag:                 true,
			withDataSets:               true,
		},
		"run without data": {
			decommissioningCleanupFlag: true,
		},
		"run": {
			decommissioningCleanupFlag: true,
			withDataSets:               true,
		},
		"run with tenant": {
			decommissioningCleanupFlag: true,
			tenant:                     "foo",
			withDataSets:               true,
		},
	}

	for name, tc := range testCases {
		t.Logf("case: %s", name)

		db.Wipe()
		client := db.Client()
		ctx := context.Background()
		if tc.tenant != "" {
			ctx = identity.WithContext(ctx, &identity.Identity{
				Tenant: tc.tenant,
			})
		}
		ds := mongo.NewDataStoreMongoWithClient(client)

		if tc.withDataSets {

			testDbName := mongo.DbName
			if tc.tenant != "" {
				testDbName = ctxstore.DbNameForTenant(tc.tenant, mongo.DbName)
			}

			c := client.Database(testDbName).Collection(mongo.DbDevicesColl)
			_, err := c.InsertMany(ctx, datasetDevices)
			assert.NoError(t, err)
			c = client.Database(testDbName).Collection(mongo.DbAuthSetColl)
			_, err = c.InsertMany(ctx, datasetAuthSets)
			assert.NoError(t, err)
			c = client.Database(testDbName).Collection(mongo.DbTokensColl)
			_, err = c.InsertMany(ctx, datasetTokens)
		}

		err := maintenanceWithDataStore(tc.decommissioningCleanupFlag, tc.tenant, tc.dryRunFlag, ds)
		assert.NoError(t, err)
	}
}

func TestPropagateStatusesInventory(t *testing.T) {
	devSet1 := []model.Device{
		{
			Id: "001",
		},
		{
			Id: "002",
		},
	}

	devSet2 := []model.Device{
		{
			Id: "003",
		},
		{
			Id: "004",
		},
		{
			Id: "005",
		},
	}

	cases := map[string]struct {
		dbDevs        map[string][]model.Device
		forcedVersion string

		cmdTenant string
		cmdDryRun bool

		errDbTenants error
		errDbDevices error
		setStatus    error

		err error
	}{
		"ok, default db, no tenant": {
			dbDevs: map[string][]model.Device{
				"deviceauth": devSet1,
			},
		},
		"ok, default db, no tenant, dry run": {
			dbDevs: map[string][]model.Device{
				"deviceauth": devSet1,
			},
			cmdDryRun: true,
		},
		"ok, >1 tenant, process all": {
			dbDevs: map[string][]model.Device{
				"deviceauth-tenant1": devSet1,
				"deviceauth-tenant2": devSet2,
			},
		},
		"ok, >1 tenant, process selected": {
			dbDevs: map[string][]model.Device{
				"deviceauth-tenant1": devSet1,
				"deviceauth-tenant2": devSet2,
			},
			cmdTenant: "tenant1",
		},
		"ok, with forced version": {
			dbDevs: map[string][]model.Device{
				"deviceauth-tenant1": devSet1,
				"deviceauth-tenant2": devSet2,
			},
			cmdTenant:     "tenant1",
			forcedVersion: "1.7.1",
		},
		"error, with bad forced version": {
			dbDevs: map[string][]model.Device{
				"deviceauth-tenant1": devSet1,
				"deviceauth-tenant2": devSet2,
			},
			cmdTenant:     "tenant1",
			forcedVersion: "and what this version might be",
			err:           errors.New("failed to parse Version: expected integer"),
		},
		"error: store get tenant dbs, abort": {
			dbDevs: map[string][]model.Device{
				"deviceauth-tenant1": devSet1,
				"deviceauth-tenant2": devSet2,
			},
			errDbTenants: errors.New("db failure"),

			err: errors.New("aborting: failed to retrieve tenant DBs: db failure"),
		},
		"error: store get devices, report but don't abort": {
			dbDevs: map[string][]model.Device{
				"deviceauth-tenant1": devSet1,
				"deviceauth-tenant2": devSet2,
			},
			errDbDevices: errors.New("db failure"),
			err:          errors.New("failed to get devices: db failure"),
		},
		"error: patch devices, report but don't abort": {
			dbDevs: map[string][]model.Device{
				"deviceauth-tenant1": devSet1,
				"deviceauth-tenant2": devSet2,
			},
			setStatus: errors.New("service failure"),
			err:       errors.New("service failure"),
		},
	}

	for k := range cases {
		tc := cases[k]
		t.Run(fmt.Sprintf("tc %s", k), func(t *testing.T) {
			var deviceStatuses = model.DevStatuses
			db := &mstore.DataStore{}
			v, _ := migrate.NewVersion(tc.forcedVersion)
			db.On("StoreMigrationVersion",
				mock.Anything,
				v).Return(nil)
			// setup GetTenantDbs
			// first, infer if we're in ST or MT
			st := len(tc.dbDevs) == 1 && tc.dbDevs["deviceauth"] != nil
			if st {
				db.On("GetTenantDbs").Return([]string{}, tc.errDbTenants)
			} else {
				dbs := []string{}
				for k := range tc.dbDevs {
					dbs = append(dbs, k)
				}
				db.On("GetTenantDbs").Return(dbs, tc.errDbTenants)
			}

			// 'final' dbs to include based on ST vs MT + tenant selection
			dbs := map[string][]model.Device{}
			if st {
				dbs["deviceauth"] = tc.dbDevs["deviceauth"]
			} else {
				if tc.cmdTenant != "" {
					k := "deviceauth-" + tc.cmdTenant
					dbs[k] = tc.dbDevs[k]
				} else {
					dbs = tc.dbDevs
				}
			}

			// setup GetDevices
			// only default db devs in ST, or
			// all devs in all dbs if no tenant selected
			// just one tenant dev set if tenant selected
			if st {
				for i := range deviceStatuses {
					db.On("GetDevices",
						context.Background(),
						uint(0),
						uint(512),
						model.DeviceFilter{Status: []string{deviceStatuses[i]}},
					).Return(
						dbs["deviceauth"],
						tc.errDbDevices,
					)
				}
			} else {
				for k, v := range dbs {
					tname := ctxstore.TenantFromDbName(k, mongo.DbName)
					m := mock.MatchedBy(func(c context.Context) bool {
						id := identity.FromContext(c)
						return id.Tenant == tname
					})

					for i := range deviceStatuses {
						db.On("GetDevices",
							m,
							uint(0),
							uint(512),
							model.DeviceFilter{Status: []string{deviceStatuses[i]}},
						).Return(
							v,
							tc.errDbDevices)
					}
				}
			}

			// setup client
			//(dry run, time source, no tenant/all tenants/selected tenant)
			NowUnixMilis = func() int64 { return int64(123456) }

			c := &minv.Client{}

			if tc.cmdDryRun == false {
				for n, devs := range dbs {
					devices := make([]model.DeviceInventoryUpdate, len(devs))
					for i, d := range devs {
						devices[i].Id = d.Id
					}
					tenant := ctxstore.TenantFromDbName(n, mongo.DbName)
					for _, status := range model.DevStatuses {
						c.On("SetDeviceStatus",
							mock.Anything,
							tenant,
							devices,
							status).Return(tc.setStatus)
					}
				}
			}

			if tc.cmdDryRun == true {
				c.AssertNotCalled(t, "SetDeviceStatus")
			}

			err := PropagateStatusesInventory(db, c, tc.cmdTenant, tc.forcedVersion, tc.cmdDryRun)
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
