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
	"fmt"
	"testing"

	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/identity"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	minv "github.com/mendersoftware/deviceauth/client/inventory/mocks"
	dconfig "github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
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
			Id:              "001",
			IdData:          "001",
			PubKey:          "001",
			Status:          model.DevStatusPending,
			Decommissioning: false,
		},
		model.Device{
			Id:              "002",
			IdData:          "002",
			PubKey:          "002",
			Status:          model.DevStatusPending,
			Decommissioning: true,
		},
	}

	datasetAuthSets := []interface{}{
		model.AuthSet{
			Id:       "001",
			DeviceId: "001",
			IdData:   "001",
			PubKey:   "001",
		},
		model.AuthSet{
			Id:       "002",
			DeviceId: "003",
			IdData:   "001",
			PubKey:   "002",
		},
	}

	datasetTokens := []interface{}{
		model.Token{
			Id:        "001",
			DevId:     "001",
			AuthSetId: "001",
			Token:     "foo",
		},
		model.Token{
			Id:        "002",
			DevId:     "003",
			AuthSetId: "002",
			Token:     "bar",
		},
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
		session := db.Session()
		ctx := context.Background()
		if tc.tenant != "" {
			ctx = identity.WithContext(ctx, &identity.Identity{
				Tenant: tc.tenant,
			})
		}
		ds := mongo.NewDataStoreMongoWithSession(session)

		if tc.withDataSets {

			testDbName := mongo.DbName
			if tc.tenant != "" {
				testDbName = ctxstore.DbNameForTenant(tc.tenant, mongo.DbName)
			}

			err := session.DB(testDbName).C(mongo.DbDevicesColl).Insert(datasetDevices...)
			assert.NoError(t, err)
			err = session.DB(testDbName).C(mongo.DbAuthSetColl).Insert(datasetAuthSets...)
			assert.NoError(t, err)
			err = session.DB(testDbName).C(mongo.DbTokensColl).Insert(datasetTokens...)
			assert.NoError(t, err)
		}

		err := maintenanceWithDataStore(tc.decommissioningCleanupFlag, tc.tenant, tc.dryRunFlag, ds)
		assert.NoError(t, err)

		session.Close()

	}
}

func TestPropagateInventory(t *testing.T) {
	devSet1 := []model.Device{
		model.Device{
			Id: "001",
			IdDataStruct: map[string]interface{}{
				"mac": "mac001",
				"sn":  "sn001",
			},
		},
		model.Device{
			Id: "002",
			IdDataStruct: map[string]interface{}{
				"mac":    "mac002",
				"number": 123,
			},
		},
	}

	devSet2 := []model.Device{
		model.Device{
			Id: "003",
			IdDataStruct: map[string]interface{}{
				"mac": "mac003",
			},
		},
		model.Device{
			Id: "004",
			IdDataStruct: map[string]interface{}{
				"mac":    "mac004",
				"sn":     "sn004",
				"number": 345,
				"arrstr": []string{"s1", "s2", "s3"},
			},
		},
		model.Device{
			Id: "005",
			IdDataStruct: map[string]interface{}{
				"mac":    "mac005",
				"sn":     "sn005",
				"arrnum": []float64{1.0, 2.4, 3.5},
			},
		},
	}

	cases := map[string]struct {
		dbDevs map[string][]model.Device

		cmdTenant string
		cmdDryRun bool

		errDbTenants error
		errDbDevices error
		errPatch     error

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
			//err: nil
		},
		"error: patch devices, report but don't abort": {
			dbDevs: map[string][]model.Device{
				"deviceauth-tenant1": devSet1,
				"deviceauth-tenant2": devSet2,
			},
			errPatch: errors.New("service failure"),
			//err: nil
		},
	}

	for k, _ := range cases {
		tc := cases[k]
		t.Run(fmt.Sprintf("tc %s", k), func(t *testing.T) {

			db := &mstore.DataStore{}

			// setup GetTenantDbs
			// first, infer if we're in ST or MT
			st := len(tc.dbDevs) == 1 && tc.dbDevs["deviceauth"] != nil
			if st {
				db.On("GetTenantDbs").Return([]string{}, tc.errDbTenants)
			} else {
				dbs := []string{}
				for k, _ := range tc.dbDevs {
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
				db.On("GetDevices",
					context.Background(),
					uint(0),
					uint(100),
					store.DeviceFilter{}).Return(
					dbs["deviceauth"],
					tc.errDbDevices)
			} else {
				for k, v := range dbs {
					tname := ctxstore.TenantFromDbName(k, mongo.DbName)
					m := mock.MatchedBy(func(c context.Context) bool {
						id := identity.FromContext(c)
						return id.Tenant == tname
					})

					db.On("GetDevices",
						m,
						uint(0),
						uint(100),
						store.DeviceFilter{}).Return(
						v,
						tc.errDbDevices)
				}
			}

			// setup client PatchDeviceV2
			//(dry run, time source, no tenant/all tenants/selected tenant)
			NowUnixMilis = func() int64 { return int64(123456) }

			c := &minv.Client{}

			if tc.cmdDryRun == false {
				for n, devs := range dbs {
					for _, d := range devs {
						tenant := ctxstore.TenantFromDbName(n, mongo.DbName)
						attrs, err := idDataToInventoryAttrs(d.IdDataStruct)

						assert.NoError(t, err)

						c.On("PatchDeviceV2",
							context.Background(),
							d.Id,
							tenant,
							"deviceauth",
							int64(123456),
							attrs).Return(tc.errPatch)
					}
				}
			}

			if tc.cmdDryRun == true {
				c.AssertNotCalled(t, "PatchDeviceV2")
			}

			err := PropagateInventory(db, c, tc.cmdTenant, tc.cmdDryRun)
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
