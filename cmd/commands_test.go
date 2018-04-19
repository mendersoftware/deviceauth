// Copyright 2018 Northern.tech AS
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
	"testing"

	"github.com/mendersoftware/go-lib-micro/identity"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/stretchr/testify/assert"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store/mongo"
)

func TestMaintenance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestMaintenance in short mode.")
	}

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
			tenant: "foo",
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
			tenant:       "foo",
			dryRunFlag:   true,
			withDataSets: true,
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
			tenant:       "foo",
			withDataSets: true,
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
