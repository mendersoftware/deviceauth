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
package mongo

import (
	"context"
	"fmt"
	"testing"

	"github.com/mendersoftware/go-lib-micro/identity"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/stretchr/testify/assert"

	"github.com/mendersoftware/deviceauth/model"
)

func TestGetDevicesBeingDecommissioned(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetDevicesBeingDecommissioned in short mode.")
	}

	testCases := []struct {
		inDevices  []interface{}
		outDevices []model.Device
		tenant     string
	}{
		{
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: true,
				},
			},
			outDevices: []model.Device{
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: true,
				},
			},
		},
		{
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: true,
				},
			},
			outDevices: []model.Device{
				model.Device{
					Id: "002",
				},
			},
			tenant: tenant,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			testDbName := DbName
			if tc.tenant != "" {
				testDbName = ctxstore.DbNameForTenant(tc.tenant, DbName)
			}

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			db := getDb(ctx)
			defer db.session.Close()
			s := db.session.Copy()
			defer s.Close()

			coll := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)
			assert.NoError(t, coll.Insert(tc.inDevices...))

			brokenDevices, err := db.GetDevicesBeingDecommissioned(testDbName)
			assert.NoError(t, err)
			assert.Equal(t, tc.outDevices[0].Id, brokenDevices[0].Id)
		})
	}
}

func TestDeleteDevicesBeingDecommissioned(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestDeleteDevicesBeingDecommissioned in short mode.")
	}

	testCases := []struct {
		inDevices []interface{}
		tenant    string
	}{
		{
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: true,
				},
			},
		},
		{
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: true,
				},
			},
			tenant: tenant,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			testDbName := DbName
			if tc.tenant != "" {
				testDbName = ctxstore.DbNameForTenant(tc.tenant, DbName)
			}

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			db := getDb(ctx)
			defer db.session.Close()
			s := db.session.Copy()
			defer s.Close()

			coll := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)
			assert.NoError(t, coll.Insert(tc.inDevices...))

			err := db.DeleteDevicesBeingDecommissioned(testDbName)
			assert.NoError(t, err)

			dbDevs, err := db.GetDevices(ctx, 0, 5)
			assert.NoError(t, err)
			for _, dbDev := range dbDevs {
				assert.Equal(t, false, dbDev.Decommissioning)
			}
		})
	}
}

func TestGetBrokenAuthSets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetBrokenAuthSets in short mode.")
	}

	testCases := []struct {
		inAuthSets     []interface{}
		inDevices      []interface{}
		outAuthSetsIds []string
		tenant         string
		err            string
	}{
		{
			inAuthSets: []interface{}{
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
			},
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
			},
			outAuthSetsIds: []string{"002"},
			err:            "",
		},
		{
			inAuthSets: []interface{}{
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
			},
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
			},
			tenant:         tenant,
			outAuthSetsIds: []string{"002"},
			err:            "",
		},
		{
			inAuthSets: []interface{}{
				model.AuthSet{
					Id:       "001",
					DeviceId: "001",
					IdData:   "001",
					PubKey:   "001",
				},
				model.AuthSet{
					Id:       "002",
					DeviceId: "002",
					IdData:   "001",
					PubKey:   "002",
				},
			},
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: true,
				},
			},
			tenant:         tenant,
			outAuthSetsIds: []string{"002"},
			err:            "",
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			testDbName := DbName
			if tc.tenant != "" {
				testDbName = ctxstore.DbNameForTenant(tc.tenant, DbName)
			}

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			db := getDb(ctx)
			defer db.session.Close()
			s := db.session.Copy()
			defer s.Close()

			coll := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbAuthSetColl)
			assert.NoError(t, coll.Insert(tc.inAuthSets...))

			coll = s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)
			assert.NoError(t, coll.Insert(tc.inDevices...))

			brokenAuthSetsIds, err := db.GetBrokenAuthSets(testDbName)
			if tc.err != "" {
				assert.Equal(t, tc.err, err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.outAuthSetsIds, brokenAuthSetsIds)
			}
		})
	}
}

func TestDeleteBrokenAuthSets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestDeleteBrokenAuthSets in short mode.")
	}

	testCases := []struct {
		inAuthSets []interface{}
		inDevices  []interface{}
		tenant     string
	}{
		{
			inAuthSets: []interface{}{
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
			},
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
			},
		},
		{
			inAuthSets: []interface{}{
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
			},
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
			},
			tenant: tenant,
		},
		{
			inAuthSets: []interface{}{
				model.AuthSet{
					Id:       "001",
					DeviceId: "001",
					IdData:   "001",
					PubKey:   "001",
				},
				model.AuthSet{
					Id:       "002",
					DeviceId: "002",
					IdData:   "001",
					PubKey:   "002",
				},
			},
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: true,
				},
			},
			tenant: tenant,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			testDbName := DbName
			if tc.tenant != "" {
				testDbName = ctxstore.DbNameForTenant(tc.tenant, DbName)
			}

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			db := getDb(ctx)
			defer db.session.Close()
			s := db.session.Copy()
			defer s.Close()

			coll := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbAuthSetColl)
			assert.NoError(t, coll.Insert(tc.inAuthSets...))

			coll = s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)
			assert.NoError(t, coll.Insert(tc.inDevices...))

			err := db.DeleteBrokenAuthSets(testDbName)
			assert.NoError(t, err)

			brokenAuthSetsIds, err := db.GetBrokenAuthSets(testDbName)
			assert.NoError(t, err)
			assert.Equal(t, 0, len(brokenAuthSetsIds))
		})
	}
}

func TestGetBrokenTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetBrokenAuthSets in short mode.")
	}

	testCases := []struct {
		inTokens     []interface{}
		inDevices    []interface{}
		outTokensIds []string
		tenant       string
	}{
		{
			inTokens: []interface{}{
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
			},
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
			},
			outTokensIds: []string{"002"},
		},
		{
			inTokens: []interface{}{
				model.Token{
					Id:    "001",
					DevId: "001",
					Token: "foo",
				},
				model.Token{
					Id:    "002",
					DevId: "003",
					Token: "bar",
				},
			},
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
			},
			tenant:       tenant,
			outTokensIds: []string{"002"},
		},
		{
			inTokens: []interface{}{
				model.Token{
					Id:    "001",
					DevId: "001",
					Token: "foo",
				},
				model.Token{
					Id:    "002",
					DevId: "002",
					Token: "bar",
				},
			},
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: true,
				},
			},
			tenant:       tenant,
			outTokensIds: []string{"002"},
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			testDbName := DbName
			if tc.tenant != "" {
				testDbName = ctxstore.DbNameForTenant(tc.tenant, DbName)
			}

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			db := getDb(ctx)
			defer db.session.Close()
			s := db.session.Copy()
			defer s.Close()

			coll := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbTokensColl)
			assert.NoError(t, coll.Insert(tc.inTokens...))

			coll = s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)
			assert.NoError(t, coll.Insert(tc.inDevices...))

			brokenTokensIds, err := db.GetBrokenTokens(testDbName)
			assert.NoError(t, err)
			assert.Equal(t, tc.outTokensIds, brokenTokensIds)
		})
	}
}

func TestDeleteBrokenTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestDeleteBrokenAuthSets in short mode.")
	}

	testCases := []struct {
		inTokens  []interface{}
		inDevices []interface{}
		tenant    string
	}{
		{
			inTokens: []interface{}{
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
			},
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
			},
		},
		{
			inTokens: []interface{}{
				model.Token{
					Id:    "001",
					DevId: "001",
					Token: "foo",
				},
				model.Token{
					Id:    "002",
					DevId: "003",
					Token: "bar",
				},
			},
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
			},
			tenant: tenant,
		},
		{
			inTokens: []interface{}{
				model.Token{
					Id:    "001",
					DevId: "001",
					Token: "foo",
				},
				model.Token{
					Id:    "002",
					DevId: "002",
					Token: "bar",
				},
			},
			inDevices: []interface{}{
				model.Device{
					Id:              "001",
					IdData:          "001",
					TenantToken:     "",
					PubKey:          "001",
					Status:          model.DevStatusPending,
					Decommissioning: false,
				},
				model.Device{
					Id:              "002",
					IdData:          "002",
					TenantToken:     "",
					PubKey:          "002",
					Status:          model.DevStatusPending,
					Decommissioning: true,
				},
			},
			tenant: tenant,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			testDbName := DbName
			if tc.tenant != "" {
				testDbName = ctxstore.DbNameForTenant(tc.tenant, DbName)
			}

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			db := getDb(ctx)
			defer db.session.Close()
			s := db.session.Copy()
			defer s.Close()

			coll := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbTokensColl)
			assert.NoError(t, coll.Insert(tc.inTokens...))

			coll = s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)
			assert.NoError(t, coll.Insert(tc.inDevices...))

			err := db.DeleteBrokenTokens(testDbName)
			assert.NoError(t, err)

			brokenTokensIds, err := db.GetBrokenTokens(testDbName)
			assert.NoError(t, err)
			assert.Equal(t, 0, len(brokenTokensIds))
		})
	}
}
