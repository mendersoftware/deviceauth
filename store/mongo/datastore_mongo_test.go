// Copyright 2016 Mender Software AS
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
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/stretchr/testify/assert"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	uto "github.com/mendersoftware/deviceauth/utils/to"
)

const (
	testDataFolder = "testdata/mongo"
)

// data set
var (
	dev1   = model.NewDevice("id1", "idData1", "", "")
	dev2   = model.NewDevice("id2", "idData2", "", "")
	token1 = model.NewToken("id1", "devId1", "token1")
	token2 = model.NewToken("id2", "devId2", "token2")
	tenant = "foo"
)

// setup devices
func setUpDevices(s *mgo.Session, ctx context.Context) error {
	inputDevices := []interface{}{
		dev1,
		dev2,
	}
	return s.DB(ctxstore.DbFromContext(ctx, DbName)).
		C(DbDevicesColl).Insert(inputDevices...)
}

// setup tokens
func setUpTokens(s *mgo.Session, ctx context.Context) error {
	inputTokens := []interface{}{
		token1,
		token2,
	}
	return s.DB(ctxstore.DbFromContext(ctx, DbName)).
		C(DbTokensColl).Insert(inputTokens...)
}

// db and test management funcs
func getDb(ctx context.Context) *DataStoreMongo {
	db.Wipe()

	ds := NewDataStoreMongoWithSession(db.Session())
	ds.Migrate(ctx, DbVersion)

	return ds
}

// custom Device comparison with 'compareTime'
func compareDevices(expected *model.Device, actual *model.Device, t *testing.T) {
	assert.Equal(t, expected.Id, actual.Id)
	assert.Equal(t, expected.TenantToken, actual.TenantToken)
	assert.Equal(t, expected.PubKey, actual.PubKey)
	assert.Equal(t, expected.IdData, actual.IdData)
	assert.Equal(t, expected.Status, actual.Status)
	compareTime(expected.CreatedTs, actual.CreatedTs, t)
	compareTime(expected.UpdatedTs, actual.UpdatedTs, t)
}

// custom time comparison since mongo stores
// time with lower precision than 'time', e.g.:
//
// 2016-06-10 08:08:18.782 vs
// 2016-06-10 08:08:18.782397877
func compareTime(expected time.Time, actual time.Time, t *testing.T) {
	assert.Equal(t, expected.Unix(), actual.Unix())
}

func TestStoreGetDeviceByIdentityData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetDeviceByIdentityDataWithTenant in short mode.")
	}

	// set this to get reliable time.Time serialization
	// (always get UTC instead of e.g. CEST)
	time.Local = time.UTC

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})

	d := getDb(dbCtx)
	defer d.session.Close()
	s := d.session.Copy()
	defer s.Close()

	err := setUpDevices(s, dbCtx)
	assert.NoError(t, err, "failed to setup input data")

	testCases := []struct {
		idData      string
		expectedDev *model.Device
		tenant      string
	}{
		{
			idData:      dev1.IdData,
			expectedDev: dev1,
			tenant:      tenant,
		},
		{
			idData: dev1.IdData,
		},
		{
			idData:      dev2.IdData,
			expectedDev: dev2,
			tenant:      tenant,
		},
		{
			idData: "foo",
			tenant: tenant,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			dev, err := d.GetDeviceByIdentityData(ctx, tc.idData)
			if tc.expectedDev != nil {
				assert.NoError(t, err, "failed to get devices")
				if assert.NotNil(t, dev) {
					compareDevices(tc.expectedDev, dev, t)
				}
			} else {
				assert.Equal(t, store.ErrDevNotFound, err)
			}
		})
	}
}

// custom AuthSet comparison with 'compareTime'
func compareAuthSet(expected *model.AuthSet, actual *model.AuthSet, t *testing.T) {
	assert.Equal(t, expected.IdData, actual.IdData)
	assert.Equal(t, expected.TenantToken, actual.TenantToken)
	assert.Equal(t, expected.PubKey, actual.PubKey)
	assert.Equal(t, expected.DeviceId, actual.DeviceId)
	assert.Equal(t, expected.Status, actual.Status)
	compareTime(uto.Time(expected.Timestamp), uto.Time(actual.Timestamp), t)
}

func TestStoreAddDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestAddDevice in short mode.")
	}
	time.Local = time.UTC

	//setup
	dev := &model.Device{
		TenantToken: "tenant",
		PubKey:      "pubkey",
		IdData:      "iddata",
		Status:      "pending",
		CreatedTs:   time.Now(),
		UpdatedTs:   time.Now(),
	}

	ctx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: "foo",
	})
	d := getDb(ctx)
	defer d.session.Close()

	err := d.AddDevice(ctx, *dev)
	assert.NoError(t, err, "failed to add device")

	found, err := d.GetDeviceByIdentityData(ctx, "iddata")
	assert.NoError(t, err)
	assert.NotNil(t, found)

	// verify that device ID was set
	assert.NotEmpty(t, found.Id)
	// clear it now to allow compareDevices() to succeed
	found.Id = ""
	compareDevices(dev, found, t)

	// add device with identical identity data
	err = d.AddDevice(ctx, model.Device{
		Id:     "foobar",
		IdData: "iddata",
	})
	assert.EqualError(t, err, store.ErrObjectExists.Error())
}

func TestStoreUpdateDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestUpdateDevice in short mode.")
	}
	time.Local = time.UTC

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	d := getDb(dbCtx)
	defer d.session.Close()
	s := d.session.Copy()
	defer s.Close()

	err := setUpDevices(s, dbCtx)
	assert.NoError(t, err, "failed to setup input data")

	now := time.Now().UTC()

	compareUpdateDev := func(t *testing.T, old model.Device,
		dev model.Device, up model.DeviceUpdate) {

		// check the fields we know are used
		if up.IdData != "" {
			assert.Equal(t, dev.IdData, up.IdData)
		} else {
			assert.Equal(t, dev.IdData, old.IdData)
		}
		if up.Decommissioning != nil {
			assert.Equal(t, dev.Decommissioning, *up.Decommissioning)
		} else {
			assert.Equal(t, dev.Decommissioning, old.Decommissioning)
		}
	}

	//test status updates
	testCases := []struct {
		id     string
		old    *model.Device
		update model.DeviceUpdate
		tenant string
		outErr string
	}{
		{
			id:     dev1.Id,
			old:    dev1,
			update: model.DeviceUpdate{Decommissioning: to.BoolPtr(true)},
			outErr: "",
			tenant: tenant,
		},
		{
			// other tenant's DB
			id:     dev1.Id,
			update: model.DeviceUpdate{Decommissioning: to.BoolPtr(true)},
			outErr: store.ErrDevNotFound.Error(),
			tenant: "",
		},
		{
			id:     "id3",
			update: model.DeviceUpdate{Status: model.DevStatusRejected},
			outErr: store.ErrDevNotFound.Error(),
			tenant: tenant,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			err = d.UpdateDevice(ctx, model.Device{Id: tc.id}, tc.update)
			if tc.outErr != "" {
				assert.EqualError(t, err, tc.outErr)
			} else {
				assert.NoError(t, err)

				//verify
				s := d.session.Copy()
				defer s.Close()

				var found model.Device

				c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)

				err = c.FindId(tc.id).One(&found)
				assert.NoError(t, err, "failed to find device")

				compareUpdateDev(t, *tc.old, found, tc.update)

				//check UpdatedTs was updated
				assert.InEpsilon(t, now.Unix(), found.UpdatedTs.Unix(), 10)
			}
		})
	}
}

func TestStoreAddToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestAddToken in short mode.")
	}

	//setup
	token := model.Token{
		Id:    "123",
		DevId: "devId",
		Token: "token",
	}

	ctx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: "foo",
	})
	d := getDb(ctx)
	defer d.session.Close()

	err := d.AddToken(ctx, token)
	assert.NoError(t, err, "failed to add token")

	//verify
	s := d.session.Copy()
	defer s.Close()

	var found model.Token

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbTokensColl)

	err = c.FindId(token.Id).One(&found)
	assert.NoError(t, err, "failed to find token")
	assert.Equal(t, found.Id, token.Id)
	assert.Equal(t, found.DevId, token.DevId)
	assert.Equal(t, found.Token, token.Token)

}

func TestStoreGetToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetToken in short mode.")
	}

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	d := getDb(dbCtx)
	defer d.session.Close()
	s := d.session.Copy()
	defer s.Close()

	err := setUpTokens(s, dbCtx)
	assert.NoError(t, err, "failed to setup input data")

	testCases := []struct {
		tokenId       string
		tenant        string
		expectedToken *model.Token
	}{
		{
			tokenId:       token1.Id,
			tenant:        tenant,
			expectedToken: token1,
		},
		{
			tokenId: token1.Id,
		},
		{
			tokenId:       token2.Id,
			tenant:        tenant,
			expectedToken: token2,
		},
		{
			tokenId: "id3",
			tenant:  tenant,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			token, err := d.GetToken(ctx, tc.tokenId)
			if tc.expectedToken != nil {
				assert.NoError(t, err, "failed to get token")
			} else {
				assert.Equal(t, store.ErrTokenNotFound, err)
			}

			assert.Equal(t, tc.expectedToken, token)
		})
	}
}

func TestStoreDeleteToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestDeleteToken in short mode.")
	}

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	d := getDb(dbCtx)
	defer d.session.Close()
	s := d.session.Copy()
	defer s.Close()

	err := setUpTokens(s, dbCtx)
	assert.NoError(t, err, "failed to setup input data")

	testCases := []struct {
		tokenId string
		tenant  string
		err     bool
	}{
		{
			tokenId: token1.Id,
			tenant:  tenant,
			err:     false,
		},
		{
			tokenId: token1.Id,
			err:     true,
		},
		{
			tokenId: token2.Id,
			tenant:  tenant,
			err:     false,
		},
		{
			tokenId: "id3",
			tenant:  tenant,
			err:     true,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			err := d.DeleteToken(ctx, tc.tokenId)
			if tc.err {
				assert.Equal(t, store.ErrTokenNotFound, err)
			} else {
				assert.NoError(t, err, "failed to delete token")
			}
		})
	}
}

func TestStoreDeleteTokenByDevId(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestDeleteTokenByDevId in short mode.")
	}

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	d := getDb(dbCtx)
	defer d.session.Close()
	s := d.session.Copy()
	defer s.Close()

	err := setUpTokens(s, dbCtx)
	assert.NoError(t, err, "failed to setup input data")

	testCases := []struct {
		devId  string
		tenant string
		err    bool
	}{
		{
			devId:  token1.DevId,
			tenant: tenant,
			err:    false,
		},
		{
			devId: token1.DevId,
			err:   true,
		},
		{
			devId:  token2.DevId,
			tenant: tenant,
			err:    false,
		},
		{
			devId:  "devId3",
			tenant: tenant,
			err:    true,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			err := d.DeleteTokenByDevId(ctx, tc.devId)
			if tc.err {
				assert.Equal(t, store.ErrTokenNotFound, err)
			} else {
				assert.NoError(t, err, "failed to delete token")
			}
		})
	}
}

func TestStoreMigrate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestMigrate in short mode.")
	}

	testCases := map[string]struct {
		tenantDbs   []string
		automigrate bool

		version string
		err     string
	}{
		DbVersion: {
			automigrate: true,
			version:     DbVersion,
			err:         "",
		},
		DbVersion + " no automigrate": {
			automigrate: false,
			version:     DbVersion,
			err:         "failed to apply migrations: db needs migration: deviceauth has version 0.0.0, needs version 1.1.0",
		},
		DbVersion + " multitenant": {
			automigrate: true,
			tenantDbs:   []string{"deviceauth-tenant1id", "deviceauth-tenant2id"},
			version:     DbVersion,
			err:         "",
		},
		DbVersion + " multitenant, no automigrate": {
			automigrate: false,
			tenantDbs:   []string{"deviceauth-tenant1id", "deviceauth-tenant2id"},
			version:     DbVersion,
			err:         "failed to apply migrations: db needs migration: deviceauth-tenant1id has version 0.0.0, needs version 1.1.0",
		},
		"0.1 error": {
			automigrate: true,
			version:     "0.1",
			err:         "failed to parse service version: failed to parse Version: unexpected EOF",
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc: %s", name), func(t *testing.T) {
			db.Wipe()
			db := NewDataStoreMongoWithSession(db.Session())

			// set up automigration
			if tc.automigrate {
				db = db.WithAutomigrate()
			}

			// set up multitenancy/tenant dbs
			if len(tc.tenantDbs) != 0 {
				db = db.WithMultitenant()

				for _, d := range tc.tenantDbs {
					err := db.session.DB(d).C("foo").Insert(bson.M{"foo": "bar"})
					assert.NoError(t, err)
				}
			}

			ctx := context.Background()
			err := db.Migrate(ctx, tc.version)
			if tc.err == "" {
				assert.NoError(t, err)

				// verify migration entry in all databases (>1 if multitenant)
				if tc.automigrate {
					dbs := []string{DbName}
					if len(tc.tenantDbs) > 0 {
						dbs = tc.tenantDbs
					}

					for _, d := range dbs {
						var out []migrate.MigrationEntry
						db.session.DB(d).C(migrate.DbMigrationsColl).Find(nil).All(&out)
						sort.Slice(out, func(i int, j int) bool {
							return migrate.VersionIsLess(out[i].Version, out[j].Version)
						})
						// the last migration should match what we want
						v, _ := migrate.NewVersion(tc.version)
						assert.Equal(t, *v, out[len(out)-1].Version)
					}
				}

			} else {
				assert.EqualError(t, err, tc.err)
			}
			db.session.Close()
		})
	}
}

func randDevStatus() string {
	statuses := []string{
		model.DevStatusAccepted,
		model.DevStatusPending,
		model.DevStatusRejected,
	}
	idx := rand.Int() % len(statuses)
	return statuses[idx]
}

func TestStoreGetDevices(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetDevices in short mode.")
	}

	ctx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: "foo",
	})
	db := getDb(ctx)
	defer db.session.Close()

	// use 100 automatically creted devices
	const devCount = 100

	devs_list := make([]model.Device, 0, devCount)

	// populate DB with a set of devices
	for i := 0; i < devCount; i++ {
		dev := model.Device{
			IdData: fmt.Sprintf("foo-%04d", i),
			PubKey: fmt.Sprintf("pubkey-%04d", i),
			Status: randDevStatus(),
		}

		devs_list = append(devs_list, dev)
		err := db.AddDevice(ctx, dev)
		assert.NoError(t, err)
	}

	testCases := []struct {
		skip            uint
		limit           uint
		expectedCount   int
		expectedStartId int
		expectedEndId   int
	}{
		{
			skip:            10,
			limit:           5,
			expectedCount:   5,
			expectedStartId: 10,
			expectedEndId:   14,
		},
		{
			// end of the range
			skip:            devCount - 10,
			limit:           15,
			expectedCount:   10,
			expectedStartId: 90,
			expectedEndId:   99,
		},
		{
			// whole range
			skip:            0,
			limit:           devCount,
			expectedCount:   devCount,
			expectedStartId: 0,
			expectedEndId:   devCount - 1,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			dbdevs, err := db.GetDevices(ctx, tc.skip, tc.limit)
			assert.NoError(t, err)

			assert.Len(t, dbdevs, tc.expectedCount)
			for i, dbidx := tc.expectedStartId, 0; i <= tc.expectedEndId; i, dbidx = i+1, dbidx+1 {
				// make sure that ID is not empty
				assert.NotEmpty(t, dbdevs[dbidx].Id)
				// clear it now so that next assert does not fail
				dbdevs[dbidx].Id = ""
				assert.EqualValues(t, devs_list[i], dbdevs[dbidx])
			}
		})
	}
}

func TestStoreAuthSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetDevices in short mode.")
	}

	ctx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: "foo",
	})
	db := getDb(ctx)
	defer db.session.Close()

	asin := model.AuthSet{
		IdData:    "foobar",
		PubKey:    "pubkey-1",
		DeviceId:  "1",
		Timestamp: uto.TimePtr(time.Now()),
	}
	err := db.AddAuthSet(ctx, asin)
	assert.NoError(t, err)

	// try to get something that does not exist
	as, err := db.GetAuthSetByDataKey(ctx, "foobar-2", "pubkey-3")
	assert.Error(t, err)

	// no tenant
	as, err = db.GetAuthSetByDataKey(context.Background(), "foobar", "pubkey-1")
	assert.Error(t, err)

	as, err = db.GetAuthSetByDataKey(ctx, "foobar", "pubkey-1")
	assert.NoError(t, err)
	assert.NotNil(t, as)

	assert.False(t, to.Bool(as.AdmissionNotified))

	err = db.UpdateAuthSet(ctx, asin, model.AuthSetUpdate{
		AdmissionNotified: to.BoolPtr(true),
		Timestamp:         uto.TimePtr(time.Now()),
	})
	assert.NoError(t, err)

	as, err = db.GetAuthSetByDataKey(ctx, "foobar", "pubkey-1")
	assert.NoError(t, err)
	assert.NotNil(t, as)
	assert.True(t, to.Bool(as.AdmissionNotified))
	assert.WithinDuration(t, time.Now(), uto.Time(as.Timestamp), time.Second)

	// clear timestamp field
	asin.Timestamp = nil
	// selectively update public key only, remaining fields should be unchanged
	err = db.UpdateAuthSet(ctx, asin, model.AuthSetUpdate{
		PubKey: "pubkey-2",
	})
	assert.NoError(t, err)

	as, err = db.GetAuthSetByDataKey(ctx, "foobar", "pubkey-2")
	assert.NoError(t, err)
	assert.NotNil(t, as)
	assert.True(t, to.Bool(as.AdmissionNotified))

	asid, err := db.GetAuthSetById(ctx, as.Id)
	assert.NoError(t, err)
	assert.NotNil(t, asid)

	assert.EqualValues(t, as, asid)

	// verify auth sets count for this device
	asets, err := db.GetAuthSetsForDevice(ctx, "1")
	assert.NoError(t, err)
	assert.Len(t, asets, 1)

	// add another auth set
	asin = model.AuthSet{
		IdData:    "foobar",
		PubKey:    "pubkey-99",
		DeviceId:  "1",
		Timestamp: uto.TimePtr(time.Now()),
	}
	err = db.AddAuthSet(ctx, asin)
	assert.NoError(t, err)

	// we should have 2 now
	asets, err = db.GetAuthSetsForDevice(ctx, "1")
	assert.NoError(t, err)
	assert.Len(t, asets, 2)
}

func TestStoreDeleteDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestStoreDeleteDevice in short mode.")
	}

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	db := getDb(dbCtx)
	defer db.session.Close()

	// setup devices
	inputDevices := []interface{}{
		dev1,
		dev2,
	}
	err := db.session.DB(ctxstore.DbFromContext(dbCtx, DbName)).
		C(DbDevicesColl).Insert(inputDevices...)
	assert.NoError(t, err, "failed to setup input data")

	s := db.session.Copy()
	defer s.Close()

	coll := s.DB(DbName).C(DbDevicesColl)

	testCases := []struct {
		devId  string
		tenant string
		err    string
	}{
		{
			devId:  dev1.Id,
			tenant: tenant,
			err:    "",
		},
		{
			devId: dev1.Id,
			err:   store.ErrDevNotFound.Error(),
		},
		{
			devId:  "100",
			tenant: tenant,
			err:    store.ErrDevNotFound.Error(),
		},
		{
			devId:  "",
			tenant: tenant,
			err:    store.ErrDevNotFound.Error(),
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			err := db.DeleteDevice(ctx, tc.devId)
			if tc.err != "" {
				assert.Equal(t, tc.err, err.Error())
			} else {
				assert.NoError(t, err)
				var found model.Device
				err = coll.FindId(tc.devId).One(&found)
				if assert.Error(t, err) {
					assert.Equal(t, err.Error(), mgo.ErrNotFound.Error())
				}
			}
		})
	}
}

func TestStoreDeleteAuthSetsForDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestStoreDeleteAuthSetsForDevice in short mode.")
	}

	authSets := []interface{}{
		model.AuthSet{
			DeviceId: "001",
			IdData:   "001",
			PubKey:   "001",
		},
		model.AuthSet{
			DeviceId: "001",
			IdData:   "001",
			PubKey:   "002",
		},
	}

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	db := getDb(dbCtx)
	defer db.session.Close()
	s := db.session.Copy()
	defer s.Close()

	coll := s.DB(ctxstore.DbFromContext(dbCtx, DbName)).C(DbAuthSetColl)
	assert.NoError(t, coll.Insert(authSets...))

	testCases := []struct {
		devId  string
		tenant string
		err    string
	}{
		{
			devId:  "001",
			tenant: tenant,
			err:    "",
		},
		{
			devId: "001",
			err:   store.ErrAuthSetNotFound.Error(),
		},
		{
			devId:  "100",
			tenant: tenant,
			err:    store.ErrAuthSetNotFound.Error(),
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			err := db.DeleteAuthSetsForDevice(ctx, tc.devId)
			if tc.err != "" {
				assert.Equal(t, tc.err, err.Error())
			} else {
				assert.NoError(t, err)
				var found model.Device
				err = coll.FindId(model.AuthSet{DeviceId: tc.devId}).One(&found)
				if assert.Error(t, err) {
					assert.Equal(t, err.Error(), mgo.ErrNotFound.Error())
				}
			}
		})
	}
}
