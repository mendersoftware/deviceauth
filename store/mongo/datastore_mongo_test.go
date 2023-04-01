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
package mongo

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	"github.com/mendersoftware/go-lib-micro/mongo/oid"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/mendersoftware/deviceauth/jwt"
	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	uto "github.com/mendersoftware/deviceauth/utils/to"
	"github.com/mendersoftware/go-lib-micro/ratelimits"
)

const (
	testDataFolder = "testdata/mongo"
)

// data set
var (
	dev1   = model.NewDevice(oid.NewUUIDv5("devID1").String(), "idData1", "")
	dev2   = model.NewDevice(oid.NewUUIDv5("devID2").String(), "idData2", "")
	token1 = &jwt.Token{Claims: jwt.Claims{
		ID:        oid.NewUUIDv5("id1"),
		Subject:   oid.NewUUIDv5("devID1"),
		ExpiresAt: jwt.Time{Time: time.Now().Add(time.Hour * 24)},
		IssuedAt:  jwt.Time{Time: time.Now()},
		Issuer:    "Mender testing",
	}}
	token2 = &jwt.Token{Claims: jwt.Claims{
		ID:        oid.NewUUIDv5("id2"),
		Subject:   oid.NewUUIDv5("devID2"),
		ExpiresAt: jwt.Time{Time: time.Now().Add(time.Hour * 24)},
		IssuedAt:  jwt.Time{Time: time.Now()},
		Issuer:    "Mender testing",
	}}
	tenant = "foo"
)

func assertEqualTokens(t *testing.T, expected, actual []jwt.Token) bool {
	var ret bool = true
	for _, ex := range expected {
		var a *jwt.Token
		for _, act := range actual {
			if act.ID == ex.ID {
				a = &act
				break
			}
		}
		if !assert.NotNil(t, a, "Expected token not found: %v", ex) {
			ret = false
			continue
		}
		ret = ret && assert.Equal(t, ex.Subject, a.Subject)
		ret = ret && assert.Equal(t, ex.Audience, a.Audience)
		ret = ret && assert.WithinDuration(t,
			ex.ExpiresAt.Time,
			a.ExpiresAt.Time, time.Second)
		ret = ret && assert.WithinDuration(t,
			ex.IssuedAt.Time,
			a.IssuedAt.Time, time.Second)
		ret = ret && assert.WithinDuration(t,
			ex.NotBefore.Time,
			a.NotBefore.Time, time.Second)
		ret = ret && assert.Equal(t, ex.Issuer, a.Issuer)
		ret = ret && assert.Equal(t, ex.Scope, a.Scope)
		ret = ret && assert.Equal(t, ex.Tenant, a.Tenant)

		ret = ret && assert.Equal(t, ex.Device, a.Device)
	}
	return ret
}

// setup devices
func setUpDevices(ctx context.Context, client *mongo.Client, tenantId string) error {
	dev1.IdDataSha256 = getIdDataHash(dev1.IdData)
	dev2.IdDataSha256 = getIdDataHash(dev2.IdData)
	dev1.TenantID = tenantId
	dev2.TenantID = tenantId
	inputDevices := bson.A{
		dev1,
		dev2,
	}
	c := client.Database(DbName).Collection(DbDevicesColl)
	_, err := c.InsertMany(ctx, inputDevices)
	return err
}

// setup tokens
func setUpTokens(ctx context.Context, client *mongo.Client, tenantId string) error {
	inputTokens := bson.A{
		token1,
		token2,
	}
	c := client.Database(DbName).Collection(DbTokensColl)
	_, err := c.InsertMany(ctx, inputTokens)
	c.UpdateOne(ctx, bson.M{dbFieldID: token1.ID}, bson.M{"$set": bson.M{dbFieldTenantID: tenantId}})
	c.UpdateOne(ctx, bson.M{dbFieldID: token2.ID}, bson.M{"$set": bson.M{dbFieldTenantID: tenantId}})
	return err
}

// db and test management funcs
func getDb(ctx context.Context) *DataStoreMongo {
	db.Wipe()

	ds := NewDataStoreMongoWithClient(db.Client())
	ds = ds.WithAutomigrate().(*DataStoreMongo)
	ds.Migrate(ctx, DbVersion)

	return ds
}

// custom Device comparison with 'compareTime'
func compareDevices(expected *model.Device, actual *model.Device, t *testing.T) {
	assert.Equal(t, expected.Id, actual.Id)
	assert.Equal(t, expected.IdData, actual.IdData)
	assert.Equal(t, expected.IdDataStruct, actual.IdDataStruct)
	assert.Equal(t, expected.IdDataSha256, actual.IdDataSha256)
	assert.Equal(t, expected.Status, actual.Status)
	assert.Equal(t, expected.ApiLimits, actual.ApiLimits)
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

func TestForEachTenant(t *testing.T) {
	testCases := []struct {
		Name string

		TenantIDs []string

		CTX     context.Context
		MapFunc store.MapFunc

		Error error
	}{{
		Name: "ok, noop",

		CTX: context.Background(),

		TenantIDs: []string{"tenant1", "tenant2", ""},
		MapFunc: func(ctx context.Context) error {
			return nil
		},
	}, {
		Name: "error, map func errored",

		CTX:       context.Background(),
		TenantIDs: []string{"tenant"},
		MapFunc: func(ctx context.Context) error {
			return errors.New("internal error")
		},

		Error: errors.New(
			"store: failed to apply mapFunc to tenant \"tenant\": internal error",
		),
	}, {
		Name: "error, context already canceled",

		CTX: func() context.Context {
			ctx, cancel := context.WithCancel(context.TODO())
			cancel()
			return ctx
		}(),
		TenantIDs: []string{"tenant"},
		MapFunc: func(ctx context.Context) error {
			return nil
		},

		Error: errors.Wrap(context.Canceled,
			`store: database operations stopped prematurely`,
		),
	}, {
		Name: "error, context timeout",

		CTX: func() context.Context {
			ctx, cancel := context.WithTimeout(context.TODO(), time.Second*3)
			go func() {
				// the things we do for go vet...
				<-time.After(time.Minute)
				cancel()
			}()
			return ctx
		}(),
		TenantIDs: []string{"tenant1", "tenant2"},
		MapFunc: func(ctx context.Context) error {
			time.Sleep(time.Second * 3)
			return nil
		},
		Error: errors.Wrap(context.DeadlineExceeded,
			"store: database operations stopped prematurely",
		),
	}}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			var (
				numCalled int
				client    = db.Client()
				setupCtx  = context.Background()
			)
			db.Wipe()
			// Initialize databases in our test setup
			for _, tenantID := range tc.TenantIDs {
				c := client.Database(DbName).Collection(DbDevicesColl)
				_, err := c.InsertMany(setupCtx, bson.A{
					model.Device{
						Id:              oid.NewUUIDv4().String(),
						IdData:          oid.NewUUIDv4().String(),
						IdDataStruct:    map[string]interface{}{"k0": "v0"},
						IdDataSha256:    []byte(oid.NewUUIDv4().String()),
						Status:          "accepted",
						Decommissioning: false,
						CreatedTs:       time.Now(),
						UpdatedTs:       time.Now(),
						AuthSets:        nil,
						ApiLimits:       ratelimits.ApiLimits{},
						Revision:        0,
						TenantID:        tenantID,
					},
				})
				assert.NoError(t, err)
			}
			ds := NewDataStoreMongoWithClient(client)

			// Wrap mapFunc to assert number of times called and
			// database legitimacy.
			mapFunc := func(ctx context.Context) error {
				numCalled++
				id := identity.FromContext(ctx)
				if id != nil {
					tenantID := id.Tenant
					assert.Contains(t, tc.TenantIDs, tenantID)
				}
				return tc.MapFunc(ctx)
			}
			// Run test:
			err := ds.ForEachTenant(tc.CTX, mapFunc)
			if tc.Error != nil {
				if assert.Error(t, err) {
					assert.Regexp(t, tc.Error.Error(), err.Error())
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, numCalled, len(tc.TenantIDs))
			}
		})
	}
}

func TestPing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestPing in short mode")
	}
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	ds := NewDataStoreMongoWithClient(db.Client())
	err := ds.Ping(ctx)
	assert.NoError(t, err)
}

func TestStoreGetDeviceByIdentityDataHash(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetDeviceByIdentityDataHash in short mode.")
	}

	// set this to get reliable time.Time serialization
	// (always get UTC instead of e.g. CEST)
	time.Local = time.UTC

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})

	d := getDb(dbCtx)

	err := setUpDevices(dbCtx, d.client, tenant)
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

			dev, err := d.GetDeviceByIdentityDataHash(ctx, getIdDataHash(tc.idData))
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
	assert.Equal(t, expected.PubKey, actual.PubKey)
	assert.Equal(t, expected.DeviceId, actual.DeviceId)
	assert.Equal(t, expected.IdDataStruct, actual.IdDataStruct)
	assert.Equal(t, expected.IdDataSha256, actual.IdDataSha256)
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
		IdData:       "iddata",
		IdDataSha256: getIdDataHash("iddata"),
		Status:       "pending",
		CreatedTs:    time.Now(),
		UpdatedTs:    time.Now(),
	}

	ctx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: "foo",
	})
	d := getDb(ctx)
	d.MigrateTenant(ctx, ctxstore.DbFromContext(ctx, DbName), DbVersion)

	err := d.AddDevice(ctx, *dev)
	assert.NoError(t, err, "failed to add device")

	found, err := d.GetDeviceByIdentityDataHash(ctx, dev.IdDataSha256)
	assert.NoError(t, err)
	assert.NotNil(t, found)

	// verify that device ID was set
	assert.NotEmpty(t, found.Id)
	// clear it now to allow compareDevices() to succeed
	found.Id = ""
	compareDevices(dev, found, t)

	// add device with identical identity data
	err = d.AddDevice(ctx, model.Device{
		Id:           "foobar",
		IdData:       "iddata",
		IdDataSha256: getIdDataHash("iddata"),
	})
	assert.EqualError(t, err, store.ErrObjectExists.Error())

	// add device with identical identity data but for different tenant
	ctx = identity.WithContext(context.Background(), &identity.Identity{
		Tenant: "bar",
	})
	d.MigrateTenant(ctx, ctxstore.DbFromContext(ctx, DbName), DbVersion)

	err = d.AddDevice(ctx, model.Device{
		Id:     "foobar",
		IdData: "iddata",
	})
	assert.NoError(t, err, "failed to add device")

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

	err := setUpDevices(dbCtx, d.client, tenant)
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
			update: model.DeviceUpdate{Decommissioning: uto.BoolPtr(true)},
			outErr: "",
			tenant: tenant,
		},
		{
			// other tenant's DB
			id:     dev1.Id,
			update: model.DeviceUpdate{Decommissioning: uto.BoolPtr(true)},
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

			err = d.UpdateDevice(ctx, tc.id, tc.update)
			if tc.outErr != "" {
				assert.EqualError(t, err, tc.outErr)
			} else {
				assert.NoError(t, err)

				//verify

				var found model.Device

				c := d.client.Database(DbName).Collection(DbDevicesColl)

				err := c.FindOne(ctx, bson.M{"_id": tc.id}).Decode(&found)
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
	ctx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: "foo",
	})
	d := getDb(ctx)

	err := d.AddToken(ctx, token1)
	assert.NoError(t, err, "failed to add token")

	//verify
	var found jwt.Token

	c := d.client.Database(DbName).Collection(DbTokensColl)
	err = c.FindOne(ctx, bson.M{"_id": token1.ID}).Decode(&found)
	assert.NoError(t, err, "failed to find token")
	assertEqualTokens(t, []jwt.Token{*token1}, []jwt.Token{found})
}

func TestStoreGetToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetToken in short mode.")
	}

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	d := getDb(dbCtx)

	err := setUpTokens(dbCtx, d.client, tenant)
	assert.NoError(t, err, "failed to setup input data")

	testCases := []struct {
		tokenID       oid.ObjectID
		tenant        string
		expectedToken *jwt.Token
	}{
		{
			tokenID:       token1.ID,
			tenant:        tenant,
			expectedToken: token1,
		},
		{
			tokenID: token1.ID,
		},
		{
			tokenID:       token2.ID,
			tenant:        tenant,
			expectedToken: token2,
		},
		{
			tokenID: oid.NewUUIDv5("id3"),
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

			token, err := d.GetToken(ctx, tc.tokenID)
			if tc.expectedToken != nil {
				assert.NoError(t, err, "failed to get token")
			} else {
				assert.Equal(t, store.ErrTokenNotFound, err)
			}

			if tc.expectedToken == nil {
				assert.Nil(t, tc.expectedToken)
			} else {
				assertEqualTokens(
					t,
					[]jwt.Token{*tc.expectedToken},
					[]jwt.Token{*token},
				)
			}
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

	err := setUpTokens(dbCtx, d.client, tenant)
	assert.NoError(t, err, "failed to setup input data")

	testCases := []struct {
		tokenID oid.ObjectID
		tenant  string
		err     bool
	}{
		{
			tokenID: token1.ID,
			tenant:  tenant,
			err:     false,
		},
		{
			tokenID: token1.ID,
			err:     true,
		},
		{
			tokenID: token2.ID,
			tenant:  tenant,
			err:     false,
		},
		{
			tokenID: oid.NewUUIDv5("id3"),
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

			err := d.DeleteToken(ctx, tc.tokenID)
			if tc.err {
				assert.Equal(t, store.ErrTokenNotFound, err)
			} else {
				assert.NoError(t, err, "failed to delete token")
			}
		})
	}
}

func TestStoreDeleteTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestDeleteTokens in short mode.")
	}

	someTokens := bson.A{
		token1,
		token2,
		&jwt.Token{Claims: jwt.Claims{
			ID:      oid.NewUUIDv5("id3"),
			Subject: oid.NewUUIDv5("devId2"),
			Issuer:  "Mender testing",
			ExpiresAt: jwt.Time{
				Time: time.Now().Add(time.Hour),
			},
		}},
	}

	testCases := map[string]struct {
		inTokens bson.A
		tenant   string
	}{
		"ok": {
			inTokens: someTokens,
		},
		"ok, empty": {},
		"ok, MT": {
			inTokens: someTokens,
			tenant:   "foo",
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc %s", name), func(t *testing.T) {
			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			d := getDb(ctx)

			if tc.inTokens != nil {
				c := d.client.Database(DbName).Collection(DbTokensColl)
				_, err := c.InsertMany(ctx, tc.inTokens)
				assert.NoError(t, err)
				if tc.tenant != "" {
					for _, token := range tc.inTokens {
						tokenId := token.(*jwt.Token).ID
						_, err := c.UpdateOne(ctx, bson.M{dbFieldID: tokenId}, bson.M{"$set": bson.M{dbFieldTenantID: tc.tenant}})
						assert.NoError(t, err)
					}
				}
			}

			err := d.DeleteTokens(ctx)
			assert.NoError(t, err)
			var out []jwt.Token

			c := d.client.Database(DbName).Collection(DbTokensColl)

			cursor, err := c.Find(ctx, bson.M{})
			assert.NoError(t, err)
			err = cursor.All(ctx, &out)
			assert.NoError(t, err)

			assert.Len(t, out, 0)
		})
	}
}

func TestStoreDeleteTokenByDevId(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestDeleteTokenByDevId in short mode.")
	}

	inTokens := bson.A{
		token1,
		token2,
		&jwt.Token{Claims: jwt.Claims{
			ID:      oid.NewUUIDv5("id3"),
			Subject: oid.NewUUIDv5("devID2"),
			Issuer:  "Mender testing",
			ExpiresAt: jwt.Time{
				Time: time.Now().Add(time.Hour),
			},
		}},
	}

	testCases := []struct {
		devID  oid.ObjectID
		tenant string

		outTokens []jwt.Token
		err       error
	}{
		{
			devID:  token1.Subject,
			tenant: "tenant-foo",

			outTokens: []jwt.Token{
				*token2,
				{Claims: jwt.Claims{
					ID:      oid.NewUUIDv5("id3"),
					Subject: oid.NewUUIDv5("devID2"),
					Issuer:  "Mender testing",
					ExpiresAt: jwt.Time{
						Time: time.Now().Add(time.Hour),
					},
				}},
			},
			err: nil,
		},
		{
			devID:  token2.Subject,
			tenant: "tenant-foo",

			outTokens: []jwt.Token{
				*token1,
			},
			err: nil,
		},
		{
			devID: oid.NewUUIDv5("devID3"),

			err: store.ErrTokenNotFound,
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

			d := getDb(ctx)

			c := d.client.Database(DbName).Collection(DbTokensColl)
			_, err := c.InsertMany(ctx, inTokens)
			assert.NoError(t, err)
			for _, token := range inTokens {
				tokenId := token.(*jwt.Token).ID
				_, err := c.UpdateOne(ctx, bson.M{dbFieldID: tokenId}, bson.M{"$set": bson.M{dbFieldTenantID: tc.tenant}})
				assert.NoError(t, err)
			}

			err = d.DeleteTokenByDevId(ctx, tc.devID)
			if tc.err != nil {
				assert.Equal(t, store.ErrTokenNotFound, err)
			} else {
				assert.NoError(t, err)
				var out []jwt.Token

				assert.NoError(t, err)
				cursor, err := c.Find(ctx, bson.M{})
				assert.NoError(t, err)
				err = cursor.All(ctx, &out)
				assert.NoError(t, err)

				assertEqualTokens(t, tc.outTokens, out)
			}
		})
	}
}

func verifyIndexes(t *testing.T, coll *mongo.Collection, expected []mongo.IndexModel) {
	cursor, err := coll.Indexes().List(context.TODO())
	assert.NoError(t, err)

	var idxs []bson.M

	err = cursor.All(context.TODO(), &idxs)
	assert.NoError(t, err)

	assert.Len(t, idxs, 1+len(expected))
	for _, expectedIdx := range expected {
		t.Logf("looking for: %+v", expectedIdx)
		found := false
		for _, idx := range idxs {
			t.Logf("index: %+v", idx)
			if idx["name"] == *expectedIdx.Options.Name {
				t.Logf("found same index, comparing")
				found = true
				assert.Equal(t, *expectedIdx.Options.Background, idx["background"])
				if idx["unique"] != nil {
					assert.Equal(t, *expectedIdx.Options.Unique, idx["unique"])
				}
				break
			}
		}
		assert.True(t, found, "index %v was not found", expectedIdx)
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
			err: "failed to apply migrations: db needs " +
				"migration: deviceauth has version 0.0.0, " +
				"needs version " + DbVersion,
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
			err: "failed to apply migrations: db needs " +
				"migration: deviceauth-tenant1id has version " +
				"0.0.0, needs version " + DbVersion,
		},
		"0.1 error": {
			automigrate: true,
			version:     "0.1",
			err:         "failed to parse service version: failed to parse Version: unexpected EOF",
		},
	}
	_false := false
	_true := true

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc: %s", name), func(t *testing.T) {
			db.Wipe()
			db := NewDataStoreMongoWithClient(db.Client())

			// set up automigration
			if tc.automigrate {
				db = db.WithAutomigrate().(*DataStoreMongo)
			}

			// set up multitenancy/tenant dbs
			if len(tc.tenantDbs) != 0 {
				db = db.WithMultitenant()

				for _, d := range tc.tenantDbs {
					c := db.client.Database(d).Collection("foo")
					_, err := c.InsertOne(context.TODO(), bson.M{"foo": "bar"})
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
						c := db.client.Database(d).Collection(migrate.DbMigrationsColl)
						cursor, err := c.Find(ctx, bson.M{})
						assert.NoError(t, err)
						err = cursor.All(ctx, &out)
						assert.NoError(t, err)
						sort.Slice(out, func(i int, j int) bool {
							return migrate.VersionIsLess(out[i].Version, out[j].Version)
						})
						// the last migration should match what we want
						v, _ := migrate.NewVersion(tc.version)
						assert.Equal(t, *v, out[len(out)-1].Version)

						// verify that all indexes are created
						verifyIndexes(t, db.client.Database(d).Collection(DbDevicesColl),
							[]mongo.IndexModel{
								{
									Keys: bson.D{
										{Key: model.DevKeyIdDataSha256, Value: 1},
									},
									Options: &options.IndexOptions{
										Background: &_false,
										Name:       &indexDevices_IdentityDataSha256,
										Unique:     &_true,
									},
								},
								{
									Keys: bson.D{
										{Key: model.DevKeyStatus, Value: 1},
										{Key: model.DevKeyId, Value: 1},
									},
									Options: &options.IndexOptions{
										Background: &_false,
										Name:       &indexDevices_Status,
									},
								},
							},
						)
						verifyIndexes(t, db.client.Database(d).Collection(DbAuthSetColl),
							[]mongo.IndexModel{
								{
									Keys: bson.D{
										{Key: model.AuthSetKeyDeviceId, Value: 1},
										{Key: model.AuthSetKeyIdDataSha256, Value: 1},
										{Key: model.AuthSetKeyPubKey, Value: 1},
									},
									Options: &options.IndexOptions{
										Background: &_false,
										Name:       &indexAuthSet_DeviceId_IdentityDataSha256_PubKey,
										Unique:     &_true,
									},
								},
								{
									Keys: bson.D{
										{Key: model.AuthSetKeyIdDataSha256, Value: 1},
										{Key: model.AuthSetKeyPubKey, Value: 1},
									},
									Options: &options.IndexOptions{
										Background: &_false,
										Name:       &indexAuthSet_IdentityDataSha256_PubKey,
										Unique:     &_true,
									},
								},
							},
						)
					}
				}

			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestStoreMigrationVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestMigrate in short mode.")
	}

	dbVersion, _ := migrate.NewVersion(DbVersion)
	testCases := map[string]struct {
		version *migrate.Version
		err     string
	}{
		DbVersion: {
			version: dbVersion,
			err:     "",
		},
		"and what version is that, error": {
			err: "version cant be nil.",
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc: %s", name), func(t *testing.T) {
			db.Wipe()
			db := NewDataStoreMongoWithClient(db.Client())

			ctx := context.Background()
			err := db.StoreMigrationVersion(ctx, tc.version)
			if tc.err == "" {
				assert.NoError(t, err)
				var out []migrate.MigrationEntry
				c := db.client.Database(DbName).Collection(migrate.DbMigrationsColl)
				cursor, err := c.Find(ctx, bson.M{})
				assert.NoError(t, err)
				err = cursor.All(ctx, &out)
				assert.NoError(t, err)
				v := tc.version
				assert.Equal(t, *v, out[len(out)-1].Version)

				// verify that all indexes are created
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func randDevStatus() string {
	statuses := []string{
		model.DevStatusAccepted,
		model.DevStatusPending,
		model.DevStatusRejected,
		model.DevStatusPreauth,
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

	// use 100 automatically creted devices
	const devCount = 100

	devsCountByStatus := make(map[string]int)

	devsList := make([]model.Device, 0, devCount)

	// populate DB with a set of devices
	for i := 0; i < devCount; i++ {
		dev := model.Device{
			Id:           fmt.Sprintf("%04d", i),
			IdData:       fmt.Sprintf("foo-%04d", i),
			IdDataSha256: []byte(fmt.Sprintf("foo-%04d", i)),
			Status:       randDevStatus(),
			TenantID:     "foo",
		}

		devsList = append(devsList, dev)
		err := db.AddDevice(ctx, dev)
		assert.NoError(t, err)
		devsCountByStatus[dev.Status]++
	}

	testCases := map[string]struct {
		skip            uint
		limit           uint
		filter          model.DeviceFilter
		expectedCount   int
		expectedStartId int
		expectedEndId   int
	}{
		"skip + limit": {
			skip:            10,
			limit:           5,
			expectedCount:   5,
			expectedStartId: 10,
			expectedEndId:   14,
		},
		"end of the range": {
			skip:            devCount - 10,
			limit:           15,
			expectedCount:   10,
			expectedStartId: 90,
			expectedEndId:   99,
		},
		"whole range": {
			skip:            0,
			limit:           devCount,
			expectedCount:   devCount,
			expectedStartId: 0,
			expectedEndId:   devCount - 1,
		},
		"filter acceted": {
			skip:  0,
			limit: devCount,
			filter: model.DeviceFilter{
				Status: []string{model.DevStatusAccepted},
			},
			expectedCount:   devCount,
			expectedStartId: 0,
			expectedEndId:   devCount - 1,
		},
		"filter rejected": {
			skip:  0,
			limit: devCount,
			filter: model.DeviceFilter{
				Status: []string{model.DevStatusRejected},
			},
			expectedCount:   devCount,
			expectedStartId: 0,
			expectedEndId:   devCount - 1,
		},
		"filter preauthorized": {
			skip:  0,
			limit: devCount,
			filter: model.DeviceFilter{
				Status: []string{model.DevStatusPreauth},
			},
			expectedCount:   devCount,
			expectedStartId: 0,
			expectedEndId:   devCount - 1,
		},
		"filter pending": {
			skip:  0,
			limit: devCount,
			filter: model.DeviceFilter{
				Status: []string{model.DevStatusPending},
			},
			expectedCount:   devCount,
			expectedStartId: 0,
			expectedEndId:   devCount - 1,
		},
		"filter by id": {
			skip:  0,
			limit: devCount,
			filter: model.DeviceFilter{
				IDs: []string{devsList[0].Id},
			},
			expectedCount:   1,
			expectedStartId: 0,
			expectedEndId:   0,
		},
		"filter by ids and statuses": {
			skip:  0,
			limit: devCount,
			filter: func() model.DeviceFilter {
				deviceIDs := make([]string, devCount/4)
				for i := range deviceIDs {
					deviceIDs[i] = devsList[i].Id
				}
				return model.DeviceFilter{
					IDs: deviceIDs,
					Status: []string{
						model.DevStatusAccepted,
						model.DevStatusPending,
						model.DevStatusRejected,
						model.DevStatusPreauth,
					},
				}
			}(),
			expectedCount:   devCount / 4,
			expectedStartId: 0,
			expectedEndId:   devCount/4 - 1,
		},
	}

	for name := range testCases {
		tc := testCases[name]
		t.Run(fmt.Sprintf("tc %s", name), func(t *testing.T) {
			dbdevs, err := db.GetDevices(ctx, tc.skip, tc.limit, tc.filter)
			assert.NoError(t, err)

			if len(tc.filter.Status) > 0 {
				if tc.filter.IDs == nil {
					var count int
					for _, stat := range tc.filter.Status {
						if c, ok := devsCountByStatus[stat]; ok {
							count += c
						}
					}
					assert.Len(t, dbdevs, count)
				} else {
					assert.Len(t, dbdevs, tc.expectedCount)
				}
				for _, d := range dbdevs {
					assert.Contains(t, tc.filter.Status, d.Status)
				}
			} else {
				assert.Len(t, dbdevs, tc.expectedCount)
				for i, dbidx := tc.expectedStartId, 0; i <= tc.expectedEndId; i, dbidx = i+1, dbidx+1 {
					// make sure that ID is not empty
					assert.NotEmpty(t, dbdevs[dbidx].Id)
					// clear it now so that next assert does not fail
					assert.EqualValues(t, devsList[i], dbdevs[dbidx])
				}
			}
			if tc.filter.IDs != nil {
				if assert.Len(t, dbdevs, len(tc.filter.IDs)) {
					for i := range dbdevs {
						assert.Equal(t,
							dbdevs[i].Id,
							tc.filter.IDs[i])
					}
				}
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

	asin := model.AuthSet{
		IdData:       "foobar",
		IdDataSha256: getIdDataHash("foobar"),
		PubKey:       "pubkey-1",
		DeviceId:     "1",
		Timestamp:    uto.TimePtr(time.Now()),
		TenantID:     tenant,
	}
	err := db.AddAuthSet(ctx, asin)
	assert.NoError(t, err)

	// try to get something that does not exist
	as, err := db.GetAuthSetByIdDataHashKey(ctx, getIdDataHash("foobar-2"), "pubkey-3")
	assert.Error(t, err)

	// no tenant
	as, err = db.GetAuthSetByIdDataHashKey(context.Background(), getIdDataHash("foobar"), "pubkey-1")
	assert.Error(t, err)

	as, err = db.GetAuthSetByIdDataHashKey(ctx, getIdDataHash("foobar"), "pubkey-1")
	assert.NoError(t, err)
	assert.NotNil(t, as)

	err = db.UpdateAuthSet(ctx, asin, model.AuthSetUpdate{
		Timestamp: uto.TimePtr(time.Now()),
	})
	assert.NoError(t, err)

	as, err = db.GetAuthSetByIdDataHashKey(ctx, getIdDataHash("foobar"), "pubkey-1")
	assert.NoError(t, err)
	assert.NotNil(t, as)
	assert.WithinDuration(t, time.Now(), uto.Time(as.Timestamp), time.Second)

	// clear timestamp field
	asin.Timestamp = nil
	// selectively update public key only, remaining fields should be unchanged
	err = db.UpdateAuthSet(ctx, asin, model.AuthSetUpdate{
		PubKey: "pubkey-2",
	})
	assert.NoError(t, err)

	as, err = db.GetAuthSetByIdDataHashKey(ctx, getIdDataHash("foobar"), "pubkey-2")
	assert.NoError(t, err)
	assert.NotNil(t, as)

	asid, err := db.GetAuthSetById(ctx, string(as.Id))
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

	// update nonexistent auth set
	err = db.UpdateAuthSet(ctx, model.AuthSet{Id: "1234"},
		model.AuthSetUpdate{
			Status: model.DevStatusAccepted,
		})
	assert.Error(t, err)
}

func TestUpdateAuthSetMultiple(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetDevices in short mode.")
	}

	ctx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	db := getDb(ctx)

	// no authset raises an error
	err := db.UpdateAuthSet(ctx, model.AuthSet{
		DeviceId: "1",
	}, model.AuthSetUpdate{
		Status: model.DevStatusRejected,
	})
	assert.EqualError(t, err, store.ErrAuthSetNotFound.Error())

	asin := model.AuthSet{
		IdData:   "foobar",
		DeviceId: "1",
		Status:   model.DevStatusAccepted,
		TenantID: tenant,
	}
	// add 5 auth sets, all with status 'accepted'
	for i := 0; i < 5; i++ {
		asin.PubKey = fmt.Sprintf("pubkey-%d", i)
		asin.Timestamp = uto.TimePtr(time.Now())
		err := db.AddAuthSet(ctx, asin)
		assert.NoError(t, err)
	}
	// add another one that is pending
	err = db.AddAuthSet(ctx, model.AuthSet{
		IdData:    "foobar",
		PubKey:    "pubkey-5",
		DeviceId:  "1",
		Status:    model.DevStatusPending,
		Timestamp: uto.TimePtr(time.Now()),
		TenantID:  tenant,
	})
	assert.NoError(t, err)

	// update all accepted to rejected in a single call
	err = db.UpdateAuthSet(ctx, model.AuthSet{
		DeviceId: "1",
		Status:   model.DevStatusAccepted,
		TenantID: tenant,
	}, model.AuthSetUpdate{
		Status: model.DevStatusRejected,
	})
	assert.NoError(t, err)

	asets, err := db.GetAuthSetsForDevice(ctx, "1")
	assert.NoError(t, err)
	assert.Len(t, asets, 6)
	for idx, aset := range asets {
		if idx < 5 {
			assert.Equal(t, model.DevStatusRejected, aset.Status)
		} else {
			// last one is pending
			assert.Equal(t, model.DevStatusPending, aset.Status)
		}
	}

	// update one but last authset to accepted
	but_last := asets[len(asets)-2]
	err = db.UpdateAuthSetById(ctx, but_last.Id,
		model.AuthSetUpdate{
			Status: model.DevStatusAccepted,
		})
	assert.NoError(t, err)

	// verify that all but last are
	asets, err = db.GetAuthSetsForDevice(ctx, "1")
	assert.NoError(t, err)
	assert.Len(t, asets, 6)
	for idx, aset := range asets {
		if aset.Id == but_last.Id {
			assert.Equal(t, model.DevStatusAccepted, aset.Status)
		} else if idx < 5 {
			assert.Equal(t, model.DevStatusRejected, aset.Status)
		} else {
			assert.Equal(t, model.DevStatusPending, aset.Status)
		}
	}

}

func TestUpdateAuthSetBson(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestUpdateAuthSetBson in short mode.")
	}

	ctx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: "foo",
	})
	db := getDb(ctx)

	asin := model.AuthSet{
		IdData:   "foobar",
		DeviceId: "1",
		Status:   model.DevStatusPending,
	}
	// add 5 auth sets, all with status 'pending'
	for i := 0; i < 5; i++ {
		asin.PubKey = fmt.Sprintf("pubkey-%d", i)
		asin.Timestamp = uto.TimePtr(time.Now())
		err := db.AddAuthSet(ctx, asin)
		assert.NoError(t, err)
	}

	// add another one that is accepted
	err := db.AddAuthSet(ctx, model.AuthSet{
		IdData:    "foobar",
		PubKey:    "pubkey-5",
		DeviceId:  "1",
		Status:    model.DevStatusAccepted,
		Timestamp: uto.TimePtr(time.Now()),
	})
	assert.NoError(t, err)

	// and another one that is preauthorized
	err = db.AddAuthSet(ctx, model.AuthSet{
		IdData:    "foobar",
		PubKey:    "pubkey-6",
		DeviceId:  "1",
		Status:    model.DevStatusPreauth,
		Timestamp: uto.TimePtr(time.Now()),
	})
	assert.NoError(t, err)

	// update all accepted/preauthorized to rejected in a single call
	err = db.UpdateAuthSet(ctx,
		bson.M{
			model.AuthSetKeyDeviceId: "1",
			"$or": []bson.M{
				{model.AuthSetKeyStatus: model.DevStatusAccepted},
				{model.AuthSetKeyStatus: model.DevStatusPreauth},
			},
		},

		model.AuthSetUpdate{
			Status: model.DevStatusRejected,
		})
	assert.NoError(t, err)

	asets, err := db.GetAuthSetsForDevice(ctx, "1")
	assert.NoError(t, err)
	assert.Len(t, asets, 7)
	for idx, aset := range asets {
		if idx < 5 {
			assert.Equal(t, model.DevStatusPending, aset.Status)
		} else {
			// last 2 are rejected
			assert.Equal(t, model.DevStatusRejected, aset.Status)
		}
	}
}

func TestStoreDeleteDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestStoreDeleteDevice in short mode.")
	}

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	db := getDb(dbCtx)

	// setup devices
	inputDevices := bson.A{
		dev1,
		dev2,
	}
	c := db.client.Database(ctxstore.DbFromContext(dbCtx, DbName)).Collection(DbDevicesColl)
	_, err := c.InsertMany(dbCtx, inputDevices)
	assert.NoError(t, err, "failed to setup input data")

	coll := db.client.Database(DbName).Collection(DbDevicesColl)

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
				err := coll.FindOne(ctx, bson.M{"_id": tc.devId}).Decode(&found)
				if assert.Error(t, err) {
					assert.Equal(t, err.Error(), mongo.ErrNoDocuments.Error())
				}
			}
		})
	}
}

func TestStoreDeleteAuthSetsForDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestStoreDeleteAuthSetsForDevice in short mode.")
	}

	authSets := bson.A{
		model.AuthSet{
			Id:       "1",
			DeviceId: "001",
			IdData:   "id-001",
			PubKey:   "key-001-1",
		},
		model.AuthSet{
			Id:       "2",
			DeviceId: "002",
			IdData:   "id-002",
			PubKey:   "key-002-1",
		},
		model.AuthSet{
			Id:       "3",
			DeviceId: "001",
			IdData:   "id-001",
			PubKey:   "key-001-2",
		},
		model.AuthSet{
			Id:       "4",
			DeviceId: "002",
			IdData:   "id-002",
			PubKey:   "key-002-2",
		},
		model.AuthSet{
			Id:       "5",
			DeviceId: "002",
			IdData:   "id-002",
			PubKey:   "key-002-3",
		},
	}

	testCases := []struct {
		devId  string
		tenant string

		outAuthSets []model.AuthSet
		err         string
	}{
		{
			devId: "001",
			outAuthSets: []model.AuthSet{
				{
					Id:       "2",
					DeviceId: "002",
					IdData:   "id-002",
					PubKey:   "key-002-1",
				},
				{
					Id:       "4",
					DeviceId: "002",
					IdData:   "id-002",
					PubKey:   "key-002-2",
				},
				{
					Id:       "5",
					DeviceId: "002",
					IdData:   "id-002",
					PubKey:   "key-002-3",
				},
			},
			tenant: tenant,
			err:    "",
		},
		{
			devId: "002",
			outAuthSets: []model.AuthSet{
				{
					Id:       "1",
					DeviceId: "001",
					IdData:   "id-001",
					PubKey:   "key-001-1",
				},
				{
					Id:       "3",
					DeviceId: "001",
					IdData:   "id-001",
					PubKey:   "key-001-2",
				},
			},
			tenant: "asdf",
			err:    "",
		},
		{
			devId:  "100",
			tenant: tenant,
			outAuthSets: []model.AuthSet{
				{
					Id:       "1",
					DeviceId: "001",
					IdData:   "id-001",
					PubKey:   "key-001-1",
				},
				{
					Id:       "2",
					DeviceId: "002",
					IdData:   "id-002",
					PubKey:   "key-002-1",
				},
				{
					Id:       "3",
					DeviceId: "001",
					IdData:   "id-001",
					PubKey:   "key-001-1",
				},
				{
					Id:       "4",
					DeviceId: "002",
					IdData:   "id-002",
					PubKey:   "key-002-2",
				},
				{
					Id:       "5",
					DeviceId: "002",
					IdData:   "id-002",
					PubKey:   "key-002-3",
				},
			},
			err: store.ErrAuthSetNotFound.Error(),
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

			db := getDb(ctx)

			c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)
			_, err := c.InsertMany(ctx, authSets)
			assert.NoError(t, err)

			err = db.DeleteAuthSetsForDevice(ctx, tc.devId)
			if tc.err != "" {
				assert.Equal(t, tc.err, err.Error())
			} else {
				assert.NoError(t, err)
				var out []model.AuthSet
				cursor, err := c.Find(ctx, bson.M{})
				assert.NoError(t, err)
				err = cursor.All(ctx, &out)
				assert.NoError(t, err)
				assert.Equal(t, tc.outAuthSets, out)
			}
		})
	}
}

func TestPutLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestPutLimit in short mode.")
	}

	lim1 := model.Limit{
		Name:  "foo",
		Value: 123,
	}
	lim2 := model.Limit{
		Name:  "bar",
		Value: 456,
	}

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	db := getDb(dbCtx)

	coll := db.client.Database(ctxstore.DbFromContext(dbCtx, DbName)).Collection(DbLimitsColl)
	_, err := coll.InsertMany(dbCtx, bson.A{lim1, lim2})
	assert.NoError(t, err)

	dbCtxOtherTenant := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: "other-" + tenant,
	})
	collOtherTenant := db.client.Database(ctxstore.DbFromContext(dbCtxOtherTenant, DbName)).Collection(DbLimitsColl)
	_, err = collOtherTenant.InsertMany(dbCtx, bson.A{lim1, lim2})
	assert.NoError(t, err)

	var lim model.Limit

	assert.NoError(t, coll.FindOne(dbCtx, bson.M{"_id": "foo"}).Decode(&lim))

	// empty limit name
	err = db.PutLimit(dbCtx, model.Limit{Name: "", Value: 123})
	assert.Error(t, err)

	// update
	err = db.PutLimit(dbCtx, model.Limit{Name: "foo", Value: 999})
	assert.NoError(t, err)
	assert.NoError(t, coll.FindOne(dbCtx, bson.M{"_id": "foo"}).Decode(&lim))
	assert.EqualValues(t, model.Limit{Name: "foo", Value: 999}, lim)

	// insert
	err = db.PutLimit(dbCtx, model.Limit{Name: "baz", Value: 9809899990})
	assert.NoError(t, err)
	assert.NoError(t, coll.FindOne(dbCtx, bson.M{"_id": "baz"}).Decode(&lim))
	assert.EqualValues(t, model.Limit{Name: "baz", Value: 9809899990}, lim)

	// switch tenants

	// the other-tenant limit 'foo' was not modified
	assert.NoError(t, collOtherTenant.FindOne(dbCtx, bson.M{"_id": "foo"}).Decode(&lim))
	assert.EqualValues(t, lim1, lim)

	// update
	err = db.PutLimit(dbCtxOtherTenant, model.Limit{Name: "bar", Value: 1234})
	assert.NoError(t, err)
	assert.NoError(t, collOtherTenant.FindOne(dbCtx, bson.M{"_id": "bar"}).Decode(&lim))
	assert.EqualValues(t, model.Limit{Name: "bar", Value: 1234}, lim)
	// original tenant is unmodified
	assert.NoError(t, coll.FindOne(dbCtx, bson.M{"_id": "bar"}).Decode(&lim))
	assert.EqualValues(t, lim2, lim)

}

func TestDeleteLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestDeleteLimit in short mode.")
	}

	lim1 := model.Limit{
		Name:  "foo",
		Value: 123,
	}
	lim2 := model.Limit{
		Name:  "bar",
		Value: 456,
	}

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	db := getDb(dbCtx)

	coll := db.client.Database(ctxstore.DbFromContext(dbCtx, DbName)).Collection(DbLimitsColl)
	_, err := coll.InsertMany(dbCtx, bson.A{lim1, lim2})
	assert.NoError(t, err)

	dbCtxOtherTenant := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: "other-" + tenant,
	})
	collOtherTenant := db.client.Database(ctxstore.DbFromContext(dbCtxOtherTenant, DbName)).Collection(DbLimitsColl)
	_, err = collOtherTenant.InsertMany(dbCtx, bson.A{lim1, lim2})
	assert.NoError(t, err)

	var lim model.Limit
	assert.NoError(t, coll.FindOne(dbCtx, bson.M{"_id": lim1.Name}).Decode(&lim))

	// delete the limit
	err = db.DeleteLimit(dbCtx, lim.Name)
	assert.NoError(t, err)

	// limit not found
	assert.Error(t, coll.FindOne(dbCtx, bson.M{"_id": lim1.Name}).Decode(&lim))

	// the other-tenant limit 'foo' was not modified
	assert.NoError(t, collOtherTenant.FindOne(dbCtx, bson.M{"_id": lim1.Name}).Decode(&lim))
	assert.EqualValues(t, lim1, lim)
}

func TestGetLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestStoreDeleteAuthSetsForDevice in short mode.")
	}

	lim1 := model.Limit{
		Name:  "foo",
		Value: 123,
		TenantID: tenant,
	}
	lim2 := model.Limit{
		Name:  "bar",
		Value: 456,
		TenantID: tenant,
	}
	lim3OtherTenant := model.Limit{
		Name:  "bar",
		Value: 920,
		TenantID: tenant,
	}

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	db := getDb(dbCtx)

	coll := db.client.Database(DbName).Collection(DbLimitsColl)
	_, err := coll.InsertMany(dbCtx, bson.A{lim1, lim2})
	assert.NoError(t, err)

	dbCtxOtherTenant := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: "other-" + tenant,
	})

	collOtherTenant := db.client.Database(DbName).Collection(DbLimitsColl)
	_, err = collOtherTenant.InsertMany(dbCtx, bson.A{lim3OtherTenant})
	assert.NoError(t, err)

	// check if value is fetched correctly
	lim, err := db.GetLimit(dbCtx, "foo")
	assert.NoError(t, err)
	assert.EqualValues(t, lim1, *lim)

	// try with something that does not exist
	lim, err = db.GetLimit(dbCtx, "nonexistent-foo")
	assert.EqualError(t, err, store.ErrLimitNotFound.Error())
	assert.Nil(t, lim)

	// switch tenants
	lim, err = db.GetLimit(dbCtxOtherTenant, "foo")
	assert.EqualError(t, err, store.ErrLimitNotFound.Error())

	lim, err = db.GetLimit(dbCtxOtherTenant, "bar")
	assert.NoError(t, err)
	assert.EqualValues(t, lim3OtherTenant, *lim)
}

func TestStoreGetDevCountByStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetDevCountByStatus in short mode.")
	}

	ctx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: "foo",
	})

	testCases := []struct {
		accepted      int
		preauthorized int
		pending       int
		rejected      int
		noauth        int
	}{
		{
			accepted:      0,
			preauthorized: 0,
			pending:       4,
			rejected:      0,
			noauth:        0,
		},
		{
			accepted:      5,
			preauthorized: 0,
			pending:       0,
			rejected:      0,
			noauth:        0,
		},
		{
			accepted:      0,
			preauthorized: 0,
			pending:       0,
			rejected:      6,
			noauth:        0,
		},
		{
			accepted:      0,
			preauthorized: 9,
			pending:       0,
			rejected:      0,
			noauth:        0,
		},
		{
			accepted:      4,
			preauthorized: 3,
			pending:       2,
			rejected:      1,
			noauth:        0,
		},
		{
			accepted:      1,
			preauthorized: 4,
			pending:       4,
			rejected:      2,
			noauth:        0,
		},
		{
			accepted:      10,
			preauthorized: 22,
			pending:       30,
			rejected:      12,
			noauth:        0,
		},
		{
			accepted:      10,
			preauthorized: 1,
			pending:       30,
			rejected:      0,
			noauth:        0,
		},
		{
			accepted:      0,
			preauthorized: 0,
			pending:       30,
			rejected:      12,
			noauth:        0,
		},
		{
			accepted:      10,
			preauthorized: 7,
			pending:       0,
			rejected:      12,
			noauth:        0,
		},
		{
			accepted:      0,
			preauthorized: 0,
			pending:       0,
			rejected:      0,
			noauth:        0,
		},
		{
			accepted:      0,
			preauthorized: 0,
			pending:       0,
			rejected:      0,
			noauth:        2,
		},
		{
			accepted:      1,
			preauthorized: 0,
			pending:       0,
			rejected:      0,
			noauth:        2,
		},
		{
			accepted:      1,
			preauthorized: 0,
			pending:       3,
			rejected:      0,
			noauth:        2,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			db := getDb(ctx)

			devs := getDevsWithStatuses(tc.accepted, tc.preauthorized, tc.pending, tc.rejected, tc.noauth)

			// populate DB with a set of devices
			for d, set := range devs {
				err := db.AddDevice(ctx, *d)
				assert.NoError(t, err)

				for _, s := range set {
					err := db.AddAuthSet(ctx, s)
					assert.NoError(t, err)
				}
			}

			cntAcc, err := db.GetDevCountByStatus(ctx, "accepted")
			cntPre, err := db.GetDevCountByStatus(ctx, "preauthorized")
			cntPen, err := db.GetDevCountByStatus(ctx, "pending")
			cntRej, err := db.GetDevCountByStatus(ctx, "rejected")
			cntNoauth, err := db.GetDevCountByStatus(ctx, "noauth")
			cntAll, err := db.GetDevCountByStatus(ctx, "")

			assert.NoError(t, err)
			assert.Equal(t, tc.accepted, cntAcc)
			assert.Equal(t, tc.preauthorized, cntPre)
			assert.Equal(t, tc.pending, cntPen)
			assert.Equal(t, tc.rejected, cntRej)
			assert.Equal(t, tc.noauth, cntNoauth)
			assert.Equal(t, tc.rejected+tc.accepted+tc.pending+tc.preauthorized+tc.noauth, cntAll)
		})
	}
}

// generate a list of devices having the desired number of total accepted/preauthorized/pending/rejected/noauth devices
// auth sets for these devs will generated semi-randomly to aggregate to a given device's target status
func getDevsWithStatuses(accepted, preauthorized, pending, rejected, noauth int) map[*model.Device][]model.AuthSet {
	total := accepted + preauthorized + pending + rejected + noauth

	res := make(map[*model.Device][]model.AuthSet)

	for i := 0; i < total; i++ {
		status := "pending"
		if i < accepted {
			status = "accepted"
		} else if i < (accepted + rejected) {
			status = "rejected"
		} else if i < (accepted + rejected + preauthorized) {
			status = "preauthorized"
		} else if i < (accepted + rejected + preauthorized + noauth) {
			status = "noauth"
		}
		dev, sets := getDevWithStatus(i, status)
		res[dev] = sets
	}

	return res
}

func getDevWithStatus(id int, status string) (*model.Device, []model.AuthSet) {
	iddata := fmt.Sprintf("foo-%04d", id)
	dev := model.Device{
		Id:     fmt.Sprintf("%d", id),
		IdData: iddata,
		Status: status,
	}

	var asets []model.AuthSet
	if status != "noauth" {
		asets = getAuthSetsForStatus(&dev, status)
	}

	return &dev, asets
}

// create a semi-random list of auth sets resultng in a desired device status
func getAuthSetsForStatus(dev *model.Device, status string) []model.AuthSet {
	n := rand.Intn(4) + 1

	asets := make([]model.AuthSet, 0, n)

	// create "rejected" auth sets, then populate
	// with some accepted/pending, depending on the target status
	for i := 0; i < n; i++ {
		set := model.AuthSet{
			IdData:    dev.IdData,
			PubKey:    fmt.Sprintf("%s-%04d", dev.IdData, i),
			DeviceId:  dev.Id,
			Timestamp: uto.TimePtr(time.Now()),
			Status:    "rejected",
		}
		asets = append(asets, set)
	}

	if status != "rejected" {
		asets[len(asets)-1].Status = status
	}

	return asets
}

func TestStoreDeleteAuthSetForDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestStoreDeleteAuthSetForDevice in short mode.")
	}

	authSets := bson.A{
		model.AuthSet{
			Id:       "001",
			DeviceId: "001",
			IdData:   "001",
			PubKey:   "001",
		},
		model.AuthSet{
			Id:       "002",
			DeviceId: "001",
			IdData:   "001",
			PubKey:   "002",
		},
	}

	dbCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	db := getDb(dbCtx)

	coll := db.client.Database(ctxstore.DbFromContext(dbCtx, DbName)).Collection(DbAuthSetColl)
	_, err := coll.InsertMany(dbCtx, authSets)
	assert.NoError(t, err)

	testCases := []struct {
		devId  string
		authId string
		tenant string
		err    string
	}{
		{
			devId:  "001",
			authId: "001",
			tenant: tenant,
			err:    "",
		},
		{
			devId:  "001",
			authId: "003",
			err:    store.ErrAuthSetNotFound.Error(),
		},
		{
			devId:  "100",
			authId: "001",
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

			err := db.DeleteAuthSetForDevice(ctx, tc.devId, tc.authId)
			if tc.err != "" {
				assert.Equal(t, tc.err, err.Error())
			} else {
				assert.NoError(t, err)
				_, err := db.GetAuthSetById(ctx, tc.authId)
				if assert.Error(t, err) {
					assert.Equal(t, err.Error(), store.ErrAuthSetNotFound.Error())
				}
			}
		})
	}
}

func TestStoreGetDeviceStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestStoreGetDeviceStatus in short mode.")
	}

	testCases := map[string]struct {
		devId      string
		tenant     string
		inAuthSets []interface{}

		status string
		err    string
	}{
		"ok, accepted": {
			devId: "001",
			inAuthSets: bson.A{
				model.AuthSet{
					Id:       "1",
					DeviceId: "001",
					Status:   model.DevStatusAccepted,
				},
				model.AuthSet{
					Id:       "2",
					DeviceId: "001",
					Status:   model.DevStatusPending,
				},
				model.AuthSet{
					Id:       "3",
					DeviceId: "001",
					Status:   model.DevStatusRejected,
				},
				model.AuthSet{
					Id:       "4",
					DeviceId: "001",
					Status:   model.DevStatusPreauth,
				},
				model.AuthSet{
					Id:       "5",
					DeviceId: "001",
					Status:   model.DevStatusPending,
				},
				model.AuthSet{
					Id:       "6",
					DeviceId: "001",
					Status:   model.DevStatusRejected,
				},
				model.AuthSet{
					Id:       "7",
					DeviceId: "001",
					Status:   model.DevStatusRejected,
				},
			},
			tenant: tenant,
			status: model.DevStatusAccepted,
			err:    "",
		},
		"ok, preauthorized": {
			devId: "001",
			inAuthSets: bson.A{
				model.AuthSet{
					Id: "1",
					// different device
					DeviceId: "002",
					Status:   model.DevStatusAccepted,
				},
				model.AuthSet{
					Id:       "2",
					DeviceId: "001",
					Status:   model.DevStatusPending,
				},
				model.AuthSet{
					Id:       "3",
					DeviceId: "001",
					Status:   model.DevStatusRejected,
				},
				model.AuthSet{
					Id:       "4",
					DeviceId: "001",
					Status:   model.DevStatusPreauth,
				},
			},
			tenant: tenant,
			status: model.DevStatusPreauth,
			err:    "",
		},
		"ok, pending": {
			devId: "001",
			inAuthSets: bson.A{
				model.AuthSet{
					Id:       "2",
					DeviceId: "001",
					Status:   model.DevStatusPending,
				},
				model.AuthSet{
					Id:       "3",
					DeviceId: "001",
					Status:   model.DevStatusRejected,
				},
			},
			tenant: tenant,
			status: model.DevStatusPending,
			err:    "",
		},
		"ok, rejected": {
			devId: "001",
			inAuthSets: bson.A{
				model.AuthSet{
					Id:       "1",
					DeviceId: "001",
					Status:   model.DevStatusRejected,
				},
				model.AuthSet{
					Id:       "2",
					DeviceId: "001",
					Status:   model.DevStatusRejected,
				},
				model.AuthSet{
					Id:       "3",
					DeviceId: "001",
					Status:   model.DevStatusRejected,
				},
			},
			tenant: tenant,
			status: model.DevStatusRejected,
			err:    "",
		},
		"auth sets not found": {
			devId:  "001",
			tenant: tenant,
			status: "",
			err:    store.ErrAuthSetNotFound.Error(),
		},
		"dev not found - different device id": {
			devId: "005",
			inAuthSets: bson.A{
				model.AuthSet{
					Id:       "1",
					DeviceId: "001",
					Status:   model.DevStatusRejected,
				},
				model.AuthSet{
					Id:       "2",
					DeviceId: "001",
					Status:   model.DevStatusRejected,
				},
				model.AuthSet{
					Id:       "3",
					DeviceId: "001",
					Status:   model.DevStatusRejected,
				},
			},
			tenant: tenant,
			status: "",
			err:    store.ErrAuthSetNotFound.Error(),
		},
		"error, too many accepted": {
			devId: "001",
			inAuthSets: bson.A{
				model.AuthSet{
					Id:       "2",
					DeviceId: "001",
					Status:   model.DevStatusAccepted,
				},
				model.AuthSet{
					Id:       "3",
					DeviceId: "001",
					Status:   model.DevStatusAccepted,
				},
			},
			tenant: tenant,
			status: "",
			err:    store.ErrDevStatusBroken.Error(),
		},
		"error, too many preauth": {
			devId: "001",
			inAuthSets: bson.A{
				model.AuthSet{
					Id:       "2",
					DeviceId: "001",
					Status:   model.DevStatusPreauth,
				},
				model.AuthSet{
					Id:       "3",
					DeviceId: "001",
					Status:   model.DevStatusPreauth,
				},
			},
			tenant: tenant,
			status: "",
			err:    store.ErrDevStatusBroken.Error(),
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc: %s", name), func(t *testing.T) {
			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			db := getDb(ctx)

			if len(tc.inAuthSets) > 0 {
				coll := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)
				_, err := coll.InsertMany(ctx, tc.inAuthSets)
				assert.NoError(t, err)
			}

			status, err := db.GetDeviceStatus(ctx, tc.devId)
			if tc.err != "" {
				assert.Equal(t, tc.err, err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.status, status)
			}
		})
	}
}

func TestStoreUpdateuthSetById(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestStoreUpdateuthSetById in short mode.")
	}

	input := bson.A{
		model.AuthSet{
			Id:       "1",
			DeviceId: "1",
			IdData:   `{"mac": "00:00:00:01", "sn":  "0001"}`,
			IdDataStruct: map[string]interface{}{
				"mac": "00:00:00:01",
				"sn":  "0001",
			},
			IdDataSha256: []byte{1, 2, 3},
			PubKey:       "pubkey1",
			Status:       "pending",
		},
		model.AuthSet{
			Id:       "2",
			DeviceId: "2",
			IdData:   `{"mac": "00:00:00:02", "sn":  "0002"}`,
			IdDataStruct: map[string]interface{}{
				"mac": "00:00:00:02",
				"sn":  "0002",
			},
			IdDataSha256: []byte{4, 5, 6},
			PubKey:       "pubkey2",
			Status:       "accepted",
		},
		model.AuthSet{
			Id:       "3",
			DeviceId: "2",
			IdData:   `{"mac": "00:00:00:03", "sn":  "0003"}`,
			IdDataStruct: map[string]interface{}{
				"mac": "00:00:00:03",
				"sn":  "0003",
			},
			IdDataSha256: []byte{7, 8, 9},
			PubKey:       "pubkey3",
			Status:       "pending",
		},
	}

	testCases := []struct {
		aid    string
		update model.AuthSetUpdate
		tenant string

		out *model.AuthSet
		err error
	}{
		{
			aid: "1",
			update: model.AuthSetUpdate{
				Status: "accepted",
			},
			out: &model.AuthSet{
				Id:       "1",
				DeviceId: "1",
				IdData:   `{"mac": "00:00:00:01", "sn":  "0001"}`,
				IdDataStruct: map[string]interface{}{
					"mac": "00:00:00:01",
					"sn":  "0001",
				},
				IdDataSha256: []byte{1, 2, 3},
				PubKey:       "pubkey1",
				Status:       "accepted",
			},
		},
		{
			aid:    "1",
			tenant: "foo",
			update: model.AuthSetUpdate{
				Status: "rejected",
			},
			out: &model.AuthSet{
				Id:       "1",
				DeviceId: "1",
				IdData:   `{"mac": "00:00:00:01", "sn":  "0001"}`,
				IdDataStruct: map[string]interface{}{
					"mac": "00:00:00:01",
					"sn":  "0001",
				},
				IdDataSha256: []byte{1, 2, 3},
				PubKey:       "pubkey1",
				Status:       "rejected",
			},
		},
		{
			aid: "2",
			update: model.AuthSetUpdate{
				Status: "rejected",
			},
			out: &model.AuthSet{
				Id:       "2",
				DeviceId: "2",
				IdData:   `{"mac": "00:00:00:02", "sn":  "0002"}`,
				IdDataStruct: map[string]interface{}{
					"mac": "00:00:00:02",
					"sn":  "0002",
				},
				IdDataSha256: []byte{4, 5, 6},
				PubKey:       "pubkey2",
				Status:       "rejected",
			},
		},
		{
			aid: "notfound",
			update: model.AuthSetUpdate{
				Status: "rejected",
			},
			err: store.ErrAuthSetNotFound,
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
			db := getDb(ctx)

			coll := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)
			_, err := coll.InsertMany(ctx, input)
			assert.NoError(t, err, "failed to setup input data")

			err = db.UpdateAuthSetById(ctx, tc.aid, tc.update)

			if tc.err != nil {
				assert.EqualError(t, tc.err, err.Error())
			} else {
				assert.NoError(t, err)

				var found model.AuthSet
				coll := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)
				err := coll.FindOne(ctx, bson.M{"_id": tc.aid}).Decode(&found)
				assert.NoError(t, err)

				compareAuthSet(tc.out, &found, t)
			}
		})
	}
}

func TestStoreGetDeviceById(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestStoreGetDeviceById in short mode.")
	}

	// set this to get reliable time.Time serialization
	// (always get UTC instead of e.g. CEST)
	time.Local = time.UTC

	indescr := []struct {
		id           string
		idData       string
		idDataSha256 []byte
		limits       ratelimits.ApiLimits
	}{
		{
			id:           "dev1",
			idData:       "idData1",
			idDataSha256: getIdDataHash("idData1"),
			//default limits
		},
		{
			id:           "dev2",
			idData:       "idData2",
			idDataSha256: getIdDataHash("idData2"),
			limits: ratelimits.ApiLimits{
				ApiQuota: ratelimits.ApiQuota{
					MaxCalls:    100,
					IntervalSec: 60,
				},
				ApiBursts: []ratelimits.ApiBurst{
					{
						Action:         "POST",
						Uri:            "/api/management/v1/deployments/device/deployments/next",
						MinIntervalSec: 3600,
					},
					{
						Action:         "PATCH",
						Uri:            "/api/devices/v1/inventory/device/attributes",
						MinIntervalSec: 60,
					},
				},
			},
		},
		{
			id:           "dev3",
			idData:       "idData4",
			idDataSha256: getIdDataHash("idData4"),
			limits: ratelimits.ApiLimits{
				ApiQuota: ratelimits.ApiQuota{
					MaxCalls:    1000,
					IntervalSec: 3600,
				},
				ApiBursts: []ratelimits.ApiBurst{},
			},
		},
	}

	indevs := make([]interface{}, len(indescr))
	for i, descr := range indescr {
		dev := model.NewDevice(oid.NewUUIDv5(descr.id).String(), descr.idData, "")
		dev.IdDataSha256 = descr.idDataSha256
		dev.ApiLimits = descr.limits
		indevs[i] = dev
	}

	testCases := []struct {
		id     string
		expIdx int
		err    error

		tenant string
	}{
		{
			id:     oid.NewUUIDv5("dev1").String(),
			expIdx: 0,
		},
		{
			id:     oid.NewUUIDv5("dev2").String(),
			expIdx: 1,
			tenant: "foo",
		},
		{
			id:     oid.NewUUIDv5("dev3").String(),
			expIdx: 2,
			tenant: "bar",
		},
		{
			id:  oid.NewUUIDv5("notfound").String(),
			err: store.ErrDevNotFound,
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

			d := getDb(ctx)

			c := d.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbDevicesColl)
			_, err := c.InsertMany(ctx, indevs)
			assert.NoError(t, err)

			out, err := d.GetDeviceById(ctx, tc.id)
			if tc.err != nil {
				assert.EqualError(t, tc.err, err.Error())
			} else {
				exp := indevs[tc.expIdx].(*model.Device)
				compareDevices(exp, out, t)
				assert.NoError(t, err)
			}
		})
	}
}

func getIdDataHash(idData string) []byte {
	hash := sha256.New()
	hash.Write([]byte(idData))
	return hash.Sum(nil)
}
