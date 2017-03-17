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
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	uto "github.com/mendersoftware/deviceauth/utils/to"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	"github.com/stretchr/testify/assert"
	"gopkg.in/mgo.v2"
)

const (
	testDataFolder = "testdata/mongo"
)

// db and test management funcs
func getDb() *DataStoreMongo {
	db.Wipe()

	ds := NewDataStoreMongoWithSession(db.Session())
	ds.Index()

	return ds
}

func setUp(db *DataStoreMongo, devs_dataset,
	authreqs_dataset string, tokens_dataset string) error {
	s := db.session.Copy()
	defer s.Close()

	if devs_dataset != "" {
		err := setUpDevices(devs_dataset, s)
		if err != nil {
			return err
		}
	}

	if tokens_dataset != "" {
		err := setUpTokens(tokens_dataset, s)
		if err != nil {
			return err
		}
	}

	return nil
}

func setUpDevices(dataset string, s *mgo.Session) error {
	devs, err := parseDevs(dataset)
	if err != nil {
		return err
	}

	c := s.DB(DbName).C(DbDevicesColl)

	for _, d := range devs {
		err = c.Insert(d)
		if err != nil {
			return err
		}
	}

	return nil
}

func setUpTokens(dataset string, s *mgo.Session) error {
	tokens, err := parseTokens(dataset)
	if err != nil {
		return err
	}

	c := s.DB(DbName).C(DbTokensColl)

	for _, t := range tokens {
		err = c.Insert(t)
		if err != nil {
			return err
		}
	}

	return nil
}

func parseDevs(dataset string) ([]model.Device, error) {
	f, err := os.Open(filepath.Join(testDataFolder, dataset))
	if err != nil {
		return nil, err
	}

	var devs []model.Device

	j := json.NewDecoder(f)
	if err = j.Decode(&devs); err != nil {
		return nil, err
	}

	return devs, nil
}

func parseDev(dataset string) (*model.Device, error) {
	res, err := parseDevs(dataset)
	if err != nil {
		return nil, err
	}

	return &res[0], nil
}

func parseTokens(dataset string) ([]model.Token, error) {
	f, err := os.Open(filepath.Join(testDataFolder, dataset))
	if err != nil {
		return nil, err
	}

	var tokens []model.Token

	j := json.NewDecoder(f)
	if err = j.Decode(&tokens); err != nil {
		return nil, err
	}

	return tokens, nil
}

func parseToken(dataset string) (*model.Token, error) {
	res, err := parseTokens(dataset)
	if err != nil {
		return nil, err
	}

	return &res[0], nil
}

func TestStoreGetDeviceByIdentityData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetDeviceById in short mode.")
	}

	// set this to get reliable time.Time serialization
	// (always get UTC instead of e.g. CEST)
	time.Local = time.UTC

	d := getDb()
	defer d.session.Close()

	err := setUp(d, "devices_input.json", "", "")
	assert.NoError(t, err, "failed to setup input data")

	testCases := []struct {
		deviceIdData string
		expected     string
	}{
		{
			deviceIdData: "0001-id-data",
			expected:     "device_expected_1.json",
		},
		{
			deviceIdData: "0002-id-data",
			expected:     "device_expected_2.json",
		},
		{
			deviceIdData: "0003",
			expected:     "",
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			var expected *model.Device

			if tc.expected != "" {
				expected, err = parseDev(tc.expected)
				assert.NoError(t, err, "failed to parse %s", tc.expected)
				assert.NotNil(t, expected)
			}

			dev, err := d.GetDeviceByIdentityData(tc.deviceIdData)
			if expected != nil {
				assert.NoError(t, err, "failed to get devices")
				if assert.NotNil(t, dev) {
					compareDevices(expected, dev, t)
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

	d := getDb()
	defer d.session.Close()

	err := d.AddDevice(*dev)
	assert.NoError(t, err, "failed to add device")

	found, err := d.GetDeviceByIdentityData("iddata")
	assert.NoError(t, err)
	assert.NotNil(t, found)

	// verify that device ID was set
	assert.NotEmpty(t, found.Id)
	// clear it now to allow compareDevices() to succeed
	found.Id = ""
	compareDevices(dev, found, t)

	// add device with identical identity data
	err = d.AddDevice(model.Device{
		Id:     "foobar",
		IdData: "iddata",
	})
	assert.EqualError(t, err, store.ErrObjectExists.Error())
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

func TestStoreUpdateDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestUpdateDevice in short mode.")
	}
	time.Local = time.UTC

	now := time.Now()

	d := getDb()
	defer d.session.Close()

	err := setUp(d, "devices_input.json", "", "")
	assert.NoError(t, err, "failed to setup input data")

	//test status updates
	testCases := []struct {
		id     string
		status string
		outErr string
	}{
		{
			id:     "0001",
			status: model.DevStatusAccepted,
			outErr: "",
		},
		{
			id:     "0002",
			status: model.DevStatusRejected,
			outErr: "",
		},
		{
			id:     "0003",
			status: model.DevStatusRejected,
			outErr: store.ErrDevNotFound.Error(),
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			updev := &model.Device{Id: tc.id, Status: tc.status}

			err = d.UpdateDevice(updev)
			if tc.outErr != "" {
				assert.EqualError(t, err, tc.outErr)
			} else {
				assert.NoError(t, err)

				//verify
				s := d.session.Copy()
				defer s.Close()

				var found model.Device

				c := s.DB(DbName).C(DbDevicesColl)

				err = c.FindId(tc.id).One(&found)
				assert.NoError(t, err, "failed to find device")

				//check all fields for equality - except UpdatedTs
				assert.Equal(t, tc.status, found.Status)

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

	d := getDb()
	defer d.session.Close()

	err := d.AddToken(token)
	assert.NoError(t, err, "failed to add token")

	//verify
	s := d.session.Copy()
	defer s.Close()

	var found model.Token

	c := s.DB(DbName).C(DbTokensColl)

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

	d := getDb()
	defer d.session.Close()

	err := setUp(d, "", "", "tokens.json")
	assert.NoError(t, err, "failed to setup input data")

	testCases := []struct {
		tokenId  string
		expected string
	}{
		{
			tokenId:  "0001",
			expected: "token_expected_1.json",
		},
		{
			tokenId:  "0002",
			expected: "token_expected_2.json",
		},
		{
			tokenId:  "0003",
			expected: "",
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			var expected *model.Token

			if tc.expected != "" {
				expected, err = parseToken(tc.expected)
				assert.NoError(t, err, "failed to parse %s", tc.expected)
				assert.NotNil(t, expected)
			}

			token, err := d.GetToken(tc.tokenId)
			if expected != nil {
				assert.NoError(t, err, "failed to get token")
			} else {
				assert.Equal(t, store.ErrTokenNotFound, err)
			}

			assert.Equal(t, expected, token)
		})
	}
}

func TestStoreDeleteToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestDeleteToken in short mode.")
	}

	d := getDb()
	defer d.session.Close()

	err := setUp(d, "", "", "tokens.json")
	assert.NoError(t, err, "failed to setup input data")

	testCases := []struct {
		tokenId string
		err     bool
	}{
		{
			tokenId: "0001",
			err:     false,
		},
		{
			tokenId: "0002",
			err:     false,
		},
		{
			tokenId: "0003",
			err:     true,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			err := d.DeleteToken(tc.tokenId)
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

	d := getDb()
	defer d.session.Close()

	err := setUp(d, "", "", "tokens.json")
	assert.NoError(t, err, "failed to setup input data")

	testCases := []struct {
		devId string
		err   bool
	}{
		{
			devId: "dev_id_1",
			err:   false,
		},
		{
			devId: "dev_id_2",
			err:   false,
		},
		{
			devId: "dev_id_3",
			err:   true,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			err := d.DeleteTokenByDevId(tc.devId)
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
		version string
		err     string
	}{
		DbVersion: {
			version: DbVersion,
			err:     "",
		},
		"0.1 error": {
			version: "0.1",
			err:     "failed to parse service version: failed to parse Version: unexpected EOF",
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc: %s", name), func(t *testing.T) {
			db := getDb()
			ctx := context.Background()

			err := db.Migrate(ctx, tc.version, nil)
			if tc.err == "" {
				assert.NoError(t, err)
				var out []migrate.MigrationEntry
				db.session.DB(DbName).C(migrate.DbMigrationsColl).Find(nil).All(&out)
				sort.Slice(out, func(i int, j int) bool {
					return migrate.VersionIsLess(out[i].Version, out[j].Version)
				})
				// the last migration should match what we want
				v, _ := migrate.NewVersion(tc.version)
				assert.Equal(t, *v, out[len(out)-1].Version)
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

	db := getDb()
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
		err := db.AddDevice(dev)
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
			dbdevs, err := db.GetDevices(tc.skip, tc.limit)
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

	db := getDb()
	defer db.session.Close()

	asin := model.AuthSet{
		IdData:    "foobar",
		PubKey:    "pubkey-1",
		DeviceId:  "1",
		Timestamp: uto.TimePtr(time.Now()),
	}
	err := db.AddAuthSet(asin)
	assert.NoError(t, err)

	// try to get something that does not exist
	as, err := db.GetAuthSetByDataKey("foobar-2", "pubkey-3")
	assert.Error(t, err)

	as, err = db.GetAuthSetByDataKey("foobar", "pubkey-1")
	assert.NoError(t, err)
	assert.NotNil(t, as)

	assert.False(t, to.Bool(as.AdmissionNotified))

	err = db.UpdateAuthSet(asin, model.AuthSetUpdate{
		AdmissionNotified: to.BoolPtr(true),
		Timestamp:         uto.TimePtr(time.Now()),
	})
	assert.NoError(t, err)

	as, err = db.GetAuthSetByDataKey("foobar", "pubkey-1")
	assert.NoError(t, err)
	assert.NotNil(t, as)
	assert.True(t, to.Bool(as.AdmissionNotified))
	assert.WithinDuration(t, time.Now(), uto.Time(as.Timestamp), time.Second)

	// clear timestamp field
	asin.Timestamp = nil
	// selectively update public key only, remaining fields should be unchanged
	err = db.UpdateAuthSet(asin, model.AuthSetUpdate{
		PubKey: "pubkey-2",
	})
	assert.NoError(t, err)

	as, err = db.GetAuthSetByDataKey("foobar", "pubkey-2")
	assert.NoError(t, err)
	assert.NotNil(t, as)
	assert.True(t, to.Bool(as.AdmissionNotified))

	asid, err := db.GetAuthSetById(as.Id)
	assert.NoError(t, err)
	assert.NotNil(t, asid)

	assert.EqualValues(t, as, asid)

	// verify auth sets count for this device
	asets, err := db.GetAuthSetsForDevice("1")
	assert.NoError(t, err)
	assert.Len(t, asets, 1)

	// add another auth set
	asin = model.AuthSet{
		IdData:    "foobar",
		PubKey:    "pubkey-99",
		DeviceId:  "1",
		Timestamp: uto.TimePtr(time.Now()),
	}
	err = db.AddAuthSet(asin)
	assert.NoError(t, err)

	// we should have 2 now
	asets, err = db.GetAuthSetsForDevice("1")
	assert.NoError(t, err)
	assert.Len(t, asets, 2)
}

func TestStoreDeleteDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestStoreDeleteDevice in short mode.")
	}

	devices := []interface{}{
		model.Device{
			Id:     "001",
			IdData: "1",
		},
		model.Device{
			Id:     "002",
			IdData: "2",
		},
	}
	db := getDb()
	defer db.session.Close()
	s := db.session.Copy()
	defer s.Close()

	coll := s.DB(DbName).C(DbDevicesColl)
	assert.NoError(t, coll.Insert(devices...))

	testCases := []struct {
		devId string
		err   string
	}{
		{
			devId: "001",
			err:   "",
		},
		{
			devId: "100",
			err:   store.ErrDevNotFound.Error(),
		},
		{
			devId: "",
			err:   store.ErrDevNotFound.Error(),
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			err := db.DeleteDevice(tc.devId)
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
	db := getDb()
	defer db.session.Close()
	s := db.session.Copy()
	defer s.Close()

	coll := s.DB(DbName).C(DbAuthSetColl)
	assert.NoError(t, coll.Insert(authSets...))

	testCases := []struct {
		devId string
		err   string
	}{
		{
			devId: "001",
			err:   "",
		},
		{
			devId: "100",
			err:   store.ErrAuthSetNotFound.Error(),
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			err := db.DeleteAuthSetsForDevice(tc.devId)
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
