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
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	return NewDataStoreMongoWithSession(db.Session())
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

	if authreqs_dataset != "" {
		err := setUpAuthReqs(authreqs_dataset, s)
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

func setUpAuthReqs(dataset string, s *mgo.Session) error {
	reqs, err := parseAuthReqs(dataset)
	if err != nil {
		return err
	}

	c := s.DB(DbName).C(DbAuthReqColl)

	for _, r := range reqs {
		err = c.Insert(r)
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

func parseDevs(dataset string) ([]Device, error) {
	f, err := os.Open(filepath.Join(testDataFolder, dataset))
	if err != nil {
		return nil, err
	}

	var devs []Device

	j := json.NewDecoder(f)
	if err = j.Decode(&devs); err != nil {
		return nil, err
	}

	return devs, nil
}

func parseDev(dataset string) (*Device, error) {
	res, err := parseDevs(dataset)
	if err != nil {
		return nil, err
	}

	return &res[0], nil
}

func parseAuthReqs(dataset string) ([]AuthReq, error) {
	f, err := os.Open(filepath.Join(testDataFolder, dataset))
	if err != nil {
		return nil, err
	}

	var reqs []AuthReq

	j := json.NewDecoder(f)
	if err = j.Decode(&reqs); err != nil {
		return nil, err
	}

	return reqs, nil
}

func parseTokens(dataset string) ([]Token, error) {
	f, err := os.Open(filepath.Join(testDataFolder, dataset))
	if err != nil {
		return nil, err
	}

	var tokens []Token

	j := json.NewDecoder(f)
	if err = j.Decode(&tokens); err != nil {
		return nil, err
	}

	return tokens, nil
}

func parseToken(dataset string) (*Token, error) {
	res, err := parseTokens(dataset)
	if err != nil {
		return nil, err
	}

	return &res[0], nil
}

func TestGetDeviceById(t *testing.T) {
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
		deviceId string
		expected string
	}{
		{
			deviceId: "0001",
			expected: "device_expected_1.json",
		},
		{
			deviceId: "0002",
			expected: "device_expected_2.json",
		},
		{
			deviceId: "0003",
			expected: "",
		},
	}

	for _, tc := range testCases {
		var expected *Device

		if tc.expected != "" {
			expected, err = parseDev(tc.expected)
			assert.NoError(t, err, "failed to parse %s", tc.expected)
			assert.NotNil(t, expected)
		}

		dev, err := d.GetDeviceById(tc.deviceId)
		if expected != nil {
			assert.NoError(t, err, "failed to get devices")
			if assert.NotNil(t, dev) {
				compareDevices(expected, dev, t)
			}
		} else {
			assert.Equal(t, ErrDevNotFound, err)
		}
	}
}

func TestGetDeviceByKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetDeviceByKey in short mode.")
	}

	// set this to get reliable time.Time serialization
	// (always get UTC instead of e.g. CEST)
	time.Local = time.UTC

	d := getDb()
	defer d.session.Close()

	err := setUp(d, "devices_input.json", "", "")
	assert.NoError(t, err, "failed to setup input data")

	testCases := []struct {
		deviceKey string
		expected  string
	}{
		{
			//device 1
			deviceKey: "0001-key",
			expected:  "device_expected_1.json",
		},
		{
			//device 2
			deviceKey: "0002-key",
			expected:  "device_expected_2.json",
		},
		{
			//device doesn't exist
			deviceKey: "0003-key",
			expected:  "",
		},
	}

	for _, tc := range testCases {
		var expected *Device

		if tc.expected != "" {
			expected, err = parseDev(tc.expected)
			assert.NoError(t, err, "failed to parse %s", tc.expected)
			assert.NotNil(t, expected)
		}

		dev, err := d.GetDeviceByKey(tc.deviceKey)
		if expected != nil {
			assert.NoError(t, err, "failed to get devices")
			if assert.NotNil(t, dev) {
				compareDevices(expected, dev, t)
			}
		} else {
			assert.Equal(t, ErrDevNotFound, err)
		}

	}
}

// custom AuthReq comparison with 'compareTime'
func compareAuthReq(expected *AuthReq, actual *AuthReq, t *testing.T) {
	assert.Equal(t, expected.IdData, actual.IdData)
	assert.Equal(t, expected.TenantToken, actual.TenantToken)
	assert.Equal(t, expected.PubKey, actual.PubKey)
	assert.Equal(t, expected.DeviceId, actual.DeviceId)
	assert.Equal(t, expected.Status, actual.Status)
	compareTime(expected.Timestamp, actual.Timestamp, t)
}

func TestAddDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestAddDevice in short mode.")
	}
	time.Local = time.UTC

	//setup
	dev := Device{
		Id:          "id",
		TenantToken: "tenant",
		PubKey:      "pubkey",
		IdData:      "iddata",
		Status:      "pending",
		CreatedTs:   time.Now(),
		UpdatedTs:   time.Now(),
	}

	d := getDb()
	defer d.session.Close()

	err := d.AddDevice(&dev)
	assert.NoError(t, err, "failed to add device")

	//verify
	s := d.session.Copy()
	defer s.Close()

	var found Device

	c := s.DB(DbName).C(DbDevicesColl)

	err = c.FindId(dev.Id).One(&found)
	assert.NoError(t, err, "failed to find device")

	compareDevices(&dev, &found, t)
}

// custom Device comparison with 'compareTime'
func compareDevices(expected *Device, actual *Device, t *testing.T) {
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

func TestUpdateDevice(t *testing.T) {
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
			status: DevStatusAccepted,
			outErr: "",
		},
		{
			id:     "0002",
			status: DevStatusRejected,
			outErr: "",
		},
		{
			id:     "0003",
			status: DevStatusRejected,
			outErr: "failed to update device: not found",
		},
	}

	for _, tc := range testCases {
		updev := &Device{Id: tc.id, Status: tc.status}

		err = d.UpdateDevice(updev)
		if tc.outErr != "" {
			assert.EqualError(t, err, tc.outErr)
		} else {
			assert.NoError(t, err)

			//verify
			s := d.session.Copy()
			defer s.Close()

			var found Device

			c := s.DB(DbName).C(DbDevicesColl)

			err = c.FindId(tc.id).One(&found)
			assert.NoError(t, err, "failed to find device")

			//check all fields for equality - except UpdatedTs
			assert.Equal(t, tc.status, found.Status)

			//check UpdatedTs was updated
			assert.InEpsilon(t, now.Unix(), found.UpdatedTs.Unix(), 10)
		}
	}
}

func TestAddToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestAddToken in short mode.")
	}

	//setup
	token := Token{
		Id:    "123",
		DevId: "devId",
		Token: "token",
	}

	d := getDb()
	defer d.session.Close()

	err := d.AddToken(&token)
	assert.NoError(t, err, "failed to add token")

	//verify
	s := d.session.Copy()
	defer s.Close()

	var found Token

	c := s.DB(DbName).C(DbTokensColl)

	err = c.FindId(token.Id).One(&found)
	assert.NoError(t, err, "failed to find token")
	assert.Equal(t, found.Id, token.Id)
	assert.Equal(t, found.DevId, token.DevId)
	assert.Equal(t, found.Token, token.Token)

}

func TestGetToken(t *testing.T) {
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

	for _, tc := range testCases {
		var expected *Token

		if tc.expected != "" {
			expected, err = parseToken(tc.expected)
			assert.NoError(t, err, "failed to parse %s", tc.expected)
			assert.NotNil(t, expected)
		}

		token, err := d.GetToken(tc.tokenId)
		if expected != nil {
			assert.NoError(t, err, "failed to get token")
		} else {
			assert.Equal(t, ErrTokenNotFound, err)
		}

		assert.Equal(t, expected, token)
	}
}

func TestDeleteToken(t *testing.T) {
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

	for _, tc := range testCases {
		err := d.DeleteToken(tc.tokenId)
		if tc.err {
			assert.Equal(t, ErrTokenNotFound, err)
		} else {
			assert.NoError(t, err, "failed to delete token")
		}
	}
}

func TestDeleteTokenByDevId(t *testing.T) {
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

	for _, tc := range testCases {
		err := d.DeleteTokenByDevId(tc.devId)
		if tc.err {
			assert.Equal(t, ErrTokenNotFound, err)
		} else {
			assert.NoError(t, err, "failed to delete token")
		}
	}
}

func TestMigrate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestMigrate in short mode.")
	}

	testCases := map[string]struct {
		version string
		err     string
	}{
		"0.1.0": {
			version: "0.1.0",
			err:     "",
		},
		"1.2.3": {
			version: "1.2.3",
			err:     "",
		},
		"0.1 error": {
			version: "0.1",
			err:     "failed to parse service version: failed to parse Version: unexpected EOF",
		},
	}

	for name, tc := range testCases {
		t.Logf("case: %s", name)

		db := getDb()

		err := db.Migrate(tc.version, nil)
		if tc.err == "" {
			assert.NoError(t, err)
			var out []migrate.MigrationEntry
			db.session.DB(DbName).C(migrate.DbMigrationsColl).Find(nil).All(&out)
			assert.Len(t, out, 1)
			v, _ := migrate.NewVersion(tc.version)
			assert.Equal(t, v, out[0].Version)
		} else {
			assert.EqualError(t, err, tc.err)
		}
		db.session.Close()
	}

}
