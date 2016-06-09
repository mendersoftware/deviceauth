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
	"github.com/stretchr/testify/assert"
	"gopkg.in/mgo.v2"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	testDataFolder = "testdata/mongo"
)

const TestDb = "127.0.0.1:27019"

// db and test management funcs
func getDb() (*DataStoreMongo, error) {
	d, err := NewDataStoreMongo(TestDb)
	if err != nil {
		return nil, err
	}

	return d, nil
}

func setUp(db *DataStoreMongo, devs_dataset, authreqs_dataset string) error {
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

func wipe(db *DataStoreMongo) error {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(DbName).C(DbDevicesColl)

	_, err := c.RemoveAll(nil)
	if err != nil {
		return err
	}

	c = s.DB(DbName).C(DbAuthReqColl)

	_, err = c.RemoveAll(nil)
	if err != nil {
		return err
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

// test funcs
func TestGetDeviceById(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetDeviceById in short mode.")
	}

	// set this to get reliable time.Time serialization
	// (always get UTC instead of e.g. CEST)
	time.Local = time.UTC

	d, err := getDb()
	if err != nil {
		t.Fatalf(err.Error())
	}

	//setup
	err = wipe(d)
	assert.NoError(t, err, "failed to wipe data")

	err = setUp(d, "devices_input.json", "")
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
		} else {
			assert.Equal(t, ErrDevNotFound, err)
		}

		assert.Equal(t, expected, dev)
	}
}

func TestGetDeviceByKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetDeviceByKey in short mode.")
	}

	// set this to get reliable time.Time serialization
	// (always get UTC instead of e.g. CEST)
	time.Local = time.UTC

	d, err := getDb()
	if err != nil {
		t.Fatalf(err.Error())
	}

	//setup
	err = wipe(d)
	assert.NoError(t, err, "failed to wipe data")

	err = setUp(d, "devices_input.json", "")
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
		} else {
			assert.Equal(t, ErrDevNotFound, err)
		}

		assert.Equal(t, expected, dev)
	}
}

func TestGetAuthRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetAuthRequests in short mode.")
	}

	// set this to get reliable time.Time serialization
	// (always get UTC instead of e.g. CEST)
	time.Local = time.UTC

	d, err := getDb()
	if err != nil {
		t.Fatalf(err.Error())
	}

	//setup
	err = wipe(d)
	assert.NoError(t, err, "failed to wipe data")

	err = setUp(d, "", "auth_reqs_input.json")
	assert.NoError(t, err, "failed to setup input data")

	testCases := []struct {
		deviceId string
		skip     int
		limit    int
		expected string
	}{
		{
			//existing device 1
			deviceId: "0001",
			skip:     0,
			limit:    0,
			expected: "auth_reqs_expected_1.json",
		},
		{
			//existing device 2
			deviceId: "0002",
			skip:     0,
			limit:    0,
			expected: "auth_reqs_expected_2.json",
		},
		{
			//existing device 1, skip + limit
			deviceId: "0001",
			skip:     1,
			limit:    1,
			expected: "auth_reqs_expected_3.json",
		},
		{
			//device doesn't exist
			deviceId: "0003",
			expected: "",
		},
	}

	for _, tc := range testCases {
		expected := []AuthReq{}

		if tc.expected != "" {
			expected, err = parseAuthReqs(tc.expected)
			assert.NoError(t, err, "failed to parse %s", tc.expected)
			assert.NotNil(t, expected)
		}

		reqs, err := d.GetAuthRequests(tc.deviceId, tc.skip, tc.limit)
		assert.NoError(t, err, "failed to get auth reqs")
		assert.Equal(t, expected, reqs)
	}
}
