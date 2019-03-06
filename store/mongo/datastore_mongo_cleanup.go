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

package mongo

import (
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/pkg/errors"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
)

const noCollectionErrMsg = "ns doesn't exist"

// Retrieves devices with decommissioning flag set
func (db *DataStoreMongo) GetDevicesBeingDecommissioned(dbName string) ([]model.Device, error) {

	s := db.session.Copy()
	defer s.Close()

	c := s.DB(dbName).C(DbDevicesColl)

	devices := []model.Device{}

	err := c.Find(model.Device{Decommissioning: true}).All(&devices)

	if err != nil && err != mgo.ErrNotFound {
		return nil, errors.Wrap(err, "failed to fetch devices")
	}

	return devices, nil
}

// Retrieves Ids of the auth sets owned by devices that are in decommissioning state or not owned by any device.
func (db *DataStoreMongo) GetBrokenAuthSets(dbName string) ([]string, error) {

	s := db.session.Copy()
	defer s.Close()

	deviceIds := []string{}
	brokenAuthSets := []string{}
	c := s.DB(dbName).C(DbAuthSetColl)

	// get all auth sets; group by device id

	job := &mgo.MapReduce{
		Map:    "function() { emit(this.device_id, 1) }",
		Reduce: "function(key, values) { return Array.sum(values) }",
	}

	var result []struct {
		DeviceId string `bson:"_id"`
		Value    int
	}

	_, err := c.Find(nil).MapReduce(job, &result)
	if err != nil {
		if err.Error() == noCollectionErrMsg {
			return nil, nil
		}
		return nil, err
	}

	for _, res := range result {
		deviceIds = append(deviceIds, res.DeviceId)
	}

	//check if devices exists
	nonexistentDevices, err := db.filterNonExistentDevices(dbName, deviceIds)
	if err != nil {
		return nil, err
	}

	// fetch auth sets for non exisitent devices
	for _, dev := range nonexistentDevices {

		authSets := []model.AuthSet{}

		err := c.Find(model.AuthSet{DeviceId: dev}).All(&authSets)
		if err != nil && err != mgo.ErrNotFound {
			return nil, errors.Wrap(err, "failed to fetch authentication sets")
		}

		for _, authSet := range authSets {
			brokenAuthSets = append(brokenAuthSets, authSet.Id)
		}
	}

	return brokenAuthSets, nil
}

// Get Ids of the tokens owned by devices that are in decommissioning state and tokens not
// owned by any device.
func (db *DataStoreMongo) GetBrokenTokens(dbName string) ([]string, error) {

	s := db.session.Copy()
	defer s.Close()

	deviceIds := []string{}
	brokenTokens := []string{}
	c := s.DB(dbName).C(DbTokensColl)

	// get all tokens; group by device id

	var result []struct {
		DeviceId string `bson:"_id"`
		Value    int
	}

	grp := bson.M{
		"$group": bson.M{
				"_id": "$device_id",
				"value": bson.M{
						"$sum": 1,
				},
		},
	}

	// find the status
	pipe := c.Pipe([]bson.M{grp})
 	err := pipe.All(&result)

	if err != nil {
		if err.Error() == noCollectionErrMsg {
			return nil, nil
		}
		return nil, err
	}

	for _, res := range result {
		deviceIds = append(deviceIds, res.DeviceId)
	}

	//check if devices exists
	nonexistentDevices, err := db.filterNonExistentDevices(dbName, deviceIds)
	if err != nil {
		return nil, err
	}

	// fetch tokens for non-exisitent devices
	for _, dev := range nonexistentDevices {

		tokens := []model.Token{}

		err := c.Find(model.TokenFilter{DevId: dev}).All(&tokens)
		if err != nil && err != mgo.ErrNotFound {
			return nil, errors.Wrap(err, "failed to fetch tokens")
		}

		for _, token := range tokens {
			brokenTokens = append(brokenTokens, token.Id)
		}
	}

	return brokenTokens, nil
}

// Deletes devices with decommissioning flag set
func (db *DataStoreMongo) DeleteDevicesBeingDecommissioned(dbName string) error {

	s := db.session.Copy()
	defer s.Close()

	c := s.DB(dbName).C(DbDevicesColl)

	_, err := c.RemoveAll(model.Device{Decommissioning: true})

	if err != nil {
		return errors.Wrap(err, "failed to delete devices")
	}

	return nil
}

// Deletes auth sets owned by devices that are in decommissioning state and auth sets not
// owned by any device.
func (db *DataStoreMongo) DeleteBrokenAuthSets(dbName string) error {

	s := db.session.Copy()
	defer s.Close()

	deviceIds := []string{}
	c := s.DB(dbName).C(DbAuthSetColl)

	// get all auth sets; group by device id
	job := &mgo.MapReduce{
		Map:    "function() { emit(this.device_id, 1) }",
		Reduce: "function(key, values) { return Array.sum(values) }",
	}
	var result []struct {
		DeviceId string `bson:"_id"`
		Value    int
	}
	_, err := c.Find(nil).MapReduce(job, &result)
	if err != nil {
		if err.Error() == noCollectionErrMsg {
			return nil
		}
		return err
	}
	for _, res := range result {
		deviceIds = append(deviceIds, res.DeviceId)
	}

	//check if devices exists
	nonexistentDevices, err := db.filterNonExistentDevices(dbName, deviceIds)
	if err != nil {
		return err
	}

	// delete authsets for non-exisitent devices
	for _, dev := range nonexistentDevices {
		_, err := c.RemoveAll(model.AuthSet{DeviceId: dev})
		if err != nil {
			return errors.Wrapf(err, "database %s, failed to delete authentication sets", dbName)
		}
	}

	return nil
}

// Deletes tokens owned by devices that are in decommissioning state and tokens not
// owned by any device.
func (db *DataStoreMongo) DeleteBrokenTokens(dbName string) error {

	s := db.session.Copy()
	defer s.Close()

	deviceIds := []string{}
	c := s.DB(dbName).C(DbTokensColl)

	// get all tokens; group by device id

	job := &mgo.MapReduce{
		Map:    "function() { emit(this.dev_id, 1) }",
		Reduce: "function(key, values) { return Array.sum(values) }",
	}

	var result []struct {
		DeviceId string `bson:"_id"`
		Value    int
	}

	_, err := c.Find(nil).MapReduce(job, &result)
	if err != nil {
		if err.Error() == store.NoCollectionErrMsg {
			return nil
		}
		return err
	}

	for _, res := range result {
		deviceIds = append(deviceIds, res.DeviceId)
	}

	//check if devices exists
	nonexistentDevices, err := db.filterNonExistentDevices(dbName, deviceIds)
	if err != nil {
		return err
	}

	// delete tokens for non exisiting devices
	for _, dev := range nonexistentDevices {
		_, err := c.RemoveAll(model.TokenFilter{DevId: dev})
		if err != nil && err != mgo.ErrNotFound {
			return errors.Wrapf(err, "database %s, failed to delete tokens", dbName)
		}
	}

	return nil
}

// Filters list of device ids.
// Result is the list of ids of non-existent devices and devices with decommissioning flag set.
func (db *DataStoreMongo) filterNonExistentDevices(dbName string, devIds []string) ([]string, error) {

	s := db.session.Copy()
	defer s.Close()

	nonexistentDevices := []string{}

	//check if device exists
	for _, devId := range devIds {
		res := model.Device{}
		err := s.DB(dbName).C(DbDevicesColl).FindId(devId).One(&res)
		if err == mgo.ErrNotFound || res.Decommissioning == true {
			nonexistentDevices = append(nonexistentDevices, devId)
		} else if err != nil {
			return nil, errors.Wrapf(err, "database %s, failed to retrieve devices", dbName)
		}
	}

	return nonexistentDevices, nil
}
