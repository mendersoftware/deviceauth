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
	"context"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
)

const noCollectionErrMsg = "ns doesn't exist"

// Retrieves devices with decommissioning flag set
func (db *DataStoreMongo) GetDevicesBeingDecommissioned(dbName string) ([]model.Device, error) {
	c := db.client.Database(dbName).Collection(DbDevicesColl)

	devices := []model.Device{}

	cursor, err := c.Find(context.Background(), model.Device{Decommissioning: true})
	if err != nil {
		return nil, err
	}
	if err = cursor.All(context.Background(), &devices); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, store.ErrDevNotFound
		}
		return nil, errors.Wrap(err, "failed to fetch devices")
	}

	return devices, nil
}

// Retrieves Ids of the auth sets owned by devices that are in decommissioning state or not owned by any device.
func (db *DataStoreMongo) GetBrokenAuthSets(dbName string) ([]string, error) {
	c := db.client.Database(dbName).Collection(DbAuthSetColl)

	deviceIds := []string{}
	brokenAuthSets := []string{}

	ctx := context.Background()

	// get all auth sets; group by device id

	group := bson.D{
		{Key: "$group", Value: bson.D{
			{Key: "_id", Value: "$device_id"}},
		},
	}
	pipeline := []bson.D{
		group,
	}
	var result []struct {
		DeviceId string `bson:"_id"`
	}

	cursor, err := c.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	if err := cursor.All(ctx, &result); err != nil {
		if err == mongo.ErrNoDocuments {
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

		cursor, err := c.Find(ctx, bson.M{"device_id": dev})
		if err != nil {
			return nil, errors.Wrap(err, "failed to fetch authentication sets")
		}
		if err = cursor.All(ctx, &authSets); err != nil {
			if err != mongo.ErrNoDocuments {
				return nil, errors.Wrap(err, "failed to fetch authentication sets")
			}
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
	c := db.client.Database(dbName).Collection(DbTokensColl)

	ctx := context.Background()

	deviceIds := []string{}
	brokenTokens := []string{}

	// get all tokens; group by device id

	group := bson.D{
		{Key: "$group", Value: bson.D{
			{Key: "_id", Value: "$dev_id"}},
		},
	}
	pipeline := []bson.D{
		group,
	}
	var result []struct {
		DeviceId string `bson:"_id"`
	}

	cursor, err := c.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	if err := cursor.All(ctx, &result); err != nil {
		if err == mongo.ErrNoDocuments {
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

		cursor, err := c.Find(ctx, model.TokenFilter{DevId: dev})
		if err != nil {
			return nil, errors.Wrap(err, "failed to fetch tokens")
		}
		if err = cursor.All(ctx, &tokens); err != nil {
			if err != mongo.ErrNoDocuments {
				return nil, errors.Wrap(err, "failed to fetch tokens")
			}
		}

		for _, token := range tokens {
			brokenTokens = append(brokenTokens, token.Id)
		}
	}

	return brokenTokens, nil
}

// Deletes devices with decommissioning flag set
func (db *DataStoreMongo) DeleteDevicesBeingDecommissioned(dbName string) error {
	c := db.client.Database(dbName).Collection(DbDevicesColl)

	_, err := c.DeleteMany(context.Background(), model.Device{Decommissioning: true})
	if err != nil {
		return errors.Wrap(err, "failed to remove decommissioned devices")
	}

	return nil
}

// Deletes auth sets owned by devices that are in decommissioning state and auth sets not
// owned by any device.
func (db *DataStoreMongo) DeleteBrokenAuthSets(dbName string) error {
	c := db.client.Database(dbName).Collection(DbAuthSetColl)

	authSets, err := db.GetBrokenAuthSets(dbName)
	if err != nil {
		return err
	}

	// delete authsets for non-exisitent devices
	for _, as := range authSets {
		_, err := c.DeleteOne(context.Background(), model.AuthSet{Id: as})
		if err != nil {
			return errors.Wrapf(err, "database %s, failed to delete authentication sets", dbName)
		}
	}

	return nil
}

// Deletes tokens owned by devices that are in decommissioning state and tokens not
// owned by any device.
func (db *DataStoreMongo) DeleteBrokenTokens(dbName string) error {
	c := db.client.Database(dbName).Collection(DbTokensColl)

	tokens, err := db.GetBrokenTokens(dbName)
	if err != nil {
		return err
	}

	// delete authsets for non-exisitent devices
	for _, t := range tokens {
		_, err := c.DeleteOne(context.Background(), model.Token{Id: t})
		if err != nil {
			return errors.Wrapf(err, "database %s, failed to delete tokens", dbName)
		}
	}

	return nil
}

// Filters list of device ids.
// Result is the list of ids of non-existent devices and devices with decommissioning flag set.
func (db *DataStoreMongo) filterNonExistentDevices(dbName string, devIds []string) ([]string, error) {
	c := db.client.Database(dbName).Collection(DbDevicesColl)

	nonexistentDevices := []string{}

	//check if device exists
	for _, devId := range devIds {
		res := model.Device{}
		err := c.FindOne(context.Background(), bson.M{"_id": devId}).Decode(&res)

		if err != nil {
			if err == mongo.ErrNoDocuments {
				nonexistentDevices = append(nonexistentDevices, devId)
			} else {
				return nil, errors.Wrapf(err, "db %s, failed to fetch device", dbName)
			}
		}

		if res.Decommissioning == true {
			nonexistentDevices = append(nonexistentDevices, devId)
		}
	}

	return nonexistentDevices, nil
}
