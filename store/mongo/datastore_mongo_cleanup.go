// Copyright 2021 Northern.tech AS
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

// Retrieves Ids of the auth sets owned by devices that are in decommissioning state or not owned by
// any device.
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
	database := db.client.Database(dbName)
	collAuthSets := database.Collection(DbAuthSetColl)
	collTokens := database.Collection(DbTokensColl)

	authSets, err := db.GetBrokenAuthSets(dbName)
	if err != nil {
		return err
	}

	// delete authsets for non-existent devices
	ctx := context.Background()
	for _, as := range authSets {
		_, err := collAuthSets.DeleteOne(ctx, model.AuthSet{Id: as})
		if err != nil {
			return errors.Wrapf(err, "database %s, failed to delete authentication sets", dbName)
		}
		// Attempt to delete token (may have already expired).
		_, _ = collTokens.DeleteOne(ctx, bson.M{"_id": as})
	}

	return nil
}

// Filters list of device ids.
// Result is the list of ids of non-existent devices and devices with decommissioning flag set.
func (db *DataStoreMongo) filterNonExistentDevices(
	dbName string,
	devIds []string,
) ([]string, error) {
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

		if res.Decommissioning {
			nonexistentDevices = append(nonexistentDevices, devId)
		}
	}

	return nonexistentDevices, nil
}
