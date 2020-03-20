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
	mopts "go.mongodb.org/mongo-driver/mongo/options"

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

	var deviceIds []string
	var brokenAuthSets []string

	ctx := context.Background()

	// get all auth sets; group by device id

	project := bson.D{
		{Key: "_id", Value: 0},
		{Key: "device_id", Value: 1},
	}
	var result []struct {
		DeviceID string `bson:"device_id"`
	}
	findOpts := mopts.Find()
	findOpts.SetProjection(project)

	cursor, err := c.Find(ctx, bson.M{}, findOpts)
	if err := cursor.All(ctx, &result); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}

	deviceIds = make([]string, len(result))
	for i, res := range result {
		deviceIds[i] = res.DeviceID
	}

	//check if devices exists
	nonexistentDevices, err := db.filterNonExistentDevices(
		ctx, dbName, deviceIds,
	)
	if err != nil {
		return nil, err
	}
	brokenAuthSets = make([]string, 0, len(nonexistentDevices))

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
	collAuthSets := db.client.Database(dbName).Collection(DbAuthSetColl)
	collTokens := db.client.Database(dbName).Collection(DbTokensColl)

	authSets, err := db.GetBrokenAuthSets(dbName)
	if err != nil {
		return err
	}

	// delete authsets for non-exisitent devices
	for _, as := range authSets {
		_, err := collAuthSets.DeleteOne(nil, bson.M{"_id": as})
		if err != nil {
			return errors.Wrapf(err, "database %s, failed to delete authentication sets", dbName)
		}
		_, err = collTokens.DeleteOne(nil, bson.M{"_id": as})
		if err != nil {
			return errors.Wrapf(err, "database %s, failed to clear JWT token", dbName)
		}
	}

	return nil
}

// Filters list of device ids.
// Result is the list of ids of non-existent devices and devices with decommissioning flag set.
func (db *DataStoreMongo) filterNonExistentDevices(
	ctx context.Context,
	dbName string,
	devIds []string,
) ([]string, error) {
	c := db.client.Database(dbName).Collection(DbDevicesColl)

	nonexistentDevices := []string{}
	query := bson.M{
		"_id": bson.M{"$nin": devIds},
	}

	cur, err := c.Find(ctx, query)
	if err != nil {
		return nil, err
	}
	var doc struct {
		ID string `bson:_id`
	}
	for cur.Next(ctx) {
		err := cur.Decode(&doc)
		if err != nil {
			return nil, err
		}
		nonexistentDevices = append(nonexistentDevices, doc.ID)
	}

	return nonexistentDevices, nil
}
