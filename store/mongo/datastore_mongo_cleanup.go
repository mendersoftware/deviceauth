// Copyright 2020 Northern.tech AS
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
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/mongo/uuid"
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
	findOpts := mopts.Find().SetProjection(project)
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

	// fetch auth sets for non exisitent devices
	query := bson.M{"device_id": bson.M{"$in": nonexistentDevices}}
	findOpts = mopts.Find().SetProjection(bson.M{"_id": 1})
	cursor, err = c.Find(ctx, query, findOpts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch authentication sets")
	}
	var doc struct {
		ID string `bson:"_id"`
	}
	brokenAuthSets = make([]string, 0, len(nonexistentDevices))
	for cursor.Next(ctx) {
		err := cursor.Decode(&doc)
		if err == mongo.ErrNoDocuments {
			return brokenAuthSets, nil
		} else if err != nil {
			return nil, errors.Wrap(err, "failed to fetch authentication sets")
		}
		brokenAuthSets = append(brokenAuthSets, doc.ID)
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
	l := log.NewEmpty()

	authSets, err := db.GetBrokenAuthSets(dbName)
	if err != nil {
		return err
	}

	// delete authsets for non-exisitent devices
	for _, as := range authSets {
		_, err := collAuthSets.DeleteOne(nil, bson.M{"_id": as})
		if err != nil {
			return errors.Wrapf(err, "database %s, failed to "+
				"delete authentication sets", dbName)
		}
		authSetUUID, _ := uuid.FromString(as)
		_, err = collTokens.DeleteOne(nil, bson.M{"_id": authSetUUID})
		if err != nil {
			l.Warnf("Error deleting token associated with authset "+
				"%s: %s", as, err.Error())
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
	var res model.Device
	c := db.client.Database(dbName).Collection(DbDevicesColl)

	nonexistentDevices := []string{}

	// We only need to know if the device is in decomissioning state
	findOpts := mopts.FindOne()
	findOpts.SetProjection(bson.M{"decommissioning": 1})

	//check if device exists
	for _, devId := range devIds {
		err := c.FindOne(ctx, bson.M{"_id": devId}, findOpts).
			Decode(&res)

		if err != nil {
			if err == mongo.ErrNoDocuments {
				nonexistentDevices = append(
					nonexistentDevices,
					devId,
				)
			} else {
				return nil, errors.Wrapf(err,
					"db %s, failed to fetch device", dbName)
			}
		}

		if res.Decommissioning {
			nonexistentDevices = append(nonexistentDevices, devId)
		}
	}

	return nonexistentDevices, nil
}
