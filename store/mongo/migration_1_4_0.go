// Copyright 2022 Northern.tech AS
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
	"time"

	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	uto "github.com/mendersoftware/deviceauth/utils/to"
)

type migration_1_4_0 struct {
	ms  *DataStoreMongo
	ctx context.Context
}

func (m *migration_1_4_0) Up(from migrate.Version) error {
	devColl := m.ms.client.Database(ctxstore.DbFromContext(m.ctx, DbName)).Collection(DbDevicesColl)

	cursor, err := devColl.Find(m.ctx, bson.M{})
	if err != nil {
		return err
	}

	var dev model.Device

	for cursor.Next(m.ctx) {
		if err = cursor.Decode(&dev); err != nil {
			continue
		}

		status, err := GetDeviceStatus(m.ctx, m.ms, dev.Id)

		if err != nil {
			if err == store.ErrAuthSetNotFound {
				status = model.DevStatusRejected
			} else {
				return errors.Wrapf(err, "Cannot determine device status for device: %s", dev.Id)
			}
		}

		update := model.DeviceUpdate{
			Status:    status,
			UpdatedTs: uto.TimePtr(time.Now().UTC()),
		}

		_, err = devColl.UpdateOne(m.ctx, bson.M{"_id": dev.Id}, bson.M{"$set": update})
		if err != nil {
			return errors.Wrap(err, "failed to update device status")
		}

	}

	if err := cursor.Close(m.ctx); err != nil {
		return errors.Wrap(err, "failed to close DB iterator")
	}

	return nil
}

func (m *migration_1_4_0) Version() migrate.Version {
	return migrate.MakeVersion(1, 4, 0)
}

// GetDeviceStatus gets device status using old database name containing tenant ID
func GetDeviceStatus(ctx context.Context, db *DataStoreMongo, devId string) (string, error) {
	var statuses = map[string]int{}

	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)

	// get device auth sets; group by status

	filter := model.AuthSet{
		DeviceId: devId,
	}

	match := bson.D{
		{Key: "$match", Value: filter},
	}
	group := bson.D{
		{Key: "$group", Value: bson.D{
			{Key: "_id", Value: "$status"},
			{Key: "count", Value: bson.M{"$sum": 1}}},
		},
	}

	pipeline := []bson.D{
		match,
		group,
	}
	var result []struct {
		Status string `bson:"_id"`
		Value  int    `bson:"count"`
	}
	cursor, err := c.Aggregate(ctx, pipeline)
	if err != nil {
		return "", err
	}
	if err := cursor.All(ctx, &result); err != nil {
		if err == mongo.ErrNoDocuments {
			return "", store.ErrAuthSetNotFound
		}
		return "", err
	}

	if len(result) == 0 {
		return "", store.ErrAuthSetNotFound
	}

	for _, res := range result {
		statuses[res.Status] = res.Value
	}

	status, err := getDeviceStatus(statuses)
	if err != nil {
		return "", err
	}

	return status, nil
}
