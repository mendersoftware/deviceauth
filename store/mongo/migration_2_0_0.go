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

	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	mstore_v1 "github.com/mendersoftware/go-lib-micro/store"
	mstore "github.com/mendersoftware/go-lib-micro/store/v2"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	mopts "go.mongodb.org/mongo-driver/mongo/options"

	"github.com/mendersoftware/deviceauth/jwt"
	"github.com/mendersoftware/deviceauth/model"
)

const (
	findBatchSize = 100
)

type migration_2_0_0 struct {
	ds  *DataStoreMongo
	ctx context.Context
}

// Up creates an index on status and id in the devices collection
func (m *migration_2_0_0) Up(from migrate.Version) error {
	// _false := false
	// _true := true
	// var expireAfterSeconds int32 = 0
	// tokenExpirationIndexName := "TokenExpiration"
	currentDbName := mstore_v1.DbFromContext(m.ctx, DbName)
	logger := log.FromContext(m.ctx)

	collectionsIndexes := map[string]struct {
		Indexes []mongo.IndexModel
	}{
		DbDevicesColl: {
			Indexes: []mongo.IndexModel{
				// create device index on status and id
				{
					Keys: bson.D{
						{Key: model.TenantIDField, Value: 1},
						{Key: model.DevKeyStatus, Value: 1},
						{Key: model.DevKeyId, Value: 1},
					},
					Options: mopts.Index().
						SetName(indexDevices_Status).
						SetUnique(false),
				}, {
					Keys: bson.D{
						{Key: model.TenantIDField, Value: 1},
						{Key: model.DevKeyIdDataSha256, Value: 1},
					},
					Options: mopts.Index().
						SetName(indexDevices_IdentityDataSha256).
						SetUnique(true),
				},
			},
		},
		DbAuthSetColl: {
			Indexes: []mongo.IndexModel{
				{
					Keys: bson.D{
						{Key: model.TenantIDField, Value: 1},
						{Key: "device_id", Value: 1},
					},
					Options: mopts.Index().
						SetName(indexAuthSet_DeviceId),
				},
				{
					Keys: bson.D{
						{Key: model.TenantIDField, Value: 1},
						{Key: model.AuthSetKeyIdDataSha256, Value: 1},
						{Key: model.AuthSetKeyPubKey, Value: 1},
					},
					Options: mopts.Index().
						SetName(indexAuthSet_IdentityDataSha256_PubKey).
						SetUnique(true),
				},
			},
		},
		DbTokensColl: {
			Indexes: []mongo.IndexModel{
				{
					Keys: bson.D{
						{Key: "exp.time", Value: 1},
					},
					Options: mopts.Index().
						SetName(indexTokens_TokenExpiration).
						SetExpireAfterSeconds(0),
				},
			},
		},
	}

	// for each collection in main deviceauth database...
	if currentDbName == DbName {
		for collection, indexModel := range collectionsIndexes {
			coll := m.ds.client.Database(currentDbName).Collection(collection)
			// drop all the existing indexes, ignoring the errors
			_, _ = coll.Indexes().DropAll(m.ctx)

			// create the new indexes
			if len(indexModel.Indexes) != 0 {
				_, err := coll.Indexes().CreateMany(m.ctx, indexModel.Indexes)
				if err != nil {
					return err
				}
			}
		}
	}

	// for each collection...
	for collection := range collectionsIndexes {
		coll := m.ds.client.Database(currentDbName).Collection(collection)
		collOut := m.ds.client.Database(DbName).Collection(collection)
		writes := make([]mongo.WriteModel, 0, findBatchSize)
		var update bson.M
		var tenantIdFilter bson.D

		if currentDbName == DbName {
			// if any documents already exist in "deviceauth" db,
			// add empty "tenant_id": "" key-value pair

			if collection == "tokens" {
				tenantIdFilter = bson.D{
					{Key: jwt.TokenTenantField, Value: bson.D{{Key: "$exists", Value: false}}},
				}
				update = bson.M{"$set": bson.M{jwt.TokenTenantField: ""}}
			} else {
				tenantIdFilter = bson.D{
					{Key: model.TenantIDField, Value: bson.D{{Key: "$exists", Value: false}}},
				}
				update = bson.M{"$set": bson.M{model.TenantIDField: ""}}
			}
			result, err := collOut.UpdateMany(m.ctx, tenantIdFilter, update)
			logger.Infof("Modified documents in main deviceauth database, collection %s count: %d",
				collection, result.ModifiedCount)
			if err != nil {
				return err
			}
		} else {
			// get all the documents in the collection
			findOptions := mopts.Find().
				SetBatchSize(findBatchSize).
				SetSort(bson.D{{Key: "_id", Value: 1}})
			cur, err := coll.Find(m.ctx, bson.D{}, findOptions)
			if err != nil {
				return err
			}
			defer cur.Close(m.ctx)

			// migrate the documents
			for cur.Next(m.ctx) {
				item := bson.D{}
				err := cur.Decode(&item)
				if err != nil {
					return err
				}

				if collection == "tokens" {
					id := identity.FromContext(m.ctx)
					if id == nil {
						return errors.New("migration error: identity is nil")
					}
					for i, field := range item {
						if field.Key == jwt.TokenTenantField {
							item[i].Value = id.Tenant
						}
					}
				} else {
					item = mstore.WithTenantID(m.ctx, item)
				}
				writes = append(writes, mongo.NewInsertOneModel().SetDocument(item))

				if len(writes) == findBatchSize {
					_, err := collOut.BulkWrite(m.ctx, writes)
					if err != nil {
						return err
					}
					writes = writes[:0]
				}
			}
			if len(writes) > 0 {
				_, err := collOut.BulkWrite(m.ctx, writes)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (m *migration_2_0_0) Version() migrate.Version {
	return migrate.MakeVersion(2, 0, 0)
}
