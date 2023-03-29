// Copyright 2022 Northern.tech AS
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	    http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.
package mongo

import (
	"context"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/mongo/oid"
	"go.mongodb.org/mongo-driver/mongo"
	mopts "go.mongodb.org/mongo-driver/mongo/options"
	"strings"

	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	mstorev1 "github.com/mendersoftware/go-lib-micro/store"
	mstore "github.com/mendersoftware/go-lib-micro/store/v2"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	findBatchSize = 255
)

type migration_2_0_0 struct {
	ds  *DataStoreMongo
	ctx context.Context
}

// Up creates an index on status and id in the devices collection
func (m *migration_2_0_0) Up(from migrate.Version) error {
	ctx := context.Background()
	client := m.ds.client

	collections := map[string]struct {
		Indexes []mongo.IndexModel
	}{
		DbAuthSetColl: {
			Indexes: []mongo.IndexModel{
				{
					Keys: bson.D{
						{Key: mstore.FieldTenantID, Value: 1},
						{Key: dbFieldID, Value: 1},
					},
					Options: mopts.Index().
						SetName(mstore.FieldTenantID + "_" + dbFieldID).
						SetUnique(true),
				},
				{
					Keys: bson.D{
						{Key: mstore.FieldTenantID, Value: 1},
						{Key: dbFieldDeviceID, Value: 1},
						{Key: dbFieldIDDataSha, Value: 1},
						{Key: dbFieldPubKey, Value: 1},
					},
					Options: mopts.Index().
						SetName(strings.Join([]string{mstore.FieldTenantID, dbFieldDeviceID, dbFieldIDDataSha, dbFieldPubKey}, "_")).
						SetUnique(true),
				},
				{
					Keys: bson.D{
						{Key: mstore.FieldTenantID, Value: 1},
						{Key: dbFieldIDDataSha, Value: 1},
						{Key: dbFieldPubKey, Value: 1},
					},
					Options: mopts.Index().
						SetName(strings.Join([]string{mstore.FieldTenantID, dbFieldIDDataSha, dbFieldPubKey}, "_")).
						SetUnique(true),
				},
			},
		},
		DbDevicesColl: {
			Indexes: []mongo.IndexModel{
				{
					Keys: bson.D{
						{Key: mstore.FieldTenantID, Value: 1},
						{Key: dbFieldID, Value: 1},
					},
					Options: mopts.Index().
						SetName(mstore.FieldTenantID + "_" + dbFieldID),
				},
				{
					Keys: bson.D{
						{Key: mstore.FieldTenantID, Value: 1},
						{Key: dbFieldIDDataSha, Value: 1},
					},
					Options: mopts.Index().
						SetName(mstore.FieldTenantID + "_" + dbFieldIDDataSha),
				},
				{
					Keys: bson.D{
						{Key: mstore.FieldTenantID, Value: 1},
						{Key: dbFieldStatus, Value: 1},
					},
					Options: mopts.Index().
						SetName(mstore.FieldTenantID + "_" + dbFieldStatus),
				},
			},
		},
		DbLimitsColl: {
			Indexes: []mongo.IndexModel{
				{
					Keys: bson.D{
						{Key: mstore.FieldTenantID, Value: 1},
						{Key: dbFieldID, Value: 1},
					},
					Options: mopts.Index().
						SetName(mstore.FieldTenantID + "_" + dbFieldID),
				},
			},
		},
		DbTokensColl: {
			Indexes: []mongo.IndexModel{
				{
					Keys: bson.D{
						{Key: mstore.FieldTenantID, Value: 1},
						{Key: dbFieldID, Value: 1},
					},
					Options: mopts.Index().
						SetName(mstore.FieldTenantID + "_" + dbFieldID),
				},
				{
					Keys: bson.D{
						{Key: mstore.FieldTenantID, Value: 1},
						{Key: dbFieldExpTime, Value: 1},
					},
					Options: mopts.Index().
						SetName(mstore.FieldTenantID + "_" + dbFieldExpTime),
				},
			},
		},
	}

	databaseName := mstorev1.DbFromContext(m.ctx, DbName)
	tenantID := mstorev1.TenantFromDbName(databaseName, DbName)
	ctx = identity.WithContext(ctx, &identity.Identity{
		Tenant: tenantID,
	})
	writes := make([]mongo.WriteModel, 0, findBatchSize)

	for collection, idxes := range collections {
		writes = writes[:0]
		findOptions := mopts.Find().
			SetBatchSize(findBatchSize).
			SetSort(bson.D{{Key: dbFieldID, Value: 1}})
		collOut := client.Database(DbName).Collection(collection)
		if databaseName == DbName {
			if len(idxes.Indexes) > 0 {
				_, err := collOut.Indexes().CreateMany(ctx, collections[collection].Indexes)
				if err != nil {
					return err
				}
			}
			_, err := collOut.UpdateMany(ctx, bson.D{
				{Key: mstore.FieldTenantID, Value: bson.D{
					{Key: "$exists", Value: false},
				}},
			}, bson.D{{Key: "$set", Value: bson.D{
				{Key: mstore.FieldTenantID, Value: ""},
			}}},
			)
			if err != nil {
				return err
			}
			continue
		}

		coll := client.Database(databaseName).Collection(collection)
		// get all the documents in the collection
		cur, err := coll.Find(ctx, bson.D{}, findOptions)
		if err != nil {
			return err
		}
		defer cur.Close(ctx)

		// migrate the documents
		if collection == DbLimitsColl {
			for cur.Next(ctx) {
				id := cur.Current.Lookup(dbFieldID)
				var currentId string
				err = id.Unmarshal(&currentId)
				var item bson.D
				if err = cur.Decode(&item); err != nil {
					return err
				}
				item = append(item, bson.E{
					Key:   dbFieldName,
					Value: currentId,
				})
				item = item[1:]
				item = findAndReplace(item, dbFieldID, oid.NewUUIDv4().String())

				writes = append(writes, mongo.
					NewReplaceOneModel().
					SetFilter(bson.D{{Key: dbFieldName, Value: id}}).
					SetUpsert(true).
					SetReplacement(mstore.WithTenantID(ctx, item)))
				if len(writes) == findBatchSize {
					_, err = collOut.BulkWrite(ctx, writes)
					if err != nil {
						return err
					}
					writes = writes[:0]
				}
			}
		} else {
			for cur.Next(ctx) {
				id := cur.Current.Lookup(dbFieldID)
				var item bson.D
				if err = cur.Decode(&item); err != nil {
					return err
				}
				writes = append(writes, mongo.
					NewReplaceOneModel().
					SetFilter(bson.D{{Key: dbFieldID, Value: id}}).
					SetUpsert(true).
					SetReplacement(mstore.WithTenantID(ctx, item)))
				if len(writes) == findBatchSize {
					_, err = collOut.BulkWrite(ctx, writes)
					if err != nil {
						return err
					}
					writes = writes[:0]
				}
			}
		}
		if len(writes) > 0 {
			_, err := collOut.BulkWrite(ctx, writes)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func findAndReplace(item bson.D, key string, value string) bson.D {
	for i, d := range item {
		if d.Key == key {
			item[i].Value = value
		}
	}
	return item
}

func (m *migration_2_0_0) Version() migrate.Version {
	return migrate.MakeVersion(2, 0, 0)
}
