// Copyright 2021 Northern.tech AS
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

	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/mendersoftware/deviceauth/model"
)

type migration_1_6_0 struct {
	ms  *DataStoreMongo
	ctx context.Context
}

func (m *migration_1_6_0) Up(from migrate.Version) error {
	_false := false
	_true := true
	authSetUniqueIndex := mongo.IndexModel{
		Keys: bson.D{
			{Key: model.AuthSetKeyIdDataSha256, Value: 1},
			{Key: model.AuthSetKeyPubKey, Value: 1},
		},
		Options: &options.IndexOptions{
			Background: &_false,
			Name:       &indexAuthSet_IdentityDataSha256_PubKey,
			Unique:     &_true,
		},
	}
	cAuthSets := m.ms.client.Database(ctxstore.DbFromContext(m.ctx, DbName)).
		Collection(DbAuthSetColl)
	authSetIndexes := cAuthSets.Indexes()
	_, err := authSetIndexes.CreateOne(m.ctx, authSetUniqueIndex)
	if err != nil {
		return errors.Wrap(
			err,
			"failed to create index containing IdDataSha256 and PubKey on auth sets",
		)
	}

	return nil
}

func (m *migration_1_6_0) Version() migrate.Version {
	return migrate.MakeVersion(1, 6, 0)
}
