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
	"strconv"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	mopts "go.mongodb.org/mongo-driver/mongo/options"

	dconf "github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
)

type migration_1_7_0 struct {
	ms  *DataStoreMongo
	ctx context.Context
}

func (m *migration_1_7_0) Up(from migrate.Version) error {
	tokenExpireSeconds, err := strconv.ParseInt(
		dconf.SettingJWTExpirationTimeoutDefault, 10, 64,
	)
	if err != nil {
		panic(err)
	}
	conf := m.ctx.Value("config")
	if conf != nil {
		if c, ok := conf.(config.Reader); ok {
			configTimeout := int64(c.GetInt(
				dconf.SettingJWTExpirationTimeout))
			if configTimeout > 0 {
				tokenExpireSeconds = configTimeout
			}
		}
	}
	indexOptions := mopts.Index()
	indexOptions.SetBackground(true)
	indexOptions.SetName("TokenTTLIndex")
	indexOptions.SetExpireAfterSeconds(int32(tokenExpireSeconds))
	ttlIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: tokenKeyIssuedAt, Value: 1}},
		Options: indexOptions,
	}

	database := m.ms.client.Database(ctxstore.DbFromContext(m.ctx, DbName))
	collTkn := database.Collection(DbTokensColl)
	err = collTkn.Drop(m.ctx)
	if err != nil {
		return err
	}

	collTkn = database.Collection(DbTokensColl)
	iw := collTkn.Indexes()
	_, err = iw.CreateOne(m.ctx, ttlIndex)

	return err
}

func (m *migration_1_7_0) Version() migrate.Version {
	return migrate.MakeVersion(1, 7, 0)
}
