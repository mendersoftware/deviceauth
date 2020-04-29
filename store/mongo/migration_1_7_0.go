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
	cinv "github.com/mendersoftware/deviceauth/client/inventory"
	dconfig "github.com/mendersoftware/deviceauth/config"
	"time"

	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/mendersoftware/deviceauth/model"
)

type migration_1_7_0 struct {
	ms  *DataStoreMongo
	ctx context.Context
}

const (
	migrationContextTimeouts = 360
	devicesBatchSize         = 512
)

func (m *migration_1_7_0) updateDevicesStatus(ctx context.Context, status string) error {
	inv := config.Config.GetString(dconfig.SettingInventoryAddr)
	c := cinv.NewClient(inv, true)
	collectionDevices := m.ms.client.Database(ctxstore.DbFromContext(m.ctx, DbName)).Collection(DbDevicesColl)
	opts := options.FindOptions{}
	opts.SetNoCursorTimeout(true)
	cur, err := collectionDevices.Find(ctx, bson.M{"status": status}, &opts)
	if err != nil {
		return err
	}
	id := identity.FromContext(m.ctx)
	var devicesIds []string
	devicesIds = make([]string, devicesBatchSize)
	var i uint
	i = 0
	for cur.Next(ctx) {
		var d model.Device
		err = cur.Decode(&d)
		if i >= devicesBatchSize {
			err = c.SetDeviceStatus(ctx, id.Tenant, devicesIds, status)
			if err != nil {
				return err
			}
			devicesIds = make([]string, devicesBatchSize)
			i = 0
		}
		devicesIds[i] = d.Id
		i++
	}
	if i >= 1 {
		err = c.SetDeviceStatus(ctx, id.Tenant, devicesIds[:i], status)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *migration_1_7_0) Up(from migrate.Version) error {
	ctx, cancel := context.WithTimeout(context.Background(), migrationContextTimeouts*time.Second)
	defer cancel()
	m.updateDevicesStatus(ctx, "accepted")
	m.updateDevicesStatus(ctx, "pending")
	m.updateDevicesStatus(ctx, "rejected")
	m.updateDevicesStatus(ctx, "preauthorized")

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
	cAuthSets := m.ms.client.Database(ctxstore.DbFromContext(m.ctx, DbName)).Collection(DbAuthSetColl)
	authSetIndexes := cAuthSets.Indexes()
	_, err := authSetIndexes.CreateOne(m.ctx, authSetUniqueIndex)
	if err != nil {
		return errors.Wrap(err, "failed to create index containing IdDataSha256 and PubKey on auth sets")
	}

	return nil
}

func (m *migration_1_7_0) Version() migrate.Version {
	return migrate.MakeVersion(1, 7, 0)
}
