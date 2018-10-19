// Copyright 2018 Northern.tech AS
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
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"

	"github.com/mendersoftware/deviceauth/model"
	uto "github.com/mendersoftware/deviceauth/utils/to"
)

type migration_1_5_0 struct {
	ms  *DataStoreMongo
	ctx context.Context
}

func (m *migration_1_5_0) Up(from migrate.Version) error {
	s := m.ms.session.Copy()

	defer s.Close()

	iter := s.DB(ctxstore.DbFromContext(m.ctx, DbName)).
		C(DbAuthSetColl).Find(nil).Iter()

	var set model.AuthSet

	for iter.Next(&set) {
		idDataStruct, err := decode(set.IdData)

		if err != nil {
			return errors.Wrapf(err, "failed to parse id data of auth set %v: %v", set.Id, set.IdData)
		}

		hash := sha256.New()
		hash.Write([]byte(set.IdData))

		update := bson.M{
			"$set": model.AuthSetUpdate{
				IdDataStruct: idDataStruct,
				IdDataSha256: hash.Sum(nil),
				Timestamp:    uto.TimePtr(time.Now()),
			},
		}

		if err := s.DB(ctxstore.DbFromContext(m.ctx, DbName)).
			C(DbAuthSetColl).UpdateId(set.Id, update); err != nil {
			return errors.Wrapf(err, "failed to update auth set %v", set.Id)
		}

	}

	if err := iter.Close(); err != nil {
		return errors.Wrap(err, "failed to close DB iterator")
	}

	err := s.DB(ctxstore.DbFromContext(m.ctx, DbName)).
		C(DbAuthSetColl).EnsureIndex(mgo.Index{
		Unique: true,
		Key: []string{
			model.AuthSetKeyDeviceId,
			model.AuthSetKeyIdDataSha256,
			model.AuthSetKeyPubKey,
		},
		Name:       indexAuthSet_DeviceId_IdentityDataSha256_PubKey,
		Background: false,
	})

	if err != nil {
		return errors.Wrap(err, "failed to create index on auth sets")
	}

	iter = s.DB(ctxstore.DbFromContext(m.ctx, DbName)).
		C(DbDevicesColl).Find(nil).Iter()

	var dev model.Device

	for iter.Next(&dev) {

		idDataStruct, err := decode(dev.IdData)

		if err != nil {
			return errors.Wrapf(err, "failed to parse id data of device %v: %v", dev.Id, dev.IdData)
		}

		hash := sha256.New()
		hash.Write([]byte(dev.IdData))

		update := bson.M{
			"$set": model.DeviceUpdate{
				IdDataStruct: idDataStruct,
				IdDataSha256: hash.Sum(nil),
				UpdatedTs:    uto.TimePtr(time.Now().UTC()),
			},
		}

		if err := s.DB(ctxstore.DbFromContext(m.ctx, DbName)).
			C(DbDevicesColl).UpdateId(dev.Id, update); err != nil {
			return errors.Wrapf(err, "failed to update device %v", dev.Id)
		}

	}

	if err := iter.Close(); err != nil {
		return errors.Wrap(err, "failed to close DB iterator")
	}

	return nil
}

func (m *migration_1_5_0) Version() migrate.Version {
	return migrate.MakeVersion(1, 5, 0)
}

func decode(what string) (map[string]interface{}, error) {
	var dec map[string]interface{}

	err := json.Unmarshal([]byte(what), &dec)
	if err != nil {
		return nil, err
	}

	return dec, nil
}
