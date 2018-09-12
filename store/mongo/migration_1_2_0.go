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

	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/utils"
)

type migration_1_2_0 struct {
	ms  *DataStoreMongo
	ctx context.Context
}

func (m *migration_1_2_0) Up(from migrate.Version) error {
	s := m.ms.session.Copy()

	defer s.Close()

	iter := s.DB(ctxstore.DbFromContext(m.ctx, DbName)).
		C(DbAuthSetColl).Find(nil).Iter()

	var set model.AuthSet

	for iter.Next(&set) {
		newIdData, err := utils.JsonSort(set.IdData)
		if err != nil {
			return errors.Wrapf(err, "failed to sort id data of auth set  %v: %v", set.Id, set.IdData)
		}

		update := model.AuthSetUpdate{
			IdData: newIdData,
		}

		if err := s.DB(ctxstore.DbFromContext(m.ctx, DbName)).
			C(DbAuthSetColl).UpdateId(set.Id, update); err != nil {
			return errors.Wrapf(err, "failed to update auth set  %v", set.Id)
		}

	}

	if err := iter.Close(); err != nil {
		return errors.Wrap(err, "failed to close DB iterator")
	}

	iter = s.DB(ctxstore.DbFromContext(m.ctx, DbName)).
		C(DbDevicesColl).Find(nil).Iter()

	var dev model.Device

	for iter.Next(&dev) {
		newIdData, err := utils.JsonSort(dev.IdData)

		if err != nil {
			return errors.Wrapf(err, "failed to sort id data of device  %v: %v", dev.Id, set.IdData)
		}

		update := model.DeviceUpdate{
			IdData: newIdData,
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

func (m *migration_1_2_0) Version() migrate.Version {
	return migrate.MakeVersion(1, 2, 0)
}
