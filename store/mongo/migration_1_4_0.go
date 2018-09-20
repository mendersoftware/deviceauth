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
	"time"

	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"

	"github.com/mendersoftware/deviceauth/model"
	uto "github.com/mendersoftware/deviceauth/utils/to"
)

type migration_1_4_0 struct {
	ms  *DataStoreMongo
	ctx context.Context
}

func (m *migration_1_4_0) Up(from migrate.Version) error {
	s := m.ms.session.Copy()

	defer s.Close()

	iter := s.DB(ctxstore.DbFromContext(m.ctx, DbName)).
		C(DbDevicesColl).Find(nil).Iter()

	var dev model.Device

	for iter.Next(&dev) {

		status, err := m.ms.GetDeviceStatus(m.ctx, dev.Id)

		if err != nil {
			return errors.Wrap(err, "Cannot determine device status")
		}

		if err := m.ms.UpdateDevice(m.ctx,
			model.Device{
				Id: dev.Id,
			},
			model.DeviceUpdate{
				Status:    status,
				UpdatedTs: uto.TimePtr(time.Now().UTC()),
			}); err != nil {
			return errors.Wrap(err, "failed to update device status")
		}

	}

	if err := iter.Close(); err != nil {
		return errors.Wrap(err, "failed to close DB iterator")
	}

	return nil
}

func (m *migration_1_4_0) Version() migrate.Version {
	return migrate.MakeVersion(1, 4, 0)
}
