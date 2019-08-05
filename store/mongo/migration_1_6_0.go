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

	"github.com/globalsign/mgo"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"

	"github.com/mendersoftware/deviceauth/model"
)

type migration_1_6_0 struct {
	ms  *DataStoreMongo
	ctx context.Context
}

func (m *migration_1_6_0) Up(from migrate.Version) error {
	s := m.ms.session.Copy()

	defer s.Close()

	err := s.DB(ctxstore.DbFromContext(m.ctx, DbName)).
		C(DbAuthSetColl).EnsureIndex(mgo.Index{
		Unique: true,
		Key: []string{
			model.AuthSetKeyIdDataSha256,
			model.AuthSetKeyPubKey,
		},
		Name:       indexAuthSet_IdentityDataSha256_PubKey,
		Background: false,
	})

	if err != nil {
		return errors.Wrap(err, "failed to create index containing IdDataSha256 and PubKey on auth sets")
	}

	return nil
}

func (m *migration_1_6_0) Version() migrate.Version {
	return migrate.MakeVersion(1, 6, 0)
}
