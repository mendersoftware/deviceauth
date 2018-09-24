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
	"testing"

	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/stretchr/testify/assert"

	"github.com/mendersoftware/deviceauth/model"
)

func TestMigration_1_4_0(t *testing.T) {
	ctx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: "foo",
	})
	db.Wipe()
	db := NewDataStoreMongoWithSession(db.Session())
	s := db.session

	// prep base version
	mig110 := migration_1_1_0{
		ms:  db,
		ctx: ctx,
	}
	mig120 := migration_1_2_0{
		ms:  db,
		ctx: ctx,
	}
	mig130 := migration_1_3_0{
		ms:  db,
		ctx: ctx,
	}
	err := mig110.Up(migrate.MakeVersion(1, 1, 0))
	assert.NoError(t, err)
	err = mig120.Up(migrate.MakeVersion(1, 2, 0))
	assert.NoError(t, err)
	err = mig130.Up(migrate.MakeVersion(1, 3, 0))
	assert.NoError(t, err)

	devs := []model.Device{
		{
			Id:     "1",
			IdData: "{\"sn\":\"0001\",\"mac\":\"00:00:00:01\"}",
			Status: "pending",
		},
		{
			Id:     "2",
			IdData: "{\"sn\":\"0002\",\"attr\":\"foo1\",\"mac\":\"00:00:00:02\"}",
			Status: "rejected",
		},
		{
			Id:     "3",
			IdData: "{\"sn\":\"0003\",\"attr\":\"foo3\",\"mac\":\"00:00:00:03\"}",
			Status: "rejected",
		},
	}

	asets := []model.AuthSet{
		{
			Id:       "1",
			DeviceId: "1",
			IdData:   "{\"sn\":\"0001\",\"mac\":\"00:00:00:01\"}",
			Status:   "accepted",
		},
		{
			Id:       "2",
			DeviceId: "2",
			IdData:   "{\"sn\":\"0002\",\"attr\":\"foo\",\"mac\":\"00:00:00:02\"}",
			Status:   "rejected",
		},
		{
			Id:       "3",
			DeviceId: "2",
			IdData:   "{\"sn\":\"0002\",\"attr\":\"foo1\",\"mac\":\"00:00:00:02\"}",
			Status:   "pending",
		},
		{
			Id:       "4",
			DeviceId: "3",
			IdData:   "{\"sn\":\"0003\",\"attr\":\"foo3\",\"mac\":\"00:00:00:03\"}",
			Status:   "rejected",
		},
	}

	for _, d := range devs {
		err = db.AddDevice(ctx, d)
		assert.NoError(t, err)
	}

	for _, a := range asets {
		err = db.AddAuthSet(ctx, a)
		assert.NoError(t, err)
	}

	// test new version
	mig140 := migration_1_4_0{
		ms:  db,
		ctx: ctx,
	}
	err = mig140.Up(migrate.MakeVersion(1, 4, 0))
	assert.NoError(t, err)

	var dev model.Device
	for _, d := range devs {
		err = s.DB(ctxstore.DbFromContext(ctx, DbName)).
			C(DbDevicesColl).FindId(d.Id).One(&dev)
		assert.NoError(t, err)
		status, err := db.GetDeviceStatus(ctx, dev.Id)
		assert.NoError(t, err)
		assert.Equal(t, status, dev.Status)
	}

	db.session.Close()
}
