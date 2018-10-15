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
	"time"

	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/stretchr/testify/assert"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/utils"
)

func TestMigration_1_2_0(t *testing.T) {
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
	err := mig110.Up(migrate.MakeVersion(0, 1, 0))
	assert.NoError(t, err)

	ts := time.Now()

	devs := []model.Device{
		{
			Id:              "1",
			PubKey:          "pubkey-1",
			IdData:          "{\"sn\":\"0001\",\"mac\":\"00:00:00:01\"}",
			Status:          "pending",
			Decommissioning: false,
			CreatedTs:       ts,
			UpdatedTs:       ts,
		},
		{
			Id:              "2",
			PubKey:          "pubkey-1",
			IdData:          "{\"sn\":\"0002\",\"attr\":\"foo1\",\"mac\":\"00:00:00:02\"}",
			Status:          "active",
			Decommissioning: false,
			CreatedTs:       ts,
			UpdatedTs:       ts,
		},
	}

	asets := []model.AuthSet{
		{
			Id:        "1",
			DeviceId:  "1",
			IdData:    "{\"sn\":\"0001\",\"mac\":\"00:00:00:01\"}",
			PubKey:    "pubkey-1",
			Timestamp: &ts,
			Status:    "pending",
		},
		{
			Id:        "2",
			DeviceId:  "2",
			IdData:    "{\"sn\":\"0002\",\"attr\":\"foo\",\"mac\":\"00:00:00:02\"}",
			PubKey:    "pubkey-2",
			Timestamp: &ts,
			Status:    "active",
		},
		{
			Id:        "3",
			DeviceId:  "2",
			IdData:    "{\"sn\":\"0002\",\"attr\":\"foo1\",\"mac\":\"00:00:00:02\"}",
			PubKey:    "pubkey-3",
			Timestamp: &ts,
			Status:    "active",
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
	mig120 := migration_1_2_0{
		ms:  db,
		ctx: ctx,
	}
	err = mig120.Up(migrate.MakeVersion(1, 1, 0))
	assert.NoError(t, err)

	var dev model.Device
	for _, d := range devs {
		err = s.DB(ctxstore.DbFromContext(ctx, DbName)).
			C(DbDevicesColl).FindId(d.Id).One(&dev)
		assert.NoError(t, err)

		id, err := utils.JsonSort(d.IdData)
		assert.NoError(t, err)

		d.IdData = id

		compareDevices(&d, &dev, t)
	}

	var set model.AuthSet
	for _, a := range asets {
		err = s.DB(ctxstore.DbFromContext(ctx, DbName)).
			C(DbAuthSetColl).FindId(a.Id).One(&set)
		assert.NoError(t, err)

		id, err := utils.JsonSort(a.IdData)
		assert.NoError(t, err)

		a.IdData = id

		compareAuthSet(&a, &set, t)
	}

	db.session.Close()
}
