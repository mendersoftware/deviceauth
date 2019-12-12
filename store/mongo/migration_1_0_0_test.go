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
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
)

func randTime(base time.Time) time.Time {
	diff := time.Duration(rand.Int()%1024) * time.Hour
	return base.Add(-diff)
}

type migration_1_0_0_TestData struct {
	// devices by device index
	devices map[int]*device_0_1_0
	// tokens by (device index << 16 + token index)
	tokens map[int]*token_0_1_0
}

func (m *migration_1_0_0_TestData) GetDev(idx int) *device_0_1_0 {
	return m.devices[idx]
}

func (m *migration_1_0_0_TestData) GetToken(didx int, tidx int) *token_0_1_0 {
	return m.tokens[didx<<16+tidx]
}

// populateDevices creates `count` devices, each with randomized number of
// tokens <0, maxTokensPerDev), returns test data it generated
func populateDevices(t *testing.T, client *mongo.Client, count int, maxTokensPerDev int) migration_1_0_0_TestData {

	td := migration_1_0_0_TestData{
		devices: map[int]*device_0_1_0{},
		tokens:  map[int]*token_0_1_0{},
	}

	for i := 0; i < count; i++ {
		devid := fmt.Sprintf("devid-0.1.0-%d", i)

		dev := device_0_1_0{
			Id:          devid,
			TenantToken: "foo",
			PubKey:      fmt.Sprintf("pubkey-0.1.0-%d", i),
			IdData:      fmt.Sprintf("id-data-0.1.0-%d", i),
			Status:      randDevStatus(),
			CreatedTs:   randTime(time.Now()),
			UpdatedTs:   time.Now(),
		}
		ctx := identity.WithContext(context.Background(), &identity.Identity{
			Tenant: tenant,
		})
		c := client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbDevicesColl)
		_, err := c.InsertOne(ctx, dev)
		assert.NoError(t, err)

		td.devices[i] = &dev

		// generate random numbers of tokens for each device
		tokens := rand.Int() % maxTokensPerDev

		c = client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbTokensColl)
		for j := 0; j < tokens; j++ {
			tok := token_0_1_0{
				Id:    fmt.Sprintf("jti-0.1.0-%d-%d", i, j),
				DevId: devid,
				Token: fmt.Sprintf("token-123-%d-%d", i, j),
			}
			td.tokens[i<<16+j] = &tok

			_, err := c.InsertOne(ctx, tok)
			assert.NoError(t, err)
		}
	}
	return td
}

func TestMigration_1_0_0(t *testing.T) {
	ctx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})
	db.Wipe()
	db := NewDataStoreMongoWithClient(db.Client())

	devCount := 100
	toksPerDev := 5

	data := populateDevices(t, db.client, devCount, toksPerDev)

	mig := migration_1_1_0{
		ms:  db,
		ctx: ctx,
	}

	err := mig.Up(migrate.MakeVersion(0, 1, 0))
	assert.NoError(t, err)

	// there should be devCount devices
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbDevicesColl)
	cnt, err := c.CountDocuments(ctx, bson.D{})
	assert.NoError(t, err)
	count := int(cnt)
	assert.Equal(t, devCount, count)

	// there should be an auth set for each device
	c = db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)
	cnt, err = c.CountDocuments(ctx, bson.D{})
	count = int(cnt)
	assert.NoError(t, err)
	assert.Equal(t, devCount, count)

	// trying to add a device with same identity data should raise conflict
	err = db.AddDevice(ctx, model.Device{
		IdData: data.GetDev(10).IdData,
	})
	assert.EqualError(t, err, store.ErrObjectExists.Error())

	// trying to add device with existing out set should raise conflict
	err = db.AddAuthSet(ctx, model.AuthSet{
		PubKey:   data.GetDev(10).PubKey,
		IdData:   data.GetDev(10).IdData,
		DeviceId: data.GetDev(10).Id,
	})
	assert.EqualError(t, err, store.ErrObjectExists.Error())

	// verify that there is an auth set for every device
	for i, dev := range data.devices {
		aset, err := db.getAuthSetByDataKey(ctx, dev.IdData, dev.PubKey)
		assert.NoError(t, err)

		// auth set ID should be the same as device ID
		assert.Equal(t, dev.Id, aset.Id)
		// and be assigned to device
		assert.Equal(t, dev.Id, aset.DeviceId)

		// auth set status should be the same as device status
		assert.Equal(t, dev.Status, aset.Status)

		// verify device tokens
		for j := 0; j < toksPerDev; j++ {
			oldtok := data.GetToken(i, j)
			if oldtok == nil {
				break
			}

			tok, err := db.GetToken(ctx, oldtok.Id)
			assert.NoError(t, err)
			assert.Equal(t, oldtok.Token, tok.Token)
			assert.Equal(t, dev.Id, tok.DevId)
			// migrated tokens should be assigned to auth set
			assert.Equal(t, aset.Id, tok.AuthSetId)
		}
	}
}

func (db *DataStoreMongo) getAuthSetByDataKey(ctx context.Context, idData string, key string) (*model.AuthSet, error) {
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)

	filter := model.AuthSet{
		IdData: idData,
		PubKey: key,
	}
	res := model.AuthSet{}

	err := c.FindOne(ctx, filter).Decode(&res)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, store.ErrDevNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch device")
		}
	}

	return &res, nil
}
