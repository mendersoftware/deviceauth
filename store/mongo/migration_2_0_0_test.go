// Copyright 2023 Northern.tech AS
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
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	"github.com/mendersoftware/go-lib-micro/mongo/oid"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	ctxstore2 "github.com/mendersoftware/go-lib-micro/store/v2"

	"github.com/mendersoftware/deviceauth/model"
)

func TestMigration_2_0_0(t *testing.T) {
	var tenantIds []string
	var ctxs []context.Context
	const maxTenants = 63
	const minTenants = 15
	const maxDevicesPerTenant = 512
	const minDevicesPerTenant = 128

	db.Wipe()
	client := db.Client()
	db := NewDataStoreMongoWithClient(client)

	tenantIds = make([]string, rand.Intn(maxTenants)+minTenants)
	ctxs = make([]context.Context, len(tenantIds))
	for i := 0; i < len(tenantIds); i++ {
		tenantIds[i] = oid.NewUUIDv4().String()
		ctx := identity.WithContext(context.Background(), &identity.Identity{
			Tenant: tenantIds[i],
		})
		ctxs[i] = ctx
		prep_2_0_0(t, ctx, db)
	}

	tenantDeviceCount := make([]int64, len(tenantIds))
	for i := 0; i < len(tenantIds); i++ {
		ctx := ctxs[i]
		for j := 0; j < rand.Intn(maxDevicesPerTenant)+minDevicesPerTenant; j++ {
			dbName := ctxstore.DbFromContext(ctx, DbName)
			devicesCollection := db.client.Database(dbName).Collection(DbDevicesColl)
			_, err := devicesCollection.InsertOne(ctx, model.Device{
				Id:     oid.NewUUIDv4().String(),
				IdData: oid.NewUUIDv4().String(),
				IdDataStruct: map[string]interface{}{
					"key":   oid.NewUUIDv4().String(),
					"value": oid.NewUUIDv4().String(),
				},
				IdDataSha256:    []byte(oid.NewUUIDv4().String()),
				Status:          "accepted",
				Decommissioning: false,
				CreatedTs:       time.Now(),
				UpdatedTs:       time.Now(),
			})
			if err == nil {
				tenantDeviceCount[i]++
			}
			_, err = devicesCollection.UpdateMany(ctx, bson.M{}, bson.M{"$unset": bson.M{dbFieldTenantID: 1}})
			assert.NoError(t, err)
		}
	}
	for i := 0; i < len(tenantIds); i++ {
		ctx := ctxs[i]
		mig200 := migration_2_0_0{
			ds:  db,
			ctx: ctx,
		}
		err := mig200.Up(migrate.MakeVersion(2, 0, 0))
		assert.NoError(t, err)
	}

	devicesCollection := db.client.Database(DbName).Collection(DbDevicesColl)
	for i := 0; i < len(tenantIds); i++ {
		count, err := devicesCollection.CountDocuments(
			ctxs[i],
			ctxstore2.WithTenantID(
				ctxs[i],
				bson.M{
					"status": "accepted",
				},
			),
		)
		assert.NoError(t, err)
		assert.Equal(t, tenantDeviceCount[i], count)
	}
}

func prep_2_0_0(t *testing.T, ctx context.Context, db *DataStoreMongo) {

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
	mig140 := migration_1_4_0{
		ms:  db,
		ctx: ctx,
	}
	mig150 := migration_1_5_0{
		ms:  db,
		ctx: ctx,
	}
	mig160 := migration_1_6_0{
		ms:  db,
		ctx: ctx,
	}
	mig170 := migration_1_7_0{
		ms:  db,
		ctx: ctx,
	}
	mig180 := migration_1_8_0{
		ds:  db,
		ctx: ctx,
	}
	mig190 := migration_1_9_0{
		ds:  db,
		ctx: ctx,
	}
	mig1100 := migration_1_10_0{
		ds:  db,
		ctx: ctx,
	}
	mig1110 := migration_1_11_0{
		ds:  db,
		ctx: ctx,
	}

	err := mig110.Up(migrate.MakeVersion(1, 1, 0))
	assert.NoError(t, err)
	err = mig120.Up(migrate.MakeVersion(1, 2, 0))
	assert.NoError(t, err)
	err = mig130.Up(migrate.MakeVersion(1, 3, 0))
	assert.NoError(t, err)
	err = mig140.Up(migrate.MakeVersion(1, 4, 0))
	assert.NoError(t, err)
	err = mig150.Up(migrate.MakeVersion(1, 5, 0))
	assert.NoError(t, err)
	err = mig160.Up(migrate.MakeVersion(1, 6, 0))
	assert.NoError(t, err)
	err = mig170.Up(migrate.MakeVersion(1, 7, 0))
	assert.NoError(t, err)
	err = mig180.Up(migrate.MakeVersion(1, 8, 0))
	assert.NoError(t, err)
	err = mig190.Up(migrate.MakeVersion(1, 9, 0))
	assert.NoError(t, err)
	err = mig1100.Up(migrate.MakeVersion(1, 10, 0))
	assert.NoError(t, err)
	err = mig1110.Up(migrate.MakeVersion(1, 11, 0))
	assert.NoError(t, err)
}
