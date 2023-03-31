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
	"fmt"
	"testing"
	"time"

	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/utils"
)

func TestMigration_1_3_0(t *testing.T) {
	goodKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzogVU7RGDilbsoUt/DdH
VJvcepl0A5+xzGQ50cq1VE/Dyyy8Zp0jzRXCnnu9nu395mAFSZGotZVr+sWEpO3c
yC3VmXdBZmXmQdZqbdD/GuixJOYfqta2ytbIUPRXFN7/I7sgzxnXWBYXYmObYvdP
okP0mQanY+WKxp7Q16pt1RoqoAd0kmV39g13rFl35muSHbSBoAW3GBF3gO+mF5Ty
1ddp/XcgLOsmvNNjY+2HOD5F/RX0fs07mWnbD7x+xz7KEKjF+H7ZpkqCwmwCXaf0
iyYyh1852rti3Afw4mDxuVSD7sd9ggvYMc0QHIpQNkD4YWOhNiE1AB0zH57VbUYG
UwIDAQAB
-----END PUBLIC KEY-----`

	badKey := `iyYyh1852rb`

	ts := time.Now()

	cases := map[string]struct {
		sets []model.AuthSet
		devs []model.Device

		err error
	}{
		"ok": {
			devs: []model.Device{
				{
					Id:              "1",
					IdData:          "{\"sn\":\"0001\"}",
					Status:          "pending",
					Decommissioning: false,
					CreatedTs:       ts,
					UpdatedTs:       ts,
				},
			},

			sets: []model.AuthSet{
				{
					Id:        "1",
					DeviceId:  "1",
					IdData:    "{\"sn\":\"0001\"}",
					PubKey:    goodKey,
					Timestamp: &ts,
					Status:    "pending",
				},
			},
		},
		"error, authset": {
			sets: []model.AuthSet{
				{
					Id:        "1",
					DeviceId:  "1",
					IdData:    "{\"sn\":\"0001\"}",
					PubKey:    badKey,
					Timestamp: &ts,
					Status:    "pending",
				},
			},
			err: errors.New("failed to normalize key of auth set 1: iyYyh1852rb: cannot decode public key"),
		},
	}

	for n, tc := range cases {
		t.Run(fmt.Sprintf("tc %s", n), func(t *testing.T) {
			ctx := identity.WithContext(context.Background(), &identity.Identity{
				Tenant: "foo",
			})

			db.Wipe()
			db := NewDataStoreMongoWithClient(db.Client())

			prep_1_2_0(t, ctx, db)

			for _, d := range tc.devs {
				err := db.AddDevice(ctx, d)
				assert.NoError(t, err)
			}

			for _, a := range tc.sets {
				err := db.AddAuthSet(ctx, a)
				assert.NoError(t, err)
			}

			mig130 := migration_1_3_0{
				ms:  db,
				ctx: ctx,
			}

			err := mig130.Up(migrate.MakeVersion(1, 2, 0))

			if tc.err == nil {
				assert.NoError(t, err)
				verify(t, ctx, db, tc.devs, tc.sets)
			} else {
				assert.EqualError(t, tc.err, err.Error())
			}
		})
	}
}

func prep_1_2_0(t *testing.T, ctx context.Context, db *DataStoreMongo) {
	migrations := []migrate.Migration{
		&migration_1_1_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_2_0{
			ms:  db,
			ctx: ctx,
		},
	}

	last := migrate.MakeVersion(0, 1, 0)
	for _, m := range migrations {
		err := m.Up(last)
		assert.NoError(t, err)
		last = m.Version()
	}
}

func verify(t *testing.T, ctx context.Context, db *DataStoreMongo, devs []model.Device, sets []model.AuthSet) {
	var set model.AuthSet
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)
	for _, a := range sets {
		err := c.FindOne(ctx, bson.M{"_id": a.Id}).Decode(&set)
		assert.NoError(t, err)

		_, err = utils.ParsePubKey(set.PubKey)
		assert.NoError(t, err)

		newKey, err := normalizeKey(a.PubKey)
		a.PubKey = newKey

		compareAuthSet(&a, &set, t)
	}

	var dev model.Device
	c = db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbDevicesColl)
	for _, d := range devs {
		err := c.FindOne(ctx, bson.M{"_id": d.Id}).Decode(&dev)
		assert.NoError(t, err)
	}

}
