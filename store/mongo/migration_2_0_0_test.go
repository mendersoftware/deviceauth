// Copyright 2022 Northern.tech AS
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
	"github.com/mendersoftware/go-lib-micro/mongo/oid"
	"github.com/mendersoftware/go-lib-micro/ratelimits"
	mstore_v1 "github.com/mendersoftware/go-lib-micro/store"
	mstore "github.com/mendersoftware/go-lib-micro/store/v2"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/mendersoftware/deviceauth/jwt"
	"github.com/mendersoftware/deviceauth/model"
)

func TestMigration_2_0_0(t *testing.T) {
	now := time.Now().UTC().Round(time.Second).Truncate(0)
	jwtTime := jwt.Time{Time: time.Now()}
	jwtNow := jwtTime.UTC().Round(time.Second).Truncate(0)

	type testStruct struct {
		Device  model.Device
		AuthSet model.AuthSet
		Token   jwt.Token
	}

	cases := map[string]struct {
		docsPerTenant map[string][]testStruct
	}{
		"single tenant": {
			docsPerTenant: map[string][]testStruct{
				"": {
					testStruct{
						Device: model.Device{
							Id:           "8725",
							IdData:       `{"mac":"52:54:00:cc:7b:1e"}`,
							IdDataSha256: []byte(`{"mac":"52:54:00:cc:7b:1e"}`),
							Status:       model.DevStatusAccepted,
							CreatedTs:    now,
							UpdatedTs:    now,
							Revision:     2,
							ApiLimits:    ratelimits.ApiLimits{},
						},
						AuthSet: model.AuthSet{
							Id:           "1234",
							IdData:       `{"mac":"52:54:00:cc:7b:1e"}`,
							IdDataSha256: []byte(`{"mac":"52:54:00:cc:7b:1e"}`),
							DeviceId:     "8725",
						},
						Token: jwt.Token{Claims: jwt.Claims{
							ID:      oid.NewUUIDv5("foo"),
							Subject: oid.NewUUIDv5("8725"),
							Issuer:  "Mender",
							ExpiresAt: jwt.Time{
								Time: time.Now().Add(time.Hour),
							},
						}},
					},
					testStruct{
						Device: model.Device{
							Id:           "8217",
							IdData:       `{"mac":"76:12:00:aa:2a:1f"}`,
							IdDataSha256: []byte(`{"mac":"76:12:00:aa:2a:1f"}`),
							Status:       model.DevStatusAccepted,
							CreatedTs:    now,
							UpdatedTs:    now,
							Revision:     2,
							ApiLimits:    ratelimits.ApiLimits{},
						},
						AuthSet: model.AuthSet{
							Id:           "1283",
							IdData:       `{"mac":"76:12:00:aa:2a:1f"}`,
							IdDataSha256: []byte(`{"mac":"76:12:00:aa:2a:1f"}`),
							DeviceId:     "8217",
						},
						Token: jwt.Token{Claims: jwt.Claims{
							ID:      oid.NewUUIDv5("bar"),
							Subject: oid.NewUUIDv5("8217"),
							Tenant:  "",
							Issuer:  "Mender",
							ExpiresAt: jwt.Time{
								Time: time.Now().Add(time.Hour),
							},
						}},
					},
				},
			},
		},
		"multi-tenant": {
			docsPerTenant: map[string][]testStruct{
				"tenant-id-1": {
					testStruct{
						Device: model.Device{
							Id:           "325454768",
							IdData:       `{"mac":"52:43:00:dd:7b:1e"}`,
							IdDataSha256: []byte(`{"mac":"52:43:00:dd:7b:1e"}`),
							Status:       model.DevStatusAccepted,
							CreatedTs:    now,
							UpdatedTs:    now,
							Revision:     2,
							ApiLimits:    ratelimits.ApiLimits{},
						},
						AuthSet: model.AuthSet{
							Id:           "8888",
							IdData:       `{"mac":"52:54:00:cc:7b:1e"}`,
							IdDataSha256: []byte(`{"mac":"52:43:00:dd:7b:1e"}`),
							DeviceId:     "325454768",
						},
						Token: jwt.Token{Claims: jwt.Claims{
							ID:      oid.NewUUIDv5("56789"),
							Subject: oid.NewUUIDv5("325454768"),
							Issuer:  "Mender",
							ExpiresAt: jwt.Time{
								Time: jwtNow,
							},
						}},
					},
					testStruct{
						Device: model.Device{
							Id:           "1821743",
							IdData:       `{"mac":"76:12:00:aa:2a:2f"}`,
							IdDataSha256: []byte(`{"mac":"76:12:00:aa:2a:2f"}`),
							Status:       model.DevStatusAccepted,
							CreatedTs:    now,
							UpdatedTs:    now,
							Revision:     2,
							ApiLimits:    ratelimits.ApiLimits{},
						},
						AuthSet: model.AuthSet{
							Id:           "7777",
							IdData:       `{"mac":"52:54:00:cc:7b:1d"}`,
							IdDataSha256: []byte(`{"mac":"52:54:00:cc:7b:1d"}`),
							DeviceId:     "1821743",
						},
						Token: jwt.Token{Claims: jwt.Claims{
							ID:      oid.NewUUIDv5("467j3h63w"),
							Subject: oid.NewUUIDv5("1821743"),
							Issuer:  "Mender",
							ExpiresAt: jwt.Time{
								Time: jwtNow,
							},
						}},
					},
				},
				"tenant-id-2": {
					testStruct{
						Device: model.Device{
							Id:           "1234546",
							IdData:       `{"mac":"d2:12:00:aa:2a:2b"}`,
							IdDataSha256: []byte(`{"mac":"d2:12:00:aa:2a:2b"}`),
							Status:       model.DevStatusAccepted,
							CreatedTs:    now,
							UpdatedTs:    now,
							Revision:     2,
							ApiLimits:    ratelimits.ApiLimits{},
						},
						AuthSet: model.AuthSet{
							Id:           "6666",
							IdData:       `{"mac":"52:54:00:cc:7b:2c"}`,
							IdDataSha256: []byte(`{"mac":"52:54:00:cc:7b:2c"}`),
							DeviceId:     "1234546",
						},
						Token: jwt.Token{Claims: jwt.Claims{
							ID:      oid.NewUUIDv5("bar"),
							Subject: oid.NewUUIDv5("1234546"),
							Issuer:  "Mender",
							ExpiresAt: jwt.Time{
								Time: jwtNow,
							},
						}},
					},
					testStruct{
						Device: model.Device{
							Id:           "9032949",
							IdData:       `{"mac":"76:12:11:aa:2a:2d"}`,
							IdDataSha256: []byte(`{"mac":"76:12:11:aa:2a:2d"}`),
							Status:       model.DevStatusAccepted,
							CreatedTs:    now,
							UpdatedTs:    now,
							Revision:     2,
							ApiLimits:    ratelimits.ApiLimits{},
						},
						AuthSet: model.AuthSet{
							Id:           "5555",
							IdData:       `{"mac":"52:54:00:cc:7b:3a"}`,
							IdDataSha256: []byte(`{"mac":"52:54:00:cc:7b:3a"}`),
							DeviceId:     "9032949",
						},
						Token: jwt.Token{Claims: jwt.Claims{
							ID:      oid.NewUUIDv5("123"),
							Subject: oid.NewUUIDv5("9032949"),
							Issuer:  "Mender",
							ExpiresAt: jwt.Time{
								Time: jwtNow,
							},
						}},
					},
				},
			},
		},
	}

	for n, tc := range cases {
		t.Run(n, func(t *testing.T) {
			ctx := context.Background()
			dbClient := db.Client()
			ds := DataStoreMongo{
				client:      dbClient,
				automigrate: true,
				multitenant: true,
			}

			// create the documents in the tenant-specific databases
			for tenant, docs := range tc.docsPerTenant {
				db.Wipe()
				ctx := ctx
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tenant,
				})

				// run the migrations up to 1.11.0
				migrations := []migrate.Migration{
					&migration_1_1_0{
						ms:  &ds,
						ctx: ctx,
					},
					&migration_1_2_0{
						ms:  &ds,
						ctx: ctx,
					},
					&migration_1_3_0{
						ms:  &ds,
						ctx: ctx,
					},
					&migration_1_4_0{
						ms:  &ds,
						ctx: ctx,
					},
					&migration_1_5_0{
						ms:  &ds,
						ctx: ctx,
					},
					&migration_1_6_0{
						ms:  &ds,
						ctx: ctx,
					},
					&migration_1_7_0{
						ms:  &ds,
						ctx: ctx,
					},
					&migration_1_8_0{
						ds:  &ds,
						ctx: ctx,
					},
					&migration_1_9_0{
						ds:  &ds,
						ctx: ctx,
					},
					&migration_1_10_0{
						ds:  &ds,
						ctx: ctx,
					},
					&migration_1_11_0{
						ds:  &ds,
						ctx: ctx,
					},
				}
				migrator := &migrate.SimpleMigrator{
					Client:      dbClient,
					Db:          mstore.DbFromContext(ctx, DbName),
					Automigrate: true,
				}

				err := migrator.Apply(ctx, migrate.MakeVersion(1, 10, 0), migrations)
				assert.NoError(t, err)

				dbName := mstore_v1.DbNameForTenant(tenant, DbName)
				devicesColl := dbClient.Database(dbName).Collection(DbDevicesColl)
				authSetsColl := dbClient.Database(dbName).Collection(DbAuthSetColl)
				tokensColl := dbClient.Database(dbName).Collection(DbTokensColl)
				// insert the documents
				devicesDocs := make([]interface{}, len(docs))
				authSetsDocs := make([]interface{}, len(docs))
				tokensDocs := make([]interface{}, len(docs))
				for i, singleCollDocs := range docs {
					devicesDocs[i] = singleCollDocs.Device
					authSetsDocs[i] = singleCollDocs.AuthSet
					tokensDocs[i] = singleCollDocs.Token
				}

				_, err = devicesColl.InsertMany(ctx, devicesDocs)
				assert.NoError(t, err)
				_, err = authSetsColl.InsertMany(ctx, authSetsDocs)
				assert.NoError(t, err)
				_, err = tokensColl.InsertMany(ctx, tokensDocs)
				assert.NoError(t, err)

				// run the 2.0.0 migration for the non-tenant-specific database
				migrations = []migrate.Migration{
					&migration_2_0_0{
						ds:  &ds,
						ctx: ctx,
					},
				}
				migrator = &migrate.SimpleMigrator{
					Client:      dbClient,
					Db:          mstore.DbFromContext(ctx, DbName),
					Automigrate: true,
				}

				err = migrator.Apply(ctx, migrate.MakeVersion(2, 0, 0), migrations)
				assert.NoError(t, err)

				foundDevices, err := ds.GetDevices(ctx, 0, 0, model.DeviceFilter{})
				assert.NoError(t, err)
				assert.Equal(t, len(docs), len(foundDevices))

				var foundAuthSets []model.AuthSet
				for _, device := range foundDevices {
					authSets, _ := ds.GetAuthSetsForDevice(ctx, device.Id)
					foundAuthSets = append(foundAuthSets, authSets...)
				}
				assert.ElementsMatch(t, authSetsDocs, foundAuthSets)

				for key := range foundDevices {
					foundDevices[key].CreatedTs = foundDevices[key].CreatedTs.Truncate(0)
					foundDevices[key].UpdatedTs = foundDevices[key].CreatedTs.Truncate(0)
				}

				assert.ElementsMatch(t, devicesDocs, foundDevices)

				// check tokens
				tokensCollNew := dbClient.Database(DbName).Collection(DbTokensColl)
				var result jwt.Token
				for _, doc := range tokensDocs {
					doc := doc.(jwt.Token)
					err = tokensCollNew.FindOne(ctx,
						bson.M{
							jwt.TokenTenantField: tenant,
							"_id":                doc.ID,
						},
					).Decode(&result)
					assert.NoError(t, err)
					assert.Equal(t, tenant, result.Tenant)
					assert.Equal(t, doc.ID, result.ID)
					assert.Equal(t, doc.Subject, result.Subject)
				}
			}
		})
	}

}
