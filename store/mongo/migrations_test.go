// Copyright 2022 Northern.tech AS
//
//    All Rights Reserved
package mongo

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestStoreMigrate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestMigrate in short mode.")
	}

	testCases := map[string]struct {
		tenantDbs   []string
		automigrate bool

		version string
		err     string
	}{
		DbVersion: {
			automigrate: true,
			version:     DbVersion,
			err:         "",
		},
		DbVersion + " no automigrate": {
			automigrate: false,
			version:     DbVersion,
			err: "failed to apply migrations: db needs " +
				"migration: deviceauth has version 0.0.0, " +
				"needs version " + DbVersion,
		},
		DbVersion + " multitenant": {
			automigrate: true,
			tenantDbs:   []string{"deviceauth-tenant1id", "deviceauth-tenant2id"},
			version:     DbVersion,
			err:         "",
		},
		DbVersion + " multitenant, no automigrate": {
			automigrate: false,
			tenantDbs:   []string{"deviceauth-tenant1id", "deviceauth-tenant2id"},
			version:     DbVersion,
			err: "failed to apply migrations: db needs " +
				"migration: deviceauth-tenant1id has version " +
				"0.0.0, needs version " + DbVersion,
		},
		"0.1 error": {
			automigrate: true,
			version:     "0.1",
			err:         "failed to parse service version: failed to parse Version: unexpected EOF",
		},
	}
	_false := false
	_true := true

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc: %s", name), func(t *testing.T) {
			db.Wipe()
			db := NewDataStoreMongoWithClient(db.Client())

			// set up automigration
			if tc.automigrate {
				db = db.WithAutomigrate().(*DataStoreMongo)
			}

			// set up multitenancy/tenant dbs
			if len(tc.tenantDbs) != 0 {
				db = db.WithMultitenant()

				for _, d := range tc.tenantDbs {
					c := db.client.Database(d).Collection("foo")
					_, err := c.InsertOne(context.TODO(), bson.M{"foo": "bar"})
					assert.NoError(t, err)
				}
			}

			ctx := context.Background()
			err := db.Migrate(ctx, tc.version)
			if tc.err == "" {
				assert.NoError(t, err)

				// verify migration entry in all databases (>1 if multitenant)
				if tc.automigrate {
					dbs := []string{DbName}
					if len(tc.tenantDbs) > 0 {
						dbs = tc.tenantDbs
					}

					for _, d := range dbs {
						var out []migrate.MigrationEntry
						c := db.client.Database(d).Collection(migrate.DbMigrationsColl)
						cursor, err := c.Find(ctx, bson.M{})
						assert.NoError(t, err)
						err = cursor.All(ctx, &out)
						assert.NoError(t, err)
						sort.Slice(out, func(i int, j int) bool {
							return migrate.VersionIsLess(out[i].Version, out[j].Version)
						})
						// the last migration should match what we want
						v, _ := migrate.NewVersion(tc.version)
						assert.Equal(t, *v, out[len(out)-1].Version)

						// verify that all indexes are created
						verifyIndexes(t, db.client.Database(d).Collection(DbDevicesColl),
							[]mongo.IndexModel{
								{
									Keys: bson.D{
										{Key: model.DevKeyIdDataSha256, Value: 1},
									},
									Options: &options.IndexOptions{
										Background: &_false,
										Name:       &indexDevices_IdentityDataSha256,
										Unique:     &_true,
									},
								},
								{
									Keys: bson.D{
										{Key: model.DevKeyStatus, Value: 1},
										{Key: model.DevKeyId, Value: 1},
									},
									Options: &options.IndexOptions{
										Background: &_false,
										Name:       &indexDevices_Status,
									},
								},
							},
						)
						verifyIndexes(t, db.client.Database(d).Collection(DbAuthSetColl),
							[]mongo.IndexModel{
								{
									Keys: bson.D{
										{Key: model.AuthSetKeyDeviceId, Value: 1},
										{Key: model.AuthSetKeyIdDataSha256, Value: 1},
										{Key: model.AuthSetKeyPubKey, Value: 1},
									},
									Options: &options.IndexOptions{
										Background: &_false,
										Name:       &indexAuthSet_DeviceId_IdentityDataSha256_PubKey,
										Unique:     &_true,
									},
								},
								{
									Keys: bson.D{
										{Key: model.AuthSetKeyIdDataSha256, Value: 1},
										{Key: model.AuthSetKeyPubKey, Value: 1},
									},
									Options: &options.IndexOptions{
										Background: &_false,
										Name:       &indexAuthSet_IdentityDataSha256_PubKey,
										Unique:     &_true,
									},
								},
							},
						)
					}
				}

			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestStoreMigrationVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestMigrate in short mode.")
	}

	dbVersion, _ := migrate.NewVersion(DbVersion)
	testCases := map[string]struct {
		version *migrate.Version
		err     string
	}{
		DbVersion: {
			version: dbVersion,
			err:     "",
		},
		"and what version is that, error": {
			err: "version cant be nil.",
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc: %s", name), func(t *testing.T) {
			db.Wipe()
			db := NewDataStoreMongoWithClient(db.Client())

			ctx := context.Background()
			err := db.StoreMigrationVersion(ctx, tc.version)
			if tc.err == "" {
				assert.NoError(t, err)
				var out []migrate.MigrationEntry
				c := db.client.Database(DbName).Collection(migrate.DbMigrationsColl)
				cursor, err := c.Find(ctx, bson.M{})
				assert.NoError(t, err)
				err = cursor.All(ctx, &out)
				assert.NoError(t, err)
				v := tc.version
				assert.Equal(t, *v, out[len(out)-1].Version)

				// verify that all indexes are created
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}
