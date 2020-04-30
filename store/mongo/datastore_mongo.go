// Copyright 2020 Northern.tech AS
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
	"crypto/tls"
	"strings"
	"time"

	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	uto "github.com/mendersoftware/deviceauth/utils/to"
)

const (
	DbVersion     = "1.7.0"
	DbName        = "deviceauth"
	DbDevicesColl = "devices"
	DbAuthSetColl = "auth_sets"
	DbTokensColl  = "tokens"
	DbLimitsColl  = "limits"
)

var (
	indexDevices_IdentityData                       = "devices:IdentityData"
	indexAuthSet_DeviceId_IdentityData_PubKey       = "auth_sets:DeviceId:IdData:PubKey"
	indexAuthSet_DeviceId_IdentityDataSha256_PubKey = "auth_sets:IdDataSha256:PubKey"
	indexAuthSet_IdentityDataSha256_PubKey          = "auth_sets:NoDeviceId:IdDataSha256:PubKey"
)

type DataStoreMongoConfig struct {
	// connection string
	ConnectionString string

	// SSL support
	SSL           bool
	SSLSkipVerify bool

	// Overwrites credentials provided in connection string if provided
	Username string
	Password string
}

type DataStoreMongo struct {
	client      *mongo.Client
	automigrate bool
	multitenant bool
}

func NewDataStoreMongoWithClient(client *mongo.Client) *DataStoreMongo {
	return &DataStoreMongo{
		client: client,
	}
}

func NewDataStoreMongo(config DataStoreMongoConfig) (*DataStoreMongo, error) {
	if !strings.Contains(config.ConnectionString, "://") {
		config.ConnectionString = "mongodb://" + config.ConnectionString
	}
	clientOptions := options.Client().ApplyURI(config.ConnectionString)

	if config.Username != "" {
		clientOptions.SetAuth(options.Credential{
			Username: config.Username,
			Password: config.Password,
		})
	}

	if config.SSL {
		tlsConfig := &tls.Config{}
		tlsConfig.InsecureSkipVerify = config.SSLSkipVerify
		clientOptions.SetTLSConfig(tlsConfig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create mongo client")
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify mongodb connection")
	}

	return NewDataStoreMongoWithClient(client), nil
}

func (db *DataStoreMongo) GetDevices(ctx context.Context, skip, limit uint, filter store.DeviceFilter) ([]model.Device, error) {

	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbDevicesColl)

	res := []model.Device{}

	pipeline := []bson.D{
		bson.D{
			{Key: "$match", Value: filter},
		},
		bson.D{
			{Key: "$sort", Value: bson.M{"_id": 1}},
		},
		bson.D{
			{Key: "$skip", Value: skip},
		},
	}

	if limit > 0 {
		pipeline = append(pipeline,
			bson.D{{Key: "$limit", Value: limit}})
	}

	cursor, err := c.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch device list")
	}
	if err := cursor.All(ctx, &res); err != nil {
		return nil, err
	}

	return res, nil
}

func (db *DataStoreMongo) GetDeviceById(ctx context.Context, id string) (*model.Device, error) {

	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbDevicesColl)

	res := model.Device{}

	err := c.FindOne(ctx, bson.M{"_id": id}).Decode(&res)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, store.ErrDevNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch device")
		}
	}

	return &res, nil
}

func (db *DataStoreMongo) GetDeviceByIdentityDataHash(ctx context.Context, idataHash []byte) (*model.Device, error) {

	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbDevicesColl)

	filter := bson.M{"id_data_sha256": idataHash}
	res := model.Device{}

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

func (db *DataStoreMongo) AddDevice(ctx context.Context, d model.Device) error {

	if d.Id == "" {
		uid, err := uuid.NewV4()
		if err != nil {
			return err
		}
		d.Id = uid.String()
	}

	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbDevicesColl)

	if _, err := c.InsertOne(ctx, d); err != nil {
		if strings.Contains(err.Error(), "duplicate key error") {
			return store.ErrObjectExists
		}
		return errors.Wrap(err, "failed to store device")
	}
	return nil
}

func (db *DataStoreMongo) UpdateDevice(ctx context.Context,
	d model.Device, updev model.DeviceUpdate) error {

	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbDevicesColl)

	updev.UpdatedTs = uto.TimePtr(time.Now().UTC())
	update := bson.M{"$set": updev}

	res, err := c.UpdateOne(ctx, bson.M{"_id": d.Id}, update)
	if err != nil {
		return errors.Wrap(err, "failed to update device")
	} else if res.MatchedCount < 1 {
		return store.ErrDevNotFound
	}

	return nil
}

func (db *DataStoreMongo) DeleteDevice(ctx context.Context, id string) error {

	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbDevicesColl)

	filter := bson.M{"_id": id}
	result, err := c.DeleteOne(ctx, filter)
	if err != nil {
		return errors.Wrap(err, "failed to remove device")
	} else if result.DeletedCount < 1 {
		return store.ErrDevNotFound
	}

	return nil
}

func (db *DataStoreMongo) AddToken(ctx context.Context, t model.Token) error {

	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbTokensColl)

	if _, err := c.InsertOne(ctx, t); err != nil {
		return errors.Wrap(err, "failed to store token")
	}

	return nil
}

func (db *DataStoreMongo) GetToken(ctx context.Context, jti string) (*model.Token, error) {

	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbTokensColl)

	res := model.Token{}

	err := c.FindOne(ctx, bson.M{"_id": jti}).Decode(&res)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, store.ErrTokenNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch token")
		}
	}

	return &res, nil
}

func (db *DataStoreMongo) DeleteToken(ctx context.Context, jti string) error {

	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbTokensColl)

	filter := bson.M{"_id": jti}
	result, err := c.DeleteOne(ctx, filter)
	if err != nil {
		return errors.Wrap(err, "failed to remove token")
	} else if result.DeletedCount < 1 {
		return store.ErrTokenNotFound
	}

	return nil
}

func (db *DataStoreMongo) DeleteTokens(ctx context.Context) error {
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbTokensColl)
	_, err := c.DeleteMany(ctx, bson.D{})

	return err
}

func (db *DataStoreMongo) DeleteTokenByDevId(ctx context.Context, devId string) error {
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbTokensColl)
	ci, err := c.DeleteMany(ctx, bson.M{"dev_id": devId})

	if err != nil {
		return errors.Wrap(err, "failed to remove tokens")
	}

	if ci.DeletedCount == 0 {
		return store.ErrTokenNotFound
	}

	return nil
}

func (db *DataStoreMongo) Migrate(ctx context.Context, version string) error {
	l := log.FromContext(ctx)

	dbs := []string{DbName}

	if db.multitenant {
		l.Infof("running migrations in multitenant mode")

		tdbs, err := migrate.GetTenantDbs(ctx, db.client, ctxstore.IsTenantDb(DbName))
		if err != nil {
			return errors.Wrap(err, "failed go retrieve tenant DBs")
		}
		dbs = tdbs
	} else {
		l.Infof("running migrations in single tenant mode")
	}

	if db.automigrate {
		l.Infof("automigrate is ON, will apply migrations")
	} else {
		l.Infof("automigrate is OFF, will check db version compatibility")
	}

	for _, d := range dbs {
		// if not in multi tenant, then tenant will be "" and identity
		// will be the same as default
		tenant := ctxstore.TenantFromDbName(d, DbName)

		if db.multitenant && tenant == "" {
			// running in multitenant but failed to determine tenant ID
			return errors.Errorf("failed to determine tenant from DB name %v", d)
		}

		tenantCtx := identity.WithContext(ctx, &identity.Identity{
			Tenant: tenant,
		})

		// TODO: we should aim to unify context usage across migrators and migrations
		// migrators use 'string' db name, migrations use DbFromContext
		// both should use one or the other; for now - just redundantly pass both ctx and db name
		err := db.MigrateTenant(tenantCtx, d, version)
		if err != nil {
			return err
		}
	}

	return nil
}

func (db *DataStoreMongo) MigrateTenant(ctx context.Context, database, version string) error {
	l := log.FromContext(ctx)

	l.Infof("migrating %s", database)

	m := migrate.SimpleMigrator{
		Client:      db.client,
		Db:          database,
		Automigrate: db.automigrate,
	}

	migrations := []migrate.Migration{
		&migration_1_1_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_2_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_3_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_4_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_5_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_6_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_7_0{
			ms:  db,
			ctx: ctx,
		},
	}

	ver, err := migrate.NewVersion(version)
	if err != nil {
		return errors.Wrap(err, "failed to parse service version")
	}

	err = m.Apply(ctx, *ver, migrations)
	if err != nil {
		return errors.Wrap(err, "failed to apply migrations")
	}

	return nil
}

func (db *DataStoreMongo) AddAuthSet(ctx context.Context, set model.AuthSet) error {
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)

	if set.Id == "" {
		uid, err := uuid.NewV4()
		if err != nil {
			return err
		}
		set.Id = uid.String()
	}

	if _, err := c.InsertOne(ctx, set); err != nil {
		if strings.Contains(err.Error(), "duplicate key error") {
			return store.ErrObjectExists
		}
		return errors.Wrap(err, "failed to store device")
	}

	return nil
}

func (db *DataStoreMongo) GetAuthSetByIdDataHashKey(ctx context.Context, idDataHash []byte, key string) (*model.AuthSet, error) {
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)

	filter := model.AuthSet{
		IdDataSha256: idDataHash,
		PubKey:       key,
	}
	res := model.AuthSet{}

	err := c.FindOne(ctx, filter).Decode(&res)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, store.ErrAuthSetNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch authentication set")
		}
	}

	return &res, nil
}

func (db *DataStoreMongo) GetAuthSetById(ctx context.Context, auth_id string) (*model.AuthSet, error) {
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)

	res := model.AuthSet{}
	err := c.FindOne(ctx, bson.M{"_id": auth_id}).Decode(&res)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, store.ErrAuthSetNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch authentication set")
		}
	}

	return &res, nil
}

func (db *DataStoreMongo) GetAuthSetsForDevice(ctx context.Context, devid string) ([]model.AuthSet, error) {
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)

	res := []model.AuthSet{}

	cursor, err := c.Find(ctx, model.AuthSet{DeviceId: devid})
	if err != nil {
		return nil, err
	}
	if err = cursor.All(ctx, &res); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, store.ErrAuthSetNotFound
		}
		return nil, errors.Wrap(err, "failed to fetch authentication sets")
	}

	return res, nil
}

func (db *DataStoreMongo) UpdateAuthSet(ctx context.Context, filter interface{}, mod model.AuthSetUpdate) error {
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)

	update := bson.M{"$set": mod}

	if res, err := c.UpdateMany(ctx, filter, update); err != nil {
		return errors.Wrap(err, "failed to update auth set")
	} else if res.MatchedCount == 0 {
		return store.ErrAuthSetNotFound
	}

	return nil
}

func (db *DataStoreMongo) UpdateAuthSetById(ctx context.Context, id string, mod model.AuthSetUpdate) error {
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)
	res, err := c.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": mod})
	if err != nil {
		return errors.Wrap(err, "failed to update auth set")
	}
	if res.MatchedCount == 0 {
		return store.ErrAuthSetNotFound
	}

	return nil
}

func (db *DataStoreMongo) DeleteAuthSetsForDevice(ctx context.Context, devid string) error {
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)

	ci, err := c.DeleteMany(ctx, model.AuthSet{DeviceId: devid})

	if err != nil {
		return errors.Wrap(err, "failed to remove authentication sets for device")
	}

	if ci.DeletedCount == 0 {
		return store.ErrAuthSetNotFound
	}

	return nil
}

func (db *DataStoreMongo) DeleteAuthSetForDevice(ctx context.Context, devId string, authId string) error {
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)

	filter := model.AuthSet{Id: authId, DeviceId: devId}
	result, err := c.DeleteOne(ctx, filter)
	if err != nil {
		return errors.Wrap(err, "failed to remove authentication set for device")
	} else if result.DeletedCount < 1 {
		return store.ErrAuthSetNotFound
	}

	return nil
}

func (db *DataStoreMongo) WithMultitenant() *DataStoreMongo {
	db.multitenant = true
	return db
}

func (db *DataStoreMongo) WithAutomigrate() store.DataStore {
	return &DataStoreMongo{
		client:      db.client,
		automigrate: true,
	}
}

func (db *DataStoreMongo) EnsureIndexes(ctx context.Context) error {
	_false := false
	_true := true

	devIdDataUniqueIndex := mongo.IndexModel{
		Keys: bson.D{
			{Key: model.DevKeyIdData, Value: 1},
		},
		Options: &options.IndexOptions{
			Background: &_false,
			Name:       &indexDevices_IdentityData,
			Unique:     &_true,
		},
	}

	authSetUniqueIndex := mongo.IndexModel{
		Keys: bson.D{
			{Key: model.AuthSetKeyDeviceId, Value: 1},
			{Key: model.AuthSetKeyIdData, Value: 1},
			{Key: model.AuthSetKeyPubKey, Value: 1},
		},
		Options: &options.IndexOptions{
			Background: &_false,
			Name:       &indexAuthSet_DeviceId_IdentityData_PubKey,
			Unique:     &_true,
		},
	}

	cDevs := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbDevicesColl)
	devIndexes := cDevs.Indexes()
	_, err := devIndexes.CreateOne(ctx, devIdDataUniqueIndex)
	if err != nil {
		return err
	}

	cAuthSets := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)
	authSetIndexes := cAuthSets.Indexes()
	_, err = authSetIndexes.CreateOne(ctx, authSetUniqueIndex)

	return err
}

func (db *DataStoreMongo) PutLimit(ctx context.Context, lim model.Limit) error {
	if lim.Name == "" {
		return errors.New("empty limit name")
	}

	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbLimitsColl)

	query := bson.M{"_id": lim.Name}

	updateOptions := options.Update()
	updateOptions.SetUpsert(true)
	if _, err := c.UpdateOne(
		ctx, query, bson.M{"$set": lim}, updateOptions); err != nil {
		return errors.Wrap(err, "failed to set or update limit")
	}

	return nil
}

func (db *DataStoreMongo) GetLimit(ctx context.Context, name string) (*model.Limit, error) {
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbLimitsColl)

	var lim model.Limit

	err := c.FindOne(ctx, bson.M{"_id": name}).Decode(&lim)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, store.ErrLimitNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch limit")
		}
	}

	return &lim, nil
}

func (db *DataStoreMongo) GetDevCountByStatus(ctx context.Context, status string) (int, error) {
	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)

	// if status == "", fallback to a simple count of all devices
	if status == "" {
		devsColl := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbDevicesColl)
		count, err := devsColl.CountDocuments(ctx, bson.D{})
		if err != nil {
			return 0, err
		}
		return int(count), nil
	}

	// compose aggregation pipeline

	// group by dev id and auth set status, count status occurences:
	// {_id: {"devid": "dev1", "status": "accepted"}, count: 1}
	// {_id: {"devid": "dev1", "status": "preauthorized"}, count: 3}
	// {_id: {"devid": "dev1", "status": "pending"}, count: 2}
	// {_id: {"devid": "dev1", "status": "rejected"}, count: 0}
	// etc. for all devs
	grp := bson.D{
		{Key: "$group", Value: bson.D{
			{Key: "_id", Value: bson.M{
				"devid":  "$device_id",
				"status": "$status",
			}},
			{Key: "count", Value: bson.M{
				"$sum": 1,
			}},
		},
		},
	}

	// project to:
	// {device_id: "1", accepted: 1}
	// {device_id: "1", preauthorized: 3}
	// {device_id: "1", pending: 2}
	// {device_id: "1", rejected: 0}
	// clunky - no easy way to transform values into fields
	proj := bson.D{
		{Key: "$project", Value: bson.M{
			"devid": "$_id.devid",
			"res": bson.M{
				"$cond": []bson.M{
					{"$eq": []string{"$_id.status", "accepted"}},
					{"accepted": "$count"},
					{"$cond": []bson.M{
						{"$eq": []string{"$_id.status", "preauthorized"}},
						{"preauthorized": "$count"},
						{"$cond": []bson.M{
							{"$eq": []string{"$_id.status", "pending"}},
							{"pending": "$count"},
							{"rejected": "$count"},
						},
						},
					},
					},
				},
			},
		},
		},
	}

	// group again to get aggregate per-status counts
	// {device_id: "1", accepted: 1, preauthorized: 3, pending: 2, rejected: 0}
	sum := bson.D{
		{Key: "$group", Value: bson.M{
			"_id":           "$devid",
			"accepted":      bson.M{"$sum": "$res.accepted"},
			"preauthorized": bson.M{"$sum": "$res.preauthorized"},
			"pending":       bson.M{"$sum": "$res.pending"},
			"rejected":      bson.M{"$sum": "$res.rejected"},
		}}}

	// actually filter devices according to status
	var filt bson.D

	// single accepted auth set = device accepted
	if status == "accepted" {
		filt = bson.D{
			{Key: "$match", Value: bson.M{
				"accepted": bson.M{"$gt": 0},
			}},
		}
	}

	// device is pending if it has no accepted and no preauthorized sets and
	// has pending sets
	if status == "pending" {
		filt = bson.D{
			{Key: "$match", Value: bson.M{
				"$and": []bson.M{
					{"accepted": bson.M{"$eq": 0}},
					{"preauthorized": bson.M{"$eq": 0}},
					{"pending": bson.M{"$gt": 0}},
				},
			}},
		}
	}

	// device is preauthorized if it has no accepted and
	// has preauthorized sets
	if status == "preauthorized" {
		filt = bson.D{
			{Key: "$match", Value: bson.M{
				"$and": []bson.M{
					{"accepted": bson.M{"$eq": 0}},
					{"preauthorized": bson.M{"$gt": 0}},
				},
			}},
		}
	}

	// device is rejected if all its sets are rejected
	if status == "rejected" {
		filt = bson.D{
			{Key: "$match", Value: bson.M{
				"$and": []bson.M{
					{"accepted": bson.M{"$eq": 0}},
					{"preauthorized": bson.M{"$eq": 0}},
					{"pending": bson.M{"$eq": 0}},
					{"rejected": bson.M{"$gt": 0}},
				},
			}},
		}
	}

	cnt := bson.D{
		{Key: "$count", Value: "count"}}

	var resp []bson.M

	cursor, err := c.Aggregate(ctx, []bson.D{grp, proj, sum, filt, cnt})
	if err != nil {
		return 0, err
	}
	if err := cursor.All(ctx, &resp); err != nil {
		if err == mongo.ErrNoDocuments {
			return 0, nil
		}
		return 0, err
	}
	if len(resp) > 0 {
		return int(resp[0]["count"].(int32)), nil
	}

	return 0, err
}

func (db *DataStoreMongo) GetDeviceStatus(ctx context.Context, devId string) (string, error) {
	var statuses = map[string]int{}

	c := db.client.Database(ctxstore.DbFromContext(ctx, DbName)).Collection(DbAuthSetColl)

	// get device auth sets; group by status

	filter := model.AuthSet{
		DeviceId: devId,
	}

	match := bson.D{
		{Key: "$match", Value: filter},
	}
	group := bson.D{
		{Key: "$group", Value: bson.D{
			{Key: "_id", Value: "$status"},
			{Key: "count", Value: bson.M{"$sum": 1}}},
		},
	}

	pipeline := []bson.D{
		match,
		group,
	}
	var result []struct {
		Status string `bson:"_id"`
		Value  int    `bson:"count"`
	}
	cursor, err := c.Aggregate(ctx, pipeline)
	if err != nil {
		return "", err
	}
	if err := cursor.All(ctx, &result); err != nil {
		if err == mongo.ErrNoDocuments {
			return "", store.ErrAuthSetNotFound
		}
		return "", err
	}

	if len(result) == 0 {
		return "", store.ErrAuthSetNotFound
	}

	for _, res := range result {
		statuses[res.Status] = res.Value
	}

	status, err := getDeviceStatus(statuses)
	if err != nil {
		return "", err
	}

	return status, nil
}

func getDeviceStatus(statuses map[string]int) (string, error) {
	if statuses[model.DevStatusAccepted] > 1 || statuses[model.DevStatusPreauth] > 1 {
		return "", store.ErrDevStatusBroken
	}

	if statuses[model.DevStatusAccepted] == 1 {
		return model.DevStatusAccepted, nil
	}

	if statuses[model.DevStatusPreauth] == 1 {
		return model.DevStatusPreauth, nil
	}

	if statuses[model.DevStatusPending] > 0 {
		return model.DevStatusPending, nil
	}

	if statuses[model.DevStatusRejected] > 0 {
		return model.DevStatusRejected, nil
	}

	return "", store.ErrDevStatusBroken
}

func (db *DataStoreMongo) GetTenantDbs() ([]string, error) {
	return migrate.GetTenantDbs(context.Background(), db.client, ctxstore.IsTenantDb(DbName))
}
