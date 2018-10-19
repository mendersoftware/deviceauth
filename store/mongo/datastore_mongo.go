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
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	uto "github.com/mendersoftware/deviceauth/utils/to"
)

const (
	DbVersion     = "1.4.0"
	DbName        = "deviceauth"
	DbDevicesColl = "devices"
	DbAuthSetColl = "auth_sets"
	DbTokensColl  = "tokens"
	DbLimitsColl  = "limits"

	indexDevices_IdentityData                       = "devices:IdentityData"
	indexAuthSet_DeviceId_IdentityData_PubKey       = "auth_sets:DeviceId:IdData:PubKey"
	indexAuthSet_DeviceId_IdentityDataSha256_PubKey = "auth_sets:IdDataSha256:PubKey"
)

var (
	// masterSession is a master session to be copied on demand
	// This is the preferred pattern with mgo (for common conn pool management, etc.)
	masterSession *mgo.Session

	// once ensures mgoMaster is created only once
	once sync.Once
)

type DataStoreMongoConfig struct {
	// MGO connection string
	ConnectionString string

	// SSL support
	SSL           bool
	SSLSkipVerify bool

	// Overwrites credentials provided in connection string if provided
	Username string
	Password string
}

type DataStoreMongo struct {
	session     *mgo.Session
	automigrate bool
	multitenant bool
}

func NewDataStoreMongoWithSession(session *mgo.Session) *DataStoreMongo {
	return &DataStoreMongo{
		session: session,
	}
}

func NewDataStoreMongo(config DataStoreMongoConfig) (*DataStoreMongo, error) {
	//init master session
	var err error
	once.Do(func() {

		var dialInfo *mgo.DialInfo
		dialInfo, err = mgo.ParseURL(config.ConnectionString)
		if err != nil {
			return
		}

		// Set 10s timeout - same as set by Dial
		dialInfo.Timeout = 10 * time.Second

		if config.Username != "" {
			dialInfo.Username = config.Username
		}
		if config.Password != "" {
			dialInfo.Password = config.Password
		}

		if config.SSL {
			dialInfo.DialServer = func(addr *mgo.ServerAddr) (net.Conn, error) {

				// Setup TLS
				tlsConfig := &tls.Config{}
				tlsConfig.InsecureSkipVerify = config.SSLSkipVerify

				conn, err := tls.Dial("tcp", addr.String(), tlsConfig)
				return conn, err
			}
		}

		masterSession, err = mgo.DialWithInfo(dialInfo)
		if err != nil {
			return
		}

		// Validate connection
		if err = masterSession.Ping(); err != nil {
			return
		}

		// force write ack with immediate journal file fsync
		masterSession.SetSafe(&mgo.Safe{
			W: 1,
			J: true,
		})
	})

	if err != nil {
		return nil, errors.Wrap(err, "failed to open mgo session")
	}

	return NewDataStoreMongoWithSession(masterSession), nil
}

func (db *DataStoreMongo) GetDevices(ctx context.Context, skip, limit uint) ([]model.Device, error) {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)

	res := []model.Device{}

	err := c.Find(nil).Sort("_id").Skip(int(skip)).Limit(int(limit)).All(&res)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch device list")
	}
	return res, nil
}

func (db *DataStoreMongo) GetDeviceById(ctx context.Context, id string) (*model.Device, error) {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)

	res := model.Device{}

	err := c.FindId(id).One(&res)

	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, store.ErrDevNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch device")
		}
	}

	return &res, nil
}

func (db *DataStoreMongo) GetDeviceByIdentityData(ctx context.Context, idata string) (*model.Device, error) {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)

	filter := bson.M{"id_data": idata}
	res := model.Device{}

	err := c.Find(filter).One(&res)

	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, store.ErrDevNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch device")
		}
	}

	return &res, nil
}

func (db *DataStoreMongo) AddDevice(ctx context.Context, d model.Device) error {
	s := db.session.Copy()
	defer s.Close()

	if err := db.EnsureIndexes(ctx, s); err != nil {
		return err
	}

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)

	if d.Id == "" {
		d.Id = bson.NewObjectId().Hex()
	}

	if err := c.Insert(d); err != nil {
		if mgo.IsDup(err) {
			return store.ErrObjectExists
		}
		return errors.Wrap(err, "failed to store device")
	}
	return nil
}

func (db *DataStoreMongo) UpdateDevice(ctx context.Context,
	d model.Device, updev model.DeviceUpdate) error {

	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)

	updev.UpdatedTs = uto.TimePtr(time.Now().UTC())
	update := bson.M{"$set": updev}

	if err := c.UpdateId(d.Id, update); err != nil {
		if err == mgo.ErrNotFound {
			return store.ErrDevNotFound
		}
		return errors.Wrap(err, "failed to update device")
	}

	return nil
}

func (db *DataStoreMongo) DeleteDevice(ctx context.Context, id string) error {
	s := db.session.Copy()
	defer s.Close()

	c := db.session.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)
	err := c.RemoveId(id)
	if err != nil {
		if err == mgo.ErrNotFound {
			return store.ErrDevNotFound
		} else {
			return errors.Wrap(err, "failed to remove device")
		}
	}

	return nil
}

func (db *DataStoreMongo) AddToken(ctx context.Context, t model.Token) error {
	s := db.session.Copy()
	defer s.Close()

	if err := db.EnsureIndexes(ctx, s); err != nil {
		return err
	}

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbTokensColl)

	if err := c.Insert(t); err != nil {
		return errors.Wrap(err, "failed to store token")
	}

	return nil
}

func (db *DataStoreMongo) GetToken(ctx context.Context, jti string) (*model.Token, error) {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbTokensColl)

	res := model.Token{}

	err := c.FindId(jti).One(&res)

	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, store.ErrTokenNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch token")
		}
	}

	return &res, nil
}

func (db *DataStoreMongo) DeleteToken(ctx context.Context, jti string) error {
	s := db.session.Copy()
	defer s.Close()

	c := db.session.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbTokensColl)
	err := c.RemoveId(jti)
	if err != nil {
		if err == mgo.ErrNotFound {
			return store.ErrTokenNotFound
		} else {
			return errors.Wrap(err, "failed to remove token")
		}
	}

	return nil
}

func (db *DataStoreMongo) DeleteTokens(ctx context.Context) error {
	s := db.session.Copy()
	defer s.Close()

	c := db.session.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbTokensColl)
	_, err := c.RemoveAll(nil)

	return err
}

func (db *DataStoreMongo) DeleteTokenByDevId(ctx context.Context, devId string) error {
	s := db.session.Copy()
	defer s.Close()

	c := db.session.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbTokensColl)
	ci, err := c.RemoveAll(bson.M{"dev_id": devId})

	if ci.Removed == 0 {
		return store.ErrTokenNotFound
	}

	if err != nil {
		return errors.Wrap(err, "failed to remove tokens")
	}

	return nil
}

func (db *DataStoreMongo) Migrate(ctx context.Context, version string) error {
	l := log.FromContext(ctx)

	dbs := []string{DbName}

	if db.multitenant {
		l.Infof("running migrations in multitenant mode")

		tdbs, err := migrate.GetTenantDbs(db.session, ctxstore.IsTenantDb(DbName))
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
		Session:     db.session,
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
	s := db.session.Copy()
	defer s.Close()

	if err := db.EnsureIndexes(ctx, s); err != nil {
		return err
	}

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbAuthSetColl)

	if set.Id == "" {
		set.Id = bson.NewObjectId().Hex()
	}

	if err := c.Insert(set); err != nil {
		if mgo.IsDup(err) {
			return store.ErrObjectExists
		}
		return errors.Wrap(err, "failed to store device")
	}
	return nil
}

func (db *DataStoreMongo) GetAuthSetByDataKey(ctx context.Context, idata string, key string) (*model.AuthSet, error) {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbAuthSetColl)

	filter := model.AuthSet{
		IdData: idata,
		PubKey: key,
	}
	res := model.AuthSet{}

	err := c.Find(filter).One(&res)

	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, store.ErrDevNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch device")
		}
	}

	return &res, nil
}

func (db *DataStoreMongo) GetAuthSetById(ctx context.Context, auth_id string) (*model.AuthSet, error) {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbAuthSetColl)

	res := model.AuthSet{}
	err := c.FindId(auth_id).One(&res)

	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, store.ErrDevNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch device")
		}
	}

	return &res, nil
}

func (db *DataStoreMongo) GetAuthSetsForDevice(ctx context.Context, devid string) ([]model.AuthSet, error) {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbAuthSetColl)

	res := []model.AuthSet{}

	err := c.Find(model.AuthSet{DeviceId: devid}).All(&res)

	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, store.ErrDevNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch device")
		}
	}

	return res, nil
}

func (db *DataStoreMongo) UpdateAuthSet(ctx context.Context, filter interface{}, mod model.AuthSetUpdate) error {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbAuthSetColl)

	ci, err := c.UpdateAll(filter, bson.M{"$set": mod})
	if err != nil {
		return errors.Wrap(err, "failed to update auth set")
	} else if ci.Updated == 0 {
		return store.ErrAuthSetNotFound
	}

	return nil
}

func (db *DataStoreMongo) DeleteAuthSetsForDevice(ctx context.Context, devid string) error {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbAuthSetColl)

	ci, err := c.RemoveAll(model.AuthSet{DeviceId: devid})

	if ci.Removed == 0 {
		return store.ErrAuthSetNotFound
	}

	if err != nil {
		return errors.Wrap(err, "failed to remove auth sets for device")
	}

	return nil
}

func (db *DataStoreMongo) DeleteAuthSetForDevice(ctx context.Context, devId string, authId string) error {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbAuthSetColl)

	err := c.Remove(model.AuthSet{Id: authId, DeviceId: devId})

	if err != nil {
		if err == mgo.ErrNotFound {
			return store.ErrAuthSetNotFound
		} else {
			return errors.Wrap(err, "failed to remove auth sets for device")
		}
	}

	return nil
}

func (db *DataStoreMongo) WithMultitenant() *DataStoreMongo {
	db.multitenant = true
	return db
}

func (db *DataStoreMongo) WithAutomigrate() store.DataStore {
	return &DataStoreMongo{
		session:     db.session,
		automigrate: true,
	}
}

func (db *DataStoreMongo) EnsureIndexes(ctx context.Context, s *mgo.Session) error {

	// devices collection
	err := s.DB(ctxstore.DbFromContext(ctx, DbName)).
		C(DbDevicesColl).EnsureIndex(mgo.Index{
		Unique: true,
		// identity data shall be unique within collection
		Key:        []string{model.DevKeyIdData},
		Name:       indexDevices_IdentityData,
		Background: false,
	})
	if err != nil {
		return err
	}

	// auth requests
	return s.DB(ctxstore.DbFromContext(ctx, DbName)).
		C(DbAuthSetColl).EnsureIndex(mgo.Index{
		Unique: true,
		// tuple (device ID,identity, public key) shall be unique within
		// collection
		Key: []string{
			model.AuthSetKeyDeviceId,
			model.AuthSetKeyIdData,
			model.AuthSetKeyPubKey,
		},
		Name:       indexAuthSet_DeviceId_IdentityData_PubKey,
		Background: false,
	})
}

func (db *DataStoreMongo) PutLimit(ctx context.Context, lim model.Limit) error {
	if lim.Name == "" {
		return errors.New("empty limit name")
	}

	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbLimitsColl)

	_, err := c.UpsertId(lim.Name, lim)
	if err != nil {
		return errors.Wrap(err, "failed to set or update limit")
	}

	return nil
}

func (db *DataStoreMongo) GetLimit(ctx context.Context, name string) (*model.Limit, error) {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbLimitsColl)

	var lim model.Limit
	err := c.FindId(name).One(&lim)
	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, store.ErrLimitNotFound
		}
		return nil, errors.Wrap(err, "failed to update auth set")
	}

	return &lim, nil
}

func (db *DataStoreMongo) GetDevCountByStatus(ctx context.Context, status string) (int, error) {
	s := db.session.Copy()
	defer s.Close()

	// if status == "", fallback to a simple count of all devices
	if status == "" {
		c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbDevicesColl)
		return c.Count()
	}

	// compose aggregation pipeline
	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbAuthSetColl)

	// group by dev id and auth set status, count status occurences:
	// {_id: {"devid": "dev1", "status": "accepted"}, count: 1}
	// {_id: {"devid": "dev1", "status": "preauthorized"}, count: 3}
	// {_id: {"devid": "dev1", "status": "pending"}, count: 2}
	// {_id: {"devid": "dev1", "status": "rejected"}, count: 0}
	// etc. for all devs
	grp := bson.M{
		"$group": bson.M{
			"_id": bson.M{
				"devid":  "$device_id",
				"status": "$status",
			},
			"count": bson.M{
				"$sum": 1,
			},
		},
	}

	// project to:
	// {device_id: "1", accepted: 1}
	// {device_id: "1", preauthorized: 3}
	// {device_id: "1", pending: 2}
	// {device_id: "1", rejected: 0}
	// clunky - no easy way to transform values into fields
	proj := bson.M{
		"$project": bson.M{
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
	}

	// group again to get aggregate per-status counts
	// {device_id: "1", accepted: 1, preauthorized: 3, pending: 2, rejected: 0}
	sum := bson.M{
		"$group": bson.M{
			"_id":           "$devid",
			"accepted":      bson.M{"$sum": "$res.accepted"},
			"preauthorized": bson.M{"$sum": "$res.preauthorized"},
			"pending":       bson.M{"$sum": "$res.pending"},
			"rejected":      bson.M{"$sum": "$res.rejected"},
		}}

	// actually filter devices according to status
	var filt bson.M

	// single accepted auth set = device accepted
	if status == "accepted" {
		filt = bson.M{
			"$match": bson.M{
				"accepted": bson.M{"$gt": 0},
			},
		}
	}

	// device is pending if it has no accepted and no preauthorized sets and
	// has pending sets
	if status == "pending" {
		filt = bson.M{
			"$match": bson.M{
				"$and": []bson.M{
					{"accepted": bson.M{"$eq": 0}},
					{"preauthorized": bson.M{"$eq": 0}},
					{"pending": bson.M{"$gt": 0}},
				},
			},
		}
	}

	// device is preauthorized if it has no accepted and
	// has preauthorized sets
	if status == "preauthorized" {
		filt = bson.M{
			"$match": bson.M{
				"$and": []bson.M{
					{"accepted": bson.M{"$eq": 0}},
					{"preauthorized": bson.M{"$gt": 0}},
				},
			},
		}
	}

	// device is rejected if all its sets are rejected
	if status == "rejected" {
		filt = bson.M{
			"$match": bson.M{
				"$and": []bson.M{
					{"accepted": bson.M{"$eq": 0}},
					{"preauthorized": bson.M{"$eq": 0}},
					{"pending": bson.M{"$eq": 0}},
					{"rejected": bson.M{"$gt": 0}},
				},
			},
		}
	}

	cnt := bson.M{
		"$count": "count",
	}

	var resp bson.M

	pipe := c.Pipe([]bson.M{grp, proj, sum, filt, cnt})
	err := pipe.One(&resp)

	switch err {
	case nil:
		break
	case mgo.ErrNotFound:
		return 0, nil
	default:
		return 0, err
	}

	return resp["count"].(int), err
}

func (db *DataStoreMongo) GetDeviceStatus(ctx context.Context, devId string) (string, error) {
	s := db.session.Copy()
	defer s.Close()

	var statuses = map[string]int{}

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbAuthSetColl)

	// get device auth sets; group by status

	job := &mgo.MapReduce{
		Map:    "function() { emit(this.status, 1) }",
		Reduce: "function(key, values) { return Array.sum(values) }",
	}

	filter := model.AuthSet{
		DeviceId: devId,
	}

	var result []struct {
		Status string `bson:"_id"`
		Value  int
	}

	_, err := c.Find(filter).MapReduce(job, &result)
	if err != nil {
		if err.Error() == store.NoCollectionErrMsg {
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

func (db *DataStoreMongo) GetAuthSets(ctx context.Context, skip, limit int, filter store.AuthSetFilter) ([]model.DevAdmAuthSet, error) {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(ctxstore.DbFromContext(ctx, DbName)).C(DbAuthSetColl)

	res := []model.AuthSet{}

	err := c.Find(filter).Sort("id").Skip(skip).Limit(limit).All(&res)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch auth sets")
	}

	resDevAdm := make([]model.DevAdmAuthSet, len(res))
	for i, r := range res {
		rda, err := model.NewDevAdmAuthSet(r)
		resDevAdm[i] = *rda
		if err != nil {
			return nil, errors.Wrap(err, "failed to fetch auth sets")
		}
	}

	return resDevAdm, nil
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
	return migrate.GetTenantDbs(db.session, ctxstore.IsTenantDb(DbName))
}
