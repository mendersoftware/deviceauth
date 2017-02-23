// Copyright 2016 Mender Software AS
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

package main

import (
	"sync"
	"time"

	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	"github.com/pkg/errors"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const (
	DbVersion     = "0.1.0"
	DbName        = "deviceauth"
	DbDevicesColl = "devices"
	DbAuthReqColl = "auth_requests"
	DbTokensColl  = "tokens"
)

var (
	// masterSession is a master session to be copied on demand
	// This is the preferred pattern with mgo (for common conn pool management, etc.)
	masterSession *mgo.Session

	// once ensures mgoMaster is created only once
	once sync.Once
)

type DataStoreMongo struct {
	session *mgo.Session
	log     *log.Logger
}

func GetDataStoreMongo(db string, l *log.Logger) (*DataStoreMongo, error) {
	d, err := NewDataStoreMongo(db)
	if err != nil {
		return nil, errors.Wrap(err, "database connection failed")
	}
	d.UseLog(l)

	return d, nil
}

func NewDataStoreMongoWithSession(session *mgo.Session) *DataStoreMongo {
	return &DataStoreMongo{
		session: session,
		log:     log.New(log.Ctx{}),
	}
}

func NewDataStoreMongo(host string) (*DataStoreMongo, error) {
	//init master session
	var err error
	once.Do(func() {
		masterSession, err = mgo.Dial(host)
	})
	if err != nil {
		return nil, errors.New("failed to open mgo session")
	}

	db := NewDataStoreMongoWithSession(masterSession)

	return db, nil
}

func (db *DataStoreMongo) GetDevices(skip, limit uint) ([]Device, error) {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(DbName).C(DbDevicesColl)

	res := []Device{}

	err := c.Find(nil).Sort("_id").Skip(int(skip)).Limit(int(limit)).All(&res)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch device list")
	}
	return res, nil
}

func (db *DataStoreMongo) GetDeviceById(id string) (*Device, error) {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(DbName).C(DbDevicesColl)

	res := Device{}

	err := c.FindId(id).One(&res)

	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, ErrDevNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch device")
		}
	}

	return &res, nil
}

func (db *DataStoreMongo) GetDeviceByKey(key string) (*Device, error) {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(DbName).C(DbDevicesColl)

	filter := bson.M{"pubkey": key}
	res := Device{}

	err := c.Find(filter).One(&res)

	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, ErrDevNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch device")
		}
	}

	return &res, nil
}

func (db *DataStoreMongo) AddDevice(d *Device) error {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(DbName).C(DbDevicesColl)

	if err := c.Insert(d); err != nil {
		return errors.Wrap(err, "failed to store device")
	}

	return nil
}

func (db *DataStoreMongo) UpdateDevice(d *Device) error {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(DbName).C(DbDevicesColl)

	updev := makeUpdate(d)
	update := bson.M{"$set": updev}

	if err := c.UpdateId(d.Id, update); err != nil {
		return errors.Wrap(err, "failed to update device")
	}

	return nil
}

func (db *DataStoreMongo) AddToken(t *Token) error {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(DbName).C(DbTokensColl)

	if err := c.Insert(t); err != nil {
		return errors.Wrap(err, "failed to store token")
	}

	return nil
}

func (db *DataStoreMongo) GetToken(jti string) (*Token, error) {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(DbName).C(DbTokensColl)

	res := Token{}

	err := c.FindId(jti).One(&res)

	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, ErrTokenNotFound
		} else {
			return nil, errors.Wrap(err, "failed to fetch token")
		}
	}

	return &res, nil
}

func (db *DataStoreMongo) DeleteToken(jti string) error {
	s := db.session.Copy()
	defer s.Close()

	c := db.session.DB(DbName).C(DbTokensColl)
	err := c.RemoveId(jti)
	if err != nil {
		if err == mgo.ErrNotFound {
			return ErrTokenNotFound
		} else {
			return errors.Wrap(err, "failed to remove token")
		}
	}

	return nil
}

func (db *DataStoreMongo) DeleteTokenByDevId(devId string) error {
	s := db.session.Copy()
	defer s.Close()

	c := db.session.DB(DbName).C(DbTokensColl)
	err := c.Remove(bson.M{"dev_id": devId})

	if err != nil {
		if err == mgo.ErrNotFound {
			return ErrTokenNotFound
		} else {
			return errors.Wrap(err, "failed to remove token")
		}
	}

	return nil
}

func (db *DataStoreMongo) Migrate(version string, migrations []migrate.Migration) error {
	m := migrate.DummyMigrator{
		Session: db.session,
		Db:      DbName,
	}

	ver, err := migrate.NewVersion(version)
	if err != nil {
		return errors.Wrap(err, "failed to parse service version")
	}

	err = m.Apply(ver, migrations)
	if err != nil {
		return errors.Wrap(err, "failed to apply migrations")
	}

	return nil
}

func makeUpdate(d *Device) *Device {
	updev := &Device{}

	if d.PubKey != "" {
		updev.PubKey = d.PubKey
	}

	if d.Status != "" {
		updev.Status = d.Status
	}

	updev.UpdatedTs = time.Now()

	return updev
}

func (db *DataStoreMongo) UseLog(l *log.Logger) {
	db.log = l.F(log.Ctx{})
}
