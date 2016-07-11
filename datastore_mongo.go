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
	"github.com/pkg/errors"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"time"
)

const (
	DbName        = "deviceauth"
	DbDevicesColl = "devices"
	DbAuthReqColl = "auth_requests"
	DbTokensColl  = "tokens"
)

type DataStoreMongo struct {
	session *mgo.Session
}

func NewDataStoreMongo(host string) (*DataStoreMongo, error) {
	s, err := mgo.Dial(host)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open mgo session")
	}
	return &DataStoreMongo{session: s}, nil
}

func (db *DataStoreMongo) GetAuthRequests(dev_id string, skip, limit int) ([]AuthReq, error) {
	s := db.session.Copy()
	defer s.Close()
	c := s.DB(DbName).C(DbAuthReqColl)

	res := []AuthReq{}

	filter := bson.M{"device_id": dev_id}

	err := c.Find(filter).Sort("-ts").Skip(skip).Limit(limit).All(&res)

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

func (db *DataStoreMongo) AddAuthReq(r *AuthReq) error {
	s := db.session.Copy()
	defer s.Close()

	c := s.DB(DbName).C(DbAuthReqColl)

	if err := c.Insert(r); err != nil {
		return errors.Wrap(err, "failed to store auth req")
	}

	return nil
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
	c := s.DB(DbName).C(DbTokensColl)
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
	c := s.DB(DbName).C(DbTokensColl)
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
