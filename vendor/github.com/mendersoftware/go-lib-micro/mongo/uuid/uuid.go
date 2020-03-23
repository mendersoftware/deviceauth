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

// Package uuid contains a wrapper of github.com/satori/go.uuid that is
// compatible with the bson standard.
package uuid

import (
	"encoding/binary"

	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

// UUID implements a bson compatible uuid on top of github.com/satori/go.uuid
// library. The structure implements the bson.ValueMarshaler and
// bson.ValueUnmarshaler interfaces built from scratch because, you guessed it,
// the mongo-driver does not support this part of the bson specification.
type UUID struct {
	uuid.UUID
}

// MarshalBSONValue provides the bson.ValueMarshaler interface.
func (u UUID) MarshalBSONValue() (bsontype.Type, []byte, error) {
	buf := make([]byte, uuid.Size+4+1)
	binary.LittleEndian.PutUint32(buf, uuid.Size)
	buf[4] = bsontype.BinaryUUID
	copy(buf[5:], u.UUID[:])
	return bsontype.Binary, buf, nil
}

// UnmarshalBSONValue provides the bson.ValueUnmarshaler interace.
func (u *UUID) UnmarshalBSONValue(t bsontype.Type, b []byte) error {
	var err error
	if t != bsontype.Binary {
		return errors.Errorf("illegal type %s for unmarshaling uuid", t)
	}
	l := binary.LittleEndian.Uint32(b)
	if l != uuid.Size {
		return errors.Errorf("illegal uuid length: %d", l)
	}
	if b[4] != bsontype.BinaryUUID {
		return errors.Errorf("illegal bson sub-type: %d, expected: %d",
			b[4], bsontype.BinaryUUID)
	}
	u.UUID, err = uuid.FromBytes(b[5:])
	return err
}

// NewUUID is just a convenience wrapper for creating new v4 UUIDs.
// In the rare case where reading the RNG should return an error,
// the nil UUID is returned.
func NewRandom() UUID {
	u, err := uuid.NewV4()
	if err != nil {
		return UUID{UUID: uuid.Nil}
	}
	return UUID{UUID: u}
}

// NewSHA1 returns a new version 5 uuid in the objectID namespace
func NewSHA1(id string) UUID {
	ret := uuid.NewV5(uuid.NamespaceOID, id)
	return UUID{UUID: ret}
}

// FromString tries to parse a hex-encoded UUID string, and returns an error
// if the string is not a valid UUID.
func FromString(id string) (UUID, error) {
	ret, err := uuid.FromString(id)
	return UUID{
		UUID: ret,
	}, err
}
