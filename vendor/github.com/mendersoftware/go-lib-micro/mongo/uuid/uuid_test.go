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

package uuid

import (
	"encoding/binary"
	"testing"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

type s struct {
	ID UUID
}

func TestUUID(t *testing.T) {
	// Test NewSHA1
	uSHA1 := NewSHA1("foobar")
	uSHA1Eq := NewSHA1("foobar")
	assert.Equal(t, uSHA1, uSHA1Eq)

	// Test FromString
	uFromString, _ := FromString(uSHA1.String())
	assert.Equal(t, uSHA1, uFromString)
	_, err := FromString("foobar")
	assert.Error(t, err)

	// Test NewRandom
	uRandom := NewRandom()
	assert.NotEqual(t, UUID{UUID: uuid.Nil}, uRandom)
	assert.NotEmpty(t, uRandom)

	// Test marshal/unmarshal bson
	bsonType, b, err := uRandom.MarshalBSONValue()
	assert.NoError(t, err)
	assert.Equal(t, bsontype.Binary, bsonType)

	// Illegal bsontype
	err = uRandom.UnmarshalBSONValue(bsontype.String, b)
	assert.Error(t, err)
	// OK
	err = uRandom.UnmarshalBSONValue(bsonType, b)
	assert.NoError(t, err)
	// Invalid sub-type
	b[4] = bsontype.BinaryGeneric
	err = uRandom.UnmarshalBSONValue(bsonType, b)
	assert.Error(t, err)
	// Invalid length
	binary.LittleEndian.PutUint32(b, 10)
	err = uRandom.UnmarshalBSONValue(bsonType, b)
	assert.Error(t, err)

	// Test bson.Marshal / bson.Unmarshal with an embedded UUID
	s1 := s{ID: uRandom}
	var res s
	b, err = bson.Marshal(s1)
	assert.NoError(t, err)
	err = bson.Unmarshal(b, &res)
	assert.NoError(t, err)
	assert.Equal(t, s1, res)
}
