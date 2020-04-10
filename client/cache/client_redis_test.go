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

package cache

import (
	"context"
	"testing"
	"time"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewClientRedis(t *testing.T) {
	c := NewClientRedis()
	assert.NotNil(t, c)
}

func TestClientRedisConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestClientRedisConnect in short mode.")
	}

	c := NewClientRedis()

	ctx := context.Background()
	err := c.Connect(ctx)

	assert.Nil(t, err)
}

func TestClientRedisSetGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestClientRedisSetGet in short mode.")
	}

	c := NewClientRedis()

	ctx := context.Background()
	err := c.Connect(ctx)
	assert.Nil(t, err)

	key, err := uuid.NewV4()
	assert.Nil(t, err)

	_, err = c.Get(ctx, key.String())
	assert.NotNil(t, err)

	err = c.Set(ctx, key.String(), "value", 2*time.Second)
	assert.Nil(t, err)

	val, err := c.Get(ctx, key.String())
	assert.Equal(t, val, val)
	assert.Nil(t, err)

	err = c.Del(ctx, key.String())
	assert.Nil(t, err)

	_, err = c.Get(ctx, key.String())
	assert.NotNil(t, err)
}
