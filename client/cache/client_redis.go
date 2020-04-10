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
	"time"

	"github.com/go-redis/redis/v7"

	"github.com/mendersoftware/go-lib-micro/config"

	dconfig "github.com/mendersoftware/deviceauth/config"
)

// ClientRedis is the Redis Client
type ClientRedis struct {
	client *redis.Client
}

// NewClientRedis returns a new Redis client
func NewClientRedis() *ClientRedis {
	return &ClientRedis{}
}

// Connect connects the client to the Redis storage
func (c *ClientRedis) Connect(ctx context.Context) error {
	redisAddress := config.Config.GetString(dconfig.SettingRedisAddress)
	redisPassword := config.Config.GetString(dconfig.SettingRedisPassword)
	redisDb := config.Config.GetInt(dconfig.SettingRedisDb)

	c.client = redis.NewClient(&redis.Options{
		Addr:     redisAddress,
		Password: redisPassword,
		DB:       redisDb,
	})

	_, err := c.client.Ping().Result()
	return err
}

// Get a value from the cache
func (c *ClientRedis) Get(ctx context.Context, key string) (string, error) {
	val, err := c.client.Get(key).Result()
	return val, err
}

// Set a value in the cache
func (c *ClientRedis) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	err := c.client.Set(key, value, expiration).Err()
	return err
}

// Del a value from the cache
func (c *ClientRedis) Del(ctx context.Context, key string) error {
	err := c.client.Del(key).Err()
	return err
}
