// Copyright 2023 Northern.tech AS
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

// Package cache introduces API throttling based
// on redis, and functions for auth token management.
//
// Throttling mechanisms
//
// 1. Quota enforcement
//
// Based on https://redislabs.com/redis-best-practices/basic-rate-limiting/, but with a flexible
// interval (ratelimits.ApiQuota.IntervalSec).
// Current usage for a device lives under key:
//
// `tenant:<tid>:device:<did>:quota:<interval_num>: <num_reqs>`
//
// expiring in the defined time window.
//
// 2. Burst control
//
// Implemented with a simple single key:
//
// `tenant:<tid>:device:<did>:burst:<action>:<url>: <last_req_ts>`
//
// expiring in ratelimits.ApiBurst.MinIntervalSec.
// The value is not really important, just the existence of the key
// means the burst was exceeded.
//
// Token Management
//
// Tokens are expected at:
// `tenant:<tid>:device:<did>:tok: <token>`
//

package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/pkg/errors"

	"github.com/go-redis/redis/v8"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/ratelimits"

	"github.com/mendersoftware/deviceauth/utils"
)

const (
	IdTypeDevice = "device"
	IdTypeUser   = "user"
	// expiration of the device check in time - one week
	CheckInTimeExpiration = time.Duration(time.Hour * 24 * 7)
)

var (
	ErrTooManyRequests = errors.New("too many requests")
)

//go:generate ../utils/mockgen.sh
type Cache interface {
	// Throttle applies desired api limits and retrieves a cached token.
	// These ops are bundled because the implementation will pipeline them for a single network
	// roundtrip for max performance.
	// Returns:
	// - the token (if any)
	// - potentially ErrTooManyRequests (other errors: internal)
	Throttle(
		ctx context.Context,
		rawToken string,
		l ratelimits.ApiLimits,
		tid,
		id,
		idtype,
		url,
		action string,
	) (string, error)

	// CacheToken caches the token under designated key, with expiration
	CacheToken(ctx context.Context, tid, id, idtype, token string, expireSec time.Duration) error

	// DeleteToken deletes the token for 'id'
	DeleteToken(ctx context.Context, tid, id, idtype string) error

	// GetLimits fetches limits for 'id'
	GetLimits(ctx context.Context, tid, id, idtype string) (*ratelimits.ApiLimits, error)

	// CacheLimits saves limits for 'id'
	CacheLimits(ctx context.Context, l ratelimits.ApiLimits, tid, id, idtype string) error

	// FlushDB clears the whole db asynchronously (FLUSHDB ASYNC)
	// TODO: replace with more fine grained key removal (per tenant)
	FlushDB(ctx context.Context) error

	// CacheCheckInTime caches the last device check in time
	CacheCheckInTime(ctx context.Context, t *time.Time, tid, id string) error

	// GetCheckInTime gets the last device check in time from cache
	GetCheckInTime(ctx context.Context, tid, id string) (*time.Time, error)

	// GetCheckInTimes gets the last device check in time from cache
	// for each device with id from the list of ids
	GetCheckInTimes(ctx context.Context, tid string, ids []string) ([]*time.Time, error)
}

type RedisCache struct {
	c               *redis.Client
	LimitsExpireSec int
	clock           utils.Clock
}

func NewRedisCache(
	addr,
	user,
	pass string,
	db int,
	timeoutSec,
	limitsExpireSec int,
) (*RedisCache, error) {
	c := redis.NewClient(&redis.Options{
		Addr:     addr,
		Username: user,
		Password: pass,
		DB:       db,
	})

	c = c.WithTimeout(time.Duration(timeoutSec) * time.Second)

	_, err := c.Ping(context.TODO()).Result()
	return &RedisCache{
		c:               c,
		LimitsExpireSec: limitsExpireSec,
		clock:           utils.NewClock(),
	}, err
}

func (rl *RedisCache) WithClock(c utils.Clock) *RedisCache {
	rl.clock = c
	return rl
}

func (rl *RedisCache) Throttle(
	ctx context.Context,
	rawToken string,
	l ratelimits.ApiLimits,
	tid,
	id,
	idtype,
	url,
	action string,
) (string, error) {
	now := rl.clock.Now().Unix()

	var tokenGet *redis.StringCmd
	var quotaInc *redis.IntCmd
	var quotaExp *redis.BoolCmd
	var burstGet *redis.StringCmd
	var burstSet *redis.StatusCmd

	pipe := rl.c.TxPipeline()

	// queue quota/burst control and token fetching
	// for piped execution
	quotaInc, quotaExp = rl.pipeQuota(ctx, pipe, l, tid, id, idtype, now)
	tokenGet = rl.pipeToken(ctx, pipe, tid, id, idtype)

	burstGet, burstSet = rl.pipeBurst(ctx,
		pipe,
		l,
		tid, id, idtype,
		url, action,
		now)

	_, err := pipe.Exec(ctx)
	if err != nil && !isErrRedisNil(err) {
		return "", err
	}

	// collect quota/burst control and token fetch results
	tok, err := rl.checkToken(tokenGet, rawToken)
	if err != nil {
		return "", err
	}

	err = rl.checkQuota(l, quotaInc, quotaExp)
	if err != nil {
		return "", err
	}

	err = rl.checkBurst(burstGet, burstSet)
	if err != nil {
		return "", err
	}

	return tok, nil
}

func (rl *RedisCache) pipeToken(
	ctx context.Context,
	pipe redis.Pipeliner,
	tid,
	id,
	idtype string,
) *redis.StringCmd {
	key := KeyToken(tid, id, idtype)
	return pipe.Get(ctx, key)
}

func (rl *RedisCache) checkToken(cmd *redis.StringCmd, raw string) (string, error) {
	err := cmd.Err()

	if err != nil {
		if isErrRedisNil(err) {
			return "", nil
		}
		return "", err
	}

	token := cmd.Val()
	if token == raw {
		return token, nil
	} else {
		// must be a stale token - we don't want to use it
		// let it expire in the background
		return "", nil
	}
}

func (rl *RedisCache) pipeQuota(
	ctx context.Context,
	pipe redis.Pipeliner,
	l ratelimits.ApiLimits,
	tid,
	id,
	idtype string,
	now int64,
) (*redis.IntCmd, *redis.BoolCmd) {
	var incr *redis.IntCmd
	var expire *redis.BoolCmd

	// not a default/empty quota
	if l.ApiQuota.MaxCalls != 0 {
		intvl := int64(now / int64(l.ApiQuota.IntervalSec))
		keyQuota := KeyQuota(tid, id, idtype, strconv.FormatInt(intvl, 10))
		incr = pipe.Incr(ctx, keyQuota)
		expire = pipe.Expire(ctx, keyQuota, time.Duration(l.ApiQuota.IntervalSec)*time.Second)
	}

	return incr, expire
}

func (rl *RedisCache) checkQuota(
	l ratelimits.ApiLimits,
	incr *redis.IntCmd,
	expire *redis.BoolCmd,
) error {
	if incr == nil && expire == nil {
		return nil
	}

	err := incr.Err()
	if err != nil && !isErrRedisNil(err) {
		return err
	}

	err = expire.Err()
	if err != nil {
		return err
	}

	quota := incr.Val()
	if quota > int64(l.ApiQuota.MaxCalls) {
		return ErrTooManyRequests
	}

	return nil
}

func (rl *RedisCache) pipeBurst(ctx context.Context,
	pipe redis.Pipeliner,
	l ratelimits.ApiLimits,
	tid, id, idtype, url, action string,
	now int64) (*redis.StringCmd, *redis.StatusCmd) {
	var get *redis.StringCmd
	var set *redis.StatusCmd

	for _, b := range l.ApiBursts {
		if b.Action == action &&
			b.Uri == url &&
			b.MinIntervalSec != 0 {

			intvl := int64(now / int64(b.MinIntervalSec))
			keyBurst := KeyBurst(tid, id, idtype, url, action, strconv.FormatInt(intvl, 10))

			get = pipe.Get(ctx, keyBurst)
			set = pipe.Set(ctx, keyBurst, now, time.Duration(b.MinIntervalSec)*time.Second)
		}
	}

	return get, set
}

func (rl *RedisCache) checkBurst(get *redis.StringCmd, set *redis.StatusCmd) error {
	if get != nil && set != nil {
		err := get.Err()

		// no error means burst was found/hit
		if err == nil {
			return ErrTooManyRequests
		}

		if isErrRedisNil(err) {
			return nil
		}

		return err
	}

	return nil
}

func (rl *RedisCache) CacheToken(
	ctx context.Context,
	tid,
	id,
	idtype,
	token string,
	expire time.Duration,
) error {
	res := rl.c.Set(ctx, KeyToken(tid, id, idtype),
		token,
		expire)
	return res.Err()
}

func (rl *RedisCache) DeleteToken(ctx context.Context, tid, id, idtype string) error {
	res := rl.c.Del(ctx, KeyToken(tid, id, idtype))
	return res.Err()
}

func (rl *RedisCache) GetLimits(
	ctx context.Context,
	tid,
	id,
	idtype string,
) (*ratelimits.ApiLimits, error) {
	res := rl.c.Get(ctx, KeyLimits(tid, id, idtype))

	if res.Err() != nil {
		if isErrRedisNil(res.Err()) {
			return nil, nil
		}
		return nil, res.Err()
	}

	var limits ratelimits.ApiLimits

	err := json.Unmarshal([]byte(res.Val()), &limits)
	if err != nil {
		return nil, err
	}

	return &limits, nil
}

func (rl *RedisCache) CacheLimits(
	ctx context.Context,
	l ratelimits.ApiLimits,
	tid,
	id,
	idtype string,
) error {
	enc, err := json.Marshal(l)
	if err != nil {
		return err
	}

	res := rl.c.Set(
		ctx,
		KeyLimits(tid, id, idtype),
		enc,
		time.Duration(rl.LimitsExpireSec)*time.Second,
	)

	return res.Err()
}

func (rl *RedisCache) FlushDB(ctx context.Context) error {
	return rl.c.FlushDBAsync(ctx).Err()
}

func KeyQuota(tid, id, idtype, intvlNum string) string {
	return fmt.Sprintf("tenant:%s:%s:%s:quota:%s", tid, idtype, id, intvlNum)
}

func KeyBurst(tid, id, idtype, url, action, intvlNum string) string {
	return fmt.Sprintf("tenant:%s:%s:%s:burst:%s:%s:%s", tid, idtype, id, url, action, intvlNum)
}

func KeyToken(tid, id, idtype string) string {
	return fmt.Sprintf("tenant:%s:%s:%s:tok", tid, idtype, id)
}

func KeyLimits(tid, id, idtype string) string {
	return fmt.Sprintf("tenant:%s:%s:%s:limits", tid, idtype, id)
}

func KeyCheckInTime(tid, id, idtype string) string {
	return fmt.Sprintf("tenant:%s:%s:%s:checkInTime", tid, idtype, id)
}

// isErrRedisNil checks for a very common non-error, "redis: nil",
// which just means the key was not found, and is normal
// it's routinely returned e.g. from GET, or pipelines containing it
func isErrRedisNil(e error) bool {
	return e.Error() == "redis: nil"
}

// TODO: move to go-lib-micro/ratelimits
func LimitsEmpty(l *ratelimits.ApiLimits) bool {
	return l.ApiQuota.MaxCalls == 0 &&
		l.ApiQuota.IntervalSec == 0 &&
		len(l.ApiBursts) == 0
}

func (rl *RedisCache) CacheCheckInTime(
	ctx context.Context,
	t *time.Time,
	tid,
	id string,
) error {
	tj, err := json.Marshal(t)
	if err != nil {
		return err
	}

	res := rl.c.Set(
		ctx,
		KeyCheckInTime(tid, id, IdTypeDevice),
		tj,
		CheckInTimeExpiration,
	)

	return res.Err()
}

func (rl *RedisCache) GetCheckInTime(
	ctx context.Context,
	tid,
	id string,
) (*time.Time, error) {
	res := rl.c.Get(ctx, KeyCheckInTime(tid, id, IdTypeDevice))

	if res.Err() != nil {
		if isErrRedisNil(res.Err()) {
			return nil, nil
		}
		return nil, res.Err()
	}

	var checkInTime time.Time

	err := json.Unmarshal([]byte(res.Val()), &checkInTime)
	if err != nil {
		return nil, err
	}

	return &checkInTime, nil
}

func (rl *RedisCache) GetCheckInTimes(
	ctx context.Context,
	tid string,
	ids []string,
) ([]*time.Time, error) {
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = KeyCheckInTime(tid, id, IdTypeDevice)
	}

	res := rl.c.MGet(ctx, keys...)

	checkInTimes := make([]*time.Time, len(ids))

	for i, v := range res.Val() {
		if v != nil {
			b, ok := v.(string)
			if !ok {
				continue
			}
			var checkInTime time.Time
			err := json.Unmarshal([]byte(b), &checkInTime)
			if err != nil {
				l := log.FromContext(ctx)
				l.Errorf("failed to unmarshal check-in time: %s", err.Error())
				continue
			}
			checkInTimes[i] = &checkInTime
		}
	}

	return checkInTimes, nil
}
