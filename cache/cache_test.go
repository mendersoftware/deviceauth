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

	"github.com/alicebob/miniredis"
	"github.com/mendersoftware/go-lib-micro/ratelimits"
	"github.com/stretchr/testify/assert"

	"github.com/mendersoftware/deviceauth/utils"
)

func init() {
	testing.Init()
}

func TestRedisCacheThrottleToken(t *testing.T) {
	r := miniredis.NewMiniRedis()
	err := r.Start()
	assert.NoError(t, err)
	defer r.Close()

	ctx := context.TODO()
	rcache, err := NewRedisCache(r.Addr(), "", "", 0, 5, 1800)
	assert.NoError(t, err)

	// token not found
	tok, err := rcache.Throttle(ctx,
		"tokenstring",
		ratelimits.ApiLimits{},
		"tenant-foo",
		"device-bar",
		IdTypeDevice,
		"/some/url",
		"GET")

	assert.NoError(t, err)
	assert.Equal(t, "", tok)

	//insert token
	r.Set(KeyToken("tenant-foo", "device-bar", IdTypeDevice), "tokenstring")
	r.SetTTL(KeyToken("tenant-foo", "device-bar", IdTypeDevice), time.Duration(10*time.Second))

	tok, err = rcache.Throttle(ctx,
		"tokenstring",
		ratelimits.ApiLimits{},
		"tenant-foo",
		"device-bar",
		IdTypeDevice,
		"/some/url",
		"GET")

	assert.NoError(t, err)
	assert.Equal(t, "tokenstring", tok)

	// wait, but before token expiration - token still found
	r.FastForward(time.Duration(5 * time.Second))
	tok, err = rcache.Throttle(ctx,
		"tokenstring",
		ratelimits.ApiLimits{},
		"tenant-foo",
		"device-bar",
		IdTypeDevice,
		"/some/url",
		"GET")

	assert.NoError(t, err)
	assert.Equal(t, "tokenstring", tok)

	// token not found past expiration
	r.FastForward(time.Duration(6 * time.Second))
	tok, err = rcache.Throttle(ctx,
		"tokenstring",
		ratelimits.ApiLimits{},
		"tenant-foo",
		"device-bar",
		IdTypeDevice,
		"/some/url",
		"GET")

	assert.NoError(t, err)
	assert.Equal(t, "", tok)

	// for some reason, the cache finds a valid token with different contents
	// and defensively rejects it
	r.Set(KeyToken("tenant-foo", "device-bar", IdTypeDevice), "unknown")
	tok, err = rcache.Throttle(ctx,
		"tokenstring",
		ratelimits.ApiLimits{},
		"tenant-foo",
		"device-bar",
		IdTypeDevice,
		"/some/url",
		"GET")

	assert.NoError(t, err)
	assert.Equal(t, "", tok)

	// again insert token with Cache method
	rcache.CacheToken(ctx,
		"tenant-foo",
		"device-bar",
		IdTypeDevice,
		"tokenstr",
		time.Duration(10*time.Second))

	tok, err = rcache.Throttle(ctx,
		"tokenstr",
		ratelimits.ApiLimits{},
		"tenant-foo",
		"device-bar",
		IdTypeDevice,
		"/some/url",
		"GET")

	assert.NoError(t, err)
	assert.Equal(t, "tokenstr", tok)

	r.SetTTL(KeyToken("tenant-foo", "device-bar", IdTypeDevice), time.Duration(10*time.Second))
	r.FastForward(time.Duration(11 * time.Second))

	tok, err = rcache.Throttle(ctx,
		"tokenstr",
		ratelimits.ApiLimits{},
		"tenant-foo",
		"device-bar",
		IdTypeDevice,
		"/some/url",
		"GET")

	assert.NoError(t, err)
	assert.Equal(t, "", tok)
}

func TestRedisCacheTokenDelete(t *testing.T) {
	ctx := context.TODO()

	r := miniredis.NewMiniRedis()
	err := r.Start()
	assert.NoError(t, err)
	defer r.Close()

	rcache, err := NewRedisCache(r.Addr(), "", "", 0, 5, 1800)

	// cache 2 tokens, remove first one, other one should still be available
	rcache.CacheToken(ctx,
		"tenant-foo",
		"device-1",
		IdTypeDevice,
		"tokenstr-1",
		time.Duration(10*time.Second))

	rcache.CacheToken(ctx,
		"tenant-foo",
		"device-2",
		IdTypeDevice,
		"tokenstr-2",
		time.Duration(10*time.Second))

	err = rcache.DeleteToken(ctx, "tenant-foo", "device-1", IdTypeDevice)
	assert.NoError(t, err)

	tok1, err := rcache.Throttle(ctx,
		"tokenstr-1",
		ratelimits.ApiLimits{},
		"tenant-foo",
		"device-1",
		IdTypeDevice,
		"/some/url",
		"GET")
	assert.NoError(t, err)
	assert.Equal(t, "", tok1)

	tok2, err := rcache.Throttle(ctx,
		"tokenstr-2",
		ratelimits.ApiLimits{},
		"tenant-foo",
		"device-2",
		IdTypeDevice,
		"/some/url",
		"GET")

	assert.NoError(t, err)
	assert.Equal(t, "tokenstr-2", tok2)

	// second delete (no token) doesn't trigger an error
	err = rcache.DeleteToken(ctx, "tenant-foo", "device-1", IdTypeDevice)
	assert.NoError(t, err)
}

func TestRedisCacheFlushDB(t *testing.T) {
	ctx := context.TODO()

	r := miniredis.NewMiniRedis()
	err := r.Start()
	assert.NoError(t, err)
	defer r.Close()

	rcache, err := NewRedisCache(r.Addr(), "", "", 0, 5, 1800)

	// cache 2 tokens and immediately flush
	rcache.CacheToken(ctx,
		"tenant-foo",
		"device-1",
		IdTypeDevice,
		"tokenstr-1",
		time.Duration(10*time.Second))

	rcache.CacheToken(ctx,
		"tenant-foo",
		"device-2",
		IdTypeDevice,
		"tokenstr-2",
		time.Duration(10*time.Second))

	err = rcache.FlushDB(ctx)
	assert.NoError(t, err)

	// no hits after flush
	tok1, err := rcache.Throttle(ctx,
		"tokenstr-1",
		ratelimits.ApiLimits{},
		"tenant-foo",
		"device-1",
		IdTypeDevice,
		"/some/url",
		"GET")
	assert.NoError(t, err)
	assert.Equal(t, "", tok1)

	tok2, err := rcache.Throttle(ctx,
		"tokenstr-2",
		ratelimits.ApiLimits{},
		"tenant-foo",
		"device-2",
		IdTypeDevice,
		"/some/url",
		"GET")

	assert.NoError(t, err)
	assert.Equal(t, "", tok2)

	// second delete (no token) doesn't trigger an error
	err = rcache.DeleteToken(ctx, "tenant-foo", "device-1", IdTypeDevice)
	assert.NoError(t, err)
}

func TestRedisCacheLimitsQuota(t *testing.T) {
	r := miniredis.NewMiniRedis()
	err := r.Start()
	assert.NoError(t, err)
	defer r.Close()

	rcache, err := NewRedisCache(r.Addr(), "", "", 0, 5, 1800)
	assert.NoError(t, err)

	// apply quota
	l := ratelimits.ApiLimits{
		ApiQuota: ratelimits.ApiQuota{
			MaxCalls:    10,
			IntervalSec: 60,
		},
	}

	// exhaust quota
	// requests past quota fail
	for i := 0; i < 10; i++ {
		tok, err := testThrottle(rcache, l)
		assert.NoError(t, err)
		assert.Equal(t, "", tok)
	}

	for i := 0; i < 10; i++ {
		tok, err := testThrottle(rcache, l)
		assert.EqualError(t, err, ErrTooManyRequests.Error())
		assert.Equal(t, "", tok)
	}

	// stand off, expire quota
	// requests pass again
	r.FastForward(time.Duration(61 * time.Second))

	for i := 0; i < 10; i++ {
		tok, err := testThrottle(rcache, l)
		assert.NoError(t, err)
		assert.Equal(t, "", tok)
	}
}

func TestRedisCacheLimitsBurst(t *testing.T) {
	r := miniredis.NewMiniRedis()
	err := r.Start()
	assert.NoError(t, err)
	defer r.Close()

	rcache, err := NewRedisCache(r.Addr(), "", "", 0, 5, 1800)
	assert.NoError(t, err)

	clock := utils.NewMockClock(1590105600)
	rcache = rcache.WithClock(clock)

	// apply burst
	l := ratelimits.ApiLimits{
		ApiBursts: []ratelimits.ApiBurst{
			{
				Action:         "GET",
				Uri:            "/some/url",
				MinIntervalSec: 10,
			},
		},
	}

	// client too quick - succeeds only every 10 secs
	for i := 0; i < 30; i++ {
		tok, err := testThrottle(rcache, l)
		if i%10 == 0 {
			assert.NoError(t, err)
		} else {
			assert.EqualError(t, err, ErrTooManyRequests.Error())
			assert.Equal(t, "", tok)
		}
		fastForward(r, clock, 1)
	}

	// well behaved client - succeeds every time
	for i := 0; i < 10; i++ {
		fastForward(r, clock, 11)
		tok, err := testThrottle(rcache, l)
		assert.NoError(t, err)
		assert.Equal(t, "", tok)
	}
}

func TestRedisCacheLimitsQuotaBurst(t *testing.T) {
	r := miniredis.NewMiniRedis()
	err := r.Start()
	assert.NoError(t, err)
	defer r.Close()

	rcache, err := NewRedisCache(r.Addr(), "", "", 0, 5, 1800)
	assert.NoError(t, err)

	// apply burst + quota
	l := ratelimits.ApiLimits{
		ApiQuota: ratelimits.ApiQuota{
			MaxCalls:    10,
			IntervalSec: 60,
		},
		ApiBursts: []ratelimits.ApiBurst{
			{
				Action:         "GET",
				Uri:            "/some/url",
				MinIntervalSec: 5,
			},
		},
	}

	// client respects burst, but not quota
	for i := 0; i < 15; i++ {
		tok, err := testThrottle(rcache, l)
		if i < 10 {
			assert.NoError(t, err)
			assert.Equal(t, "", tok)
		} else {
			assert.EqualError(t, err, ErrTooManyRequests.Error())
			assert.Equal(t, "", tok)
		}
		r.FastForward(time.Duration(6 * time.Second))
	}

	// fully reset limits
	r.FastForward(time.Duration(61 * time.Second))

	// client is well within quota, but abuses burst
	for i := 0; i < 15; i++ {
		tok, err := testThrottle(rcache, l)
		if i > 0 {
			assert.EqualError(t, err, ErrTooManyRequests.Error())
			assert.Equal(t, "", tok)
		}
		r.FastForward(time.Duration(4 * time.Second))
	}

	// fully reset limits
	r.FastForward(time.Duration(61 * time.Second))

	// quota applies on any url, but burst doesn't
	for i := 0; i < 15; i++ {
		tok, err := rcache.Throttle(context.TODO(),
			"tokenstring",
			l,
			"tenant-foo",
			"device-bar",
			IdTypeDevice,
			"/other/url",
			"GET")
		if i < 10 {
			assert.NoError(t, err)
			assert.Equal(t, "", tok)
		} else {
			assert.EqualError(t, err, ErrTooManyRequests.Error())
			assert.Equal(t, "", tok)
		}
		r.FastForward(time.Duration(1 * time.Second))
	}
}

func TestRedisCacheGetSetLimits(t *testing.T) {
	r := miniredis.NewMiniRedis()
	err := r.Start()
	assert.NoError(t, err)
	defer r.Close()

	ctx := context.TODO()

	limitsExpSec := 1800

	rcache, err := NewRedisCache(r.Addr(), "", "", 0, 5, limitsExpSec)
	assert.NoError(t, err)

	res, err := rcache.GetLimits(ctx, "tenant-foo", "device-bar", IdTypeDevice)

	assert.Nil(t, res)
	assert.NoError(t, err)

	l := ratelimits.ApiLimits{
		ApiQuota: ratelimits.ApiQuota{
			MaxCalls:    10,
			IntervalSec: 60,
		},
		ApiBursts: []ratelimits.ApiBurst{
			{
				Action:         "GET",
				Uri:            "/some/url",
				MinIntervalSec: 5,
			},
		},
	}
	err = rcache.CacheLimits(ctx, l, "tenant-foo", "device-bar", IdTypeDevice)
	assert.NoError(t, err)

	res, err = rcache.GetLimits(ctx, "tenant-foo", "device-bar", IdTypeDevice)
	assert.NoError(t, err)
	assert.Equal(t, l, *res)

	r.FastForward(time.Duration(limitsExpSec+1) * time.Second)

	res, err = rcache.GetLimits(ctx, "tenant-foo", "device-bar", IdTypeDevice)
	assert.NoError(t, err)
	assert.Nil(t, res)

}

func testThrottle(c Cache, limits ratelimits.ApiLimits) (string, error) {
	return c.Throttle(context.TODO(),
		"tokenstring",
		limits,
		"tenant-foo",
		"device-bar",
		IdTypeDevice,
		"/some/url",
		"GET")
}

// fastForward moves time forward consistently in a given miniredis instance,
// and a given mock clock
func fastForward(r *miniredis.Miniredis, c utils.Clock, secs int64) {
	r.FastForward(time.Duration(secs) * time.Second)
	c.Forward(secs)
}
