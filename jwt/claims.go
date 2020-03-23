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
package jwt

import (
	"encoding/json"
	"time"

	"github.com/mendersoftware/go-lib-micro/mongo/uuid"
)

type Claims struct {
	ID        *uuid.UUID `json:"jti" bson:"_id"`
	Subject   *uuid.UUID `json:"sub" bson:"dev_id"`
	ExpiresAt *Time      `json:"exp" bson:"exp"`
	IssuedAt  *Time      `json:"iat" bson:"iat"`
	Issuer    string     `json:"iss" bson:"iss"`
	Audience  string     `json:"aud,omitempty" bson:"aud,omitempty"`
	NotBefore int64      `json:"nbf,omitempty" bson:"nbf,omitempty"`
	Scope     string     `json:"scp,omitempty" bson:"scp,omitempty"`
	Tenant    string     `json:"mender.tenant,omitempty" bson:"mender.tenant,omitempty"`
	Device    bool       `json:"mender.device,omitempty" bson:"mender.device"`
}

type Time struct {
	time.Time `bson:"time"`
}

func (e *Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.Unix())
}

func (e *Time) UnmarshalJSON(b []byte) error {
	var unixTime int64
	err := json.Unmarshal(b, &unixTime)
	if err != nil {
		return err
	}
	e.Time = time.Unix(unixTime, 0)
	return nil
}

// Valid checks if claims are valid. Returns error if validation fails.
// Note that for now we're only using iss, exp, sub, scp.
// Basic checks are done here, field correctness (e.g. issuer) - at the service
// level, where this info is available.
func (c *Claims) Valid() error {
	if c.Issuer == "" ||
		c.Subject == nil ||
		c.IssuedAt == nil ||
		c.ExpiresAt == nil ||
		c.ID == nil {
		return ErrTokenInvalid
	}

	now := time.Now()
	if now.After(c.ExpiresAt.Time) {
		return ErrTokenExpired
	}

	return nil
}
