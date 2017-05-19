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
package jwt

import (
	"time"
)

type Claims struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	ID        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Scope     string `json:"scp,omitempty"`
}

// Valid checks if claims are valid. Returns error if validation fails.
// Note that for now we're only using iss, exp, sub, scp.
// Basic checks are done here, field correctness (e.g. issuer) - at the service level, where this info is available.
func (c *Claims) Valid() error {
	if c.Issuer == "" ||
		c.ExpiresAt == 0 ||
		c.Subject == "" ||
		c.Scope == "" {
		return ErrTokenInvalid
	}

	if !verifyExp(c.ExpiresAt) {
		return ErrTokenExpired
	}

	return nil
}

func verifyExp(exp int64) bool {
	now := time.Now().Unix()
	return now <= exp
}
