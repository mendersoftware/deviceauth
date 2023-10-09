// Copyright 2023 Northern.tech AS
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	    http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.
package jwt

import (
	"github.com/pkg/errors"
)

var (
	ErrTokenExpired = errors.New("jwt: token expired")
	ErrTokenInvalid = errors.New("jwt: token invalid")
)

// Handler jwt generator/verifier
//
//go:generate ../utils/mockgen.sh
type Handler interface {
	ToJWT(t *Token) (string, error)
	// FromJWT parses the token
	// returns:
	// ErrTokenInvalid when the token is invalid (malformed, missing required claims, etc.)
	FromJWT(string) (*Token, error)
	// Validate does basic validity checks (Claims.Valid()).
	// returns:
	// ErrTokenExpired when the token is valid but expired
	// ErrTokenInvalid when the token is invalid (malformed, missing required claims, etc.)
	Validate(string) error
}
