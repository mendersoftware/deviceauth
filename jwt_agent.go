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
	"crypto/rsa"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

var (
	ErrTokenExpired = errors.New("jwt: token expired")
	ErrTokenInvalid = errors.New("jwt: token ivalid")
)

// Token field names
const (
	issuerClaim     = "iss"
	subjectClaim    = "sub"
	expirationClaim = "exp"
	jwtIdClaim      = "jti"
)

// Errors
const (
	ErrMsgPrivKeyReadFailed    = "failed to read server private key file"
	ErrMsgPrivKeyNotPEMEncoded = "server private key not PEM-encoded"
	ErrMsgCreateTokenFailed    = "failed to create token"
)

type JWTAgentConfig struct {
	// server private key
	PrivateKey *rsa.PrivateKey
	// expiration timeout in seconds
	ExpirationTimeout int64
	// token issuer
	Issuer string
}

type JWTAgent struct {
	privKey    *rsa.PrivateKey
	issuer     string
	expTimeout int64
	log        *log.Logger
}

type JWTAgentApp interface {
	GenerateTokenSignRS256(devId string) (*Token, error)
	ValidateTokenSignRS256(token string) (string, error)
	log.ContextLogger
}

// Generates JWT token signed using RS256
func (j *JWTAgent) GenerateTokenSignRS256(devId string) (*Token, error) {
	// Generate token ID
	jti := generateTokenId()
	// Set claims
	claims := jwt.StandardClaims{
		Issuer:    j.issuer,
		ExpiresAt: time.Now().Unix() + j.expTimeout,
		Subject:   devId,
		Id:        jti,
	}
	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(j.privKey)
	if err != nil {
		return nil, errors.Wrap(err, ErrMsgCreateTokenFailed)
	}
	return NewToken(jti, devId, tokenString), nil
}

// Validates token.
// Returns jti and nil if token is valid or "" and error otherwise
func (j *JWTAgent) ValidateTokenSignRS256(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("Unexpected signing method: " + token.Method.Alg())
		}
		// TODO:
		// do we need different keys for different tokens (groups, tenants)?
		// if yes, keys will be stored in database not in files
		// and API for placing keys in database will be needed
		return &j.privKey.PublicKey, nil
	})

	if err != nil {
		if vErr, ok := err.(*jwt.ValidationError); ok {
			if (vErr.Errors & jwt.ValidationErrorExpired) != 0 {
				return "", ErrTokenExpired
			}
		}
		return "", errors.Wrap(err, "token invalid")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if jtiStr, ok := claims[jwtIdClaim].(string); ok {
			return jtiStr, nil
		}
	}
	return "", errors.New("Token invalid")
}

func (j *JWTAgent) UseLog(l *log.Logger) {
	j.log = l.F(log.Ctx{})
}

// Generates token Id - actually token Id is a UUID v4
func generateTokenId() string {
	return uuid.NewV4().String()
}

func NewJWTAgent(c JWTAgentConfig) *JWTAgent {
	return &JWTAgent{
		privKey:    c.PrivateKey,
		issuer:     c.Issuer,
		expTimeout: c.ExpirationTimeout,
		log:        log.New(log.Ctx{}),
	}
}
