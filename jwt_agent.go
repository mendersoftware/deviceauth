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
	"crypto/x509"
	"encoding/pem"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"io/ioutil"
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
	// path to server private key
	ServerPrivKeyPath string
	// token issuer
	Issuer string
}

type JWTAgent struct {
	key    *rsa.PrivateKey
	issuer string
}

type JWTAgentApp interface {
	GenerateTokenSignRS256(devId string, expiration int64) (*Token, error)
	ValidateTokenSignRS256(token string) (bool, error)
}

// Generates JWT token signed using RS256
func (j *JWTAgent) GenerateTokenSignRS256(
	devId string, expiration int64) (*Token, error) {
	// Create the token
	token := jwt.New(jwt.SigningMethodRS256)
	// Set claims
	token.Claims[issuerClaim] = j.issuer
	token.Claims[subjectClaim] = devId
	token.Claims[expirationClaim] = expiration
	jti := generateTokenId()
	token.Claims[jwtIdClaim] = jti
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(j.key)
	if err != nil {
		return nil, errors.Wrap(err, ErrMsgCreateTokenFailed)
	}
	return NewToken(jti, devId, tokenString), nil
}

// TODO: stub only
func (j *JWTAgent) ValidateTokenSignRS256(tokenString string) (bool, error) {
	return true, nil
}

func getRSAPrivKey(privKeyPath string) (*rsa.PrivateKey, error) {
	// read key from file
	pemData, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, ErrMsgPrivKeyReadFailed)
	}
	// decode pem key
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New(ErrMsgPrivKeyNotPEMEncoded)
	}
	// check if it is a RSA PRIVATE KEY
	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		return nil, errors.New(
			"unknown server private key type " + got + " want " + want)
	}
	// return parsed key
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Generates token Id - actually token Id is a UUID v4
func generateTokenId() string {
	return uuid.NewV4().String()
}

func NewJWTAgent(c JWTAgentConfig) (*JWTAgent, error) {
	// get RSA private key structure from pem key file
	priv, err := getRSAPrivKey(c.ServerPrivKeyPath)
	if err != nil {
		return nil, err
	}
	return &JWTAgent{
		key:    priv,
		issuer: c.Issuer,
	}, nil
}
