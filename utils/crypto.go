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
package utils

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/pkg/errors"
)

const (
	ErrVerify = "verification failed"
)

func VerifyAuthReqSign(signature, pubkey string, content []byte) error {
	hash := sha256.New()
	_, err := bytes.NewReader(content).WriteTo(hash)
	if err != nil {
		return errors.Wrap(err, ErrVerify)
	}

	decodedSig, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return errors.Wrap(err, ErrVerify)
	}

	block, _ := pem.Decode([]byte(pubkey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New(ErrVerify)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.Wrap(err, ErrVerify)
	}

	keyStruct, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.Wrap(err, ErrVerify)
	}

	err = rsa.VerifyPKCS1v15(keyStruct, crypto.SHA256, hash.Sum(nil), decodedSig)
	if err != nil {
		return errors.Wrap(err, ErrVerify)
	}

	return nil
}
