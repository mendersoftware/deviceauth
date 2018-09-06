// Copyright 2018 Northern.tech AS
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
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"github.com/pkg/errors"
)

const (
	ErrMsgVerify = "verification failed"

	//PEM identifier of an RSA public key, needed for decoding
	//key content from a string
	PubKeyBlockType = "PUBLIC KEY"
)

func VerifyAuthReqSign(signature string, pubkey interface{}, content []byte) error {
	hash := sha256.New()
	_, err := bytes.NewReader(content).WriteTo(hash)
	if err != nil {
		return errors.Wrap(err, ErrMsgVerify)
	}

	decodedSig, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return errors.Wrap(err, ErrMsgVerify)
	}

	key, ok := pubkey.(*rsa.PublicKey)
	if !ok {
		return errors.Wrap(err, ErrMsgVerify)
	}

	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash.Sum(nil), decodedSig)
	if err != nil {
		return errors.Wrap(err, ErrMsgVerify)
	}

	return nil
}

//ParsePubKey
func ParsePubKey(pubkey string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pubkey))
	if block == nil || block.Type != PubKeyBlockType {
		return nil, errors.New("cannot decode public key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "cannot decode public key")
	}

	return key, nil
}

func SerializePubKey(key interface{}) (string, error) {

	switch key.(type) {
	case *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey:
		break
	default:
		return "", errors.New("unrecognizable public key type")
	}

	asn1, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}

	out := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1,
	})

	if out == nil {
		return "", err
	}

	return string(out), nil
}
