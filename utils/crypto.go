// Copyright 2019 Northern.tech AS
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

	"golang.org/x/crypto/ed25519"

	"github.com/pkg/errors"
)

const (
	ErrMsgVerify = "verification failed"

	//PEM identifier of an RSA public key, needed for decoding
	//key content from a string
	PubKeyBlockType = "PUBLIC KEY"
)

func VerifyAuthReqSign(signature string, pubkey interface{}, content []byte) error {
	decodedSig, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return errors.Wrap(err, ErrMsgVerify)
	}

	switch key := pubkey.(type) {
	case *rsa.PublicKey:
		hash := sha256.New()
		_, err := bytes.NewReader(content).WriteTo(hash)
		if err != nil {
			return errors.Wrap(err, ErrMsgVerify)
		}

		err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash.Sum(nil), decodedSig)
		if err != nil {
			return errors.Wrap(err, ErrMsgVerify)
		}

	case *ed25519.PublicKey:
		ok := ed25519.Verify(*key, content, decodedSig)
		if !ok {
			return errors.New("ed25519 signature verification failed")
		}

	default:
		return errors.Errorf("unsupported public key")
	}

	return nil
}

//ParsePubKey
func ParsePubKey(pubkey string, keytype string) (interface{}, error) {
	switch keytype {
	case "ed25519":
		key, err := base64.StdEncoding.DecodeString(pubkey)
		if err != nil {
			return nil, errors.Wrap(err, "cannot decode public ed25519 key")
		}

		keyStruct := ed25519.PublicKey(key)

		return &keyStruct, nil

	default:
		block, _ := pem.Decode([]byte(pubkey))
		if block == nil || block.Type != PubKeyBlockType {
			return nil, errors.New("cannot decode public key")
		}

		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "cannot parse public x509 key")
		}

		keyStruct, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("unsupported rsa key type")
		}

		return keyStruct, nil
	}
}

func SerializePubKey(key interface{}) (string, error) {

	switch pubkey := key.(type) {
	case *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey:
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

	case *ed25519.PublicKey:
		b64 := make([]byte, base64.StdEncoding.EncodedLen(len(*pubkey)))
		base64.StdEncoding.Encode(b64, *pubkey)

		return string(b64), nil

	default:
		return "", errors.New("unrecognizable public key type")
	}
}
