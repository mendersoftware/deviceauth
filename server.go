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
	"net/http"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"
)

func SetupAPI(stacktype string) (*rest.Api, error) {
	api := rest.NewApi()
	if err := SetupMiddleware(api, stacktype); err != nil {
		return nil, errors.Wrap(err, "failed to setup middleware")
	}

	//this will override the framework's error resp to the desired one:
	// {"error": "msg"}
	// instead of:
	// {"Error": "msg"}
	rest.ErrorFieldName = "error"

	return api, nil
}

// DevAuthAppFor returns a factory function that creates DevAuthApp and sets it
// up using `c` as configuration source and `key` as private key.
func DevAuthAppFor(c config.Reader, key *rsa.PrivateKey) DevAuthFactory {
	return func(l *log.Logger) (DevAuthApp, error) {
		db, err := GetDataStoreMongo(c.GetString(SettingDb), l)
		if err != nil {
			return nil, errors.Wrap(err, "database connection failed")
		}

		jwtHandler := NewJWTAgent(JWTAgentConfig{
			PrivateKey:        key,
			ExpirationTimeout: int64(c.GetInt(SettingJWTExpirationTimeout)),
			Issuer:            c.GetString(SettingJWTIssuer),
		})

		devAdmClientConf := DevAdmClientConfig{
			DevAdmAddr: c.GetString(SettingDevAdmAddr),
		}
		invClientConf := InventoryClientConfig{
			InventoryAddr: c.GetString(SettingInventoryAddr),
		}

		devauth := NewDevAuth(db,
			NewDevAdmClient(devAdmClientConf),
			NewInventoryClient(invClientConf),
			jwtHandler)
		devauth.UseLog(l)

		return devauth, nil
	}
}

func RunServer(c config.Reader) error {

	l := log.New(log.Ctx{})

	privKey, err := loadRSAPrivKey(c.GetString(SettingServerPrivKeyPath))
	if err != nil {
		return errors.Wrap(err, "failed to read rsa private key")
	}

	api, err := SetupAPI(c.GetString(SettingMiddleware))
	if err != nil {
		return errors.Wrap(err, "API setup failed")
	}

	devauthapi := NewDevAuthApiHandler(DevAuthAppFor(c, privKey))

	apph, err := devauthapi.GetApp()
	if err != nil {
		return errors.Wrap(err, "device admission API handlers setup failed")
	}
	api.SetApp(apph)

	addr := c.GetString(SettingListen)
	l.Printf("listening on %s", addr)

	return http.ListenAndServe(addr, api.MakeHandler())
}
