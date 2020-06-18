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
package main

import (
	"net/http"
	"time"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"

	api_http "github.com/mendersoftware/deviceauth/api/http"
	"github.com/mendersoftware/deviceauth/client/orchestrator"
	"github.com/mendersoftware/deviceauth/client/tenant"
	dconfig "github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/deviceauth/devauth"
	"github.com/mendersoftware/deviceauth/jwt"
	"github.com/mendersoftware/deviceauth/keys"
	"github.com/mendersoftware/deviceauth/store/mongo"
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

func RunServer(c config.Reader) error {

	l := log.New(log.Ctx{})

	privKey, err := keys.LoadRSAPrivate(c.GetString(dconfig.SettingServerPrivKeyPath))
	if err != nil {
		return errors.Wrap(err, "failed to read rsa private key")
	}

	db, err := mongo.NewDataStoreMongo(
		mongo.DataStoreMongoConfig{
			ConnectionString: c.GetString(dconfig.SettingDb),

			SSL:           c.GetBool(dconfig.SettingDbSSL),
			SSLSkipVerify: c.GetBool(dconfig.SettingDbSSLSkipVerify),

			Username: c.GetString(dconfig.SettingDbUsername),
			Password: c.GetString(dconfig.SettingDbPassword),
		})
	if err != nil {
		return errors.Wrap(err, "database connection failed")
	}

	jwtHandler := jwt.NewJWTHandlerRS256(privKey)

	orchClientConf := orchestrator.Config{
		OrchestratorAddr: c.GetString(dconfig.SettingOrchestratorAddr),
		Timeout:          time.Duration(30) * time.Second,
	}

	devauth := devauth.NewDevAuth(db,
		orchestrator.NewClient(orchClientConf),
		jwtHandler,
		devauth.Config{
			Issuer:             c.GetString(dconfig.SettingJWTIssuer),
			ExpirationTime:     int64(c.GetInt(dconfig.SettingJWTExpirationTimeout)),
			DefaultTenantToken: c.GetString(dconfig.SettingDefaultTenantToken),
			InventoryAddr:      config.Config.GetString(dconfig.SettingInventoryAddr),
		})

	if tadmAddr := c.GetString(dconfig.SettingTenantAdmAddr); tadmAddr != "" {
		l.Infof("settting up tenant verification")

		tc := tenant.NewClient(tenant.Config{
			TenantAdmAddr: tadmAddr,
		})

		devauth = devauth.WithTenantVerification(tc)
	}

	api, err := SetupAPI(c.GetString(dconfig.SettingMiddleware))
	if err != nil {
		return errors.Wrap(err, "API setup failed")
	}

	devauthapi := api_http.NewDevAuthApiHandlers(devauth, db)

	apph, err := devauthapi.GetApp()
	if err != nil {
		return errors.Wrap(err, "device authentication API handlers setup failed")
	}
	api.SetApp(apph)

	addr := c.GetString(dconfig.SettingListen)
	l.Printf("listening on %s", addr)

	return http.ListenAndServe(addr, api.MakeHandler())
}
