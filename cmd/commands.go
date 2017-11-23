// Copyright 2017 Northern.tech AS
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
package cmd

import (
	"context"
	"fmt"

	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/identity"
	mstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"

	dconfig "github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/deviceauth/store/mongo"
)

func makeDataStoreConfig() mongo.DataStoreMongoConfig {
	return mongo.DataStoreMongoConfig{
		ConnectionString: config.Config.GetString(dconfig.SettingDb),

		SSL:           config.Config.GetBool(dconfig.SettingDbSSL),
		SSLSkipVerify: config.Config.GetBool(dconfig.SettingDbSSLSkipVerify),

		Username: config.Config.GetString(dconfig.SettingDbUsername),
		Password: config.Config.GetString(dconfig.SettingDbPassword),
	}

}

func Migrate(c config.Reader, tenant string, listTenantsFlag bool) error {
	db, err := mongo.NewDataStoreMongo(makeDataStoreConfig())

	if err != nil {
		return errors.Wrap(err, "failed to connect to db")
	}

	// list tenants only
	if listTenantsFlag {
		return listTenants(db)
	}

	db = db.WithAutomigrate().(*mongo.DataStoreMongo)

	tenantCtx := identity.WithContext(context.Background(), &identity.Identity{
		Tenant: tenant,
	})

	dbname := mstore.DbFromContext(tenantCtx, mongo.DbName)
	if err != nil {
		return errors.Wrap(err, "failed to decode dbname")
	}

	err = db.MigrateTenant(tenantCtx, dbname, mongo.DbVersion)
	if err != nil {
		return errors.Wrap(err, "failed to run migrations")
	}

	return nil
}

func listTenants(db *mongo.DataStoreMongo) error {
	tdbs, err := db.GetTenantDbs()
	if err != nil {
		return errors.Wrap(err, "failed go retrieve tenant DBs")
	}

	for _, tenant := range tdbs {
		fmt.Println(mstore.TenantFromDbName(tenant, mongo.DbName))
	}

	return nil
}
