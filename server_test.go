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
	"testing"

	"github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/stretchr/testify/assert"
)

func TestSetupApi(t *testing.T) {
	// expecting an error
	api, err := SetupAPI("foo")
	assert.Nil(t, api)
	assert.Error(t, err)

	api, err = SetupAPI(EnvDev)
	assert.NotNil(t, api)
	assert.Nil(t, err)
}

func TestDevAuthAppFor(t *testing.T) {
	//this will ping the db, so it;s a 'long' test
	if testing.Short() {
		t.Skip("skipping TestGetDevAuth in short mode.")
	}

	// GetDevAuth will initialize data store that tries to connect to a DB
	// specified in configuration. Since we are using dbtest, an on demand DB will
	// be started. However we still need to figure out the address the test
	// instance is listening on, so that we can set it in DevAuth configuration.
	// configuration.
	session := db.Session()
	defer session.Close()
	dbs := session.LiveServers()
	assert.Len(t, dbs, 1)

	dbaddr := dbs[0]
	t.Logf("test db address: %s", dbaddr)

	config.SetDefaults(config.Config, configDefaults)
	config.Config.Set(SettingDb, dbaddr)
	config.Config.Set(SettingServerPrivKeyPath, "testdata/private.pem")
	factory := DevAuthAppFor(config.Config, nil)

	d, err := factory(log.New(log.Ctx{}))
	assert.NoError(t, err)
	assert.NotNil(t, d)

	// cleanup DB session
	da, _ := d.(*DevAuth)
	mdb, _ := da.db.(*DataStoreMongo)
	mdb.session.Close()
}
