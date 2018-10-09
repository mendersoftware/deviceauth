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
package migrate_test

import (
	"testing"

	"github.com/globalsign/mgo/bson"
	"github.com/stretchr/testify/assert"

	. "github.com/mendersoftware/go-lib-micro/mongo/migrate"
	"github.com/mendersoftware/go-lib-micro/store"
)

func TestGetTenantDbs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestGetTenantDbs in short mode.")
	}

	baseDb := "servicename"
	testCases := map[string]struct {
		dbs []string
	}{
		"no tenant dbs": {
			dbs: []string{},
		},
		"1 tenant db": {
			dbs: []string{
				baseDb + "-tenant1",
			},
		},
		">1 tenant db": {
			dbs: []string{
				baseDb + "-tenant1",
				baseDb + "-tenant2",
				baseDb + "-tenant3",
			},
		},
	}
	for name := range testCases {
		tc := testCases[name]
		t.Run(name, func(t *testing.T) {
			db.Wipe()
			session := db.Session()

			// dummy insert on test dbs to create them
			for _, db := range tc.dbs {
				err := session.DB(db).C("foo").Insert(bson.M{"foo": "bar"})
				assert.NoError(t, err)
			}

			res, err := GetTenantDbs(session, store.IsTenantDb(baseDb))
			assert.NoError(t, err)
			assert.Equal(t, tc.dbs, res)

			session.Close()
		})
	}
}
