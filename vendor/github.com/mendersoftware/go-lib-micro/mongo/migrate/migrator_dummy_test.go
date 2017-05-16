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
package migrate_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/mendersoftware/go-lib-micro/mongo/migrate"
)

func TestDummyMigratorApply(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestDummyMigratorApply in short mode.")
	}

	testCases := map[string]struct {
		InputMigration *MigrationEntry
		InputVersion   Version

		OutputVersion Version
	}{
		"ok - empty state": {
			InputMigration: nil,
			InputVersion:   Version{Major: 1, Minor: 0, Patch: 0},

			OutputVersion: Version{Major: 1, Minor: 0, Patch: 0},
		},

		"ok - already has version": {
			InputMigration: &MigrationEntry{
				Version:   Version{Major: 1, Minor: 0, Patch: 0},
				Timestamp: time.Now(),
			},
			InputVersion:  Version{Major: 1, Minor: 0, Patch: 0},
			OutputVersion: Version{Major: 1, Minor: 0, Patch: 0},
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		//setup
		db.Wipe()
		session := db.Session()
		if tc.InputMigration != nil {
			err := session.DB("test").C(DbMigrationsColl).Insert(tc.InputMigration)
			assert.NoError(t, err)
		}

		//test
		m := &DummyMigrator{Session: session, Db: "test"}
		m.Apply(context.Background(), tc.InputVersion, nil)

		//verify
		var out []MigrationEntry
		session.DB("test").C(DbMigrationsColl).Find(nil).All(&out)
		assert.Len(t, out, 1)
		assert.Equal(t, tc.OutputVersion, out[0].Version)
		session.Close()
	}
}
