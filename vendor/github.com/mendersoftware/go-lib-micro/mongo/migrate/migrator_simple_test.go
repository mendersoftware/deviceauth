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
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/mendersoftware/go-lib-micro/mongo/migrate"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate/mocks"
)

func TestSimpleMigratorApply(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestDummyMigratorApply in short mode.")
	}

	makeMigration := func(v Version, from Version, err error) Migration {
		m := &mocks.Migration{}
		m.On("Up", from).Return(err)
		m.On("Version").Return(v)
		return m
	}

	testCases := map[string]struct {
		InputMigrations []MigrationEntry
		InputVersion    Version

		Migrators []Migration

		OutputVersion Version
		OutputError   error
	}{
		"ok - empty state": {
			InputMigrations: nil,
			InputVersion:    MakeVersion(1, 0, 0),

			OutputVersion: MakeVersion(1, 0, 0),
		},

		"ok - already has version": {
			InputMigrations: []MigrationEntry{
				{
					Version:   MakeVersion(1, 0, 0),
					Timestamp: time.Now(),
				},
			},
			InputVersion:  MakeVersion(1, 0, 0),
			OutputVersion: MakeVersion(1, 0, 0),
		},
		"ok - add default target version": {
			InputMigrations: []MigrationEntry{
				{
					Version:   MakeVersion(1, 0, 0),
					Timestamp: time.Now(),
				},
			},
			InputVersion:  MakeVersion(1, 1, 0),
			OutputVersion: MakeVersion(1, 1, 0),
		},
		"ok - ran migrations": {
			InputMigrations: []MigrationEntry{
				{
					Version:   MakeVersion(1, 0, 0),
					Timestamp: time.Now(),
				},
				{
					Version:   MakeVersion(1, 0, 1),
					Timestamp: time.Now(),
				},
			},
			InputVersion:  MakeVersion(1, 1, 0),
			OutputVersion: MakeVersion(1, 1, 0),

			Migrators: []Migration{
				makeMigration(MakeVersion(1, 0, 1), MakeVersion(1, 0, 0), nil),
				makeMigration(MakeVersion(1, 1, 0), MakeVersion(1, 0, 1), nil),
			},
		},
		"ok - migration to lower": {
			InputMigrations: nil,
			InputVersion:    MakeVersion(0, 1, 0),
			OutputVersion:   MakeVersion(0, 1, 0),

			Migrators: []Migration{
				makeMigration(MakeVersion(1, 0, 1), MakeVersion(0, 0, 0), nil),
				makeMigration(MakeVersion(1, 1, 0), MakeVersion(1, 0, 1), nil),
			},
		},
		"err - failed migration": {
			InputMigrations: []MigrationEntry{
				{
					Version:   MakeVersion(1, 0, 0),
					Timestamp: time.Now(),
				},
			},
			InputVersion: MakeVersion(1, 1, 0),
			// migration 1.0.3 fails, thus the output should remain at 1.0.2
			OutputVersion: MakeVersion(1, 0, 2),

			Migrators: []Migration{
				makeMigration(MakeVersion(1, 0, 1), MakeVersion(1, 0, 0), nil),
				makeMigration(MakeVersion(1, 0, 3), MakeVersion(1, 0, 2), errors.New("failed")),
				makeMigration(MakeVersion(1, 0, 2), MakeVersion(1, 0, 1), nil),
			},

			OutputError: errors.New("failed to apply migration from 1.0.2 to 1.0.3: failed"),
		},
	}

	for name := range testCases {
		tc := testCases[name]
		t.Run(name, func(t *testing.T) {

			//setup
			db.Wipe()
			session := db.Session()
			for i := range tc.InputMigrations {
				err := session.DB("test").C(DbMigrationsColl).
					Insert(tc.InputMigrations[i])
				assert.NoError(t, err)
			}

			//test
			m := &SimpleMigrator{Session: session, Db: "test"}
			err := m.Apply(context.Background(), tc.InputVersion, tc.Migrators)
			if tc.OutputError != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tc.OutputError.Error())
			} else {
				assert.NoError(t, err)
			}

			//verify
			var out []MigrationEntry
			session.DB("test").C(DbMigrationsColl).Find(nil).All(&out)
			// sort applied migrations
			sort.Slice(out, func(i int, j int) bool {
				return VersionIsLess(out[i].Version, out[j].Version)
			})
			// applied migration should be last
			assert.Equal(t, tc.OutputVersion, out[len(out)-1].Version)
			session.Close()
		})
	}
}
