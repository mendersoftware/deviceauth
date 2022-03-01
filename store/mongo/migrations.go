// Copyright 2022 Northern.tech AS
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

package mongo

import (
	"context"

	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	ctxstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
)

func (db *DataStoreMongo) Migrate(ctx context.Context, version string) error {
	l := log.FromContext(ctx)

	dbs := []string{DbName}

	if db.multitenant {
		l.Infof("running migrations in multitenant mode")

		tdbs, err := migrate.GetTenantDbs(ctx, db.client, ctxstore.IsTenantDb(DbName))
		if err != nil {
			return errors.Wrap(err, "failed go retrieve tenant DBs")
		}
		dbs = append(dbs, tdbs...)
	} else {
		l.Infof("running migrations in single tenant mode")
	}

	if db.automigrate {
		l.Infof("automigrate is ON, will apply migrations")
	} else {
		l.Infof("automigrate is OFF, will check db version compatibility")
	}

	for _, d := range dbs {
		// if not in multi tenant, then tenant will be "" and identity
		// will be the same as default
		tenant := ctxstore.TenantFromDbName(d, DbName)

		tenantCtx := identity.WithContext(ctx, &identity.Identity{
			Tenant: tenant,
		})

		// TODO: we should aim to unify context usage across migrators and migrations
		// migrators use 'string' db name, migrations use DbFromContext
		// both should use one or the other; for now - just redundantly pass both ctx and db name
		err := db.MigrateTenant(tenantCtx, d, version)
		if err != nil {
			return err
		}
	}

	return nil
}

func (db *DataStoreMongo) MigrateTenant(ctx context.Context, database, version string) error {
	l := log.FromContext(ctx)

	l.Infof("migrating %s", database)

	m := migrate.SimpleMigrator{
		Client:      db.client,
		Db:          database,
		Automigrate: db.automigrate,
	}

	migrations := []migrate.Migration{
		&migration_1_1_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_2_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_3_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_4_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_5_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_6_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_7_0{
			ms:  db,
			ctx: ctx,
		},
		&migration_1_8_0{
			ds:  db,
			ctx: ctx,
		},
		&migration_1_9_0{
			ds:  db,
			ctx: ctx,
		},
		&migration_1_10_0{
			ds:  db,
			ctx: ctx,
		},
		&migration_1_11_0{
			ds:  db,
			ctx: ctx,
		},
	}

	ver, err := migrate.NewVersion(version)
	if err != nil {
		return errors.Wrap(err, "failed to parse service version")
	}

	err = m.Apply(ctx, *ver, migrations)
	if err != nil {
		return errors.Wrap(err, "failed to apply migrations")
	}

	return nil
}
