// Copyright 2021 Northern.tech AS
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
	"context"
	"fmt"
	"os"

	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"
	"github.com/urfave/cli"

	cinv "github.com/mendersoftware/deviceauth/client/inventory"
	"github.com/mendersoftware/deviceauth/client/orchestrator"
	"github.com/mendersoftware/deviceauth/client/tenant"
	"github.com/mendersoftware/deviceauth/cmd"
	dconfig "github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/deviceauth/store/mongo"
)

func main() {
	doMain(os.Args)
}

func doMain(args []string) {
	var configPath string
	var debug bool

	app := cli.NewApp()
	app.Usage = "Device Authentication Service"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name: "config",
			Usage: "Config `FILE`." +
				" Supports JSON, TOML, YAML and HCL formatted configs.",
			Destination: &configPath,
		},
		cli.BoolFlag{
			Name:  "dev",
			Usage: "Use development setup",
		},
		cli.BoolFlag{
			Name:        "debug",
			Usage:       "Enable debug logging",
			Destination: &debug,
		},
	}

	app.Commands = []cli.Command{
		{
			Name:  "server",
			Usage: "Run the service as a server",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "automigrate",
					Usage: "Run database migrations before starting.",
				},
			},

			Action: cmdServer,
		},
		{
			Name:  "migrate",
			Usage: "Run migrations and exit",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "tenant",
					Usage: "Tenant ID (optional).",
				},
				cli.BoolFlag{
					Name:  "list-tenants",
					Usage: "List Tenant IDs. Not performing migrations.",
				},
			},

			Action: cmdMigrate,
		},
		{
			Name:  "propagate-inventory-statuses",
			Usage: "Push device statuses to inventory",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "tenant_id",
					Usage: "Tenant ID (optional) - propagate for just a single tenant.",
				},
				cli.StringFlag{
					Name:  "force-set-migration",
					Usage: "Migration version to be stored in migration_info collection.",
				},
				cli.BoolFlag{
					Name: "dry-run",
					Usage: "Do not perform any inventory modifications," +
						" just scan and print devices.",
				},
			},

			Action: cmdPropagateStatusesInventory,
		},
		{
			Name:  "propagate-inventory-id-data",
			Usage: "Push device id_data to inventory",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "tenant_id",
					Usage: "Tenant ID (optional) - propagate for just a single tenant.",
				},
				cli.BoolFlag{
					Name: "dry-run",
					Usage: "Do not perform any inventory modifications," +
						" just scan and print devices.",
				},
			},

			Action: cmdPropagateIdDataInventory,
		},
		{
			Name:  "maintenance",
			Usage: "Run maintenance operations and exit",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "decommissioning-cleanup",
					Usage: "Cleanup devauth database from leftovers after failed decommissioning",
				},
				cli.StringFlag{
					Name:  "tenant",
					Usage: "Tenant ID (optional).",
				},
				cli.BoolFlag{
					Name: "dry-run",
					Usage: "Do not perform any modifications and serves" +
						" only as a way to inspect changes and detect if any are necessary",
				},
			},

			Action: cmdMaintenance,
		}, {
			Name:  "check-device-limits",
			Usage: "Warn users if user is approaching device limit",
			Description: "Loops through all tenant databases and " +
				"checks if the number of devices is over a " +
				"threshold of the allowed limit and sends an " +
				"email asking the user to upgrade or decomission" +
				"unused devices.",
			Flags: []cli.Flag{
				cli.Float64Flag{
					Name:  "threshold, t",
					Value: 90.0,
					Usage: "Threshold in percent (%) of " +
						"device limit that trigger " +
						"email event.",
				},
			},
			Action: cmdCheckDeviceLimits,
		},
	}

	app.Action = cmdServer
	app.Before = func(args *cli.Context) error {
		log.Setup(debug)

		err := config.FromConfigFile(configPath, dconfig.Defaults)
		if err != nil {
			return cli.NewExitError(
				fmt.Sprintf("error loading configuration: %s", err),
				1)
		}

		// Enable setting config values by environment variables
		config.Config.SetEnvPrefix("DEVICEAUTH")
		config.Config.AutomaticEnv()

		return nil
	}

	_ = app.Run(args)
}

func cmdServer(args *cli.Context) error {
	devSetup := args.GlobalBool("dev")

	l := log.New(log.Ctx{})

	if devSetup {
		l.Infof("setting up development configuration")
		config.Config.Set(dconfig.SettingMiddleware, EnvDev)
	}

	db, err := mongo.NewDataStoreMongo(makeDataStoreConfig())
	if err != nil {
		return cli.NewExitError(
			fmt.Sprintf("failed to connect to db: %v", err),
			2)
	}

	if args.Bool("automigrate") {
		db = db.WithAutomigrate().(*mongo.DataStoreMongo)
	}

	if config.Config.Get(dconfig.SettingTenantAdmAddr) != "" {
		db = db.WithMultitenant()
	}

	ctx := context.Background()
	err = db.Migrate(ctx, mongo.DbVersion)
	if err != nil {
		return cli.NewExitError(
			fmt.Sprintf("failed to run migrations: %v", err),
			3)
	}

	l.Print("Device Authentication Service starting up")

	err = RunServer(config.Config)
	if err != nil {
		return cli.NewExitError(err.Error(), 4)
	}

	return nil
}

func cmdMigrate(args *cli.Context) error {
	err := cmd.Migrate(config.Config, args.String("tenant"), args.Bool("list-tenants"))
	if err != nil {
		return cli.NewExitError(err, 5)
	}
	return nil
}

func cmdMaintenance(args *cli.Context) error {
	err := cmd.Maintenance(
		args.Bool("decommissioning-cleanup"),
		args.String("tenant"),
		args.Bool("dry-run"),
	)
	if err != nil {
		return cli.NewExitError(err, 6)
	}
	return nil
}

func cmdPropagateStatusesInventory(args *cli.Context) error {
	db, err := mongo.NewDataStoreMongo(makeDataStoreConfig())
	if err != nil {
		return err
	}

	inv := config.Config.GetString(dconfig.SettingInventoryAddr)
	c := cinv.NewClient(inv, false)

	err = cmd.PropagateStatusesInventory(db,
		c,
		args.String("tenant_id"),
		args.String("force-set-migration"),
		args.Bool("dry-run"))
	if err != nil {
		return cli.NewExitError(err, 7)
	}
	return nil
}

func cmdPropagateIdDataInventory(args *cli.Context) error {
	db, err := mongo.NewDataStoreMongo(makeDataStoreConfig())
	if err != nil {
		return err
	}

	inv := config.Config.GetString(dconfig.SettingInventoryAddr)
	c := cinv.NewClient(inv, false)

	err = cmd.PropagateIdDataInventory(db,
		c,
		args.String("tenant_id"),
		args.Bool("dry-run"))
	if err != nil {
		return cli.NewExitError(err, 7)
	}
	return nil
}

func makeDataStoreConfig() mongo.DataStoreMongoConfig {
	return mongo.DataStoreMongoConfig{
		ConnectionString: config.Config.GetString(dconfig.SettingDb),

		SSL:           config.Config.GetBool(dconfig.SettingDbSSL),
		SSLSkipVerify: config.Config.GetBool(dconfig.SettingDbSSLSkipVerify),

		Username: config.Config.GetString(dconfig.SettingDbUsername),
		Password: config.Config.GetString(dconfig.SettingDbPassword),
	}

}

func cmdCheckDeviceLimits(args *cli.Context) error {
	mgoConf := makeDataStoreConfig()
	ds, err := mongo.NewDataStoreMongo(mgoConf)
	if err != nil {
		return errors.Wrap(err, "cmd: failed to initialize DataStore client")
	}
	// Initialize tenantadm and workflows clients.
	tadm := tenant.NewClient(tenant.Config{
		TenantAdmAddr: config.Config.GetString(
			dconfig.SettingTenantAdmAddr,
		),
	})
	wflows := orchestrator.NewClient(orchestrator.Config{
		OrchestratorAddr: config.Config.GetString(
			dconfig.SettingOrchestratorAddr,
		),
	})
	return cmd.CheckDeviceLimits(
		args.Float64("threshold"),
		ds, tadm, wflows,
	)
}
