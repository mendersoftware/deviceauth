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
	"context"
	"fmt"
	"os"

	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/urfave/cli"

	"github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/deviceauth/store/mongo"
)

func main() {
	var configPath string
	var debug bool

	app := cli.NewApp()
	app.Usage = "Device Authentication Service"
	app.Version = CreateVersionString()

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "config",
			Usage:       "Configuration `FILE`. Supports JSON, TOML, YAML and HCL formatted configs.",
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

	app.Action = cmdServer
	app.Before = func(args *cli.Context) error {
		log.Setup(debug)

		err := config.FromConfigFile(configPath, configDefaults)
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

	app.Run(os.Args)
}

func cmdServer(args *cli.Context) error {
	devSetup := args.GlobalBool("dev")

	l := log.New(log.Ctx{})

	if devSetup {
		l.Infof("setting up development configuration")
		config.Config.Set(SettingMiddleware, EnvDev)
	}

	db, err := mongo.NewDataStoreMongo(config.Config.GetString(SettingDb))
	if err != nil {
		return cli.NewExitError(
			fmt.Sprintf("failed to connect to db: %v", err),
			3)
	}

	ctx := context.Background()
	err = db.Migrate(ctx, mongo.DbVersion)
	if err != nil {
		return cli.NewExitError(
			fmt.Sprintf("failed to run migrations: %v", err),
			3)
	}

	l.Printf("Device Authentication Service, version %s starting up",
		CreateVersionString())

	err = RunServer(config.Config)
	if err != nil {
		return cli.NewExitError(err.Error(), 4)
	}

	return nil
}
