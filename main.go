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
	"flag"
	"github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/deviceauth/log"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

func main() {
	var configPath string
	var printVersion bool
	var devSetup bool
	var debug bool

	flag.StringVar(&configPath, "config",
		"config.yaml",
		"Configuration file path. Supports JSON, TOML, YAML and HCL formatted configs.")
	flag.BoolVar(&printVersion, "version",
		false, "Show version")
	flag.BoolVar(&devSetup, "dev",
		false, "Use development setup")
	flag.BoolVar(&debug, "debug",
		false, "Enable debug logging")

	flag.Parse()

	log.Setup(debug)

	l := log.New("main")

	_, err := HandleConfigFile(configPath)
	if err != nil {
		l.Fatalf("error loading configuration: %s", err)
	}

	l.Printf("Device Authentication Service, version %s starting up",
		CreateVersionString())

	for {
	}
}

func HandleConfigFile(filePath string) (config.Handler, error) {

	c := viper.New()
	c.SetConfigFile(filePath)

	// Set default values for config
	config.SetDefaults(c, configDefaults)

	// Find and read the config file
	if err := c.ReadInConfig(); err != nil {
		return nil, errors.Wrap(err, "failed to read configuration")
	}

	// Validate config
	if err := config.ValidateConfig(c, configValidators...); err != nil {
		return nil, errors.Wrap(err, "failed to validate configuration")
	}

	return c, nil
}
