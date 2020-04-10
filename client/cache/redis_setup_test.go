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

package cache

import (
	"flag"
	"os"
	"strings"
	"testing"

	dconfig "github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/go-lib-micro/config"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if !testing.Short() {
		setupRedis()
	}
	result := m.Run()
	os.Exit(result)
}

func setupRedis() {
	config.SetDefaults(config.Config, dconfig.Defaults)

	config.Config.SetEnvPrefix("DEVICEAUTH")
	config.Config.AutomaticEnv()
	config.Config.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
}
