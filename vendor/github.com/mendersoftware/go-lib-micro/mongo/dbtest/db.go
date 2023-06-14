// Copyright 2023 Northern.tech AS
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

// Copyright 2010-2013 Gustavo Niemeyer <gustavo@niemeyer.net>

// mgo - MongoDB driver for Go

// Copyright (c) 2010-2013 - Gustavo Niemeyer <gustavo@niemeyer.net>

// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:

// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package dbtest

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"gopkg.in/tomb.v2"
)

// DBServer controls a MongoDB server process to be used within test suites.
//
// The test server is started when Client is called the first time and should
// remain running for the duration of all tests, with the Wipe method being
// called between tests (before each of them) to clear stored data. After all tests
// are done, the Stop method should be called to stop the test server.
//
// Before the DBServer is used the SetPath method must be called to define
// the location for the database files to be stored.
type DBServer struct {
	Ctx     context.Context
	timeout time.Duration
	client  *mongo.Client
	output  bytes.Buffer
	server  *exec.Cmd
	dbpath  string
	host    string
	tomb    tomb.Tomb
}

// SetPath defines the path to the directory where the database files will be
// stored if it is started. The directory path itself is not created or removed
// by the test helper.
func (dbs *DBServer) SetPath(dbpath string) {
	dbs.dbpath = dbpath
}

func (dbs *DBServer) SetTimeout(timeout int) {
	dbs.timeout = time.Duration(timeout)
}

func (dbs *DBServer) start() {
	if dbs.server != nil {
		panic("DBServer already started")
	}
	if dbs.dbpath == "" {
		panic("DBServer.SetPath must be called before using the server")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic("unable to listen on a local address: " + err.Error())
	}
	addr := l.Addr().(*net.TCPAddr)
	l.Close()
	dbs.host = addr.String()

	args := []string{
		"--dbpath", dbs.dbpath,
		"--bind_ip", "127.0.0.1",
		"--port", strconv.Itoa(addr.Port),
		"--nojournal",
	}
	dbs.tomb = tomb.Tomb{}
	dbs.server = exec.Command("mongod", args...)
	dbs.server.Stdout = &dbs.output
	dbs.server.Stderr = &dbs.output
	err = dbs.server.Start()
	if err != nil {
		// print error to facilitate troubleshooting as the panic will be caught in a panic handler
		fmt.Fprintf(os.Stderr, "mongod failed to start: %v\n", err)
		panic(err)
	}
	dbs.tomb.Go(dbs.monitor)
	dbs.Wipe()
}

func (dbs *DBServer) monitor() error {
	dbs.server.Process.Wait()
	if dbs.tomb.Alive() {
		// Present some debugging information.
		fmt.Fprintf(os.Stderr, "---- mongod process died unexpectedly:\n")
		fmt.Fprintf(os.Stderr, "%s", dbs.output.Bytes())
		fmt.Fprintf(os.Stderr, "---- mongod processes running right now:\n")
		cmd := exec.Command("/bin/sh", "-c", "ps auxw | grep mongod")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		cmd.Run()
		fmt.Fprintf(os.Stderr, "----------------------------------------\n")

		panic("mongod process died unexpectedly")
	}
	return nil
}

// Stop stops the test server process, if it is running.
//
// It's okay to call Stop multiple times. After the test server is
// stopped it cannot be restarted.
//
// All database clients must be closed before or while the Stop method
// is running. Otherwise Stop will panic after a timeout informing that
// there is a client leak.
func (dbs *DBServer) Stop() {
	if dbs.client != nil {
		if dbs.client != nil {
			dbs.client.Disconnect(dbs.Ctx)
			dbs.client = nil
		}
	}
	if dbs.server != nil {
		dbs.tomb.Kill(nil)
		// Windows doesn't support Interrupt
		if runtime.GOOS == "windows" {
			dbs.server.Process.Signal(os.Kill)
		} else {
			dbs.server.Process.Signal(os.Interrupt)
		}
		select {
		case <-dbs.tomb.Dead():
		case <-time.After(5 * time.Second):
			panic("timeout waiting for mongod process to die")
		}
		dbs.server = nil
	}
}

// Client returns a new client to the server. The returned client
// must be disconnected after the tests are finished.
//
// The first call to Client will start the DBServer.
func (dbs *DBServer) Client() *mongo.Client {
	if dbs.server == nil {
		dbs.start()
	}
	if dbs.client == nil {
		var err error

		if dbs.timeout == 0 {
			dbs.timeout = 8
		}
		clientOptions := options.Client().ApplyURI("mongodb://" + dbs.host + "/test")
		dbs.Ctx = context.Background() // context.WithTimeout(context.Background(), dbs.timeout*time.Second)
		dbs.client, err = mongo.Connect(dbs.Ctx, clientOptions)
		if err != nil {
			panic(err)
		}
		if dbs.client == nil {
			panic("cant connect")
		}
	}
	return dbs.client
}

func (dbs *DBServer) CTX() context.Context {
	return dbs.Ctx
}

// Wipe drops all created databases and their data.
func (dbs *DBServer) Wipe() {
	if dbs.server == nil || dbs.client == nil {
		return
	}
	client := dbs.Client()
	names, err := client.ListDatabaseNames(dbs.Ctx, bson.M{})
	if err != nil {
		panic(err)
	}
	for _, name := range names {
		switch name {
		case "admin", "local", "config":
		default:
			err = dbs.client.Database(name).Drop(dbs.Ctx)
			if err != nil {
				panic(err)
			}
		}
	}
}
