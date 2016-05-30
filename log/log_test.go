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
package log

import (
	"github.com/Sirupsen/logrus"
	"testing"
)

func TestNew(t *testing.T) {
	l := New("foo")

	if l.Module != "foo" {
		t.Fatalf("incorrect module, expected foo, got %s", l.Module)
	}
}

func TestSetup(t *testing.T) {
	// setup with debug on
	Setup(false)

	l := New("foo")

	if l.Level != logrus.InfoLevel {
		t.Fatalf("expected info level")
	}

	Setup(true)

	l = New("foo")

	if l.Level != logrus.DebugLevel {
		t.Fatalf("expected debug level")
	}

}

func TestWithFields(t *testing.T) {

	Setup(false)

	l := New("foo")

	exp := map[string]interface{}{
		"bar":    1,
		"baz":    "cafe",
		"module": "foo",
	}
	e := l.WithFields(logrus.Fields{
		"bar": exp["bar"],
		"baz": exp["baz"],
	})

	if len(e.Data) != len(exp) {
		t.Fatalf("log fields number mismatch: expected %v got %v",
			len(exp), len(e.Data))
	}

	for k, v := range e.Data {
		ev, ok := exp[k]
		if ok != true {
			t.Fatalf("unexpected key: %s", k)
		}
		if ev != v {
			t.Fatalf("value mismatch: got %+v expected %+v",
				v, ev)
		}
	}
}
