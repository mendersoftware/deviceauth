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
)

type Logger struct {
	logrus.Logger
	Module string
}

var (
	loggerBase = logrus.New()
)

func Setup(debug bool) {
	if debug == true {
		loggerBase.Level = logrus.DebugLevel
	} else {
		loggerBase.Level = logrus.InfoLevel
	}

	loggerBase.Formatter = &logrus.TextFormatter{
		FullTimestamp: true,
	}
}

// return new logger with Module set to `name`
func New(name string) *Logger {
	logger := Logger{
		// inherit config from standard logger
		Logger: *loggerBase,
		Module: name,
	}

	return &logger
}

// return new logrus.Entry with field 'module' filled with module name
// (as passed to New())
func (l *Logger) WithFields(fields logrus.Fields) *logrus.Entry {
	fields["module"] = l.Module

	return l.Logger.WithFields(fields)
}
