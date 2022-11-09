/*
Copyright © 2022 SYLVAIN AFCHAIN

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package baloum

type Logger interface {
	Info(params ...interface{})
	Infof(format string, params ...interface{})

	Debug(params ...interface{})
	Debugf(format string, params ...interface{})

	Error(params ...interface{})
	Errorf(format string, params ...interface{})
}

type NullLogger struct{}

func (l NullLogger) Debug(params ...interface{})                 {}
func (l NullLogger) Debugf(format string, params ...interface{}) {}

func (l NullLogger) Error(params ...interface{})                 {}
func (l NullLogger) Errorf(format string, params ...interface{}) {}

func (l NullLogger) Info(params ...interface{})                 {}
func (l NullLogger) Infof(format string, params ...interface{}) {}
