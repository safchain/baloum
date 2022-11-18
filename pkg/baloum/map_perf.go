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

import "errors"

type MapPerfStorage struct {
	vm   *VM
	data chan []byte
}

func (m *MapPerfStorage) Lookup(key []byte) (uint64, error) {
	return 0, errors.New("operation not supported")
}

func (m *MapPerfStorage) Update(key []byte, value []byte, kind MapUpdateType) (bool, error) {
	return false, errors.New("operation not supported")
}

func (m *MapPerfStorage) Delete(key []byte) (bool, error) {
	return false, errors.New("operation not supported")
}

func (m *MapPerfStorage) Keys() ([][]byte, error) {
	return nil, errors.New("operation not supported")
}

func (m *MapPerfStorage) Read() (<-chan []byte, error) {
	return m.data, nil
}

func (m *MapPerfStorage) Write(data []byte) error {
	select {
	case m.data <- data:
	default:
		return errors.New("chan busy")
	}
	return nil
}

func NewMapPerfStorage(vm *VM, id int, keySize, valueSize, maxEntries, flags uint32) (MapStorage, error) {
	return &MapPerfStorage{
		vm:   vm,
		data: make(chan []byte, 1000),
	}, nil
}
