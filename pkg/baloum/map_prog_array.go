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

import (
	"errors"
	"fmt"
)

type MapProgArrayStorage struct {
	vm         *VM
	maxEntries uint32

	data []uint64
}

func (m *MapProgArrayStorage) Lookup(key []byte) (uint64, error) {
	idx, err := mapArrayKeyIndex(key)
	if err != nil {
		return 0, err
	}

	if idx > len(m.data) {
		return 0, errors.New("out of bound")
	}

	fmt.Printf(">>>>>>>>>: %+v\n", m.data)

	return m.data[idx], nil
}

func (m *MapProgArrayStorage) Update(key []byte, value []byte, kind MapUpdateType) (bool, error) {
	idx, err := mapArrayKeyIndex(key)
	if err != nil {
		return false, err
	}

	if idx > len(m.data) {
		return false, errors.New("out of bound")
	}

	m.vm.heap.Free(m.data[idx])
	m.data[idx] = m.vm.heap.AllocWith(value)

	fmt.Printf(">>>>>>>>>: %+v\n", m.data)

	return true, nil
}

func (m *MapProgArrayStorage) Delete(key []byte) (bool, error) {
	return false, errors.New("operation not supported")
}

func (m *MapProgArrayStorage) Keys() ([][]byte, error) {
	return nil, errors.New("operation not supported")
}

func (m *MapProgArrayStorage) Read() (<-chan []byte, error) {
	return nil, errors.New("operation not supported")
}

func (m *MapProgArrayStorage) Write(data []byte) error {
	return errors.New("operation not supported")
}

func NewMapProgArrayStorage(vm *VM, keySize, valueSize, maxEntries, flags uint32) (MapStorage, error) {
	data := make([]uint64, maxEntries)
	for i := range data {
		data[i] = vm.heap.Alloc(int(valueSize))
	}

	return &MapProgArrayStorage{
		vm:         vm,
		maxEntries: maxEntries,
		data:       data,
	}, nil
}
