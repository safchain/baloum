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
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime/debug"
)

type MapProgArrayStorage struct {
	vm         *VM
	maxEntries uint32
	valueSize  uint32

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

	m.vm.SetBytes(m.data[idx], value, uint64(m.valueSize))

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

	var value []byte

	switch valueSize {
	case 4:
		value = make([]byte, 4)
		binary.NativeEndian.PutUint32(value, math.MaxUint32)
	case 8:
		value = make([]byte, 8)
		binary.NativeEndian.PutUint64(value, math.MaxUint64)
	default:
		debug.PrintStack()
		return nil, fmt.Errorf("value size not supported: %d", valueSize)
	}

	for i := range data {
		data[i] = vm.heap.AllocWith(value)
	}

	return &MapProgArrayStorage{
		vm:         vm,
		maxEntries: maxEntries,
		valueSize:  valueSize,
		data:       data,
	}, nil
}
