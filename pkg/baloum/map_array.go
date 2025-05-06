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
)

// MapArrayStorage is the type for the map array storage
type MapArrayStorage struct {
	vm         *VM
	maxEntries uint32
	valueSize  uint32

	data []uint64
}

// mapArrayKeyIndex converts a key to an index
func mapArrayKeyIndex(key []byte) (int, error) {
	var idx int
	switch len(key) {
	case 2:
		idx = int(binary.NativeEndian.Uint16(key))
	case 4:
		idx = int(binary.NativeEndian.Uint32(key))
	case 8:
		idx = int(binary.NativeEndian.Uint64(key))
	default:
		return 0, errors.New("incorrect key size")
	}

	return idx, nil
}

// Lookup looks up a key in the map
func (m *MapArrayStorage) Lookup(key []byte) (uint64, error) {
	idx, err := mapArrayKeyIndex(key)
	if err != nil {
		return 0, err
	}

	if idx > len(m.data) {
		return 0, errors.New("out of bound")
	}

	return m.data[idx], nil
}

// Update updates a key in the map
func (m *MapArrayStorage) Update(key []byte, value []byte, kind MapUpdateType) (bool, error) {
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

// Delete deletes a key in the map
func (m *MapArrayStorage) Delete(key []byte) (bool, error) {
	return false, errors.New("operation not supported")
}

// Keys returns the keys of the map
func (m *MapArrayStorage) Keys() ([][]byte, error) {
	var keys [][]byte

	for idx := range m.data {
		key := make([]byte, 4)
		binary.NativeEndian.PutUint32(key, uint32(idx))
		keys = append(keys, key)
	}

	return keys, nil
}

// Read reads the map
func (m *MapArrayStorage) Read() (<-chan []byte, error) {
	return nil, errors.New("operation not supported")
}

// Write writes to the map
func (m *MapArrayStorage) Write(data []byte) error {
	return errors.New("operation not supported")
}

// NewMapArrayStorage creates a new map array storage
func NewMapArrayStorage(vm *VM, keySize, valueSize, maxEntries, flags uint32) (MapStorage, error) {
	data := make([]uint64, maxEntries)
	for i := range data {
		data[i] = vm.heap.Alloc(int(valueSize))
	}

	return &MapArrayStorage{
		vm:         vm,
		maxEntries: maxEntries,
		valueSize:  valueSize,
		data:       data,
	}, nil
}
